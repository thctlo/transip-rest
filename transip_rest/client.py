"""Minimal REST client for the TransIP API v6.

Implements only the authentication flow and the generic DNS entry
operations (list/create/delete) needed by callers such as the
certbot-dns-transip plugin and the transip-dns CLI. Not a full wrapper
of TransIP's API.

The authentication signing scheme (RSA PKCS#1 v1.5 padding, SHA-512,
standard base64 encoding of the signature, POST body to /v6/auth) and
the DNS entry endpoint shapes come from TransIP's own API
documentation (https://api.transip.nl/rest/docs.html, section
"Authentication" and "Domains > DNS") and were cross-checked for
correctness against two independently licensed open source clients
(no code copied from either): roaldnefs/python-transip (LGPL-3.0) and
Jerrythafast/transip-dyndns (GPL-3.0).
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import string
import time
from pathlib import Path
from typing import Optional, Union

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .exceptions import TransipApiError
from .tokencache import FileTokenCache

API_BASE = "https://api.transip.nl/v6"
_NONCE_ALPHABET = string.ascii_letters + string.digits

# TransIP access tokens are JWTs (https://jwt.io/) whose "exp" claim is
# exactly what the server itself enforces - decoding it directly avoids
# having to re-derive an expiry from the free-form `expiration_time`
# string we sent in the request (e.g. "30 minutes"). A token within this
# many seconds of its real expiry is treated as already expired, so a
# request never starts with a token that could expire mid-flight.
_EXPIRY_SKEW_SECONDS = 30

# Label for a *new* token request is always this prefix plus a random,
# unique suffix (see _get_token). TransIP's API rejects a request for a
# new token under a label that still has an active (unexpired) token -
# a fixed, reused label is what causes "... already used in another
# active access token" once a previous call's token hasn't expired yet.
# TransIP's own Go SDK (transip/gotransip, authenticator/authenticator.go)
# uses the same pattern: a stable prefix for human recognisability in
# the control panel, with a unique suffix per request so two requests
# can never collide.
_LABEL_SUFFIX_LENGTH = 12


def _generate_nonce(length: int = 32) -> str:
    return "".join(secrets.choice(_NONCE_ALPHABET) for _ in range(length))


def _sign(message: bytes, private_key) -> str:
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA512())
    return base64.b64encode(signature).decode("ascii")


def _decode_jwt_expiry(token: str) -> Optional[float]:
    """Return a JWT's `exp` claim as a unix timestamp, or None if undecodable."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    padded_payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded_payload))
    except (ValueError, binascii.Error):
        return None
    exp = payload.get("exp") if isinstance(payload, dict) else None
    return float(exp) if isinstance(exp, (int, float)) else None


class TransipClient:
    """Client for TransIP API v6: authentication and DNS entry management."""

    def __init__(
        self,
        username: str,
        private_key_pem: bytes,
        global_key: bool = False,
        token_expiration: str = "30 minutes",
        label: str = "transip-rest",
        token_cache_path: Optional[Union[str, os.PathLike]] = None,
    ) -> None:
        self._username = username
        self._private_key = serialization.load_pem_private_key(
            private_key_pem, password=None
        )
        self._global_key = global_key
        self._token_expiration = token_expiration
        self._label_prefix = label
        self._session = requests.Session()
        self._token: Optional[str] = None
        self._token_expires_at: Optional[float] = None
        self._token_cache = (
            FileTokenCache(Path(token_cache_path), key=f"{username}:{label}")
            if token_cache_path is not None
            else None
        )

    def _token_is_valid(self) -> bool:
        if self._token is None:
            return False
        if self._token_expires_at is None:
            # Created by us earlier this same process and not decodable as
            # a JWT (shouldn't normally happen) - there is no cache or
            # second process involved, so the in-memory copy is trusted
            # for the rest of this process's lifetime.
            return True
        return time.time() + _EXPIRY_SKEW_SECONDS < self._token_expires_at

    def _adopt_token(self, token: str) -> None:
        self._token = token
        self._token_expires_at = _decode_jwt_expiry(token)

    def invalidate_token(self) -> None:
        """Drop the in-memory and cached token so the next call requests a fresh one."""
        self._token = None
        self._token_expires_at = None
        if self._token_cache is not None:
            self._token_cache.clear()

    def _get_token(self) -> str:
        if self._token_is_valid():
            return self._token

        if self._token_cache is not None and self._token is None:
            cached = self._token_cache.get()
            if cached:
                self._adopt_token(cached)
                if self._token_is_valid():
                    return self._token
                self._token = None
                self._token_expires_at = None

        # A unique suffix per request means two requests - even made
        # moments apart, e.g. _perform() then _cleanup() - never collide
        # on label, which is what previously caused "the label ... is
        # already used in another active access token": the prior token
        # (same fixed label) simply hadn't expired yet.
        label = f"{self._label_prefix}-{_generate_nonce(_LABEL_SUFFIX_LENGTH)}"
        body = {
            "login": self._username,
            "nonce": _generate_nonce(),
            "read_only": False,
            "expiration_time": self._token_expiration,
            "label": label,
            "global_key": self._global_key,
        }
        request = requests.Request("POST", f"{API_BASE}/auth", json=body)
        prepared = self._session.prepare_request(request)
        # Sign the exact bytes that will be sent. Signing a separately
        # re-serialized copy of the body would produce a signature that
        # does not match what TransIP receives, and the request would be
        # rejected.
        signature = _sign(prepared.body, self._private_key)
        prepared.headers["Signature"] = signature

        response = self._session.send(prepared)
        try:
            data = self._parse_response(response)
        except TransipApiError as exc:
            if response.status_code == 401 and "already used in another active access token" in str(exc):
                raise TransipApiError(
                    f"A TransIP access token labelled {label!r} is already active and has "
                    "not expired yet. TransIP's API has no documented way to list or revoke "
                    "a token without already holding a valid one for it - either wait for it "
                    "to expire on its own, or revoke it manually in the TransIP control panel "
                    "under Account > API."
                ) from exc
            raise
        token = data.get("token")
        if not token:
            raise TransipApiError("Authentication response did not contain a token")
        self._adopt_token(token)
        if self._token_cache is not None and self._token_expires_at is not None:
            self._token_cache.set(self._token)
        return self._token

    @staticmethod
    def _parse_response(response: requests.Response) -> dict:
        if response.status_code >= 400:
            try:
                error = response.json().get("error", response.text)
            except ValueError:
                error = response.text
            raise TransipApiError(f"TransIP API error ({response.status_code}): {error}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise TransipApiError(f"Could not parse TransIP API response: {exc}") from exc

    def _request(
        self, method: str, path: str, json_body: Optional[dict] = None, _retry: bool = True
    ) -> dict:
        headers = {"Authorization": f"Bearer {self._get_token()}"}
        response = self._session.request(
            method, f"{API_BASE}{path}", json=json_body, headers=headers
        )
        if response.status_code == 401 and _retry:
            # The token we just used was rejected - expired earlier than
            # expected, or revoked out of band (e.g. via the control
            # panel). Drop it and retry exactly once with a fresh one
            # instead of surfacing a confusing auth error for what is
            # really just a stale token.
            self.invalidate_token()
            return self._request(method, path, json_body, _retry=False)
        return self._parse_response(response)

    def list_domains(self) -> list[str]:
        data = self._request("GET", "/domains")
        return [d["name"] for d in data.get("domains", [])]

    def find_domain(self, domain_name: str) -> str:
        """Find the base domain TransIP manages that matches a (sub)domain name."""
        domains = set(self.list_domains())
        if not domains:
            raise TransipApiError("TransIP API returned no domains for this account")
        labels = domain_name.split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in domains:
                return candidate
        raise TransipApiError(
            f"Could not find a TransIP-managed base domain for {domain_name!r}"
        )

    def list_dns_entries(self, domain: str) -> list[dict]:
        data = self._request("GET", f"/domains/{domain}/dns")
        return data.get("dnsEntries", [])

    def create_dns_entry(
        self, domain: str, name: str, record_type: str, content: str, expire: int = 86400
    ) -> None:
        entry = {"name": name, "expire": expire, "type": record_type, "content": content}
        self._request("POST", f"/domains/{domain}/dns", {"dnsEntry": entry})

    def delete_dns_entry(
        self, domain: str, name: str, record_type: str, content: str, expire: int = 86400
    ) -> None:
        entry = {"name": name, "expire": expire, "type": record_type, "content": content}
        self._request("DELETE", f"/domains/{domain}/dns", {"dnsEntry": entry})
