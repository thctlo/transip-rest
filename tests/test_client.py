"""Unit tests for transip_rest.client - fully mocked, no live API calls."""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from transip_rest.client import TransipClient, _sign
from transip_rest.exceptions import TransipApiError


@pytest.fixture
def private_key_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _make_jwt(exp: float) -> str:
    """Build a minimal, structurally-valid JWT string with a given `exp`.

    The signature part is never checked by our client (TransIP's server
    is the one that verifies it), so it's left as an arbitrary string -
    only the header/payload shape needs to be real base64url+JSON.
    """

    def _b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f'{_b64({"alg": "RS256", "typ": "JWT"})}.{_b64({"exp": exp})}.sig'


def test_sign_produces_verifiable_signature(private_key_pem):
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    message = b'{"login": "test", "nonce": "abc"}'
    signature_b64 = _sign(message, key)
    signature = base64.b64decode(signature_b64)
    # Must verify against the matching public key with the same
    # padding/hash scheme TransIP documents (PKCS#1 v1.5 + SHA-512).
    key.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA512())


def test_get_token_sends_signed_request_and_caches(private_key_pem, requests_mock):
    requests_mock.post(
        "https://api.transip.nl/v6/auth",
        json={"token": "fake-jwt-token"},
        status_code=201,
    )
    client = TransipClient(username="testuser", private_key_pem=private_key_pem)
    token = client._get_token()
    assert token == "fake-jwt-token"
    assert requests_mock.call_count == 1

    # Calling again must not re-request a token: it should be cached.
    client._get_token()
    assert requests_mock.call_count == 1

    sent = requests_mock.request_history[0]
    assert "Signature" in sent.headers
    body = json.loads(sent.body)
    assert body["login"] == "testuser"
    assert len(body["nonce"]) == 32


def test_find_domain_matches_longest_suffix(private_key_pem, requests_mock):
    requests_mock.post("https://api.transip.nl/v6/auth", json={"token": "t"}, status_code=201)
    requests_mock.get(
        "https://api.transip.nl/v6/domains",
        json={"domains": [{"name": "example.com"}]},
    )
    client = TransipClient(username="u", private_key_pem=private_key_pem)
    assert client.find_domain("_acme-challenge.www.example.com") == "example.com"


def test_find_domain_raises_when_not_found(private_key_pem, requests_mock):
    requests_mock.post("https://api.transip.nl/v6/auth", json={"token": "t"}, status_code=201)
    requests_mock.get("https://api.transip.nl/v6/domains", json={"domains": []})
    client = TransipClient(username="u", private_key_pem=private_key_pem)
    with pytest.raises(TransipApiError):
        client.find_domain("example.com")


def test_api_error_raises_with_message(private_key_pem, requests_mock):
    requests_mock.post("https://api.transip.nl/v6/auth", json={"token": "t"}, status_code=201)
    requests_mock.get(
        "https://api.transip.nl/v6/domains/example.com/dns",
        json={"error": "Domain with name 'example.com' not found"},
        status_code=404,
    )
    client = TransipClient(username="u", private_key_pem=private_key_pem)
    with pytest.raises(TransipApiError, match="not found"):
        client.list_dns_entries("example.com")


def test_create_dns_entry_posts_correct_body(private_key_pem, requests_mock):
    requests_mock.post("https://api.transip.nl/v6/auth", json={"token": "t"}, status_code=201)
    requests_mock.post("https://api.transip.nl/v6/domains/example.com/dns", status_code=201)
    client = TransipClient(username="u", private_key_pem=private_key_pem)
    client.create_dns_entry("example.com", "_acme-challenge", "TXT", "abc123", expire=60)

    sent = requests_mock.request_history[-1]
    body = json.loads(sent.body)
    assert body == {
        "dnsEntry": {"name": "_acme-challenge", "expire": 60, "type": "TXT", "content": "abc123"}
    }


def test_delete_dns_entry_sends_delete_with_body(private_key_pem, requests_mock):
    requests_mock.post("https://api.transip.nl/v6/auth", json={"token": "t"}, status_code=201)
    requests_mock.delete("https://api.transip.nl/v6/domains/example.com/dns", status_code=204)
    client = TransipClient(username="u", private_key_pem=private_key_pem)
    client.delete_dns_entry("example.com", "_acme-challenge", "TXT", "abc123", expire=60)

    sent = requests_mock.request_history[-1]
    assert sent.method == "DELETE"
    body = json.loads(sent.body)
    assert body["dnsEntry"]["content"] == "abc123"


def test_update_dns_entry_sends_patch_with_body(private_key_pem, requests_mock):
    requests_mock.post("https://api.transip.nl/v6/auth", json={"token": "t"}, status_code=201)
    requests_mock.patch("https://api.transip.nl/v6/domains/example.com/dns", status_code=204)
    client = TransipClient(username="u", private_key_pem=private_key_pem)
    client.update_dns_entry("example.com", "_acme-challenge", "TXT", "new-content", expire=60)

    sent = requests_mock.request_history[-1]
    assert sent.method == "PATCH"
    body = json.loads(sent.body)
    assert body == {
        "dnsEntry": {"name": "_acme-challenge", "expire": 60, "type": "TXT", "content": "new-content"}
    }


def test_each_token_request_gets_a_unique_label(private_key_pem, requests_mock):
    """Regression test for the root cause of the original bug: a fixed,
    reused label is what made a second auth request collide with the
    still-active token from the first ("label ... already used in
    another active access token"). Each request must carry its own
    unique label under the configured prefix."""
    requests_mock.post(
        "https://api.transip.nl/v6/auth",
        [
            {"json": {"token": _make_jwt(time.time() - 10)}, "status_code": 201},
            {"json": {"token": _make_jwt(time.time() + 3600)}, "status_code": 201},
        ],
    )
    client = TransipClient(username="u", private_key_pem=private_key_pem, label="certbot-dns-transip")
    client._get_token()
    client.invalidate_token()
    client._get_token()

    assert requests_mock.call_count == 2
    labels = [json.loads(req.body)["label"] for req in requests_mock.request_history]
    assert labels[0] != labels[1]
    assert all(label.startswith("certbot-dns-transip-") for label in labels)


def test_token_with_future_expiry_is_reused_in_memory(private_key_pem, requests_mock):
    requests_mock.post(
        "https://api.transip.nl/v6/auth",
        json={"token": _make_jwt(time.time() + 3600)},
        status_code=201,
    )
    client = TransipClient(username="u", private_key_pem=private_key_pem)
    client._get_token()
    client._get_token()
    client._get_token()

    assert requests_mock.call_count == 1


def test_token_near_expiry_is_not_reused(private_key_pem, requests_mock):
    """A token inside the safety skew must be treated as already expired."""
    requests_mock.post(
        "https://api.transip.nl/v6/auth",
        json={"token": _make_jwt(time.time() + 5)},
        status_code=201,
    )
    client = TransipClient(username="u", private_key_pem=private_key_pem)
    client._get_token()
    client._get_token()

    assert requests_mock.call_count == 2


def test_token_is_persisted_and_reused_across_client_instances(
    private_key_pem, requests_mock, tmp_path
):
    cache_path = tmp_path / "token-cache.json"
    requests_mock.post(
        "https://api.transip.nl/v6/auth",
        json={"token": _make_jwt(time.time() + 3600)},
        status_code=201,
    )
    requests_mock.get(
        "https://api.transip.nl/v6/domains", json={"domains": [{"name": "example.com"}]}
    )

    first_client = TransipClient(
        username="u", private_key_pem=private_key_pem, token_cache_path=cache_path
    )
    first_client._get_token()
    assert requests_mock.call_count == 1

    # A brand new client instance (simulating a separate certbot process)
    # must pick up the still-valid cached token instead of requesting a
    # fresh one under the same label.
    second_client = TransipClient(
        username="u", private_key_pem=private_key_pem, token_cache_path=cache_path
    )
    second_client.list_domains()

    auth_calls = [r for r in requests_mock.request_history if r.path == "/v6/auth"]
    assert len(auth_calls) == 1  # auth was NOT called again


def test_cached_token_for_a_different_label_is_ignored(private_key_pem, requests_mock, tmp_path):
    cache_path = tmp_path / "token-cache.json"
    requests_mock.post(
        "https://api.transip.nl/v6/auth",
        json={"token": _make_jwt(time.time() + 3600)},
        status_code=201,
    )

    client_a = TransipClient(
        username="u", private_key_pem=private_key_pem, label="label-a", token_cache_path=cache_path
    )
    client_a._get_token()
    assert requests_mock.call_count == 1

    client_b = TransipClient(
        username="u", private_key_pem=private_key_pem, label="label-b", token_cache_path=cache_path
    )
    client_b._get_token()
    assert requests_mock.call_count == 2


def test_expired_token_triggers_one_retry_with_fresh_token(private_key_pem, requests_mock):
    requests_mock.post(
        "https://api.transip.nl/v6/auth",
        [
            {"json": {"token": _make_jwt(time.time() + 3600)}, "status_code": 201},
            {"json": {"token": _make_jwt(time.time() + 3600)}, "status_code": 201},
        ],
    )
    requests_mock.get(
        "https://api.transip.nl/v6/domains",
        [
            {"status_code": 401, "json": {"error": "invalid token"}},
            {"json": {"domains": [{"name": "example.com"}]}, "status_code": 200},
        ],
    )
    client = TransipClient(username="u", private_key_pem=private_key_pem)

    domains = client.list_domains()

    assert domains == ["example.com"]
    # one initial auth + one re-auth after the 401, no more
    auth_calls = [r for r in requests_mock.request_history if r.path == "/v6/auth"]
    assert len(auth_calls) == 2


def test_persistent_401_is_raised_not_swallowed(private_key_pem, requests_mock):
    requests_mock.post(
        "https://api.transip.nl/v6/auth",
        json={"token": _make_jwt(time.time() + 3600)},
        status_code=201,
    )
    requests_mock.get(
        "https://api.transip.nl/v6/domains",
        status_code=401,
        json={"error": "invalid token"},
    )
    client = TransipClient(username="u", private_key_pem=private_key_pem)

    with pytest.raises(TransipApiError):
        client.list_domains()


def test_duplicate_label_error_gets_a_clear_explanation(private_key_pem, requests_mock):
    requests_mock.post(
        "https://api.transip.nl/v6/auth",
        status_code=401,
        json={"error": "The label 'certbot-dns-transip-abc123' is already used in another active access token."},
    )
    client = TransipClient(username="u", private_key_pem=private_key_pem, label="certbot-dns-transip")

    with pytest.raises(TransipApiError, match="control panel"):
        client._get_token()


def test_private_key_and_token_never_appear_in_logs(private_key_pem, requests_mock, caplog, tmp_path):
    token = _make_jwt(time.time() + 3600)
    requests_mock.post("https://api.transip.nl/v6/auth", json={"token": token}, status_code=201)
    requests_mock.get(
        "https://api.transip.nl/v6/domains", json={"domains": [{"name": "example.com"}]}
    )

    with caplog.at_level("DEBUG"):
        client = TransipClient(
            username="u",
            private_key_pem=private_key_pem,
            token_cache_path=tmp_path / "cache.json",
        )
        client.list_domains()

    log_text = caplog.text
    assert token not in log_text
    assert private_key_pem.decode() not in log_text
