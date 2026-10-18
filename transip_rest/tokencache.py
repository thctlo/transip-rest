"""File-based cache for a single TransIP API access token.

Mirrors the design TransIP's own Go SDK uses for the same purpose
(transip/gotransip, authenticator/filetokencache.go): persist the last
good token to disk, keyed by a name derived from the account, so a
still-valid token survives across separate process invocations instead
of being re-requested under the same label every time - which is what
causes the "label ... already used in another active access token"
error when the previous token has not expired yet.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional, Union


class FileTokenCache:
    """Reads/writes one cached token in a single JSON file.

    Best-effort by design: any failure to read or write the cache file
    (missing directory, permission denied, corrupt content) is treated
    as a cache miss / no-op rather than an error - caching is purely an
    optimization, it must never be able to break the actual DNS
    operation the caller is trying to perform.
    """

    def __init__(self, path: Union[str, os.PathLike], key: str) -> None:
        self._path = Path(path)
        self._key = key

    def get(self) -> Optional[str]:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(data, dict) or data.get("key") != self._key:
            return None
        token = data.get("token")
        return token if isinstance(token, str) and token else None

    def set(self, token: str) -> None:
        payload = {"key": self._key, "token": token}
        tmp_path = self._path.with_name(self._path.name + f".{os.getpid()}.tmp")
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.replace(tmp_path, self._path)
        except OSError:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def clear(self) -> None:
        try:
            self._path.unlink(missing_ok=True)
        except OSError:
            pass
