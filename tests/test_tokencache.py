"""Unit tests for transip_rest.tokencache.FileTokenCache."""
import os

from transip_rest.tokencache import FileTokenCache


def test_get_returns_none_when_file_does_not_exist(tmp_path):
    cache = FileTokenCache(tmp_path / "missing.json", key="user:label")
    assert cache.get() is None


def test_set_then_get_round_trips(tmp_path):
    path = tmp_path / "cache.json"
    cache = FileTokenCache(path, key="user:label")
    cache.set("the-token")
    assert cache.get() == "the-token"


def test_set_writes_file_with_restrictive_permissions(tmp_path):
    path = tmp_path / "cache.json"
    cache = FileTokenCache(path, key="user:label")
    cache.set("the-token")
    mode = os.stat(path).st_mode & 0o777
    assert mode == 0o600


def test_get_ignores_cache_for_a_different_key(tmp_path):
    path = tmp_path / "cache.json"
    cache_a = FileTokenCache(path, key="user-a:label")
    cache_a.set("token-a")

    cache_b = FileTokenCache(path, key="user-b:label")
    assert cache_b.get() is None


def test_get_ignores_corrupt_cache_file(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text("not valid json{{{")
    cache = FileTokenCache(path, key="user:label")
    assert cache.get() is None


def test_clear_removes_the_file(tmp_path):
    path = tmp_path / "cache.json"
    cache = FileTokenCache(path, key="user:label")
    cache.set("the-token")
    assert path.exists()

    cache.clear()
    assert not path.exists()


def test_clear_on_missing_file_does_not_raise(tmp_path):
    cache = FileTokenCache(tmp_path / "missing.json", key="user:label")
    cache.clear()  # must not raise


def test_set_in_unwritable_directory_does_not_raise(tmp_path):
    missing_dir = tmp_path / "no-such-dir" / "cache.json"
    cache = FileTokenCache(missing_dir, key="user:label")
    cache.set("the-token")  # best-effort: must not raise
    assert cache.get() is None
