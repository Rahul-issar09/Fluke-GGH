"""LP5/LP6 — where the Gemini key comes from, that AEGIS never saves it, and that texts are scrubbed of it.

Decision Q-4 (revised 2026-10-22): the key is asked for every run and kept in memory only. An
operator may still provide it through the environment or a key file — AEGIS itself never writes it.
"""

from __future__ import annotations

import pytest

from aegis.llm.base import LlmError
from aegis.llm.secrets import ENV_KEY, ENV_KEY_FILE, SecretRegistry, SecretStore, check_key_shape, fingerprint, last4

pytestmark = pytest.mark.phase("LP5")

KEY = "AIzaSyLP5-secret-test-key-0000000000001"
OTHER = "AIzaSyLP5-unrelated-google-key-00000002"


def store(environ=None, registry=None):
    return SecretStore(environ or {}, registry=registry or SecretRegistry())


# ---------------------------------------------------------------- reading
def test_nothing_configured():
    assert store().get() is None


def test_environment_wins_then_file_then_this_session(tmp_path):
    key_file = tmp_path / "gemini.key"
    key_file.write_text("AIzaSyFROM-file-0000000000000000000000004\n", encoding="utf-8")
    s = store({ENV_KEY: KEY, ENV_KEY_FILE: str(key_file)})
    s.put(OTHER)
    assert s.get().source == "env"
    s = store({ENV_KEY_FILE: str(key_file)})
    s.put(OTHER)
    assert s.get().source == "file"
    s = store()
    s.put(OTHER)
    assert (s.get().source, s.get().value.get_secret_value()) == ("session", OTHER)


def test_the_sdks_own_variables_are_never_read():
    assert store({"GOOGLE_API_KEY": OTHER, "GEMINI_API_KEY": OTHER}).get() is None


def test_a_stored_key_never_shows_itself():
    stored = store({ENV_KEY: KEY}).get()
    assert KEY not in repr(stored) and KEY not in str(stored.describe())
    assert stored.describe() == {"configured": True, "source": "env", "fingerprint": fingerprint(KEY), "last4": "0001"}


# ---------------------------------------------------------------- the session key: memory only, never saved
def test_put_keeps_the_key_in_memory_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = store()
    stored = s.put(f"  {KEY}\n")
    assert stored.source == "session" and s.get().value.get_secret_value() == KEY
    assert list(tmp_path.iterdir()) == []


def test_a_new_process_does_not_know_the_key():
    first = store()
    first.put(KEY)
    assert store().get() is None            # what a restart looks like: the key must be entered again


def test_delete_forgets_the_session_key():
    s = store()
    s.put(KEY)
    assert s.delete() is True and s.get() is None and s.delete() is False


def test_no_aegis_code_uses_a_persistent_key_store():
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "aegis"
    users = []
    for py in root.rglob("*.py"):
        for node in ast.walk(ast.parse(py.read_text(encoding="utf-8"))):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else (
                [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            if any(n.split(".")[0] == "keyring" for n in names):
                users.append(str(py.relative_to(root)))
    assert users == []


# ---------------------------------------------------------------- shape, fingerprint, scrubbing
@pytest.mark.parametrize("bad", ["", "short", "has spaces in it 1234567890", "x" * 300, "AIza\nSy" + "0" * 30])
def test_odd_keys_are_refused_before_any_network_call(bad):
    with pytest.raises(LlmError) as err:
        check_key_shape(bad)
    assert err.value.kind == "invalid_api_key"


def test_fingerprint_and_last4():
    assert fingerprint(KEY).startswith("sha256:") and len(fingerprint(KEY)) == len("sha256:") + 16
    assert fingerprint(KEY) != fingerprint(OTHER) and KEY not in fingerprint(KEY)
    assert last4(KEY) == "0001" and last4("short-key") is None


def test_scrub_removes_known_keys_and_anything_shaped_like_one():
    reg = SecretRegistry()
    reg.register("custom-secret-value-123")
    text = f"failed for {KEY} and custom-secret-value-123 at https://x/?key={OTHER}"
    out = reg.scrub(text)
    assert KEY not in out and OTHER not in out and "custom-secret-value-123" not in out
    assert out.count("[REDACTED]") == 3


def test_entering_or_reading_a_key_registers_it_for_scrubbing():
    reg = SecretRegistry()
    store({ENV_KEY: "plain-but-long-secret-0000000000"}, registry=reg).get()
    store(registry=reg).put("another-plain-long-secret-00000")
    out = reg.scrub("x plain-but-long-secret-0000000000 y another-plain-long-secret-00000")
    assert "plain-but-long" not in out and "another-plain" not in out
