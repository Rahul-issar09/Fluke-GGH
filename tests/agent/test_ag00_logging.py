"""Tests for AG00.1 — logging & observability setup."""

from __future__ import annotations

import ast
import io
import json
import pathlib

import pytest

from aegis import config, observability as obs

pytestmark = pytest.mark.phase("AG00")

_AEGIS_DIR = pathlib.Path(__file__).resolve().parents[2] / "aegis"


@pytest.fixture(autouse=True)
def _reset_logging():
    obs.reset_logging()
    obs.clear_ctx()
    yield
    obs.reset_logging()
    obs.clear_ctx()


def _capture(json_mode: bool = True) -> io.StringIO:
    stream = io.StringIO()
    obs.configure_logging(level="DEBUG", json=json_mode, stream=stream)
    return stream


def _last_record(stream: io.StringIO) -> dict:
    lines = [ln for ln in stream.getvalue().strip().splitlines() if ln.strip()]
    assert lines, "no log output captured"
    return json.loads(lines[-1])


def test_logger_namespaced():
    stream = _capture()
    obs.get_logger("evidence").info("hello")
    rec = _last_record(stream)
    assert rec["logger"] == "aegis.evidence"
    assert rec["event"] == "hello"
    assert rec["level"] == "info"
    assert "timestamp" in rec


def test_context_bound_in_record():
    stream = _capture()
    obs.bind(scan_id="S-0001", node="check_bola", tool="bola")
    obs.get_logger("workers.runtime").info("checking")
    rec = _last_record(stream)
    assert rec["scan_id"] == "S-0001"
    assert rec["node"] == "check_bola"
    assert rec["tool"] == "bola"


def test_clear_ctx_removes_context():
    stream = _capture()
    obs.bind(scan_id="S-0001")
    obs.clear_ctx()
    obs.get_logger("api").info("after clear")
    rec = _last_record(stream)
    assert "scan_id" not in rec


def test_redact_hides_secret_value():
    stream = _capture()
    obs.get_logger("safety").info("tool call", api_key="sk_live_SUPERSECRET", note="ok")
    raw = stream.getvalue()
    rec = _last_record(stream)
    assert "sk_live_SUPERSECRET" not in raw
    assert rec["api_key"] == obs.REDACTED
    assert rec["note"] == "ok"


def test_redact_function_nested():
    red = obs.redact(
        {
            "outer": {"password": "p", "ok": 1},
            "payload_json": "big raw body",
            "items": [{"authorization": "Bearer x"}, {"safe": 2}],
        }
    )
    assert red["outer"]["password"] == obs.REDACTED
    assert red["outer"]["ok"] == 1
    assert red["payload_json"] == obs.REDACTED
    assert red["items"][0]["authorization"] == obs.REDACTED
    assert red["items"][1]["safe"] == 2


def test_request_id_not_redacted():
    # 'request_id' must survive even though 'request' is a redacted payload key.
    stream = _capture()
    obs.bind(request_id="R-1")
    obs.get_logger("api").info("req")
    rec = _last_record(stream)
    assert rec["request_id"] == "R-1"
    assert obs.redact({"request": "body"})["request"] == obs.REDACTED


def test_double_configure_idempotent():
    stream = _capture()
    # second call with a different stream must be ignored (no duplicate handler)
    obs.configure_logging(level="DEBUG", json=True, stream=io.StringIO())
    obs.get_logger("x").info("once")
    lines = [ln for ln in stream.getvalue().strip().splitlines() if ln.strip()]
    assert len(lines) == 1


def test_logging_settings_defaults_and_env(monkeypatch):
    monkeypatch.delenv("AEGIS_LOGGING__LEVEL", raising=False)
    monkeypatch.delenv("AEGIS_LOGGING__JSON", raising=False)
    s = config.get_logging_settings()
    assert s.level == "INFO" and s.json is True

    monkeypatch.setenv("AEGIS_LOGGING__LEVEL", "DEBUG")
    monkeypatch.setenv("AEGIS_LOGGING__JSON", "false")
    s2 = config.get_logging_settings()
    assert s2.level == "DEBUG" and s2.json is False


def test_no_print_in_aegis():
    offenders: list[str] = []
    for py in _AEGIS_DIR.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "print"
            ):
                offenders.append(f"{py.relative_to(_AEGIS_DIR.parent)}:{n.lineno}")
    assert not offenders, f"print() found in aegis/: {offenders}"
