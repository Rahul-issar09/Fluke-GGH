"""LP6 — the API key never appears in logs, stored decisions, API errors, MCP output, audit or any file."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from aegis import observability as obs
from aegis.api.errors import error_response
from aegis.llm.base import ProviderId
from aegis.llm.consent import DISCLOSURE_VERSION, ConsentInput
from aegis.mcp.redaction import scrub_text
from aegis.secret_scrub import REGISTRY
from fakes.fake_provider import FakeProvider, manager_with, memory_secrets

pytestmark = pytest.mark.phase("LP6")

SENTINEL = "AIzaSyLEAK-sentinel-never-print-me-0099"   # Google-shaped, not real
PLAIN = "plain-secret-without-google-shape-0042"      # caught only because it is registered


@pytest.fixture
def logs():
    obs.reset_logging()
    stream = io.StringIO()
    obs.configure_logging(level="DEBUG", json=True, stream=stream)
    yield stream
    obs.reset_logging()


def test_logs_are_scrubbed_including_exceptions(logs):
    REGISTRY.register(PLAIN)
    log = obs.get_logger("test.leak")
    log.warning("llm.unparseable", error=f"bad answer for {SENTINEL}", detail={"nested": [PLAIN]})
    try:
        raise RuntimeError(f"client failed with key={SENTINEL} and {PLAIN}")
    except RuntimeError:
        log.exception("boom")
    out = logs.getvalue()
    assert "llm.unparseable" in out and "boom" in out
    assert SENTINEL not in out and PLAIN not in out


def test_stored_decisions_are_scrubbed(store):
    s = store.add_scan("code")
    d = store.add_decision(s.id, "explain", "fallback", error=f"llm unavailable: {SENTINEL}",
                           input_summary={"q": SENTINEL}, output={"why": SENTINEL})
    row = next(r for r in store.list_decisions(s.id) if r.id == d.id)
    assert SENTINEL not in (row.error + row.input_summary_json + row.output_json)


def test_api_error_details_are_scrubbed():
    body = json.loads(error_response(422, "invalid_api_key", f"Gemini refused {SENTINEL}").body)
    assert SENTINEL not in json.dumps(body)


def test_mcp_text_is_scrubbed():
    assert SENTINEL not in scrub_text(f"answer mentions {SENTINEL}")


async def test_a_whole_online_switch_leaves_the_key_nowhere_on_disk(tmp_path, logs):
    cloud = FakeProvider([RuntimeError(f"Gemini said no to {SENTINEL}")], provider=ProviderId.gemini, location="cloud")
    mgr = manager_with(tmp_path, FakeProvider(), cloud, secrets=memory_secrets(None))
    result, vid = await mgr.validate(ProviderId.gemini, "cloud-model", SENTINEL)
    status = await mgr.activate(ProviderId.gemini, "cloud-model", validation_id=vid, actor="ui",
                                consent=ConsentInput(disclosure_version=DISCLOSURE_VERSION, accepted=True))
    from aegis.agent.llm import structured_call
    from pydantic import BaseModel

    class Out(BaseModel):
        ok: bool

    with pytest.raises(RuntimeError):
        await structured_call(Out, "s", {"q": 1}, lambda _o: [], manager=mgr, scope="chat")
    await mgr.go_offline(actor="ui")

    assert SENTINEL not in json.dumps(status)
    assert SENTINEL not in logs.getvalue()
    leaked = [p for p in Path(tmp_path).rglob("*") if p.is_file() and SENTINEL.encode() in p.read_bytes()]
    assert leaked == []
    assert any(e["event"] == "provider_activated" for e in mgr.audit.read())     # the audit exists, without the key
