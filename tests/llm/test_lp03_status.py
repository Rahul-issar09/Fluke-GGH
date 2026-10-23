"""LP3 — a scan says which model it used and whether the model could answer (audit, report, health)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from aegis.api.main import create_app
from aegis.config import AppSettings, ModelSettings
from aegis.llm.status import scan_llm_summary
from aegis.reports.json_report import build_json_report
from aegis.services.scan_service import get_audit
from fakes.fake_llm import PickFirstLLM

pytestmark = pytest.mark.phase("LP3")

PINNED = {"provider": "ollama", "model": "qwen2.5:7b", "location": "local", "generation": 0, "options": {}}


def scan(llm=PINNED):
    return SimpleNamespace(config_json=json.dumps({"llm": llm} if llm else {}))


def d(node, source, error=None, valid=True):
    return SimpleNamespace(node=node, source=source, error=error, valid=valid)


@pytest.mark.parametrize("decisions, status, answered, unavailable", [
    ([], "not_used", 0, 0),
    ([d("investigate", "rule")], "not_used", 0, 0),
    ([d("explain", "llm"), d("remediate", "llm_retry")], "ok", 2, 0),
    ([d("explain", "fallback", "cited id(s) not in the retrieved context")], "ok", 0, 0),    # a refusal, not an outage
    ([d("explain", "llm"), d("explain", "fallback", "llm unavailable: ConnectionError")], "degraded", 1, 1),
    ([d("explain", "fallback", "llm unavailable: ConnectionError"),
      d("explain", "llm", valid=False)], "unavailable", 0, 1),                                   # refused attempts don't count
    ([d("dispatch", "fallback", "llm unavailable: x")], "not_used", 0, 0),                       # not a model step
])
def test_status(decisions, status, answered, unavailable):
    out = scan_llm_summary(scan(), decisions)
    assert (out["status"], out["answered"], out["unavailable"]) == (status, answered, unavailable)
    assert (out["provider"], out["model"], out["location"]) == ("ollama", "qwen2.5:7b", "local")


def test_the_first_outage_is_the_reason():
    out = scan_llm_summary(scan(), [d("explain", "fallback", "llm unavailable: model_not_found"),
                                    d("explain", "fallback", "llm unavailable: ConnectionError")])
    assert out["reason"] == "llm unavailable: model_not_found"


def test_a_scan_from_before_pinning_has_no_model_recorded():
    out = scan_llm_summary(scan(llm=None), [d("explain", "llm")])
    assert out["provider"] is None and out["status"] == "ok"


def test_audit_and_report_carry_it(store, tmp_path):
    s = store.add_scan("correlated", config_json=json.dumps({"llm": PINNED}))
    store.add_decision(s.id, "explain", "fallback", error="llm unavailable: ConnectionError")
    assert get_audit(store, s.id)["llm"]["status"] == "unavailable"
    report = build_json_report(store, s.id, data_dir=tmp_path)
    assert report["audit"]["ai"] == get_audit(store, s.id)["llm"]
    assert report["audit"]["ai"]["reason"] == "llm unavailable: ConnectionError"


def test_health_reports_the_active_model_and_keeps_the_ollama_block(tmp_path):
    settings = AppSettings(data_dir=str(tmp_path / "data"), offline_db_dir=str(tmp_path / "offline-db"),
                           model=ModelSettings(ollama_url="http://127.0.0.1:9"))
    app = create_app(settings, agent_overrides={"llm": PickFirstLLM()})
    with TestClient(app, base_url="http://127.0.0.1:8000", raise_server_exceptions=False) as c:
        body = c.get("/api/health").json()
    assert set(body["ollama"]) >= {"url", "model", "reachable", "model_present"}          # unchanged for old clients
    llm = body["llm"]
    assert (llm["provider"], llm["model"], llm["location"]) == ("ollama", "qwen2.5:7b", "local")
    assert llm["ready"] is False
    assert "not reachable" in llm["reason"] and "will not switch to an online model" in llm["reason"]
