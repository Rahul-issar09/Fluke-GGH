"""LP7 — /api/llm/*: read the configuration, find and validate a model, switch, go offline, forget the key.

The key is sent in a request body only, kept in the API process's memory (asked for every run), and
never returned. Changing routes need ``X-AEGIS-Intent: llm-config``; on an API without a token they
also need to come from this machine.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from aegis.api.main import create_app
from aegis.config import ApiSettings, AppSettings, ModelSettings
from aegis.llm.consent import DISCLOSURE_VERSION
from fakes.fake_llm import PickFirstLLM
from fakes.fake_provider import FakeGemini, FakeProvider, manager_with, memory_secrets

pytestmark = pytest.mark.phase("LP7")

KEY = "AIzaSyLP7-route-test-key-00000000000009"
INTENT = {"X-AEGIS-Intent": "llm-config", "X-AEGIS-Client": "ui"}
LOCAL = dict(base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000))


def Cloud():
    return FakeGemini(KEY)


def app(tmp_path, *, token=None, **llm):
    mgr = manager_with(tmp_path / "cfg", FakeProvider(), Cloud(), secrets=memory_secrets(None), **llm)
    settings = AppSettings(data_dir=str(tmp_path / "data"), offline_db_dir=str(tmp_path / "offline-db"),
                           model=ModelSettings(ollama_url="http://127.0.0.1:9"), api=ApiSettings(auth_token=token))
    return create_app(settings, agent_overrides={"llm_manager": mgr, "llm": PickFirstLLM()}), mgr


@pytest.fixture
def c(tmp_path):
    application, mgr = app(tmp_path)
    with TestClient(application, raise_server_exceptions=False, **LOCAL) as client:
        client.mgr = mgr
        yield client


def go_online(c, *, consent=True, source=False):
    v = c.post("/api/llm/validate", json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": KEY},
               headers=INTENT)
    assert v.status_code == 200, v.text
    body = {"provider": "gemini", "model": "gemini-2.5-flash", "validation_id": v.json()["validation_id"]}
    if consent:
        body["consent"] = {"disclosure_version": DISCLOSURE_VERSION, "accepted": True, "allow_source_code": source}
    return c.put("/api/llm/config", json=body, headers=INTENT)


# ---------------------------------------------------------------- reads
def test_providers(c):
    out = {p["id"]: p for p in c.get("/api/llm/providers").json()}
    assert out["ollama"]["active"] is True and out["ollama"]["needs_key"] is False
    assert out["gemini"]["location"] == "cloud" and out["gemini"]["needs_key"] is True


def test_config_starts_offline_with_the_notice_and_local_embeddings(c):
    cfg = c.get("/api/llm/config").json()
    assert (cfg["provider"], cfg["location"], cfg["awaiting_key"]) == ("ollama", "local", False)
    assert cfg["key"] == {"configured": False}
    assert cfg["disclosure"]["version"] == DISCLOSURE_VERSION and "not offline" in cfg["disclosure"]["text"]
    assert cfg["embeddings"]["location"] == "local"


# ---------------------------------------------------------------- discovery and validation
def test_discover_with_a_key_in_the_body(c):
    r = c.post("/api/llm/discover", json={"provider": "gemini", "api_key": KEY}, headers=INTENT)
    assert r.status_code == 200 and [m["id"] for m in r.json()["models"]] == ["gemini-2.5-flash"]


@pytest.mark.parametrize("body, status, error", [
    ({"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "AIzaSyWRONG-route-key-0000000000000000"},
     422, "invalid_api_key"),
    ({"provider": "gemini", "model": "gemini-9", "api_key": KEY}, 422, "model_not_found"),
    ({"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "short"}, 422, "invalid request"),
])
def test_validation_failures_are_clear(c, body, status, error):
    r = c.post("/api/llm/validate", json=body, headers=INTENT)
    assert (r.status_code, r.json()["error"]) == (status, error)
    assert KEY not in r.text and "AIzaSyWRONG" not in r.text   # a key is never echoed, not even in a 422


def test_validation_returns_a_one_time_id_and_the_notice(c):
    r = c.post("/api/llm/validate", json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": KEY},
               headers=INTENT).json()
    assert r["ok"] and r["validation_id"] and r["consent_on_record"] is False
    assert r["disclosure"]["version"] == DISCLOSURE_VERSION and "structured_output" in r["capabilities"]


# ---------------------------------------------------------------- switching
def test_switch_online_and_back(c):
    r = go_online(c)
    assert r.status_code == 200, r.text
    cfg = r.json()
    assert (cfg["provider"], cfg["model"], cfg["location"]) == ("gemini", "gemini-2.5-flash", "cloud")
    assert cfg["key"]["source"] == "session" and cfg["key"]["last4"] == "0009" and KEY not in r.text
    assert cfg["consent"]["via"] == "ui"
    off = c.put("/api/llm/config", json={"provider": "ollama"}, headers=INTENT)
    assert off.status_code == 200 and off.json()["location"] == "local" and off.json()["consent"] is None


def test_online_needs_consent(c):
    r = go_online(c, consent=False)
    assert (r.status_code, r.json()["error"]) == (409, "consent_required")


def test_a_used_validation_is_gone(c):
    v = c.post("/api/llm/validate", json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": KEY},
               headers=INTENT).json()["validation_id"]
    body = {"provider": "gemini", "model": "gemini-2.5-flash", "validation_id": v,
            "consent": {"disclosure_version": DISCLOSURE_VERSION, "accepted": True}}
    assert c.put("/api/llm/config", json=body, headers=INTENT).status_code == 200
    r = c.put("/api/llm/config", json=body, headers=INTENT)
    assert (r.status_code, r.json()["error"]) == (410, "validation_expired")


def test_forget_the_key(c):
    go_online(c)
    r = c.delete("/api/llm/credentials/gemini", headers=INTENT)
    assert r.status_code == 200 and r.json()["location"] == "local" and r.json()["key"] == {"configured": False}


def test_health_and_config_agree(c):
    go_online(c)
    health, cfg = c.get("/api/health").json()["llm"], c.get("/api/llm/config").json()
    assert (health["provider"], health["model"], health["location"]) == (cfg["provider"], cfg["model"], cfg["location"])


def test_the_test_route_is_rate_limited(c):
    assert c.post("/api/llm/test", headers=INTENT).json()["ok"] is True
    r = c.post("/api/llm/test", headers=INTENT)
    assert (r.status_code, r.json()["error"]) == (429, "provider_rate_limited")


# ---------------------------------------------------------------- environment and kill-switch
def test_kill_switch(tmp_path):
    application, _ = app(tmp_path, allow_cloud=False)
    with TestClient(application, raise_server_exceptions=False, **LOCAL) as c:
        assert {p["id"]: p for p in c.get("/api/llm/providers").json()}["gemini"]["allowed"] is False
        r = c.post("/api/llm/validate", json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": KEY},
                   headers=INTENT)
        assert (r.status_code, r.json()["error"]) == (403, "cloud_disabled")


def test_a_provider_pinned_by_the_environment(tmp_path):
    application, _ = app(tmp_path, provider="ollama")
    with TestClient(application, raise_server_exceptions=False, **LOCAL) as c:
        r = go_online(c)
        assert (r.status_code, r.json()["error"]) == (409, "managed_by_environment")


# ---------------------------------------------------------------- protection (§9.6)
def test_changes_need_the_intent_header(c):
    r = c.put("/api/llm/config", json={"provider": "ollama"})
    assert r.status_code == 422 and "X-AEGIS-Intent" in r.json()["detail"]


@pytest.mark.parametrize("kw, headers, error, read", [
    (dict(base_url="http://127.0.0.1:8000", client=("192.168.1.20", 50000)), {}, "config_api_forbidden", 200),  # network
    (dict(base_url="http://aegis.example.com", client=("127.0.0.1", 50000)), {}, "host_not_allowed", 403),     # rebinding
    (LOCAL, {"Origin": "https://evil.example.com"}, "config_api_forbidden", 200),                            # other site
    (LOCAL, {"Sec-Fetch-Site": "cross-site"}, "config_api_forbidden", 200),
])
def test_an_open_api_refuses_changes_from_anywhere_but_this_machine(tmp_path, kw, headers, error, read):
    application, mgr = app(tmp_path)
    with TestClient(application, raise_server_exceptions=False, **kw) as c:
        r = c.post("/api/llm/validate", json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": KEY},
                   headers={**INTENT, **headers})
        assert (r.status_code, r.json()["error"]) == (403, error)
        # reads stay open to this machine; a rebound name gets nothing at all (LP11, S-4)
        assert c.get("/api/llm/config").status_code == read
    assert mgr.secrets.get() is None


def test_the_vite_dev_proxy_is_accepted(tmp_path):
    application, _ = app(tmp_path)
    with TestClient(application, raise_server_exceptions=False, **LOCAL) as c:
        r = c.put("/api/llm/config", json={"provider": "ollama"}, headers={**INTENT, "Origin": "http://127.0.0.1:5173"})
        assert r.status_code == 200


def test_with_a_token_the_network_is_allowed_but_the_token_is_required(tmp_path):
    application, _ = app(tmp_path, token="s3cret-token-value")
    with TestClient(application, raise_server_exceptions=False, base_url="http://aegis.lan:8000",
                    client=("192.168.1.20", 50000)) as c:
        assert c.put("/api/llm/config", json={"provider": "ollama"}, headers=INTENT).status_code == 401
        ok = c.put("/api/llm/config", json={"provider": "ollama"},
                   headers={**INTENT, "Authorization": "Bearer s3cret-token-value"})
        assert ok.status_code == 200


def test_the_key_appears_in_no_response_and_no_log(tmp_path, caplog):
    application, mgr = app(tmp_path)
    with TestClient(application, raise_server_exceptions=False, **LOCAL) as c:
        bodies = [c.post("/api/llm/discover", json={"provider": "gemini", "api_key": KEY}, headers=INTENT).text,
                  go_online(c).text, c.get("/api/llm/config").text, c.get("/api/health").text,
                  c.get("/openapi.json").text]
    assert all(KEY not in b for b in bodies)
    assert KEY not in caplog.text
    assert KEY not in json.dumps(mgr.audit.read())
