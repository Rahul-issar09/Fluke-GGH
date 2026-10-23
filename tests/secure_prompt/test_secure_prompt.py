"""Secure Prompt: Gemini Online mode only, one validated model call, OWASP-mapped reasons.

Everything runs against a scripted fake Gemini: no network, no real key.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from aegis.api.main import create_app
from aegis.config import ApiSettings, AppSettings, ModelSettings
from aegis.llm.consent import DISCLOSURE_VERSION
from aegis.secure_prompt.schemas import Bullet, ModelResult
from aegis.secure_prompt.service import validate_result
from fakes.fake_llm import FakeLLM, PickFirstLLM
from fakes.fake_provider import FakeGemini, FakeProvider, manager_with, memory_secrets

KEY = "AIzaSySecurePrompt-test-key-0000000007"
INTENT = {"X-AEGIS-Intent": "llm-config", "X-AEGIS-Client": "ui"}
LOCAL = dict(base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000))
PROMPT = {"prompt": "make a login API with email and password", "language": "python"}


def good(**changes) -> ModelResult:
    data = dict(
        language="python",
        code="from flask import Flask\napp = Flask(__name__)\n",
        bullets=[
            Bullet(owasp="A07", action="Login is rate limited and returns one generic error.", why="Stops guessing and user enumeration."),
            Bullet(owasp="A02", action="Passwords are hashed with argon2id and a per-user salt.", why="A leaked database cannot be cheaply reversed."),
            Bullet(owasp="A03", action="All SQL uses parameterised queries.", why="User input can never change the query."),
        ],
        not_applicable=["A10"],
        not_covered=["Dependency versions (A06) are not checked."],
    )
    data.update(changes)
    return ModelResult(**data)


@pytest.fixture
def world(tmp_path):
    cloud = FakeGemini(KEY)
    cloud.runnable = FakeLLM([])
    mgr = manager_with(tmp_path / "cfg", FakeProvider(), cloud, secrets=memory_secrets(None))
    settings = AppSettings(data_dir=str(tmp_path / "data"), offline_db_dir=str(tmp_path / "offline-db"),
                           model=ModelSettings(ollama_url="http://127.0.0.1:9"), api=ApiSettings())
    app = create_app(settings, agent_overrides={"llm_manager": mgr, "llm": PickFirstLLM()})
    with TestClient(app, raise_server_exceptions=False, **LOCAL) as client:
        client.mgr, client.cloud = mgr, cloud
        yield client


def go_online(c) -> None:
    v = c.post("/api/llm/validate", json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": KEY}, headers=INTENT)
    assert v.status_code == 200, v.text
    body = {"provider": "gemini", "model": "gemini-2.5-flash", "validation_id": v.json()["validation_id"],
            "consent": {"disclosure_version": DISCLOSURE_VERSION, "accepted": True, "allow_source_code": False}}
    assert c.put("/api/llm/config", json=body, headers=INTENT).status_code == 200


def script(c, *items) -> None:
    c.cloud.runnable.script = list(items)


# ---------------------------------------------------------------- gating
def test_offline_mode_is_refused_and_nothing_is_sent(world):
    script(world, good())
    r = world.post("/api/secure-prompt", json=PROMPT)
    assert r.status_code == 409 and r.json()["error"] == "online_required"
    assert "Gemini Online mode" in r.json()["detail"]
    assert world.cloud.runnable.calls == []


def test_a_bad_request_is_a_422(world):
    go_online(world)
    assert world.post("/api/secure-prompt", json={"prompt": "hi"}).status_code == 422
    assert world.post("/api/secure-prompt", json={**PROMPT, "extra": 1}).status_code == 422


# ---------------------------------------------------------------- the result
def test_online_returns_code_bullets_and_coverage(world):
    go_online(world)
    script(world, good())
    r = world.post("/api/secure-prompt", json=PROMPT)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["provider"] == "gemini" and out["model"] == "gemini-2.5-flash" and out["owasp_version"] == "2021"
    assert out["verified"] is False and "not scanned or run" in out["disclaimer"]
    assert [b["owasp"] for b in out["bullets"]] == ["A02", "A03", "A07"]                    # grouped in OWASP order
    assert out["bullets"][0]["category"] == "Cryptographic Failures"
    status = {row["id"]: row["status"] for row in out["coverage"]}
    assert status["A02"] == status["A03"] == status["A07"] == "covered"
    assert status["A10"] == "not_applicable" and status["A06"] == "not_covered" and len(status) == 10
    assert out["not_covered"] == ["Dependency versions (A06) are not checked."]


def test_the_request_is_sent_as_data_with_secrets_scrubbed(world):
    go_online(world)
    script(world, good())
    secret = "AIzaSyLeakedInThePrompt0000000000000001"
    world.post("/api/secure-prompt", json={"prompt": f"login API, my key is {secret}", "language": "flask"})
    system, human = world.cloud.runnable.calls[0]
    payload = json.loads(human.content)
    assert secret not in human.content and "[REDACTED]" in payload["user_request"]
    assert payload["language"] == "flask" and "A03" in payload["allowed_owasp_ids"]
    assert "untrusted" in system.content


def test_one_corrective_retry_then_success(world):
    go_online(world)
    script(world, good(bullets=good().bullets[:1]), good())                                  # first answer has 1 bullet
    r = world.post("/api/secure-prompt", json=PROMPT)
    assert r.status_code == 200 and len(world.cloud.runnable.calls) == 2


def test_two_unusable_answers_is_a_clear_502(world):
    go_online(world)
    script(world, good(not_covered=[]), good(not_covered=[]))
    r = world.post("/api/secure-prompt", json=PROMPT)
    assert r.status_code == 502 and r.json()["error"] == "generation_failed"


def test_going_offline_stops_the_feature(world):
    go_online(world)
    script(world, good())
    assert world.put("/api/llm/config", json={"provider": "ollama"}, headers=INTENT).status_code == 200
    assert world.post("/api/secure-prompt", json=PROMPT).status_code == 409


# ---------------------------------------------------------------- audit and validation rules
def test_the_call_is_audited_without_the_prompt(world):
    go_online(world)
    script(world, good())
    world.post("/api/secure-prompt", json=PROMPT)
    lines = [json.loads(x) for x in (world.mgr.audit.path).read_text(encoding="utf-8").splitlines()]
    entry = next(x for x in lines if x["event"] == "secure_prompt")
    assert entry["outcome"] == "ok" and entry["bullets"] == 3 and entry["prompt_chars"] == len(PROMPT["prompt"])
    assert PROMPT["prompt"] not in json.dumps(lines)


def test_validation_rules():
    assert validate_result(good()) == []
    assert any("at least 3" in p for p in validate_result(good(bullets=good().bullets[:2])))
    assert any("not_applicable" in p for p in validate_result(good(not_applicable=["A02"])))
    assert any("not_covered" in p for p in validate_result(good(not_covered=[])))
    overclaim = good(bullets=[*good().bullets[:2], Bullet(owasp="A01", action="Checks owners.", why="This makes the app 100% secure.")])
    assert any("100% secure" in p for p in validate_result(overclaim))
    assert any("empty" in p for p in validate_result(good(code="   ")))
