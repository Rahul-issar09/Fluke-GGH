"""LP3 — the agent nodes reach the model only through the provider manager, and every safety check
before and after the call still decides what is kept (LLM_PROVIDER_PHASES §9.8)."""

from __future__ import annotations

import json
import shutil

import pytest

from _corr_helpers import seed_runtime_bac
from _graph_helpers import make_run
from aegis.agent.nodes.explain import explain
from aegis.agent.nodes.investigate import investigate
from aegis.agent.nodes.prepare import prepare
from aegis.agent.nodes.remediate import CLOUD_SOURCE_CONSENT, remediate
from aegis.agent.prompt_guard import ALLOWED_KEYS
from aegis.agent.schemas import Claim, Explanation, NextStep, NextStepDecision
from aegis.evidence.models import Mode
from aegis.llm.base import LlmSnapshot, ProviderId
from fakes.demo_apps import ROOT
from fakes.fake_provider import FakeProvider, manager_with
from fakes.tool_executors import git_only_executor

pytestmark = pytest.mark.phase("LP3")


def _explanation(finding_id: str, evidence_id: str) -> Explanation:
    return Explanation(finding_id=finding_id, claims=[
        Claim(field="what", text="Another user's account can be read.", evidence_ids=[evidence_id]),
        Claim(field="impact", text="Customer data is exposed.", evidence_ids=[evidence_id]),
    ])


def _world(store, tmp_path, mgr, mode=Mode.correlated, **overrides):
    scan_id, state, config = make_run(store, tmp_path, mode, llm=None, llm_manager=mgr, **overrides)
    deps = config["configurable"]["deps"]
    return dict(store=store, scan=scan_id, state=state, config=config, deps=deps)


def _rows(w, node, finding_id):
    return [d for d in w["store"].list_decisions(w["scan"], finding_id) if d.node == node]


def _pin(w, snapshot: LlmSnapshot) -> None:
    w["store"].update_scan(w["scan"], config_json=json.dumps({"llm": snapshot.to_dict()}))


# ---------------------------------------------------------------- prepare pins the model
async def test_prepare_pins_the_active_model_on_the_scan(store, tmp_path):
    mgr = manager_with(tmp_path / "cfg", FakeProvider())
    w = _world(store, tmp_path, mgr, Mode.runtime)
    await prepare(w["state"], w["config"])
    cfg = json.loads(store.get_scan(w["scan"]).config_json)
    assert cfg["llm"] == mgr.snapshot.to_dict()
    assert cfg["llm"]["location"] == "local" and "allowlist" in cfg  # nothing else was lost


# ---------------------------------------------------------------- explain
async def test_explain_goes_through_the_manager_and_its_payload_is_still_guarded(store, tmp_path):
    fake = FakeProvider()
    w = _world(store, tmp_path, manager_with(tmp_path / "cfg", fake))
    finding = seed_runtime_bac(store, w["scan"])
    own = store.evidence_for(finding)[0].id
    fake.runnable.script.append(_explanation(finding, own))

    await explain(w["state"], w["config"])

    assert len(fake.used) == 1                            # the call went through the provider
    (row,) = _rows(w, "explain", finding)
    assert (row.source, row.valid) == ("llm", True)
    payload = json.loads(fake.runnable.calls[0][1].content)
    assert set(payload) <= ALLOWED_KEYS                   # the prompt guard still shaped it


async def test_claims_citing_invented_evidence_are_still_refused(store, tmp_path):
    fake = FakeProvider()
    w = _world(store, tmp_path, manager_with(tmp_path / "cfg", fake))
    finding = seed_runtime_bac(store, w["scan"])
    fake.runnable.script.extend([_explanation(finding, "E-9999")] * 2)

    await explain(w["state"], w["config"])

    *refused, final = _rows(w, "explain", finding)
    assert [(d.source, d.valid) for d in refused] == [("llm", False), ("llm_retry", False)]
    assert (final.source, json.loads(final.output_json)) == ("fallback", {"claims": []})


async def test_a_scan_keeps_the_model_it_started_with(store, tmp_path):
    fake = FakeProvider()
    w = _world(store, tmp_path, manager_with(tmp_path / "cfg", fake))
    finding = seed_runtime_bac(store, w["scan"])
    fake.runnable.script.append(_explanation(finding, store.evidence_for(finding)[0].id))
    pinned = LlmSnapshot(ProviderId.ollama, "the-model-at-scan-start", "local", generation=0)
    _pin(w, pinned)

    await explain(w["state"], w["config"])

    assert fake.used == [pinned]


async def test_going_offline_revokes_a_cloud_scan_mid_way_without_calling_the_cloud(store, tmp_path):
    local, cloud = FakeProvider(), FakeProvider(provider=ProviderId.gemini, location="cloud")
    w = _world(store, tmp_path, manager_with(tmp_path / "cfg", local, cloud))   # active: offline
    finding = seed_runtime_bac(store, w["scan"])
    _pin(w, LlmSnapshot(ProviderId.gemini, "cloud-model", "cloud"))             # the scan started online

    await explain(w["state"], w["config"])

    (row,) = _rows(w, "explain", finding)
    assert (row.source, row.error) == ("fallback", "llm unavailable: revoked")
    assert cloud.used == [] and cloud.runnable.calls == [] and local.used == []  # no silent switch either


# ---------------------------------------------------------------- investigate
async def test_investigate_goes_through_the_manager(store, tmp_path):
    fake = FakeProvider()
    w = _world(store, tmp_path, manager_with(tmp_path / "cfg", fake))
    finding = seed_runtime_bac(store, w["scan"])
    store.add_decision(w["scan"], "investigate", "rule", finding_id=finding, output={"next_step": "request_source_evidence"})
    own = store.evidence_for(finding)[0].id
    fake.runnable.script.append(NextStepDecision(finding_id=finding, next_step=NextStep.mark_sufficient,
                                                 reason_evidence_ids=[own]))

    await investigate(w["state"], w["config"])

    assert len(fake.used) == 1
    assert _rows(w, "investigate", finding)[-1].source == "llm"


async def test_an_unreachable_model_keeps_the_old_wording(store, tmp_path):
    fake = FakeProvider([ConnectionError("ollama is down")])
    w = _world(store, tmp_path, manager_with(tmp_path / "cfg", fake))
    finding = seed_runtime_bac(store, w["scan"])
    store.add_decision(w["scan"], "investigate", "rule", finding_id=finding, output={"next_step": "request_source_evidence"})

    await investigate(w["state"], w["config"])

    assert _rows(w, "investigate", finding)[-1].error == "llm unavailable: ConnectionError"


# ---------------------------------------------------------------- remediate: source code and consent
def _remediate_world(store, tmp_path, mgr):
    w = _world(store, tmp_path, mgr, tool_executor=git_only_executor)
    src = tmp_path / "scan"
    shutil.copytree(ROOT / "demo-app" / "app", src / "app")
    store.update_scan(w["scan"], source_path=str(src))
    finding = seed_runtime_bac(store, w["scan"])
    text = (src / "app" / "routes" / "accounts.py").read_text(encoding="utf-8")
    line = next(i for i, l in enumerate(text.split("\n"), 1) if "row = request.app.state.db.execute" in l)
    store.update_finding_fields(finding, file="app/routes/accounts.py", function="get_account", line=line)
    return w, finding


async def test_source_code_is_not_sent_to_a_cloud_model_without_consent(store, tmp_path):
    local, cloud = FakeProvider(), FakeProvider(provider=ProviderId.gemini, location="cloud")
    mgr = manager_with(tmp_path / "cfg", local, cloud, provider="gemini", gemini_model="cloud-model", record_consent=True)
    assert mgr.snapshot.location == "cloud"
    w, finding = _remediate_world(store, tmp_path, mgr)

    out = await remediate(w["state"], w["config"])

    assert out["errors"] == []
    final = _rows(w, "remediate", finding)[-1]
    assert (final.source, final.error) == ("fallback", CLOUD_SOURCE_CONSENT)
    assert cloud.used == [] and local.used == []          # neither the cloud nor a silent local fallback


async def test_a_local_model_still_drafts_fixes(store, tmp_path):
    fake = FakeProvider([ConnectionError("down")])
    w, finding = _remediate_world(store, tmp_path, manager_with(tmp_path / "cfg", fake))

    await remediate(w["state"], w["config"])

    assert len(fake.used) == 1                            # local: the source was offered to the model
    assert _rows(w, "remediate", finding)[-1].error == "llm unavailable: ConnectionError"
