"""LP6 — with the separate source-code consent, a cloud model may draft fixes; without it, never."""

from __future__ import annotations

import shutil

import pytest

from _corr_helpers import seed_runtime_bac
from _graph_helpers import make_run
from aegis.agent.nodes.remediate import CLOUD_SOURCE_CONSENT, remediate
from aegis.evidence.models import Mode
from aegis.llm.base import ProviderId
from fakes.demo_apps import ROOT
from fakes.fake_provider import FakeProvider, manager_with
from fakes.tool_executors import git_only_executor

pytestmark = pytest.mark.phase("LP6")


def _world(store, tmp_path, mgr):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated, llm=None, llm_manager=mgr,
                                      tool_executor=git_only_executor)
    src = tmp_path / "scan"
    shutil.copytree(ROOT / "demo-app" / "app", src / "app")
    store.update_scan(scan_id, source_path=str(src))
    finding = seed_runtime_bac(store, scan_id)
    text = (src / "app" / "routes" / "accounts.py").read_text(encoding="utf-8")
    line = next(i for i, l in enumerate(text.split("\n"), 1) if "row = request.app.state.db.execute" in l)
    store.update_finding_fields(finding, file="app/routes/accounts.py", function="get_account", line=line)
    return scan_id, state, config, finding


@pytest.mark.parametrize("allow, sent", [(True, True), (False, False)])
async def test_source_code_reaches_a_cloud_model_only_with_its_own_consent(store, tmp_path, allow, sent):
    cloud = FakeProvider([ConnectionError("cloud down")], provider=ProviderId.gemini, location="cloud")
    mgr = manager_with(tmp_path / "cfg", FakeProvider(), cloud, provider="gemini", gemini_model="cloud-model",
                       record_consent=True, allow_source_code=allow)
    scan_id, state, config, finding = _world(store, tmp_path, mgr)

    await remediate(state, config)

    final = [d for d in store.list_decisions(scan_id, finding) if d.node == "remediate"][-1]
    assert bool(cloud.used) is sent
    if sent:
        assert "handler_source" in cloud.runnable.calls[0][1].content    # the masked code was offered
    else:
        assert final.error == CLOUD_SOURCE_CONSENT and cloud.runnable.calls == []
