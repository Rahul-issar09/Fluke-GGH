"""AG11.2 — approval interrupt, commit and resolve (fix graph + fix service)."""

from __future__ import annotations

import json
import os
import shutil
import stat
from contextlib import asynccontextmanager

import httpx
import pytest
from langgraph.types import Command

from _corr_helpers import seed_runtime_bac
from _graph_helpers import make_run
from aegis.agent.deps import AgentDeps
from aegis.agent.fix_graph import build_fix_graph
from aegis.evidence.models import FindingState, Mode
from aegis.evidence.state_machine import transition
from aegis.fix.committer import ROTATE_WARNING
from aegis.fix.verifier import PatchedTarget
from aegis.services.fix_service import FixService, FixServiceError
from aegis.services.job_runner import open_checkpointer
from fakes.demo_apps import ROOT, HostRouter, create_app_from_dir
from fakes.fake_llm import FakeLLM
from fakes.tool_executors import fix_executor
from test_ag10_remediate import ACCOUNTS, line_of, read
from test_ag11_verify import CONFIG_PY, FROM_ENV, GOOD, SECRET_VALUE, bad, unified

pytestmark = pytest.mark.phase("AG11")

ALLOW = ("demo-app:5000", "callback:8080", "patched-build:5000")  # as .aegis.yml safety.allowlist would list it


def patched_build(router: HostRouter, builds: list):
    async def start(workspace):
        app = create_app_from_dir(workspace, f"fixgraph_build_{len(builds)}_{id(router)}")
        builds.append(workspace)
        router._routes["patched-build"] = httpx.ASGITransport(app=app)
        return PatchedTarget(base_url="http://patched-build:5000", built_from_workspace=True)

    return start


class World(dict):
    __getattr__ = dict.__getitem__

    def deps(self) -> AgentDeps:
        """Fresh collaborators, as a restarted server would build them (same database and folders)."""
        router, builds = HostRouter({}), self.setdefault("builds", [])
        return AgentDeps(
            store=self.store,
            data_dir=str(self.tmp / "data"),
            default_allowlist=ALLOW,
            http_transport=router,
            rate_limit_rps=1000.0,
            rate_limit_burst=1000,
            tool_executor=fix_executor,
            patched_target=patched_build(router, builds),
            llm=FakeLLM([]),  # the fix graph never asks the model: any call would fail the test
        )

    @asynccontextmanager
    async def service(self):
        async with open_checkpointer(self.tmp / "data" / "checkpoints.db") as saver:
            yield FixService(self.deps(), build_fix_graph(saver))


@pytest.fixture
def mode3(store, tmp_path):
    scan_id, _state, _config = make_run(store, tmp_path, Mode.correlated)
    src = tmp_path / "scan"
    shutil.copytree(ROOT / "demo-app" / "app", src / "app")
    store.update_scan(scan_id, source_path=str(src), status="completed")
    line = line_of(read(ACCOUNTS), "row = request.app.state.db.execute")
    runtime = seed_runtime_bac(store, scan_id)  # F-0012-style: confirmed by the differential replay
    store.update_finding_fields(runtime, file=ACCOUNTS, function="get_account", line=line)
    twin = store.add_finding(scan_id, type="broken_access_control", file=ACCOUNTS, line=line, source="worker2.semgrep")
    store.add_evidence(scan_id, "code_location", "semgrep", {"file": ACCOUNTS, "line": line, "rule": "fastapi-missing-owner-check"}, finding_id=twin.id)
    return World(store=store, scan=scan_id, src=src, finding=runtime, tmp=tmp_path)


def draft(w, fix) -> str:
    text = read(ACCOUNTS)
    return w.store.add_fix_attempt(w.finding, unified(ACCOUNTS, text, fix(text)), status="drafted", verify_report={"draft": {"source": "llm"}}).id


def resolved_with(w, finding_id):
    rows = [t for t in w.store.list_transitions([finding_id]) if t.to_state == "resolved"]
    return [json.loads(t.evidence_ids) for t in rows], rows


# --------------------------------------------------------------------------------------------- #
# the two tests the plan names
# --------------------------------------------------------------------------------------------- #
async def test_ag11_pauses_then_resumes(mode3):
    w = mode3
    fix_id = draft(w, GOOD)

    async with w.service() as service:
        paused = await service.start(w.finding)
    # ---- the server stops here; nothing but the database and the checkpoint survive ----

    assert paused["status"] == "awaiting_approval"
    assert paused["approval"]["fix_id"] == fix_id and paused["approval"]["verify_report"]["passed"] is True
    assert paused["approval"]["modes"] == ["patch", "apply"]
    assert w.store.get_scan(w.scan).status.value == "awaiting_approval"
    assert w.store.get_finding(w.finding).state is FindingState.confirmed       # nothing happens without approval

    async with w.service() as restarted:
        assert (await restarted.get(fix_id))["status"] == "awaiting_approval"   # the pause survived
        done = await restarted.commit(fix_id, "patch")

    assert done["status"] == "committed" and done["commit_mode"] == "patch"
    patch = w.tmp / "data" / "patches" / f"{fix_id}.diff"
    assert patch.is_file() and w.store.get_fix_attempt(fix_id).diff in patch.read_text(encoding="utf-8")
    assert (w.src / ACCOUNTS).read_text(encoding="utf-8") == read(ACCOUNTS)  # patch mode touches nothing of the user's
    assert w.store.get_finding(w.finding).state is FindingState.resolved
    assert w.store.get_scan(w.scan).status.value == "completed"


async def test_ag11_resolve_on_apply(mode3):
    w = mode3
    fix_id = draft(w, GOOD)
    async with w.service() as service:
        await service.start(w.finding)
        done = await service.commit(fix_id, "apply")

    workspace = w.tmp / "data" / "workspaces" / fix_id
    assert (w.src / ACCOUNTS).read_bytes() == (workspace / ACCOUNTS).read_bytes()        # the verified file
    assert 'row["owner_id"] != user["id"]' in (w.src / ACCOUNTS).read_text(encoding="utf-8")

    # F-0012 reaches RESOLVED, backed by the retest evidence of the verification
    finding = w.store.get_finding(w.finding)
    assert finding.state is FindingState.resolved
    (evidence_ids,), (row,) = resolved_with(w, w.finding)
    retest = done["verify_report"]["retest_evidence_ids"]
    assert evidence_ids == retest and len(retest) == 2 and row.actor == "verifier"
    assert {w.store.get_evidence(i).kind for i in retest} == {"retest"}
    assert done["resolution"] == {"resolved": True, "evidence_ids": retest}
    assert done["verify_report"]["commit"]["ok"] is True and done["draft"] == {"source": "llm"}


# --------------------------------------------------------------------------------------------- #
# failure cases the plan names
# --------------------------------------------------------------------------------------------- #
async def test_a_fix_that_failed_verification_cannot_be_committed(mode3):
    w = mode3
    fix_id = draft(w, bad)
    async with w.service() as service:
        result = await service.start(w.finding)
        assert result["status"] == "failed" and result["approval"] is None
        with pytest.raises(FixServiceError, match="only a verified fix can be committed") as err:
            await service.commit(fix_id, "apply")
    assert err.value.code == 409
    assert (w.src / ACCOUNTS).read_text(encoding="utf-8") == read(ACCOUNTS)
    assert w.store.get_finding(w.finding).state is FindingState.confirmed
    assert w.store.get_scan(w.scan).status.value == "completed"                 # nothing is waiting


# (``resume=None`` is not a resume at all to LangGraph, and ``{}`` is read as an empty map of answers
# keyed by interrupt id — both simply leave the graph paused; the service never sends either)
@pytest.mark.parametrize("answer", [{}, {"mode": None}, {"mode": "yolo"}, {"mode": "pr"}, {"approved": True}, "apply"])
async def test_resuming_without_an_approval_stays_paused(mode3, answer):
    w = mode3
    fix_id = draft(w, GOOD)
    async with w.service() as service:
        await service.start(w.finding)
        config = service._config(fix_id)
        await service.graph.ainvoke(Command(resume=answer), config)          # bypassing the service's checks

        status = await service.get(fix_id)
        assert status["status"] == "awaiting_approval" and (status["approval"]["refused"] or answer == {})
        assert w.store.get_finding(w.finding).state is FindingState.confirmed
        assert not (w.tmp / "data" / "patches").exists()
        # the approval step itself let nothing through: no commit was even attempted
        snapshot = await service.graph.aget_state(config)
        assert snapshot.values["approved"] is False and snapshot.values["commit_mode"] is None
        assert "commit" not in (json.loads(w.store.get_fix_attempt(fix_id).verify_report_json)["verify"])

        assert (await service.commit(fix_id, "patch"))["status"] == "committed"  # a real approval still works


@pytest.mark.parametrize("mode, code, message", [("pr", 409, "conflict C6"), ("yolo", 422, "unknown commit mode")])
async def test_the_service_refuses_modes_that_cannot_be_approved(mode3, mode, code, message):
    w = mode3
    fix_id = draft(w, GOOD)
    async with w.service() as service:
        await service.start(w.finding)
        with pytest.raises(FixServiceError, match=message) as err:
            await service.commit(fix_id, mode)
        assert err.value.code == code and (await service.get(fix_id))["status"] == "awaiting_approval"


async def test_apply_never_overwrites_a_file_changed_since_verification(mode3):
    w = mode3
    fix_id = draft(w, GOOD)
    async with w.service() as service:
        await service.start(w.finding)
        users_edit = read(ACCOUNTS) + "\n# the user kept working\n"
        (w.src / ACCOUNTS).write_text(users_edit, encoding="utf-8", newline="\n")

        refused = await service.commit(fix_id, "apply")
        assert refused["status"] == "awaiting_approval"                          # back to the human
        assert "has changed since the fix was verified" in refused["approval"]["refused"]
        assert (w.src / ACCOUNTS).read_text(encoding="utf-8") == users_edit         # their work is intact
        assert w.store.get_finding(w.finding).state is FindingState.confirmed

        done = await service.commit(fix_id, "patch")                              # another mode still can
    assert done["status"] == "committed" and w.store.get_finding(w.finding).state is FindingState.resolved


async def test_apply_is_refused_on_a_read_only_source(mode3):
    w = mode3
    fix_id = draft(w, GOOD)
    target = w.src / ACCOUNTS
    async with w.service() as service:
        await service.start(w.finding)
        os.chmod(target, stat.S_IREAD)
        try:
            refused = await service.commit(fix_id, "apply")
        finally:
            os.chmod(target, stat.S_IREAD | stat.S_IWRITE)
    assert "read-only" in refused["approval"]["refused"] and target.read_text(encoding="utf-8") == read(ACCOUNTS)


async def test_apply_is_refused_for_a_cloned_repository(mode3):
    w = mode3
    w.store.update_scan(w.scan, repo_url="https://example.invalid/repo.git")
    fix_id = draft(w, GOOD)
    async with w.service() as service:
        await service.start(w.finding)
        refused = await service.commit(fix_id, "apply")
        assert "cloned repository" in refused["approval"]["refused"]
        assert (await service.commit(fix_id, "patch"))["status"] == "committed"


async def test_only_a_fresh_draft_can_be_started(mode3):
    w = mode3
    async with w.service() as service:
        with pytest.raises(FixServiceError, match="no fresh fix draft") as err:
            await service.start(w.finding)
        assert err.value.code == 409
        with pytest.raises(FixServiceError) as missing:
            await service.start("F-9999")
        assert missing.value.code == 404

        draft(w, GOOD)
        await service.start(w.finding)
        with pytest.raises(FixServiceError, match="latest: verified"):
            await service.start(w.finding)


def test_the_fix_service_needs_a_checkpointer(store, tmp_path):
    with pytest.raises(ValueError, match="checkpointer"):
        FixService(AgentDeps(store=store), build_fix_graph())


# --------------------------------------------------------------------------------------------- #
# a secret: the fix carries the rotate warning
# --------------------------------------------------------------------------------------------- #
async def test_a_secret_fix_says_the_key_must_be_rotated(store, tmp_path):
    scan_id, _s, _c = make_run(store, tmp_path, Mode.code)
    src = tmp_path / "scan"
    (src / "config.py").write_text(CONFIG_PY, encoding="utf-8", newline="\n")
    store.update_scan(scan_id, source_path=str(src))
    finding = store.add_finding(scan_id, type="secret", file="config.py", line=3, source="worker2.gitleaks")
    ev = store.add_evidence(scan_id, "secret", "gitleaks", {"file": "config.py", "line": 3, "value": "***REDACTED***", "verified": True}, finding_id=finding.id)
    transition(store, finding.id, "confirmed", evidence_ids=[ev.id], actor="worker", reason="verified secret")
    fix_id = store.add_fix_attempt(finding.id, unified("config.py", CONFIG_PY, CONFIG_PY.replace(f'API_KEY = "{SECRET_VALUE}"\n', FROM_ENV)), status="drafted").id

    w = World(store=store, scan=scan_id, src=src, finding=finding.id, tmp=tmp_path)
    async with w.service() as service:
        await service.start(finding.id)
        done = await service.commit(fix_id, "patch")

    assert done["verify_report"]["commit"]["warnings"] == [ROTATE_WARNING]
    patch_text = (tmp_path / "data" / "patches" / f"{fix_id}.diff").read_text(encoding="utf-8")
    assert f"# WARNING: {ROTATE_WARNING}" in patch_text and SECRET_VALUE in patch_text.split("---", 1)[1]  # the diff itself is exact
    assert store.get_finding(finding.id).state is FindingState.resolved


async def test_a_committed_fix_for_an_unconfirmed_finding_is_not_resolved(store, tmp_path):
    scan_id, _s, _c = make_run(store, tmp_path, Mode.code)
    src = tmp_path / "scan"
    (src / "config.py").write_text(CONFIG_PY, encoding="utf-8", newline="\n")
    store.update_scan(scan_id, source_path=str(src))
    finding = store.add_finding(scan_id, type="secret", file="config.py", line=3, source="worker2.gitleaks")
    store.add_evidence(scan_id, "secret", "gitleaks", {"file": "config.py", "line": 3, "value": "***REDACTED***"}, finding_id=finding.id)
    fix_id = store.add_fix_attempt(finding.id, unified("config.py", CONFIG_PY, CONFIG_PY.replace(f'API_KEY = "{SECRET_VALUE}"\n', FROM_ENV)), status="drafted").id

    w = World(store=store, scan=scan_id, src=src, finding=finding.id, tmp=tmp_path)
    async with w.service() as service:
        await service.start(finding.id)
        done = await service.commit(fix_id, "patch")
    assert done["status"] == "committed" and done["resolution"]["resolved"] is False
    assert "not a legal transition" in done["resolution"]["reason"]          # only the state machine decides
    assert store.get_finding(finding.id).state is FindingState.candidate


# --------------------------------------------------------------------------------------------- #
# shape
# --------------------------------------------------------------------------------------------- #
def test_the_fix_graph_has_the_designed_steps():
    nodes = set(build_fix_graph().get_graph().nodes)
    assert nodes == {
        "__start__", "make_copy", "apply_diff", "verify_static", "verify_tests", "verify_runtime",
        "record", "mark_failed", "await_approval", "commit", "__end__",
    }
