"""AG10.2 — the pieces remediate stands on: prompt guard, git policy, executor, and the full graph."""

from __future__ import annotations

import json
import shutil

import pytest

from _corr_helpers import seed_handlers, seed_static
from _graph_helpers import make_run
from aegis.agent import prompt_guard as pg
from aegis.agent.graph import build_aegis_graph
from aegis.agent.schemas import FixDraft
from aegis.evidence.models import Mode
from aegis.safety.models import ToolCall
from aegis.safety.policies import PolicyError, validate_args
from aegis.workers import executor
from aegis.workers.executor import _git, execute_tool
from fakes.demo_apps import ROOT
from fakes.fake_llm import PickFirstLLM
from fakes.tool_executors import git_only_executor
from test_ag10_remediate import ACCOUNTS, model_diff

pytestmark = pytest.mark.phase("AG10")

BASE = {"finding_id": "F-0001", "evidence_ids": ["E-0001"]}


# --- prompt guard ---------------------------------------------------------------------------------- #
def test_handler_source_and_fix_hint_are_allowed_fields():
    out = pg.build_payload({**BASE, "handler_source": "   1 | def f():", "fix_hint": "check the owner"})
    assert out["handler_source"] and out["fix_hint"]


@pytest.mark.parametrize("raw", ["code", "snippet", "source"])
def test_raw_code_fields_are_still_forbidden(raw):
    with pytest.raises(pg.PromptGuardError):
        pg.build_payload({**BASE, raw: "def f(): pass"})


def test_a_large_handler_needs_the_larger_budget_and_the_default_still_refuses_it():
    big = {**BASE, "handler_source": "x = 1\n" * 1500}
    with pytest.raises(pg.PromptGuardError, match="budget"):
        pg.build_payload(big)
    assert pg.build_payload(big, max_bytes=16000)["handler_source"]
    with pytest.raises(pg.PromptGuardError, match="budget"):
        pg.build_payload({**BASE, "handler_source": "x = 1\n" * 4000}, max_bytes=16000)


# --- git policy ------------------------------------------------------------------------------------ #
def test_apply_check_accepts_a_patch_inside_its_workdir(tmp_path):
    args = validate_args("git", {"op": "apply_check", "patch": str(tmp_path / "fix.patch"), "workdir": str(tmp_path)})
    assert args["op"] == "apply_check"


@pytest.mark.parametrize(
    "make",
    [
        lambda d: {"op": "apply_check", "patch": str(d.parent / "evil.patch"), "workdir": str(d)},   # outside workdir
        lambda d: {"op": "apply_check", "patch": str(d / ".." / "x.patch"), "workdir": str(d)},      # traversal
        lambda d: {"op": "apply_check", "workdir": str(d)},                                         # no patch
        lambda d: {"op": "apply_check", "patch": str(d / "p"), "workdir": str(d), "repo": "x"},      # mixed with clone args
        lambda d: {"op": "clone"},                                                                  # clone needs repo + dest
        lambda d: {"op": "clone", "repo": "r", "dest": "d", "patch": str(d / "p")},                  # clone with patch
        lambda d: {"op": "apply", "patch": str(d / "p"), "workdir": str(d)},                         # unknown operation
        lambda d: {"op": "apply_check", "patch": str(d / "p"), "workdir": str(d), "extra": "--exec"},  # unknown arg
    ],
)
def test_git_arguments_outside_the_policy_are_refused(tmp_path, make):
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(PolicyError):
        validate_args("git", make(work))


# --- executor --------------------------------------------------------------------------------------- #
def test_the_git_builder_is_a_read_only_check_run_in_the_workdir(tmp_path):
    spec = _git({"op": "apply_check", "patch": str(tmp_path / "fix.patch"), "workdir": str(tmp_path)})
    assert spec.argv[:3] == ["git", "apply", "--check"] and spec.argv[3].endswith("fix.patch")
    assert "--index" not in spec.argv and "--apply" not in spec.argv
    assert spec.cwd == str(tmp_path.resolve()) and spec.env["GIT_TERMINAL_PROMPT"] == "0"


def test_the_git_builder_builds_only_its_known_operations():
    # clone (TNW-1, tested in test_tnw1_repo_clone), apply_check and apply; anything else is refused
    assert "--no-such-operation" in _git({"op": "push", "repo": "r"}).argv
    assert "clone" in _git({"op": "clone", "repo": "https://github.com/a/b", "dest": "d"}).argv


async def test_a_real_git_check_accepts_a_good_patch_and_rejects_a_bad_one(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"one\ntwo\nthree\n")
    good = b"--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n one\n-two\n+2\n three\n"
    bad = b"--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n one\n-NOPE\n+2\n three\n"
    for name, patch, ok in (("good.patch", good, True), ("bad.patch", bad, False)):
        (tmp_path / name).write_bytes(patch)
        call = ToolCall(tool="git", scan_id="S-1", args={"op": "apply_check", "patch": str(tmp_path / name), "workdir": str(tmp_path)})
        result = await execute_tool(call, call.args, [])
        assert result.ok is ok, result
    assert (tmp_path / "a.txt").read_bytes() == b"one\ntwo\nthree\n"      # a check never changes anything


async def test_a_missing_git_is_reported_as_not_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(executor, "find_binary", lambda name: None)
    call = ToolCall(tool="git", scan_id="S-1", args={"op": "apply_check", "patch": str(tmp_path / "p"), "workdir": str(tmp_path)})
    result = await execute_tool(call, call.args, [])
    assert result.ok is False and result.blocked_reason.startswith("tool not installed")


# --- the full graph ---------------------------------------------------------------------------------- #
class FixesTheAccessBug(PickFirstLLM):
    """Answers remediation questions for the access-control handler with a correct, sloppy-numbered diff."""

    async def ainvoke(self, messages):
        payload = json.loads(messages[1].content)
        if "handler_source" in payload and payload["type"] == "broken_access_control":
            self.calls.append(list(messages))
            self.payloads.append(payload)
            return FixDraft(finding_id=payload["finding_id"], unified_diff=model_diff(ACCOUNTS), evidence_ids=payload["evidence_ids"][:1])
        return await super().ainvoke(messages)


async def test_the_whole_graph_drafts_a_fix_and_changes_nothing_else(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated, tool_executor=git_only_executor)
    src = tmp_path / "scan"
    shutil.copytree(ROOT / "demo-app" / "app", src / "app")
    store.update_scan(scan_id, source_path=str(src))
    seed_handlers(store, scan_id)
    seed_static(store, scan_id)
    for f in store.list_findings(scan_id):  # the shared fixture was written for a smaller file: use the real handler line
        if f.file == ACCOUNTS:
            store.update_finding_fields(f.id, line=36)
    config["configurable"]["deps"].llm = FixesTheAccessBug()
    before_source = {p: p.read_bytes() for p in src.rglob("*.py")}

    final = await build_aegis_graph().ainvoke(state, config)

    assert final["errors"] == [] and final["completed_stages"][-1] == "finalize"
    drafted = [(f, a) for f in store.list_findings(scan_id) for a in store.list_fix_attempts(f.id)]
    assert drafted, "no fix was drafted for any finding"
    for finding, attempt in drafted:
        assert attempt.status == "drafted" and attempt.diff.startswith("--- a/") and ACCOUNTS in attempt.diff
        assert finding.state.value != "resolved" and finding.fix_diff is None   # a draft is not a verified fix
    assert {p: p.read_bytes() for p in src.rglob("*.py")} == before_source       # the user's code is untouched

