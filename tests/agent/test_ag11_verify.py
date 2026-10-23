"""AG11.1 — apply a drafted fix to a copy and prove it there (workspace, applier, verifiers)."""

from __future__ import annotations

import difflib
import json
import shutil
import sys

import httpx
import pytest

from _corr_helpers import seed_runtime_bac
from _graph_helpers import make_run
from aegis.evidence.models import FindingState, Mode
from aegis.fix.verifier import PatchedTarget, VerifyContext, VerifyError, translate_line, verify_fix
from aegis.fix.workspace import WorkspaceError, make_workspace, tree_hash, workspace_path
from aegis.safety.allowlist import Allowlist
from aegis.safety.controller import SafetyController
from aegis.safety.models import ToolCall, ToolResult
from aegis.safety.policies import PolicyError, validate_args
from aegis.safety.rate_limiter import RateLimiter
from aegis.safety.test_inputs import TestInputLibrary
from aegis.workers.executor import _git, _pytest, _semgrep, no_tools_executor
from fakes.demo_apps import ROOT, HostRouter, create_app_from_dir, identities_path
from fakes.tool_executors import fix_executor
from test_ag10_remediate import ACCOUNTS, FIXES, SECRET_VALUE, line_of, patched, read

pytestmark = pytest.mark.phase("AG11")

PATCHED_HOST = "patched-build:5000"
ALLOW = ["demo-app:5000", "callback:8080", PATCHED_HOST]


def unified(rel: str, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True), f"a/{rel}", f"b/{rel}"))


GOOD = FIXES[ACCOUNTS]


def bad(text: str) -> str:  # applies, changes nothing that matters
    return patched(text, ("    # PLANTED WEAKNESS (IDOR): no check that the account belongs to the caller.\n", "    # reviewed\n"))


def breaks_the_feature(text: str) -> str:  # an owner check the wrong way round: the owner is refused
    return patched(
        text,
        ("    current_user(request)  # authenticated, but...\n", "    user = current_user(request)\n"),
        ('        raise HTTPException(status_code=404, detail="account not found")\n    return _row(row)\n',
         '        raise HTTPException(status_code=404, detail="account not found")\n'
         '    if row["owner_id"] == user["id"]:\n        raise HTTPException(status_code=403, detail="forbidden")\n    return _row(row)\n'),
    )


# --------------------------------------------------------------------------------------------- #
# a Mode 3 world: the demo source, its runtime finding + static twin, and a patched-build host
# --------------------------------------------------------------------------------------------- #
class World(dict):
    __getattr__ = dict.__getitem__


def make_controller(store, executor=fix_executor, allow=ALLOW):
    return SafetyController(
        Allowlist(allow), TestInputLibrary.load(), RateLimiter(1000.0, 1000), executor=executor, audit_sink=store.add_tool_call_log
    )


@pytest.fixture
def mode3(store, tmp_path):
    scan_id, _state, _config = make_run(store, tmp_path, Mode.correlated)
    src = tmp_path / "scan"
    shutil.copytree(ROOT / "demo-app" / "app", src / "app")
    store.update_scan(scan_id, source_path=str(src))
    line = line_of(read(ACCOUNTS), "row = request.app.state.db.execute")

    runtime = seed_runtime_bac(store, scan_id)
    store.update_finding_fields(runtime, file=ACCOUNTS, function="get_account", line=line)
    twin = store.add_finding(scan_id, type="broken_access_control", file=ACCOUNTS, line=line, source="worker2.semgrep")
    store.add_evidence(scan_id, "code_location", "semgrep", {"file": ACCOUNTS, "line": line, "rule": "fastapi-missing-owner-check"}, finding_id=twin.id)

    router = HostRouter({})
    builds = []

    async def from_workspace(workspace):
        app = create_app_from_dir(workspace, f"patched_build_{len(builds)}")
        builds.append(workspace)
        router._routes["patched-build"] = httpx.ASGITransport(app=app)
        return PatchedTarget(base_url="http://patched-build:5000", built_from_workspace=True)

    ctx = VerifyContext(
        store=store,
        controller=make_controller(store),
        workspaces_root=tmp_path / "data" / "workspaces",
        allowlist=Allowlist(ALLOW),
        http_transport=router,
        rate_limit_rps=1000.0,
        rate_limit_burst=1000,
        patched_target=from_workspace,
    )
    return World(store=store, scan=scan_id, src=src, finding=runtime, twin=twin.id, ctx=ctx, builds=builds, tmp=tmp_path)


def draft(w, fix, finding=None) -> str:
    text = read(ACCOUNTS)
    return w.store.add_fix_attempt(finding or w.finding, unified(ACCOUNTS, text, fix(text)), status="drafted").id


def report_of(w, fix_id):
    attempt = w.store.get_fix_attempt(fix_id)
    return attempt, json.loads(attempt.verify_report_json)["verify"]


# --------------------------------------------------------------------------------------------- #
# the three tests the plan names
# --------------------------------------------------------------------------------------------- #
async def test_ag11_original_unchanged(mode3):
    w = mode3
    before = tree_hash(w.src)
    original_bytes = (w.src / ACCOUNTS).read_bytes()

    fix_id = draft(w, GOOD)
    await verify_fix(w.ctx, fix_id)

    assert tree_hash(w.src) == before and (w.src / ACCOUNTS).read_bytes() == original_bytes
    attempt = w.store.get_fix_attempt(fix_id)
    workspace = w.tmp / "data" / "workspaces" / fix_id
    assert attempt.workspace_path == str(workspace)
    assert 'row["owner_id"] != user["id"]' in (workspace / ACCOUNTS).read_text(encoding="utf-8")   # the copy got the fix
    assert not (workspace / ".aegis-fix.patch").exists()                                             # no patch left behind


async def test_ag11_good_fix_all_pass(mode3):
    w = mode3
    fix_id = draft(w, GOOD)

    report = await verify_fix(w.ctx, fix_id)

    attempt, stored = report_of(w, fix_id)
    assert attempt.status == "verified" and report == stored
    assert report["passed"] is True and report["reason"] is None
    assert report["static"]["status"] == "passed" and report["static"]["rules"] == ["fastapi-missing-owner-check"]
    assert report["tests"]["status"] == "skipped"                     # the demo app has no tests
    runtime = report["runtime"]
    assert runtime["status"] == "passed" and runtime["built_from_workspace"] is True
    assert runtime["checks"] and all(c["owner_status"] == 200 and c["other_status"] == 403 for c in runtime["checks"])

    # each passing proof is retest evidence on the finding — but the finding is not resolved here
    evidence = [w.store.get_evidence(i) for i in report["retest_evidence_ids"]]
    assert [(e.kind, e.tool, e.finding_id) for e in evidence] == [("retest", "semgrep", w.finding), ("retest", "bola", w.finding)]
    assert w.store.get_finding(w.finding).state is FindingState.confirmed
    assert w.builds == [w.tmp / "data" / "workspaces" / fix_id]       # the runtime check ran the patched copy


async def test_ag11_bad_fix_failed_reason(mode3):
    w = mode3
    fix_id = draft(w, bad)

    report = await verify_fix(w.ctx, fix_id)

    attempt, _ = report_of(w, fix_id)
    assert attempt.status == "failed" and report["passed"] is False
    assert report["reason"].startswith("static check failed: the detector still fires")
    assert report["static"]["status"] == "failed"
    assert report["runtime"]["status"] == "failed" and "identity B still reads" in report["runtime"]["reason"]
    assert report["retest_evidence_ids"] == [] and not [e for e in w.store.evidence_for(w.finding) if e.kind == "retest"]
    assert w.store.get_finding(w.finding).state is FindingState.confirmed       # the finding stays open


# --------------------------------------------------------------------------------------------- #
# each check catches what it should
# --------------------------------------------------------------------------------------------- #
async def test_a_fix_that_locks_out_the_owner_passes_static_but_fails_at_runtime(mode3):
    w = mode3
    report = await verify_fix(w.ctx, draft(w, breaks_the_feature))
    assert report["static"]["status"] == "passed"                     # the rule only sees an owner comparison...
    assert report["runtime"]["status"] == "failed"                    # ...the replay sees the owner refused
    assert "the owner's own requests no longer succeed" in report["runtime"]["reason"]
    assert report["passed"] is False
    # the static pass alone is not stored as retest evidence: a failed fix must never look resolvable
    assert report["retest_evidence_ids"] == [] and not [e for e in w.store.evidence_for(w.finding) if e.kind == "retest"]


async def test_a_diff_that_does_not_apply_fails_without_running_any_check(mode3):
    w = mode3
    stale = unified(ACCOUNTS, "def nothing():\n    pass\n", "def nothing():\n    return 1\n")
    fix_id = w.store.add_fix_attempt(w.finding, stale, status="drafted").id
    report = await verify_fix(w.ctx, fix_id)
    assert report["passed"] is False and report["reason"].startswith("the diff does not apply")
    assert {report[c]["status"] for c in ("static", "tests", "runtime")} == {"not_run"} and w.builds == []
    assert w.store.get_fix_attempt(fix_id).status == "failed"


async def test_without_a_patched_build_a_runtime_finding_cannot_be_verified(mode3):
    w = mode3
    w.ctx.patched_target = None
    report = await verify_fix(w.ctx, draft(w, GOOD))
    assert report["static"]["status"] == "passed" and report["runtime"]["status"] == "unavailable"
    assert report["passed"] is False and report["reason"].startswith("runtime check unavailable")
    assert report["retest_evidence_ids"] == [] and not [e for e in w.store.evidence_for(w.finding) if e.kind == "retest"]


async def test_a_patched_build_that_does_not_start_fails_the_fix(mode3):
    w = mode3

    async def crashes(workspace):
        raise ImportError("cannot import name 'x'")

    w.ctx.patched_target = crashes
    report = await verify_fix(w.ctx, draft(w, GOOD))
    assert report["runtime"]["status"] == "failed" and "does not start" in report["runtime"]["reason"]
    assert report["passed"] is False


async def test_the_patched_build_host_is_never_added_to_the_allowlist(mode3):
    w = mode3
    w.ctx.allowlist = Allowlist(["demo-app:5000", "callback:8080"])       # the scan's own scope
    report = await verify_fix(w.ctx, draft(w, GOOD))
    assert report["runtime"]["status"] == "unavailable" and "not on the allowlist" in report["runtime"]["reason"]
    assert report["passed"] is False


async def test_without_semgrep_the_static_check_cannot_pass(mode3):
    w = mode3
    w.ctx.controller = make_controller(w.store, executor=_git_but_no_semgrep)
    report = await verify_fix(w.ctx, draft(w, GOOD))
    assert report["static"]["status"] == "unavailable" and "tool not installed: semgrep" in report["static"]["reason"]
    assert report["passed"] is False and report["reason"].startswith("static check unavailable")


async def _git_but_no_semgrep(call, args, inputs):
    if call.tool == "semgrep":
        return await no_tools_executor(call, args, inputs)
    return await fix_executor(call, args, inputs)


async def test_every_tool_ran_through_the_safety_controller_and_was_audited(mode3):
    w = mode3
    await verify_fix(w.ctx, draft(w, GOOD))
    tools = [c.tool for c in w.store.list_tool_calls(w.scan)]
    assert tools == ["git", "semgrep"] and all(c.blocked_reason is None for c in w.store.list_tool_calls(w.scan))


async def test_only_a_fresh_draft_is_verified(mode3):
    w = mode3
    fix_id = draft(w, GOOD)
    await verify_fix(w.ctx, fix_id)
    with pytest.raises(VerifyError, match="not a fresh draft"):
        await verify_fix(w.ctx, fix_id)
    with pytest.raises(VerifyError, match="unknown"):
        await verify_fix(w.ctx, "X-9999")


async def test_the_draft_report_is_kept_next_to_the_verify_report(mode3):
    w = mode3
    text = read(ACCOUNTS)
    fix_id = w.store.add_fix_attempt(w.finding, unified(ACCOUNTS, text, GOOD(text)), status="drafted", verify_report={"draft": {"source": "llm"}}).id
    await verify_fix(w.ctx, fix_id)
    stored = json.loads(w.store.get_fix_attempt(fix_id).verify_report_json)
    assert stored["draft"] == {"source": "llm"} and stored["verify"]["passed"] is True


# --------------------------------------------------------------------------------------------- #
# code-only scans: a leaked secret, and the project's own tests
# --------------------------------------------------------------------------------------------- #
CONFIG_PY = f'import os\n\nAPI_KEY = "{SECRET_VALUE}"\n\n\ndef key_present():\n    return bool(API_KEY)\n'
TEST_PY = (
    "import pathlib\nimport sys\n\nsys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))\n"
    "import config\n\n\ndef test_key_check_runs():\n    assert config.key_present() in (True, False)\n"
)
FROM_ENV = 'API_KEY = os.environ.get("API_KEY", "")\n'
FROM_ENV_OR_CRASH = 'API_KEY = os.environ["AEGIS_TEST_UNSET_KEY"]\n'


@pytest.fixture
def code_world(store, tmp_path):
    def build(*, tests: str | None = TEST_PY, extra_test: str | None = None):
        scan_id, _s, _c = make_run(store, tmp_path, Mode.code)
        src = tmp_path / "scan"
        (src / "config.py").write_text(CONFIG_PY, encoding="utf-8", newline="\n")
        if tests:
            (src / "tests").mkdir()
            (src / "tests" / "test_config.py").write_text(tests + (extra_test or ""), encoding="utf-8", newline="\n")
        store.update_scan(scan_id, source_path=str(src))
        finding = store.add_finding(scan_id, type="secret", file="config.py", line=3, source="worker2.gitleaks")
        store.add_evidence(scan_id, "secret", "gitleaks", {"file": "config.py", "line": 3, "rule": "generic-api-key", "value": "***REDACTED***"}, finding_id=finding.id)
        ctx = VerifyContext(store=store, controller=make_controller(store), workspaces_root=tmp_path / "data" / "workspaces", allowlist=Allowlist(ALLOW))
        return World(store=store, scan=scan_id, src=src, finding=finding.id, ctx=ctx)

    return build


def secret_fix(w, new_line: str) -> str:
    return w.store.add_fix_attempt(w.finding, unified("config.py", CONFIG_PY, CONFIG_PY.replace(f'API_KEY = "{SECRET_VALUE}"\n', new_line)), status="drafted").id


async def test_a_removed_secret_is_proven_by_its_absence_and_the_tests(code_world):
    w = code_world()
    report = await verify_fix(w.ctx, secret_fix(w, FROM_ENV))
    assert report["passed"] is True
    assert report["static"]["status"] == "passed" and report["static"]["check"] == "secret_removed"
    assert report["tests"]["status"] == "passed" and report["tests"]["exit_code"] == 0
    assert report["runtime"]["status"] == "skipped"                         # a code-only scan
    (ev,) = [w.store.get_evidence(i) for i in report["retest_evidence_ids"]]
    assert (ev.kind, ev.tool) == ("retest", "aegis.fix") and SECRET_VALUE not in ev.payload_json


async def test_a_fix_that_keeps_the_secret_fails(code_world):
    w = code_world()
    keeps = f'API_KEY = os.environ.get("API_KEY", "{SECRET_VALUE}")\n'
    report = await verify_fix(w.ctx, secret_fix(w, keeps))
    assert report["static"]["status"] == "failed" and report["static"]["reason"] == "the leaked value is still in the file"
    assert report["passed"] is False


async def test_a_fix_that_breaks_the_projects_tests_fails(code_world):
    w = code_world()
    report = await verify_fix(w.ctx, secret_fix(w, FROM_ENV_OR_CRASH))
    assert report["static"]["status"] == "passed"
    assert report["tests"]["status"] == "failed" and report["tests"]["baseline_exit_code"] == 0
    assert report["passed"] is False and report["reason"].startswith("tests check failed")


async def test_tests_that_already_failed_cannot_judge_the_fix(code_world):
    w = code_world(extra_test="\n\ndef test_already_broken():\n    assert 1 == 2\n")
    report = await verify_fix(w.ctx, secret_fix(w, FROM_ENV))
    assert report["tests"]["status"] == "inconclusive" and report["tests"]["baseline_exit_code"] == 1
    assert report["passed"] is True                                     # the secret check still proves it


async def test_a_project_without_tests_skips_the_tests_check(code_world):
    w = code_world(tests=None)
    report = await verify_fix(w.ctx, secret_fix(w, FROM_ENV))
    assert report["tests"] == {"status": "skipped", "reason": "the project has no tests"} and report["passed"] is True
    assert [c.tool for c in w.store.list_tool_calls(w.scan)] == ["git"]  # pytest never ran


async def test_a_fix_nothing_can_prove_is_not_verified(code_world):
    w = code_world(tests=None)
    w.store.update_finding_fields(w.finding, type="sqli")              # no semgrep evidence, no runtime re-test
    report = await verify_fix(w.ctx, secret_fix(w, FROM_ENV))
    assert report["passed"] is False and report["reason"].startswith("nothing could prove this fix")


# --------------------------------------------------------------------------------------------- #
# building blocks
# --------------------------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "line, expected",
    [(1, 1), (5, 5), (6, 7), (7, 8), (10, 11), (12, 12), (13, 14), (20, 21)],
)
def test_translate_line_follows_the_diff(line, expected):
    old = "".join(f"l{n}\n" for n in range(1, 21))
    new = old.replace("l6\n", "new\nl6\n").replace("l11\n", "").replace("l12\n", "x\ny\n")
    assert translate_line(unified("f.txt", old, new), line) == expected


def test_workspace_ids_and_roots_are_checked(tmp_path):
    with pytest.raises(WorkspaceError):
        workspace_path(tmp_path / "workspaces", "../escape")
    with pytest.raises(WorkspaceError):
        workspace_path(tmp_path / "elsewhere", "X-0001")
    src = tmp_path / "src"
    src.mkdir()
    with pytest.raises(WorkspaceError, match="contain each other"):
        make_workspace(src, src / "workspaces", "X-0001")


def test_a_workspace_is_a_clean_copy_and_a_stale_one_is_replaced(tmp_path):
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    (src / ".git" / "HEAD").write_text("ref", encoding="utf-8")
    (src / "pkg" / "__pycache__").mkdir(parents=True)
    (src / "pkg" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (src / "pkg" / "__pycache__" / "a.pyc").write_bytes(b"\0")
    root = tmp_path / "data" / "workspaces"
    (root / "X-0001").mkdir(parents=True)
    (root / "X-0001" / "stale.txt").write_text("old", encoding="utf-8")

    ws = make_workspace(src, root, "X-0001")
    files = sorted(p.relative_to(ws).as_posix() for p in ws.rglob("*") if p.is_file())
    assert files == ["pkg/a.py"]


def test_git_may_only_apply_a_patch_inside_a_fix_workspace(tmp_path):
    ws = tmp_path / "workspaces" / "X-0001"
    ws.mkdir(parents=True)
    assert validate_args("git", {"op": "apply", "patch": str(ws / "p"), "workdir": str(ws)})["op"] == "apply"
    user_tree = tmp_path / "project"
    user_tree.mkdir()
    with pytest.raises(PolicyError, match="fix workspace"):
        validate_args("git", {"op": "apply", "patch": str(user_tree / "p"), "workdir": str(user_tree)})


@pytest.mark.parametrize("config", ["auto", "p/python", "r/python.lang", "https://semgrep.dev/c/p/ci", "rules/does-not-exist.yml"])
def test_semgrep_only_runs_local_rules(tmp_path, config):
    with pytest.raises(PolicyError):
        validate_args("semgrep", {"path": str(tmp_path), "config": config})


def test_semgrep_files_must_stay_inside_the_scanned_folder(tmp_path):
    rules = str(ROOT / "rules" / "semgrep")
    assert validate_args("semgrep", {"path": str(tmp_path), "config": rules, "files": ["app/x.py"]})
    for outside in ("../x.py", str(tmp_path.parent / "x.py")):
        with pytest.raises(PolicyError):
            validate_args("semgrep", {"path": str(tmp_path), "config": rules, "files": [outside]})


def test_pytest_takes_a_folder_and_nothing_else(tmp_path):
    assert validate_args("pytest", {"workdir": str(tmp_path)}) == {"workdir": str(tmp_path)}
    with pytest.raises(PolicyError):
        validate_args("pytest", {"workdir": str(tmp_path), "args": ["-p", "evil"]})


def test_the_builders_pin_each_tool_to_its_folder_and_keep_it_offline(tmp_path):
    ws = tmp_path / "workspaces" / "X-0001"
    ws.mkdir(parents=True)
    git = _git({"op": "apply", "patch": str(ws / "p"), "workdir": str(ws)})
    assert git.argv[:3] == ["git", "apply", "--whitespace=nowarn"] and "--check" not in git.argv
    assert git.env["GIT_CEILING_DIRECTORIES"] == str(ws.resolve().parent) and git.cwd == str(ws.resolve())

    sg = _semgrep({"path": str(ws), "config": str(ROOT / "rules" / "semgrep" / "weak-hash.yml"), "files": ["a.py"]})
    assert {"--metrics=off", "--disable-version-check", "--json"} <= set(sg.argv) and sg.argv[-1] == "a.py"
    assert sg.env["SEMGREP_SEND_METRICS"] == "off" and sg.cwd == str(ws.resolve())

    py = _pytest({"workdir": str(ws)})
    try:
        assert py.argv[:3] == [sys.executable, "-m", "pytest"]
        assert py.argv[py.argv.index("--rootdir") + 1] == str(ws.resolve())
        assert py.argv[py.argv.index("--confcutdir") + 1] == str(ws.resolve())
        assert (pytest_ini := py.argv[py.argv.index("-c") + 1]).endswith("pytest.ini") and not pytest_ini.startswith(str(ws))
    finally:
        shutil.rmtree(py.cleanup_dir, ignore_errors=True)


def test_a_projects_own_pytest_config_is_used(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\naddopts = '-q'\n", encoding="utf-8")
    py = _pytest({"workdir": str(tmp_path)})
    assert py.argv[py.argv.index("-c") + 1] == str((tmp_path / "pyproject.toml").resolve()) and py.cleanup_dir is None
