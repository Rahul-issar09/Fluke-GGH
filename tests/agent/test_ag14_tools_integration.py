"""AG14.1 — the code worker with the real semgrep and gitleaks (opt-in: ``pytest -m tools``).

Both are looked up on PATH, in ``AEGIS_TOOL_DIRS``, or in the project's ``.tools`` folders. The
default suite uses stand-ins; these tests show the real tools produce the same findings.
"""

from __future__ import annotations

import json
import os

import pytest

from aegis.agent.nodes.worker_stage import run_steps
from aegis.workers import executor
from aegis.workers.executor import execute_tool
from fakes.demo_apps import ROOT
from fakes.tool_executors import fix_executor
from test_ag10_remediate import SECRET_VALUE
from test_ag14_code_worker import STEPS, code_scan

pytestmark = [pytest.mark.phase("AG14"), pytest.mark.tools]

_TOOL_DIRS = [ROOT / ".tools" / "semgrep" / "Scripts", *(ROOT / ".tools" / t for t in ("gitleaks", "trufflehog", "osv-scanner", "trivy", "syft"))]


@pytest.fixture(autouse=True)
def real_tools(monkeypatch):
    extra = [str(d) for d in _TOOL_DIRS if d.is_dir()]
    monkeypatch.setenv("AEGIS_TOOL_DIRS", os.pathsep.join(filter(None, [*extra, os.environ.get("AEGIS_TOOL_DIRS")])))
    missing = [t for t in ("semgrep", "gitleaks") if executor.find_binary(t) is None]
    if missing:
        pytest.skip(f"not installed: {', '.join(missing)}")


def found(store, scan_id):
    return {(f.type, f.file, f.line) for f in store.list_findings(scan_id)}


async def test_the_real_tools_find_every_planted_code_weakness(store, tmp_path):
    scan_id, state, config, _ = code_scan(store, tmp_path, executor=execute_tool)
    out = await run_steps("code", STEPS, state, config)
    assert out.get("errors", []) == [], out
    assert found(store, scan_id) == {
        ("sqli", "app/routes/users.py", 16),
        ("broken_access_control", "app/routes/accounts.py", 37),
        ("secret", "app/config.py", 6),
        ("ssrf", "app/routes/fetch.py", 17),
    }
    stored = "\n".join(e.payload_json for e in store.list_evidence(scan_id))
    assert SECRET_VALUE not in stored                                     # gitleaks --redact + the wrapper
    tools = [c.tool for c in store.list_tool_calls(scan_id)]
    assert {"semgrep", "gitleaks"} <= set(tools)                          # both ran through the safety layer


async def test_the_real_tools_find_nothing_in_the_patched_app(store, tmp_path):
    scan_id, state, config, _ = code_scan(store, tmp_path, app="demo-app-patched", executor=execute_tool)
    await run_steps("code", STEPS, state, config)
    assert store.list_findings(scan_id) == []


async def test_the_stand_ins_agree_with_the_real_tools(store, tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "standin").mkdir()
    real_scan, state, config, _ = code_scan(store, tmp_path / "real", executor=execute_tool)
    await run_steps("code", STEPS, state, config)
    fake_scan, state, config, _ = code_scan(store, tmp_path / "standin", executor=fix_executor)
    await run_steps("code", STEPS, state, config)
    assert found(store, real_scan) == found(store, fake_scan)


async def test_a_single_file_follow_up_with_the_real_semgrep(store, tmp_path):
    scan_id, state, config, _ = code_scan(store, tmp_path, executor=execute_tool)
    await run_steps("code", ["semgrep"], state, config, target={"file": "app/routes/users.py"})
    assert found(store, scan_id) == {("sqli", "app/routes/users.py", 16)}
    flow = [json.loads(e.payload_json) for e in store.list_evidence(scan_id, kind="dataflow_path")]
    assert flow and flow[0]["source"] == ["search_users(name)", 12]


CASES = sorted((ROOT / "tests" / "fixtures" / "semgrep_cases").iterdir())


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_each_rule_fires_on_its_marked_lines_and_nothing_else(case):
    from aegis.safety.models import ToolCall

    examples = sorted(p.name for p in case.iterdir() if p.stem in ("bad", "good"))
    assert any(n.startswith("bad.") for n in examples) and any(n.startswith("good.") for n in examples), examples
    for name in examples:
        args = {"path": str(case), "config": str(ROOT / "rules" / "semgrep" / f"{case.name}.yml"), "files": [name]}
        result = await execute_tool(ToolCall(tool="semgrep", scan_id="S-1", args=args), args, [])
        assert result.ok and not result.output["errors"], result
        got = sorted(r["start"]["line"] for r in result.output["results"])
        lines = (case / name).read_text(encoding="utf-8").splitlines()
        want = [n for n, line in enumerate(lines, 1) if f"ruleid: {case.name}" in line]
        assert got == want, (name, got, want)
        assert name.startswith("good.") or want, "a bad example must mark at least one line"


# --------------------------------------------------------------------------------------------- #
# OSV / Trivy / TruffleHog / Syft against the staged offline databases
# --------------------------------------------------------------------------------------------- #
OFFLINE_DB = ROOT / "offline-db"


def _need(*tools):
    missing = [t for t in tools if executor.find_binary("osv-scanner" if t == "osv" else t) is None]
    if missing:
        pytest.skip(f"not installed: {', '.join(missing)}")
    if not (OFFLINE_DB / "osv").is_dir() or not (OFFLINE_DB / "trivy").is_dir():
        pytest.skip("offline databases not staged (scripts/stage_offline)")


def _summary(store, scan_id):
    return {(f.type, f.file, f.line, f.state.value, tuple(json.loads(f.sources))) for f in store.list_findings(scan_id)}


@pytest.mark.parametrize("app", ["demo-app", "demo-app-patched"])
async def test_the_real_scanners_agree_with_their_recordings(store, tmp_path, app):
    import shutil

    from aegis.agent.nodes.worker_stage import STAGE_STEPS
    from test_ag14_more_scanners import full_scan

    _need("trufflehog", "osv", "trivy", "syft")
    (tmp_path / "real").mkdir()
    (tmp_path / "recorded").mkdir()
    real_scan, state, config, _ = full_scan(store, tmp_path / "real", app=app, executor=execute_tool)
    deps = config["configurable"]["deps"]
    shutil.rmtree(deps.offline_db_dir)
    deps.offline_db_dir = str(OFFLINE_DB)                                   # the real staged databases
    out = await run_steps("code", STAGE_STEPS["code"], state, config)
    assert out.get("errors", []) == [] and out.get("steps_skipped", []) == [], out

    fake_scan, state, config, _ = full_scan(store, tmp_path / "recorded", app=app, executor=fix_executor)
    await run_steps("code", STAGE_STEPS["code"], state, config)
    assert _summary(store, real_scan) == _summary(store, fake_scan)
    if app == "demo-app-patched":
        assert store.list_findings(real_scan) == []
    else:
        assert ("vulnerable_dependency", "requirements.txt", 8, "corroborated", ("worker2.osv", "worker2.trivy")) in _summary(store, real_scan)
    tools = {c.tool for c in store.list_tool_calls(real_scan)}
    assert {"osv", "trivy", "trufflehog", "syft"} <= tools                  # all through the safety layer
