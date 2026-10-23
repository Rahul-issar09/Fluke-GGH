"""AG11.1 — fix verification with the real semgrep (opt-in: ``pytest -m tools``).

semgrep is looked up on PATH, in ``AEGIS_TOOL_DIRS``, or in the project's ``.tools/semgrep``
venv (kept apart from the main venv because it pins older packages). The default suite
uses ``semgrep_standin``; these tests show the stand-in and the real rules agree.
"""

from __future__ import annotations

import os

import pytest

from aegis.fix.verifier import verify_fix
from aegis.workers import executor
from aegis.workers.executor import execute_tool
from fakes.demo_apps import ROOT
from fakes.tool_executors import semgrep_standin
from test_ag10_remediate import ACCOUNTS, FIXES, USERS, read
from test_ag11_verify import GOOD, bad, draft, make_controller, mode3  # noqa: F401 - fixture

pytestmark = [pytest.mark.phase("AG11"), pytest.mark.tools]

RULES = ROOT / "rules" / "semgrep"
_VENV = ROOT / ".tools" / "semgrep" / "Scripts"


@pytest.fixture(autouse=True)
def real_semgrep(monkeypatch):
    if _VENV.is_dir():
        monkeypatch.setenv("AEGIS_TOOL_DIRS", os.pathsep.join(filter(None, [str(_VENV), os.environ.get("AEGIS_TOOL_DIRS")])))
    if executor.find_binary("semgrep") is None:
        pytest.skip("semgrep is not installed")


async def _real(tmp_path, rel: str, text: str, rule: str) -> list[int]:
    from aegis.safety.models import ToolCall

    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_text(text, encoding="utf-8", newline="\n")
    args = {"path": str(tmp_path), "config": str(RULES / f"{rule}.yml"), "files": [rel]}
    result = await execute_tool(ToolCall(tool="semgrep", scan_id="S-1", args=args), args, [])
    assert result.ok and not result.output["errors"], result
    return sorted(r["start"]["line"] for r in result.output["results"])


def _standin(tmp_path, rel: str, rule: str) -> list[int]:
    args = {"path": str(tmp_path), "config": str(RULES / f"{rule}.yml"), "files": [rel]}
    return sorted(r["start"]["line"] for r in semgrep_standin(args).output["results"])


@pytest.mark.parametrize(
    "rel, rule, fixed",
    [
        (ACCOUNTS, "fastapi-missing-owner-check", FIXES[ACCOUNTS]),
        (USERS, "fastapi-sqli", FIXES[USERS]),
        ("app/routes/fetch.py", "python-ssrf", lambda t: (ROOT / "demo-app-patched" / "app" / "routes" / "fetch.py").read_text(encoding="utf-8")),
    ],
)
async def test_the_standin_matches_real_semgrep_before_and_after_the_fix(tmp_path, rel, rule, fixed):
    for label, text in (("vulnerable", read(rel)), ("fixed", fixed(read(rel)))):
        folder = tmp_path / label
        real = await _real(folder, rel, text, rule)
        assert real == _standin(folder, rel, rule), label
        assert bool(real) is (label == "vulnerable"), (label, real)


async def test_real_semgrep_proves_the_good_fix_and_rejects_the_bad_one(mode3):
    w = mode3
    w.ctx.controller = make_controller(w.store, executor=execute_tool)   # real git, real semgrep
    good = await verify_fix(w.ctx, draft(w, GOOD))
    assert good["static"]["status"] == "passed" and good["passed"] is True, good

    worse = await verify_fix(w.ctx, draft(w, bad))
    assert worse["static"]["status"] == "failed" and worse["passed"] is False, worse


def test_the_demo_rules_are_local_rule_files():
    names = {p.name for p in RULES.glob("*.yml")}
    assert {"fastapi-missing-owner-check.yml", "fastapi-sqli.yml", "python-ssrf.yml"} <= names
    assert "weak-hash.yml" not in names           # weak crypto moved to the crypto worker (rules/crypto, AG15)
