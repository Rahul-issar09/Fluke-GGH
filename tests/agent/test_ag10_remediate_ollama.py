"""AG10.2 — remediate against the real local model (opt-in: ``pytest -m ollama``).

A scripted model cannot show whether the prompt produces a usable diff. This runs the real node with
qwen2.5:7b on the demo's access-control finding. The model may honestly fail to produce a diff that
applies — then there is simply no draft, which is a valid outcome — but if a draft exists it must
apply cleanly, and the user's source must be untouched either way.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess

import httpx
import pytest

from _corr_helpers import seed_runtime_bac
from _graph_helpers import make_run
from aegis.agent.nodes.remediate import remediate
from aegis.config import ModelSettings
from aegis.evidence.models import Mode
from fakes.demo_apps import ROOT
from fakes.tool_executors import git_only_executor
from test_ag10_remediate import ACCOUNTS, line_of, read

pytestmark = [pytest.mark.phase("AG10"), pytest.mark.ollama, pytest.mark.slow]

_URL = os.getenv("AEGIS_OLLAMA_URL", "http://localhost:11434")
_MODEL = os.getenv("AEGIS_MODEL", "qwen2.5:7b")


def _reachable() -> bool:
    try:
        httpx.get(f"{_URL}/api/tags", timeout=2.0)
        return True
    except Exception:
        return False


def _hashes(root: pathlib.Path) -> dict[str, str]:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob("*")) if p.is_file()}


async def test_the_real_model_drafts_a_fix_that_applies_or_honestly_drafts_nothing(store, tmp_path):
    if not _reachable():
        pytest.skip(f"Ollama not reachable at {_URL}")

    scan_id, state, config = make_run(store, tmp_path, Mode.correlated, tool_executor=git_only_executor)
    src = tmp_path / "scan"
    shutil.copytree(ROOT / "demo-app" / "app", src / "app")
    store.update_scan(scan_id, source_path=str(src))
    runtime = seed_runtime_bac(store, scan_id)
    store.update_finding_fields(runtime, file=ACCOUNTS, function="get_account", line=line_of(read(ACCOUNTS), "row = request.app.state.db.execute"))
    deps = config["configurable"]["deps"]
    deps.llm = None  # the real model
    deps.llm_settings = ModelSettings(name=_MODEL, ollama_url=_URL, temperature=0.1, num_ctx=8192)
    before = _hashes(src)

    out = await remediate(state, config)

    assert out["errors"] == [] and _hashes(src) == before                      # nothing failed, nothing was touched
    rows = [d for d in store.list_decisions(scan_id, runtime) if d.node == "remediate"]
    detail = [(d.source, d.valid, (d.error or "")[:160]) for d in rows]
    print("remediate decisions:", detail)
    attempts = store.list_fix_attempts(runtime)
    if not attempts:
        pytest.skip(f"the model produced no applicable diff (valid outcome, no draft): {detail}")

    (attempt,) = attempts
    assert attempt.status == "drafted"
    copy = tmp_path / "applied"
    shutil.copytree(src, copy)
    applied = subprocess.run(["git", "apply", "-"], input=attempt.diff.encode("utf-8"), cwd=copy, capture_output=True)
    assert applied.returncode == 0, applied.stderr.decode()
    assert json.loads(attempt.verify_report_json)["draft"]["source"] in ("llm", "llm_retry")
