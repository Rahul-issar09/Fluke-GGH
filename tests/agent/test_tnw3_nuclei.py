"""TNW-3 — Nuclei: the pinned binary and templates, the AEGIS template profile, the scan's rate.

* the policy only accepts an http(s) URL, the staged ``nuclei-templates`` folder and a sane rate,
* the runtime step runs Nuclei at the scan's rate limit (``AEGIS_SCAN__RATE_LIMIT_RPS``),
* Nuclei's real output on the demo (recorded) becomes ``misconfig`` candidates without any request
  or response content,
* ``test_real_nuclei_on_the_demo_app`` (``-m tools``) runs the real binary and templates against
  the demo app served on a free port.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

import aegis.agent.nodes.runtime_subgraph  # noqa: F401 - registers the runtime steps
from _graph_helpers import make_run
from aegis.agent.nodes.worker_stage import run_steps
from aegis.config import get_app_settings
from aegis.evidence.adapters.nuclei import NucleiAdapter
from aegis.evidence.models import Mode
from aegis.evidence.normalizer import ingest
from aegis.safety.models import ToolResult
from aegis.safety.policies import PolicyError, validate_args
from aegis.workers import executor
from fakes.demo_apps import ROOT

pytestmark = pytest.mark.phase("TNW-3")

RECORDED = ROOT / "tests" / "fixtures" / "tools" / "nuclei_demo.jsonl"
STAGED = ROOT / "offline-db" / "nuclei-templates"


def recorded_rows() -> list[dict]:
    return [json.loads(line) for line in RECORDED.read_text(encoding="utf-8").splitlines() if line.strip()]


# --------------------------------------------------------------------------------------------- #
# policy + settings
# --------------------------------------------------------------------------------------------- #
def test_the_nuclei_policy(tmp_path):
    templates = tmp_path / "nuclei-templates"
    templates.mkdir()
    ok = validate_args("nuclei", {"url": "https://example.com", "templates": str(templates)})
    assert ok["rate_limit"] == 5
    bad = [
        ({"url": "ftp://x", "templates": str(templates)}, "http"),
        ({"url": "http://x", "templates": str(tmp_path)}, "staged nuclei-templates"),
        ({"url": "http://x", "templates": str(tmp_path / "missing" / "nuclei-templates")}, "staged nuclei-templates"),
        ({"url": "http://x", "templates": str(templates), "rate_limit": 0}, "between 1 and 100"),
        ({"url": "http://x", "templates": str(templates), "rate_limit": 500}, "between 1 and 100"),
        ({"url": "http://x", "templates": str(templates), "severity": "info"}, "Extra inputs"),
    ]
    for args, why in bad:
        with pytest.raises(PolicyError, match=why):
            validate_args("nuclei", args)


def test_the_scan_rate_limit_setting(monkeypatch):
    assert get_app_settings().rate_limit_rps == 5.0
    monkeypatch.setenv("AEGIS_SCAN__RATE_LIMIT_RPS", "50")
    assert get_app_settings().rate_limit_rps == 50.0


async def test_the_runtime_step_runs_nuclei_at_the_scans_rate(store, tmp_path):
    (tmp_path / "offline-db" / "nuclei-templates").mkdir(parents=True)
    calls = []

    async def fake(call, args, inputs):
        calls.append(args)
        return ToolResult(ok=True, tool=call.tool, exit_code=0, output=recorded_rows())

    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, tool_executor=fake, rate_limit_rps=250.0)
    out = await run_steps("runtime", ["validate_target", "check_misconfig"], state, config)
    assert out.get("errors", []) == []
    assert calls == [{"url": "http://demo-app:5000", "templates": str(tmp_path / "offline-db" / "nuclei-templates"), "rate_limit": 100}]
    assert sorted(f.route for f in store.list_findings(scan_id) if f.type == "misconfig") == ["GET /docs", "GET /openapi.json", "GET /redoc"]


# --------------------------------------------------------------------------------------------- #
# the recorded real output
# --------------------------------------------------------------------------------------------- #
def test_the_recorded_demo_output_becomes_misconfig_candidates(store):
    scan = store.add_scan(mode="runtime", status="running", target_url="http://127.0.0.1:5000", config_json="{}")
    ids = ingest(store, scan.id, NucleiAdapter(mode="runtime").parse(recorded_rows(), scan.id))
    findings = {f.route: f for f in store.list_findings(scan.id)}
    assert len(ids) == 3 and set(findings) == {"GET /docs", "GET /openapi.json", "GET /redoc"}
    for f in findings.values():
        assert (f.type, f.owasp, getattr(f.state, "value", f.state), f.severity) == ("misconfig", "A05", "candidate", 0.1)
        (ev,) = store.evidence_for(f.id)
        payload = json.loads(ev.payload_json)
        assert payload["template_id"] in {"swagger-api", "openapi", "redoc-api-docs"}
        assert not {"curl-command", "response", "headers"} & set(payload)


# --------------------------------------------------------------------------------------------- #
# the real binary and templates (opt-in: -m tools)
# --------------------------------------------------------------------------------------------- #
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.tools
async def test_real_nuclei_on_the_demo_app(store, tmp_path, monkeypatch):
    nuclei_dir = ROOT / ".tools" / "nuclei"
    monkeypatch.setenv("AEGIS_TOOL_DIRS", os.pathsep.join(filter(None, [str(nuclei_dir), os.environ.get("AEGIS_TOOL_DIRS")])))
    if executor.find_binary("nuclei") is None or not (STAGED / "http").is_dir():
        pytest.skip("nuclei or its templates are not staged (see TOOL_NOT_WORKING.md TNW-3)")
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "--factory", "app.main:create_app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT / "demo-app", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(80):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
                break
            except Exception:  # noqa: BLE001 - still starting
                time.sleep(0.25)
        url, target = f"http://127.0.0.1:{port}", f"127.0.0.1:{port}"
        scan_id, state, config = make_run(
            store, tmp_path, Mode.runtime, tool_executor=executor.execute_tool, http_transport=None,
            default_allowlist=(target,), offline_db_dir=str(ROOT / "offline-db"), rate_limit_rps=100.0,
        )
        store.update_scan(scan_id, target_url=url)
        out = await run_steps("runtime", ["validate_target", "check_misconfig"], state, config)
        assert out.get("errors", []) == [], out
        routes = sorted(f.route for f in store.list_findings(scan_id) if f.type == "misconfig")
        assert routes == ["GET /docs", "GET /openapi.json", "GET /redoc"]
        (call,) = [c for c in store.list_tool_calls(scan_id) if c.tool == "nuclei"]
        assert call.exit_code == 0 and call.blocked_reason is None and call.target_host == target
    finally:
        proc.terminate()
