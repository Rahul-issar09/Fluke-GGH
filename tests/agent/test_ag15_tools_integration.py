"""AG15.1 — the crypto worker with real semgrep and real sslyze (opt-in: ``pytest -m tools``).

Starts each demo app's HTTPS server (``serve_https.py``) on a free port and scans it for real; the
findings must match the default tests' (stand-in semgrep + recorded sslyze reports).
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

import pytest

import aegis.agent.nodes.crypto_subgraph  # noqa: F401 - registers the crypto steps
from aegis.agent.nodes.worker_stage import STAGE_STEPS, run_steps
from aegis.workers import executor
from aegis.workers.executor import execute_tool
from fakes.demo_apps import ROOT
from test_ag15_crypto import crypto_scan, found

pytestmark = [pytest.mark.phase("AG15"), pytest.mark.tools]


@pytest.fixture(autouse=True)
def real_tools(monkeypatch):
    semgrep = ROOT / ".tools" / "semgrep" / "Scripts"
    if semgrep.is_dir():
        monkeypatch.setenv("AEGIS_TOOL_DIRS", os.pathsep.join(filter(None, [str(semgrep), os.environ.get("AEGIS_TOOL_DIRS")])))
    missing = [t for t in ("semgrep", "sslyze") if executor.find_binary(t) is None]
    if missing:
        pytest.skip(f"not installed: {', '.join(missing)}")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def https_server():
    servers = []

    def start(app: str) -> str:
        port = _free_port()
        proc = subprocess.Popen([sys.executable, "serve_https.py", "--port", str(port)], cwd=ROOT / app, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        servers.append(proc)
        ctx = ssl._create_unverified_context()
        for _ in range(80):
            try:
                urllib.request.urlopen(f"https://127.0.0.1:{port}/health", context=ctx, timeout=1)
                return f"127.0.0.1:{port}"
            except Exception:  # noqa: BLE001 - still starting
                time.sleep(0.25)
        raise RuntimeError("the demo HTTPS server did not start")

    yield start
    for proc in servers:
        proc.terminate()


@pytest.mark.parametrize("app", ["demo-app", "demo-app-patched"])
async def test_real_semgrep_and_sslyze_agree_with_the_default_tests(store, tmp_path, https_server, app):
    target = https_server(app)
    (tmp_path / "real").mkdir()
    (tmp_path / "replay").mkdir()

    scan_id, state, config = crypto_scan(store, tmp_path / "real", app=app, executor=execute_tool)
    config["configurable"]["deps"].default_allowlist = (target,)
    cfg = json.loads(store.get_scan(scan_id).config_json)
    cfg["options"] = {"tls_targets": [target]}
    store.update_scan(scan_id, config_json=json.dumps(cfg))
    out = await run_steps("crypto", STAGE_STEPS["crypto"], state, config)
    assert out.get("errors", []) == [] and out.get("steps_skipped", []) == [], out

    replay_id, state, config = crypto_scan(store, tmp_path / "replay", app=app)
    await run_steps("crypto", STAGE_STEPS["crypto"], state, config)

    def comparable(scan):  # the TLS target's port differs between the two runs
        return sorted((f.type, f.file, f.line, f.title.split(" (")[0]) for f in store.list_findings(scan))

    assert comparable(scan_id) == comparable(replay_id)
    if app == "demo-app":
        assert ("weak_tls", "app/tls.py", 9) in found(store, scan_id)
    else:
        assert found(store, scan_id, "weak_tls") == [] and found(store, scan_id, "weak_crypto") == []
    assert {"semgrep", "sslyze"} <= {c.tool for c in store.list_tool_calls(scan_id)}
