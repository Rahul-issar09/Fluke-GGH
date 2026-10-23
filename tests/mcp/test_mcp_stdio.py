"""MCP over stdio — the way an editor launches the server (MCP_PHASES MCP07.1, invariant M-9).

These start ``python -m aegis.mcp.server`` as a real subprocess from another working directory,
with only the environment an editor config would pass, and check that stdout carries nothing
but MCP (JSON-RPC) messages — a single stray log line there would break the editor's connection.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters

pytestmark = pytest.mark.phase("MCP")

ROOT = Path(__file__).resolve().parents[2]


def _env(data_dir: Path, **extra) -> dict[str, str]:
    return {"PYTHONPATH": str(ROOT), "AEGIS_DATA_DIR": str(data_dir),
            "AEGIS_OLLAMA_URL": "http://127.0.0.1:11434", "AEGIS_LOGGING__LEVEL": "INFO", **extra}


def _seed(store) -> str:
    scan = store.add_scan(mode="code").id
    f = store.add_finding(scan, type="secret", file="app/config.py", line=3, source="w")
    store.add_evidence(scan, "code_location", "gitleaks", finding_id=f.id, payload={"file": "app/config.py", "line": 3})
    store.update_finding_fields(f.id, severity=0.8, risk=0.3, what="A hard-coded key is in the configuration.")
    return f.id


async def test_an_editor_can_launch_the_server_from_any_directory(store, tmp_path):
    fid = _seed(store)
    elsewhere = tmp_path / "editor-cwd"
    elsewhere.mkdir()
    params = StdioServerParameters(command=sys.executable, args=["-m", "aegis.mcp.server"],
                                   env=_env(tmp_path), cwd=str(elsewhere))
    async with Client(params, read_timeout_seconds=60) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        result = await c.call_tool("list_findings", {})
    assert len(names) == 8   # the seven read tools + llm_status (LLM_PROVIDER_PHASES LP10)
    assert [f["id"] for f in result.structured_content["findings"]] == [fid]


def _talk(env: dict, cwd: Path) -> subprocess.CompletedProcess:
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}
    return subprocess.run([sys.executable, "-m", "aegis.mcp.server"], input=json.dumps(init) + "\n",
                          capture_output=True, text=True, env=env, cwd=str(cwd), timeout=60)


def test_stdout_carries_only_protocol_messages(store, tmp_path):
    import os

    _seed(store)
    env = {**{k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH", "TEMP", "TMP")}, **_env(tmp_path)}
    proc = _talk(env, tmp_path)
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert lines, f"no reply; stderr: {proc.stderr[-500:]}"
    for line in lines:
        message = json.loads(line)                          # every stdout line is JSON-RPC, nothing else
        assert message.get("jsonrpc") == "2.0"
    assert any(json.loads(line).get("id") == 1 for line in lines)
    assert '"event"' in proc.stderr                         # the logs went to stderr


def test_startup_refuses_a_public_model_url_or_missing_data(tmp_path):
    import os

    base = {k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH", "TEMP", "TMP")}
    public = _talk({**base, **_env(tmp_path, AEGIS_OLLAMA_URL="http://8.8.8.8:11434")}, tmp_path)
    assert public.returncode == 2 and "local models only" in public.stderr and public.stdout == ""
    missing = _talk({**base, **_env(tmp_path / "none")}, tmp_path)
    assert missing.returncode == 2 and "no AEGIS data at" in missing.stderr and missing.stdout == ""
