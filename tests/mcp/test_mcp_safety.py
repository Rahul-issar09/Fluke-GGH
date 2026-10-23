"""MCP safety pieces — local-only model URL (M-7), redaction (M-3), read-only boundary (M-1),
the startup checks, and the editor config (MCP_PHASES MCP05, MCP10, MCP12)."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from aegis.mcp.cli import build_config
from aegis.mcp.redaction import scrub_text
from aegis.safety.model_host import ModelHostRefused, check_model_url
from aegis.services.read_services import NoAegisData, build_read_services

pytestmark = pytest.mark.phase("MCP")

MCP_DIR = Path(__file__).resolve().parents[2] / "aegis" / "mcp"


# ------------------------------------------------------------------------------ local-only model URL
@pytest.mark.parametrize("url", [
    "http://127.0.0.1:11434", "http://[::1]:11434", "http://192.168.1.20:11434", "http://10.0.0.5:11434",
    "http://172.16.3.4:11434",
])
def test_local_and_private_model_urls_are_allowed(url):
    assert check_model_url(url)


@pytest.mark.parametrize("url", ["http://8.8.8.8:11434", "https://1.1.1.1/v1"])
def test_public_model_urls_are_refused(url):
    with pytest.raises(ModelHostRefused, match="local models only"):
        check_model_url(url)


def test_a_name_is_judged_by_what_it_resolves_to():
    assert check_model_url("http://my-ollama:11434", resolver=lambda h: ["192.168.0.7"])
    with pytest.raises(ModelHostRefused, match="public address"):
        check_model_url("http://api.example.com", resolver=lambda h: ["93.184.216.34"])
    with pytest.raises(ModelHostRefused, match="public address"):   # one public answer is enough to refuse
        check_model_url("http://mixed", resolver=lambda h: ["127.0.0.1", "93.184.216.34"])


def test_unresolvable_and_malformed_urls_are_refused():
    def fail(_host):
        raise OSError("no such host")

    with pytest.raises(ModelHostRefused, match="does not resolve"):
        check_model_url("http://ollama:11434", resolver=fail)
    for bad in ("", "ollama:11434", "ftp://127.0.0.1"):
        with pytest.raises(ModelHostRefused):
            check_model_url(bad)


# ------------------------------------------------------------------------------ redaction
@pytest.mark.parametrize("text, secret", [
    ("GET / HTTP/1.1\nAuthorization: Bearer abcdefgh12345678\n", "abcdefgh12345678"),
    ("Cookie: session=deadbeefcafe\n", "deadbeefcafe"),
    ("curl -H 'x' https://h/?api_key=AKIA1234567890&x=1", "AKIA1234567890"),
    ('password = "hunter2hunter2"', "hunter2hunter2"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow"),
])
def test_credentials_inside_text_are_scrubbed(text, secret):
    assert secret not in scrub_text(text)


def test_ordinary_text_is_left_alone():
    text = "GET /api/accounts/1 returned 200 with owner fields"
    assert scrub_text(text) == text


# ------------------------------------------------------------------------------ read-only boundary (M-1)
_FORBIDDEN_MODULES = (
    "aegis.services.scan_service", "aegis.services.fix_service", "aegis.services.job_runner",
    "aegis.evidence.state_machine", "aegis.agent.graph", "aegis.agent.fix_graph", "aegis.fix",
    "aegis.workers", "aegis.chat.indexer",
)


@pytest.mark.parametrize("module", ["server.py", "redaction.py", "audit.py", "schemas.py"])
def test_the_mcp_server_imports_no_write_paths(module):
    tree = ast.parse((MCP_DIR / module).read_text(encoding="utf-8"))
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    bad = {m for m in imported if any(m == f or m.startswith(f + ".") for f in _FORBIDDEN_MODULES)}
    assert not bad, f"{module} imports write-side modules: {bad}"
    calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not {c for c in calls if c.startswith(("add_", "update_", "delete_"))}


# ------------------------------------------------------------------------------ startup
def test_a_missing_database_is_reported_never_created(tmp_path):
    from aegis.config import AppSettings

    with pytest.raises(NoAegisData, match="no AEGIS data at"):
        build_read_services(AppSettings(data_dir=str(tmp_path / "nowhere")))
    assert not (tmp_path / "nowhere" / "aegis.db").exists()


# ------------------------------------------------------------------------------ editor config
def test_the_editor_config_uses_absolute_paths_and_no_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_API__AUTH_TOKEN", "do-not-copy-me")
    monkeypatch.chdir(tmp_path)
    block = build_config(data_dir="data", model="qwen2.5:7b", ollama_url="http://127.0.0.1:11434",
                         embed_model="bge-m3", embed_dim=1024)
    server = block["mcpServers"]["aegis"]
    assert Path(server["command"]).is_absolute() and server["args"] == ["-m", "aegis.mcp.server"]
    env = server["env"]
    assert Path(env["AEGIS_DATA_DIR"]).is_absolute() and Path(env["PYTHONPATH"]).is_absolute()
    assert env["AEGIS_MODEL"] == "qwen2.5:7b" and env["AEGIS_CHAT__EMBED_DIM"] == "1024"
    assert "do-not-copy-me" not in json.dumps(block) and not any("TOKEN" in k or "KEY" in k for k in env)
