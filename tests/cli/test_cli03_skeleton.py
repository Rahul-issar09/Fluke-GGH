"""CLI03 — the CLI skeleton (CLI_PHASES.md).

Command map visible in --help, `version`, `--json` purity, exit codes, logs on stderr only, text that
any console can show, the `commands/`+`ui/` boundary, and a fast start (no heavy imports).
"""

from __future__ import annotations

import ast
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from aegis.cli import errors
from aegis.cli.commands import planned
from aegis.cli.context import build_context
from aegis.cli.main import app
from aegis.cli.ui.output import Output, to_jsonable
from aegis.cli.ui.theme import ASCII, safe_text, supports_unicode, symbols

pytestmark = pytest.mark.phase("CLI03")

ROOT = Path(__file__).resolve().parents[2]
CLI_DIR = ROOT / "aegis" / "cli"
runner = CliRunner()


def _run(*args: str):
    return runner.invoke(app, list(args))


# ------------------------------------------------------------------------------------------ command map
def test_top_level_help_lists_every_group_and_command():
    result = _run("--help")
    assert result.exit_code == 0
    top = [name for (group, name) in planned.PLANNED if group is None]
    for name in [*planned.GROUPS, *top, "version"]:
        assert name in result.stdout, name


@pytest.mark.parametrize("group", sorted(planned.GROUPS))
def test_each_group_lists_its_commands(group):
    result = _run(group, "--help")
    assert result.exit_code == 0
    for (g, name) in planned.PLANNED:
        if g == group:
            assert name in result.stdout, f"{group} {name}"


def test_a_planned_command_says_which_phase_brings_it():
    result = _run("fix", "verify", "F-0001", "--anything")
    assert result.exit_code == errors.UNAVAILABLE
    assert "aegis fix verify" in result.stderr and "CLI08" in result.stderr and result.stdout == ""


def test_no_arguments_and_unknown_commands():
    assert _run().exit_code == 0
    assert _run("no-such-command").exit_code == 2


# ------------------------------------------------------------------------------------------ version / --json
def test_version_human_output(tmp_path):
    result = _run("version")
    assert result.exit_code == 0
    assert result.stdout.startswith("AEGIS ") and "Connects to" in result.stdout and "AEGIS API at" in result.stdout
    local = _run("--local", "--data-dir", str(tmp_path), "version")
    assert "local data folder" in local.stdout and "Model" in local.stdout


def test_json_output_is_exactly_one_document(tmp_path):
    result = _run("--json", "--local", "--data-dir", str(tmp_path), "version")
    assert result.exit_code == 0
    info = json.loads(result.stdout)                      # the whole of stdout parses
    assert info["mode"] == "local" and info["data_dir"] == str(tmp_path.resolve()) and info["api"] is None
    assert {"aegis", "python", "model", "ollama_url", "embedding_model"} <= set(info)


def test_the_api_is_the_default_backend(monkeypatch):
    monkeypatch.delenv("AEGIS_API_URL", raising=False)
    info = json.loads(_run("--json", "version").stdout)
    assert info["mode"] == "api" and info["api"] == "http://127.0.0.1:8000" and info["model"] is None
    assert json.loads(_run("--api", "http://10.0.0.5:8000", "--json", "version").stdout)["api"] == "http://10.0.0.5:8000"
    backend = build_context(api="http://10.0.0.5:8000").backend()
    assert backend.mode == "api" and backend.describe() == {"mode": "api", "api": "http://10.0.0.5:8000"}
    backend.close()


def test_local_backend_with_the_local_flag(tmp_path):
    backend = build_context(data_dir=str(tmp_path), local=True).backend()
    assert backend.mode == "local" and backend.describe()["data_dir"] == str(tmp_path.resolve())


# ------------------------------------------------------------------------------------------ exit codes
def _domain_errors():
    from aegis.api.errors import Conflict, NotFound
    from aegis.chat.embedder import EmbeddingUnavailable
    from aegis.evidence.state_machine import IllegalTransition
    from aegis.router import RequestInvalid
    from aegis.safety.model_host import ModelHostRefused
    from aegis.services.query_service import NotAvailable, QueryNotFound
    from aegis.services.read_services import NoAegisData
    from aegis.services.runtime import StartupError
    from aegis.services.scan_service import ScanConflict, ScanNotFound

    return [
        (ScanNotFound("S-9999"), errors.NOT_FOUND), (QueryNotFound("F-9999"), errors.NOT_FOUND), (NotFound("x"), errors.NOT_FOUND),
        (ScanConflict("busy"), errors.CONFLICT), (Conflict("x"), errors.CONFLICT), (IllegalTransition("x"), errors.CONFLICT),
        (RequestInvalid("bad url"), errors.USAGE),
        (NotAvailable("x"), errors.UNAVAILABLE), (NoAegisData("x"), errors.UNAVAILABLE), (StartupError("x"), errors.UNAVAILABLE),
        (ModelHostRefused("x"), errors.UNAVAILABLE), (EmbeddingUnavailable("x"), errors.UNAVAILABLE),
    ]


def test_domain_errors_map_to_their_exit_codes():
    for exc, code in _domain_errors():
        assert errors.classify(exc)[0] == code, type(exc).__name__


def test_fix_service_errors_follow_their_http_status():
    from aegis.services.fix_service import FixServiceError

    assert [errors.classify(FixServiceError("x", c))[0] for c in (404, 409, 422)] == [errors.NOT_FOUND, errors.CONFLICT, errors.USAGE]


def test_interrupt_and_unknown_errors():
    assert errors.classify(KeyboardInterrupt())[0] == errors.INTERRUPTED
    code, message, hint = errors.classify(ZeroDivisionError("boom"))
    assert code == errors.FAILED and "ZeroDivisionError" in message and "--verbose" in hint


def test_a_failing_command_reports_on_stderr_with_its_exit_code():
    from aegis.services.scan_service import ScanNotFound

    demo = typer.Typer()

    @demo.callback()
    def root(ctx: typer.Context) -> None:
        ctx.obj = build_context()

    @demo.command()
    @errors.cli_command
    def boom(ctx: typer.Context) -> None:
        raise ScanNotFound("unknown scan S-9999")

    result = runner.invoke(demo, ["boom"])
    assert result.exit_code == errors.NOT_FOUND
    assert "error: unknown scan S-9999" in result.stderr and result.stdout == ""


# ------------------------------------------------------------------------------------------ stdout stays clean
def test_logs_go_to_stderr_never_stdout(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run([sys.executable, "-m", "aegis.cli", "-v", "--json", "--data-dir", str(tmp_path), "version"],
                          cwd=tmp_path, env=env, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert proc.returncode == 0, proc.stderr[-400:]
    json.loads(proc.stdout)                               # stdout is only the JSON document
    assert "cli.version" in proc.stderr                   # the -v log line went to stderr


def test_json_is_ascii_escaped_and_handles_models():
    from aegis.api.schemas import GateOut

    buf = io.StringIO()
    Output(json_mode=True, stdout=buf).json({"text": "risk — high", "gate": GateOut(passed=False, exit_code=1)})
    text = buf.getvalue()
    assert text.isascii() and json.loads(text) == {"text": "risk — high", "gate": {"passed": False, "exit_code": 1, "blocking_findings": []}}
    assert to_jsonable(Path("a")) == "a"


# ------------------------------------------------------------------------------------------ any console
class _Stream(io.StringIO):
    def __init__(self, encoding: str):
        super().__init__()
        self._enc = encoding

    @property
    def encoding(self) -> str:
        return self._enc


def test_a_cp1252_console_gets_ascii_symbols_and_safe_text():
    legacy, modern = _Stream("cp1252"), _Stream("utf-8")
    assert not supports_unicode(legacy) and symbols(legacy) == ASCII
    assert supports_unicode(modern)
    assert safe_text("scan → done — ✓", legacy) == "scan -> done - OK"
    assert safe_text("scan → done", modern) == "scan → done"


def test_tables_fall_back_to_ascii_borders_on_a_legacy_console():
    legacy = _Stream("cp1252")
    out = Output(stdout=legacy, color=False)
    out.table(["id", "title"], [["F-0001", "Broken access control — accounts"]])
    text = legacy.getvalue()
    text.encode("cp1252")                                 # printable on that console
    assert "F-0001" in text and "accounts" in text


def test_table_cells_are_printed_as_given_not_read_as_markup():
    buf = io.StringIO()
    Output(stdout=buf, color=False).table(["note"], [['pip install -e ".[gemini]"'], ["[bold]x[/bold]"]])
    assert '".[gemini]"' in buf.getvalue() and "[bold]x[/bold]" in buf.getvalue()


def test_all_help_text_is_ascii():
    """Typer prints help itself, outside the ui layer: a non-ASCII character there crashes ``--help``
    on a Windows pipe (cp1252). Keep every help string ASCII."""
    bad = []
    for path in sorted(CLI_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            texts = []
            if isinstance(node, ast.keyword) and node.arg == "help" and isinstance(node.value, ast.Constant):
                texts = [node.value.value]
            elif isinstance(node, ast.Assign) and any(getattr(t, "id", "") in ("HELP", "GROUPS", "PLANNED") for t in node.targets):
                texts = [c.value for c in ast.walk(node.value) if isinstance(c, ast.Constant)]
            bad += [f"{path.name}:{node.lineno}" for t in texts if isinstance(t, str) and not t.isascii()]
    assert not bad, f"non-ASCII help text: {bad}"


def test_errors_and_notes_go_to_stderr():
    out_buf, err_buf = io.StringIO(), io.StringIO()
    out = Output(stdout=out_buf, stderr=err_buf)
    out.error("something failed", hint="try this")
    out.note("a note")
    assert out_buf.getvalue() == "" and "error: something failed" in err_buf.getvalue() and "a note" in err_buf.getvalue()
    quiet_err = io.StringIO()
    Output(stdout=io.StringIO(), stderr=quiet_err, quiet=True).note("hidden")
    assert quiet_err.getvalue() == ""


# ------------------------------------------------------------------------------------------ boundary + speed
_FORBIDDEN = ("aegis.services", "aegis.agent", "aegis.evidence", "aegis.chat", "aegis.workers", "aegis.fix",
              "aegis.graph", "aegis.risk", "aegis.api.routers", "aegis.mcp", "aegis.router")


@pytest.mark.parametrize("path", sorted(str(p.relative_to(ROOT)) for d in ("commands", "ui") for p in (CLI_DIR / d).glob("*.py")))
def test_commands_and_ui_only_talk_to_the_backend(path):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    bad = sorted(m for m in imported if any(m == f or m.startswith(f + ".") for f in _FORBIDDEN))
    assert not bad, f"{path} imports {bad}; go through aegis.cli.backend instead"


def test_starting_the_cli_does_not_load_the_agent_or_services():
    code = ("import sys, aegis.cli.main; "
            "heavy = [m for m in sys.modules if m.startswith(('langgraph', 'chromadb', 'aegis.services', 'aegis.agent'))]; "
            "print(','.join(sorted(heavy)))")
    proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=60,
                          env={**os.environ, "PYTHONPATH": str(ROOT)})
    assert proc.returncode == 0, proc.stderr[-300:]
    assert proc.stdout.strip() == "", f"loaded at startup: {proc.stdout.strip()}"
