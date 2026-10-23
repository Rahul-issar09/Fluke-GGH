"""``aegis report`` and ``aegis gate`` (CLI_PHASES.md CLI05)."""

from __future__ import annotations

import sys
import webbrowser
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from aegis.cli.commands._common import check_id, session
from aegis.cli.errors import USAGE, CliError, cli_command
from aegis.cli.ui.views import gate_view, report_view, to_data

__all__ = ["BUILT", "register"]

BUILT = {(None, "report"), (None, "gate")}

SCAN_ARG = typer.Argument(None, metavar="[SCAN]", help="Scan id like S-0016 (default: the latest scan).")


class Format(str, Enum):
    html = "html"
    json = "json"
    cbom = "cbom"
    sarif = "sarif"


def _write_stdout(content: bytes) -> None:
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(content)
        buffer.flush()
    else:
        sys.stdout.write(content.decode("utf-8", errors="replace"))


def register(app: typer.Typer, groups: dict[str, typer.Typer]) -> None:
    @app.command("report", help="Write or open a scan's report: html (default), json or cbom. -o - prints it to stdout.")
    @cli_command
    def report(
        typer_ctx: typer.Context,
        scan_id: Optional[str] = SCAN_ARG,
        fmt: Format = typer.Option(Format.html, "--format", "-f", help="html, json, cbom (sarif: not built yet)."),
        output: Optional[str] = typer.Option(None, "--output", "-o", metavar="FILE",
                                             help="Write the report to FILE ('-' = stdout). Default: the report AEGIS stored."),
        open_it: bool = typer.Option(False, "--open", help="Open the report afterwards (browser for html)."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            if output == "-" and (ctx.out.json_mode or open_it):
                raise CliError("-o - prints the report itself; it cannot be combined with --json or --open", USAGE)
            sid = be.resolve_scan(check_id("scan", scan_id))
            rep = be.get_report(sid, fmt.value)
            if output == "-":
                _write_stdout(rep["content"])
                return
            if output:
                target = Path(output).expanduser().resolve()
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(rep["content"])
                path = str(target)
            elif rep["path"]:
                path = rep["path"]                                    # the report AEGIS already stored
            else:                                                     # built on demand: save it here
                target = (Path.cwd() / rep["filename"]).resolve()
                target.write_bytes(rep["content"])
                path = str(target)
            info = {"scan_id": sid, "format": fmt.value, "path": path, "bytes": len(rep["content"])}
            ctx.out.emit(info, report_view(info))
            if open_it:
                webbrowser.open(Path(path).as_uri())

    @app.command("gate", help="CI gate verdict. The exit code is the verdict: 0 clean, 1 blocking findings, 2 scan not complete.")
    @cli_command
    def gate(
        typer_ctx: typer.Context,
        scan_id: Optional[str] = SCAN_ARG,
        threshold: Optional[float] = typer.Option(None, "--threshold", min=0.0, max=1.0,
                                                  help="Risk at or above which a finding blocks (default: the gate setting)."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            sid = be.resolve_scan(check_id("scan", scan_id))
            verdict = to_data(be.gate(sid, threshold))
            details = {f["id"]: f for f in to_data(be.list_findings(sid))} if verdict["blocking_findings"] else {}
            ctx.out.emit(verdict, gate_view(sid, verdict, details, threshold))
        raise typer.Exit(verdict["exit_code"])
