"""``aegis graph`` and ``aegis cbom`` (CLI_PHASES.md CLI04) — read-only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from aegis.cli.commands._common import check_id, session
from aegis.cli.errors import cli_command
from aegis.cli.ui.views import cbom_view, graph_view, to_data

__all__ = ["BUILT", "register"]

BUILT = {(None, "graph"), (None, "cbom")}

SCAN_ARG = typer.Argument(None, metavar="[SCAN]", help="Scan id like S-0016 (default: the latest scan).")
EXPORT = typer.Option(None, "--export", "-o", metavar="FILE", help="Also write the full JSON to this file.")


def _export(ctx, data: dict, path: Optional[Path]) -> None:
    if path is None:
        return
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ctx.out.note(f"wrote {target}")


def register(app: typer.Typer, groups: dict[str, typer.Typer]) -> None:
    @app.command("graph", help="Attack paths of a scan (endpoint -> handler -> sink -> finding); --export writes the full graph.")
    @cli_command
    def graph(typer_ctx: typer.Context, scan_id: Optional[str] = SCAN_ARG, export: Optional[Path] = EXPORT) -> None:
        with session(typer_ctx) as (ctx, be):
            sid = be.resolve_scan(check_id("scan", scan_id))
            data = to_data(be.get_graph(sid))
            _export(ctx, data, export)
            ctx.out.emit(data, graph_view(data))

    @app.command("cbom", help="Cryptography bill of materials of a scan (CycloneDX); --export writes the file.")
    @cli_command
    def cbom(typer_ctx: typer.Context, scan_id: Optional[str] = SCAN_ARG, export: Optional[Path] = EXPORT) -> None:
        with session(typer_ctx) as (ctx, be):
            sid = be.resolve_scan(check_id("scan", scan_id))
            data = to_data(be.get_cbom(sid))
            _export(ctx, data, export)
            ctx.out.emit(data, cbom_view(sid, data))
