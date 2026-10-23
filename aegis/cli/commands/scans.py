"""``aegis scan list | status | audit`` (CLI_PHASES.md CLI04) — scan history, read-only."""

from __future__ import annotations

from typing import Optional

import typer

from aegis.cli.commands._common import check_id, session
from aegis.cli.errors import cli_command
from aegis.cli.ui.views import audit_view, scan_status_view, scans_view, to_data

__all__ = ["BUILT", "register"]

BUILT = {("scan", "list"), ("scan", "status"), ("scan", "audit")}

SCAN_ARG = typer.Argument(None, metavar="[SCAN]", help="Scan id like S-0016 (default: the latest scan).")


def register(app: typer.Typer, groups: dict[str, typer.Typer]) -> None:
    scan = groups["scan"]

    @scan.command("list", help="Recent scans, newest first.")
    @cli_command
    def scan_list(
        typer_ctx: typer.Context,
        limit: int = typer.Option(20, "--limit", "-n", min=1, max=500, help="How many scans to show."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            scans = to_data(be.list_scans(limit))
            ctx.out.emit(scans, scans_view(scans))

    @scan.command("status", help="Status, stages and finding counts of a scan.")
    @cli_command
    def scan_status(typer_ctx: typer.Context, scan_id: Optional[str] = SCAN_ARG) -> None:
        with session(typer_ctx) as (ctx, be):
            sid = be.resolve_scan(check_id("scan", scan_id))
            status = to_data(be.scan_status(sid))
            ctx.out.emit(status, scan_status_view(status))

    @scan.command("audit", help="What ran and what was decided: tool calls, agent decisions, state changes.")
    @cli_command
    def scan_audit(
        typer_ctx: typer.Context,
        scan_id: Optional[str] = SCAN_ARG,
        decisions: bool = typer.Option(False, "--decisions", help="List every agent decision instead of a summary."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            sid = be.resolve_scan(check_id("scan", scan_id))
            audit = to_data(be.scan_audit(sid))
            ctx.out.emit(audit, audit_view(audit, all_decisions=decisions))
