"""``aegis findings list | show`` and ``aegis evidence show`` (CLI_PHASES.md CLI04) — read-only."""

from __future__ import annotations

from enum import Enum
from typing import Optional

import typer

from aegis.cli.commands._common import check_id, session
from aegis.cli.errors import cli_command
from aegis.cli.ui.views import evidence_view, finding_view, findings_view, to_data

__all__ = ["BUILT", "register"]

BUILT = {("findings", "list"), ("findings", "show"), ("evidence", "show")}


class State(str, Enum):
    candidate = "candidate"
    corroborated = "corroborated"
    confirmed = "confirmed"
    resolved = "resolved"


class Mode(str, Enum):
    code = "code"
    runtime = "runtime"
    correlated = "correlated"


class Sort(str, Enum):
    risk = "risk"
    id = "id"


def _owasp(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip().upper()
    if len(value) != 3 or value[0] != "A" or not value[1:].isdigit():
        raise typer.BadParameter(f"{value!r} is not an OWASP category (like A01)")
    return value


def register(app: typer.Typer, groups: dict[str, typer.Typer]) -> None:
    findings, evidence = groups["findings"], groups["evidence"]

    @findings.command("list", help="Ranked findings of a scan: open ones by risk, then resolved ones.")
    @cli_command
    def findings_list(
        typer_ctx: typer.Context,
        scan_id: Optional[str] = typer.Option(None, "--scan", "-s", help="Scan id (default: the latest scan)."),
        severity_min: Optional[float] = typer.Option(None, "--severity-min", min=0.0, max=1.0, help="Only severity >= this."),
        owasp: Optional[str] = typer.Option(None, "--owasp", callback=_owasp, help="OWASP category like A01."),
        state: Optional[State] = typer.Option(None, "--state", help="Only findings in this state."),
        mode: Optional[Mode] = typer.Option(None, "--mode", help="Only findings found in this mode."),
        sort: Sort = typer.Option(Sort.risk, "--sort", help="risk (highest first) or id."),
        limit: Optional[int] = typer.Option(None, "--limit", "-n", min=1, help="Show at most this many."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            sid = be.resolve_scan(check_id("scan", scan_id))
            found = to_data(be.list_findings(
                sid, severity_min=severity_min, owasp=owasp,
                state=state.value if state else None, mode=mode.value if mode else None, sort=sort.value,
            ))
            shown = found[:limit] if limit else found
            ctx.out.emit(shown, findings_view(sid, shown, len(found)))

    @findings.command("show", help="One finding: what, where, impact, exploit, fix, risk factors and evidence.")
    @cli_command
    def findings_show(
        typer_ctx: typer.Context,
        finding_id: str = typer.Argument(..., metavar="FINDING", help="Finding id like F-0103."),
        diff: bool = typer.Option(False, "--diff", help="Also show the drafted fix's diff."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            detail = to_data(be.get_finding(check_id("finding", finding_id)))
            ctx.out.emit(detail, finding_view(detail, show_diff=diff))

    @evidence.command("show", help="One evidence record: a digest, or --raw for the payload (credentials redacted).")
    @cli_command
    def evidence_show(
        typer_ctx: typer.Context,
        evidence_id: str = typer.Argument(..., metavar="EVIDENCE", help="Evidence id like E-0222."),
        raw: bool = typer.Option(False, "--raw", help="Show the recorded payload (secrets, tokens and cookies redacted)."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            record = to_data(be.get_evidence(check_id("evidence", evidence_id), raw=raw))
            ctx.out.emit(record, evidence_view(record))
