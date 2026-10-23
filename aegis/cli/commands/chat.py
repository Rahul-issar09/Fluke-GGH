"""``aegis ask`` and ``aegis chat`` (cli_new_phases.md N3) — questions about a scan's findings.

Answered by the API (``POST /api/ask``): counts and lists come straight from the findings (instant);
"why / how" questions go to AEGIS's local model and cite finding and evidence ids. A question that is
not about the scan's findings gets "No finding matches." — the API decides that, never the CLI.
"""

from __future__ import annotations

from typing import Optional

import typer

from aegis.cli.commands._common import check_id, session
from aegis.cli.commands.llm import before_model_use
from aegis.cli.errors import USAGE, CliError, cli_command
from aegis.cli.ui.views import answer_view, finding_view, findings_view, to_data

__all__ = ["BUILT", "ask_once", "chat_loop", "register", "save_report"]

BUILT = {(None, "ask"), (None, "chat")}

CHAT_HELP = ("Commands: /findings  /show F-0103  /report  /scan S-0016  /help  /quit   "
             "(Ctrl+C or an empty Ctrl+Z/Ctrl+D also quits)")


def save_report(be, scan_id: str) -> str:
    """Where the scan's HTML report is: the copy AEGIS stored, or a fresh one saved in this folder."""
    from pathlib import Path

    report = be.get_report(scan_id, "html")
    if report.get("path"):
        return report["path"]
    target = (Path.cwd() / report["filename"]).resolve()
    target.write_bytes(report["content"])
    return str(target)


def _api_only(ctx) -> None:
    if ctx.local:
        raise CliError("questions are answered by the AEGIS API; remove --local", USAGE)


def ask_once(ctx, be, scan_id: str, question: str) -> dict:
    question = question.strip()
    if not question:
        raise CliError("the question is empty", USAGE)
    if not ctx.out.json_mode:
        ctx.out.note("thinking (AEGIS's local model; explanations can take a minute) ...")
    return to_data(be.ask(scan_id, question))


def chat_loop(ctx, be, scan_id: str, read=input) -> None:
    """Ask question after question about *scan_id* until /quit (or end of input)."""
    out = ctx.out
    out.heading(f"Ask about {scan_id}. {CHAT_HELP}")
    while True:
        try:
            line = read("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            out.line()
            return
        if not line:
            continue
        if line in ("/quit", "/exit", "/q", "/menu"):
            return
        if line.startswith("/show"):
            parts = line.split()
            try:
                if len(parts) < 2:
                    raise CliError("give a finding id: /show F-0103")
                finding_view(to_data(be.get_finding(check_id("finding", parts[1]))))(out)
            except (typer.BadParameter, CliError) as exc:
                out.error(str(exc))
            continue
        if line == "/report":
            try:
                out.line(f"Report: {save_report(be, scan_id)}")
            except CliError as exc:
                out.error(str(exc), exc.hint)
            continue
        if line == "/help":
            out.line(CHAT_HELP)
            continue
        if line == "/findings":
            found = to_data(be.list_findings(scan_id))
            findings_view(scan_id, found[:10], len(found))(out)
            continue
        if line.startswith("/scan"):
            parts = line.split()
            try:
                wanted = check_id("scan", parts[1]) if len(parts) > 1 else scan_id
                be.scan_status(wanted)                       # switch only to a scan that exists
                scan_id = wanted
                out.line(f"Now asking about {scan_id}.")
            except (typer.BadParameter, CliError) as exc:
                out.error(str(exc), f"still asking about {scan_id}")
            continue
        if line.startswith("/"):
            out.error(f"unknown command {line.split()[0]}", hint=CHAT_HELP)
            continue
        try:
            answer_view(ask_once(ctx, be, scan_id, line))(out)
        except CliError as exc:
            out.error(str(exc), exc.hint)


def register(app: typer.Typer, groups: dict[str, typer.Typer]) -> None:
    @app.command("ask", help="Ask one question about a scan's findings (answered by AEGIS's local model, with citations).")
    @cli_command
    def ask(
        typer_ctx: typer.Context,
        question: str = typer.Argument(..., help='The question, in quotes: "why is F-0103 a risk?"'),
        scan_id: Optional[str] = typer.Option(None, "--scan", "-s", help="Scan id (default: the latest scan)."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            _api_only(ctx)
            sid = be.resolve_scan(check_id("scan", scan_id))
            before_model_use(ctx, be)            # this run's Gemini key, if Online mode waits for it
            answer = ask_once(ctx, be, sid, question)
            ctx.out.emit(answer, answer_view(answer))

    @app.command("chat", help="Ask questions about a scan's findings, one after another (/quit to stop).")
    @cli_command
    def chat(
        typer_ctx: typer.Context,
        scan_id: Optional[str] = typer.Option(None, "--scan", "-s", help="Scan id (default: the latest scan)."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            _api_only(ctx)
            if ctx.out.json_mode:
                raise CliError("chat is interactive; use `aegis ask --json` for one answer as JSON", USAGE)
            sid = be.resolve_scan(check_id("scan", scan_id))
            before_model_use(ctx, be)
            chat_loop(ctx, be, sid)
