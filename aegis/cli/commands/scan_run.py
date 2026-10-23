"""``aegis scan run | watch | cancel`` (cli_new_phases.md N2) — scans run in the AEGIS API.

The CLI sends what the user typed to ``POST /api/scans``; the API validates it (allowlist, allowed
folders, git hosts, identities) and picks the mode — URL only → M1, folder or repo only → M2, both →
M3. The CLI follows ``GET /api/scans/{id}/events`` and prints a summary at the end. Ctrl+C stops
*watching* only: the scan keeps running in the API.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer

from aegis.cli.commands._common import check_id, session
from aegis.cli.errors import FAILED, INTERRUPTED, OK, USAGE, CliError, cli_command
from aegis.cli.ui.progress import MODE_LABELS, Progress, summary_view
from aegis.cli.ui.views import to_data

__all__ = ["BUILT", "build_request", "follow", "mode_of", "register"]

BUILT = {("scan", "run"), ("scan", "watch"), ("scan", "cancel")}

AUTH_NOTE = "Only scan systems you own or have written permission to test."


def mode_of(body: dict) -> str:
    """The mode the API will choose (same rule as ``aegis/router.py``), for display only."""
    has_url, has_source = bool(body.get("url")), bool(body.get("folder") or body.get("repo"))
    return "M3" if has_url and has_source else "M1" if has_url else "M2"


def build_request(url: str | None, folder: str | None, repo: str | None, identities: str | None,
                  tls_targets: list[str] | None = None) -> dict:
    """The ``POST /api/scans`` body. Catches obvious typos here; everything else is the API's call."""
    url, folder, repo, identities = (v.strip().strip('"').strip("'") if v else None for v in (url, folder, repo, identities))
    if not (url or folder or repo):
        raise CliError("give what to scan: --url (M1), --folder or --repo (M2), or --url with --folder/--repo (M3)", USAGE)
    if folder and repo:
        raise CliError("--folder and --repo cannot be used together: give one source of code", USAGE)
    if url and not url.startswith(("http://", "https://")):
        raise CliError(f"--url must start with http:// or https:// (got {url!r})", USAGE)
    if url and not identities:
        raise CliError("--url needs --identities: a file with two test accounts (owner A, attacker B)", USAGE,
                       hint="see demo-app/identities.yml for the format")
    if repo and not repo.startswith("https://"):
        raise CliError(f"--repo must be an https:// link, like https://github.com/owner/name (got {repo!r})", USAGE)
    body: dict = {}
    if url:
        body["url"] = url
    if folder:
        path = Path(folder).expanduser().resolve()
        if not path.is_dir():
            raise CliError(f"folder not found: {path}", USAGE)
        body["folder"] = str(path)
    if repo:
        body["repo"] = repo
    if identities:
        path = Path(identities).expanduser().resolve()
        if not path.is_file():
            raise CliError(f"identities file not found: {path}", USAGE)
        body["identities"] = str(path)
    if tls_targets:
        body["options"] = {"tls_targets": list(tls_targets)}
    return body


def follow(ctx, be, scan_id: str) -> int:
    """Show live progress, then the summary. Returns the exit code (0 completed, 1 failed/cancelled)."""
    progress = Progress(ctx.out)
    if not ctx.out.json_mode:
        ctx.out.line(f"Following {scan_id} (Ctrl+C stops watching; the scan keeps running) ...")
    try:
        for event in be.scan_events(scan_id):
            progress.show(event)
            if progress.final:
                break
    except KeyboardInterrupt:
        ctx.out.line()
        ctx.out.note(f"Stopped watching. {scan_id} continues in the AEGIS API.")
        ctx.out.note(f"  watch again: aegis scan watch {scan_id}    cancel it: aegis scan cancel {scan_id}")
        raise typer.Exit(INTERRUPTED) from None
    scan = to_data(be.scan_status(scan_id))
    findings = to_data(be.list_findings(scan_id)) if scan["status"] in ("completed", "awaiting_approval") else []
    gate = to_data(be.gate(scan_id)) if scan["status"] in ("completed", "awaiting_approval") else None
    summary = {"scan": scan, "findings": findings[:5], "total_findings": len(findings), "gate": gate}
    ctx.out.emit(summary, summary_view(scan, findings, gate))
    return OK if scan["status"] in ("completed", "awaiting_approval") else FAILED


def _api_only(ctx) -> None:
    if ctx.local:
        raise CliError("scans run in the AEGIS API; remove --local", USAGE)


def register(app: typer.Typer, groups: dict[str, typer.Typer]) -> None:
    scan = groups["scan"]

    @scan.command("run", help="Start a scan in the AEGIS API and follow it: --url (M1), --folder/--repo (M2), or both (M3).")
    @cli_command
    def scan_run(
        typer_ctx: typer.Context,
        url: Optional[str] = typer.Option(None, "--url", "-u", help="Running web app: live (https://...) or local (http://127.0.0.1:5000)."),
        identities: Optional[str] = typer.Option(None, "--identities", "-i", metavar="FILE", help="Two test accounts (needed with --url)."),
        folder: Optional[str] = typer.Option(None, "--folder", "-f", metavar="PATH", help="Local source-code folder."),
        repo: Optional[str] = typer.Option(None, "--repo", "-r", metavar="URL", help="Public repo link, e.g. https://github.com/owner/name."),
        tls_target: Optional[List[str]] = typer.Option(None, "--tls-target", metavar="HOST:PORT", help="Extra TLS endpoint to check (repeatable)."),
        detach: bool = typer.Option(False, "--detach", "-d", help="Start the scan and return its id without following it."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            _api_only(ctx)
            body = build_request(url, folder, repo, identities, tls_target)
            mode = mode_of(body)
            if not ctx.out.json_mode:
                ctx.out.heading(f"Scan mode: {MODE_LABELS[mode]}")
            if body.get("url"):
                ctx.out.warn(AUTH_NOTE)          # always shown (stderr), even with --json or -q
            scan_id = be.start_scan(body)
            if detach:
                ctx.out.emit({"scan_id": scan_id, "mode": mode}, lambda out: out.line(
                    f"Started {scan_id}. Follow it: aegis scan watch {scan_id}"))
                return
            code = follow(ctx, be, scan_id)
        raise typer.Exit(code)

    @scan.command("watch", help="Follow a scan live (also replays the steps already done), then show its summary.")
    @cli_command
    def scan_watch(
        typer_ctx: typer.Context,
        scan_id: Optional[str] = typer.Argument(None, metavar="[SCAN]", help="Scan id (default: the latest scan)."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            _api_only(ctx)
            code = follow(ctx, be, be.resolve_scan(check_id("scan", scan_id)))
        raise typer.Exit(code)

    @scan.command("cancel", help="Cancel a running scan (cancelling a finished scan changes nothing).")
    @cli_command
    def scan_cancel(
        typer_ctx: typer.Context,
        scan_id: str = typer.Argument(..., metavar="SCAN", help="Scan id like S-0017."),
    ) -> None:
        with session(typer_ctx) as (ctx, be):
            _api_only(ctx)
            sid = check_id("scan", scan_id)
            be.cancel_scan(sid)
            ctx.out.emit({"scan_id": sid, "cancelled": True}, lambda out: out.line(f"Cancel requested for {sid}."))
