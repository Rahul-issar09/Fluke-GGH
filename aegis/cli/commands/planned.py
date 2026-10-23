"""Every command of the CLI, registered from the start (CLI_PHASES.md section 5).

The groups and commands below are visible in ``--help`` now, so the whole command map is
discoverable. A command whose phase is not built yet says which phase brings it and exits with
code 5 (unavailable). As each phase is built, its module registers the real command and this table
loses that entry.
"""

from __future__ import annotations

import typer

from aegis.cli.errors import UNAVAILABLE, CliError, cli_command

__all__ = ["GROUPS", "PLANNED", "register"]

# group name -> help text
GROUPS: dict[str, str] = {
    "scan": "Start, watch, cancel and resume scans; list scans and their audit trail.",
    "findings": "Ranked findings of a scan, and one finding explained.",
    "evidence": "The evidence behind a finding (a digest by default; --raw is redacted).",
    "fix": "Verify a drafted fix on a copy of the code, then approve it.",
    "config": "Show the settings in effect; write a starter settings file.",
    "offline-db": "Stage the offline vulnerability databases (the only online step).",
    "api": "Run the AEGIS REST API.",
    "mcp": "The MCP server for code editors (e.g. Antigravity).",
    "demo": "Start and stop the local demo apps, the API and the UI.",
}

# (group or None for top level, command) -> (phase, help)
PLANNED: dict[tuple[str | None, str], tuple[str, str]] = {
    ("scan", "run"): ("CLI06", "Start a scan: --url (M1), --folder/--repo (M2), or both (M3)."),
    ("scan", "watch"): ("CLI06", "Follow a running scan live."),
    ("scan", "list"): ("CLI04", "Recent scans."),
    ("scan", "status"): ("CLI04", "Status, stages and counts of a scan (latest if omitted)."),
    ("scan", "audit"): ("CLI04", "Tool calls, agent decisions and state transitions of a scan."),
    ("scan", "cancel"): ("CLI07", "Cancel a running scan."),
    ("scan", "resume"): ("CLI07", "Resume a scan that was interrupted."),
    ("findings", "list"): ("CLI04", "Ranked findings of a scan."),
    ("findings", "show"): ("CLI04", "One finding: what, where, impact, exploit, fix, risk factors."),
    ("evidence", "show"): ("CLI04", "One evidence record."),
    ("fix", "verify"): ("CLI08", "Verify the drafted fix of a finding on a copy of the code."),
    ("fix", "status"): ("CLI08", "Verification report of a fix."),
    ("fix", "diff"): ("CLI08", "The diff of a fix."),
    ("fix", "approve"): ("CLI08", "Approve a verified fix (patch or apply) - asks to confirm."),
    ("config", "show"): ("CLI10", "Settings in effect (secrets hidden)."),
    ("config", "init"): ("CLI10", "Write a commented starter settings file."),
    ("offline-db", "stage"): ("CLI10", "Download the offline vulnerability databases (needs internet, once)."),
    ("api", "serve"): ("CLI11", "Start the REST API (default 127.0.0.1:8000)."),
    ("mcp", "serve"): ("CLI11", "Start the MCP server over stdio."),
    ("mcp", "config"): ("CLI11", "Print the editor config block for the MCP server."),
    ("mcp", "test"): ("CLI11", "Test the MCP server the way an editor launches it."),
    ("demo", "up"): ("CLI11", "Start the demo apps, the API and the UI."),
    ("demo", "down"): ("CLI11", "Stop what `demo up` started."),
    ("demo", "status"): ("CLI11", "Show what the demo is running."),
    (None, "gate"): ("CLI05", "CI gate: exit 0 clean, 1 blocking findings, 2 scan not complete."),
    (None, "graph"): ("CLI04", "Attack paths or the full security graph of a scan."),
    (None, "cbom"): ("CLI04", "The cryptography bill of materials of a scan."),
    (None, "report"): ("CLI05", "Write (and open) the HTML, JSON or CBOM report of a scan."),
    (None, "ask"): ("CLI09", "Ask one question about a scan's findings."),
    (None, "chat"): ("CLI09", "Ask questions about a scan's findings, one after another."),
    (None, "index"): ("CLI09", "Rebuild the chat index of a scan."),
    (None, "doctor"): ("CLI10", "Check tools, Ollama, models and data; says what to fix."),
    (None, "tools"): ("CLI10", "Which scanners are installed, and where."),
}

_PASSTHROUGH = {"allow_extra_args": True, "ignore_unknown_options": True}


def _stub(path: str, phase: str):
    @cli_command
    def command(ctx: typer.Context) -> None:
        raise CliError(
            f"`aegis {path}` is not built yet - it arrives in phase {phase}",
            UNAVAILABLE,
            hint="see CLI_PHASES.md for the build order",
        )

    return command


def register(app: typer.Typer, *, built: set[tuple[str | None, str]] = frozenset()) -> dict[str, typer.Typer]:
    """Add every group and every not-yet-built command to *app*; return the groups by name."""
    groups = {name: typer.Typer(name=name, help=text, no_args_is_help=True) for name, text in GROUPS.items()}
    for (group, name), (phase, text) in PLANNED.items():
        if (group, name) in built:
            continue
        target = groups[group] if group else app
        path = f"{group} {name}" if group else name
        target.command(name, help=f"{text}  [phase {phase}]", context_settings=_PASSTHROUGH)(_stub(path, phase))
    for name, sub in groups.items():
        app.add_typer(sub, name=name)
    return groups
