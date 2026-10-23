"""Entry point of the `aegis` command (CLI_PHASES.md CLI01, CLI03).

Installed as a console script by ``pyproject.toml`` (``aegis = "aegis.cli.main:main"``) and also
runnable as ``python -m aegis.cli``. The root callback turns the global options into one
:class:`~aegis.cli.context.CliContext` (settings, output, log level, backend choice) that every
command reads. Every command of the plan is registered (``commands/planned.py``); the ones not built
yet say which phase brings them. Typing ``aegis`` alone in a terminal opens the interactive menu
(``ui/menu.py``); in a script or pipe it shows the help.

Heavy AEGIS modules are imported inside commands only, so ``aegis --help`` and ``aegis version`` are fast.
"""

from __future__ import annotations

from typing import Optional

import typer

from aegis.cli.commands import chat, findings, graph, llm, planned, report, scan_run, scans, setup, version
from aegis.cli.context import build_context

__all__ = ["app", "main"]

HELP = (
    "AEGIS - offline, evidence-first application-security and crypto-risk scanner.\n\n"
    "Scan a live or local web app (M1), source code from a repo link or folder (M2), or both together "
    "(M3), then read the findings and ask questions about them - all from this terminal."
)

app = typer.Typer(
    name="aegis",
    help=HELP,
    add_completion=False,   # shell completion is set up in CLI17
)


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    json_output: bool = typer.Option(False, "--json", help="Print one JSON document (the API's shapes) instead of tables."),
    data_dir: Optional[str] = typer.Option(None, "--data-dir", help="Data folder for --local (default: AEGIS_DATA_DIR or ./data)."),
    api: Optional[str] = typer.Option(None, "--api", metavar="URL",
                                      help="AEGIS API address (default: AEGIS_API_URL or http://127.0.0.1:8000)."),
    local: bool = typer.Option(False, "--local", help="Read results from the local data folder instead of the API (read commands only)."),
    token: Optional[str] = typer.Option(None, "--token", envvar="AEGIS_API__AUTH_TOKEN", show_envvar=False,
                                        help="Bearer token for --api (or AEGIS_API__AUTH_TOKEN)."),
    no_color: bool = typer.Option(False, "--no-color", help="No colours (also: NO_COLOR, or when output is piped)."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only results and errors."),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="More log detail on stderr (-v, -vv)."),
) -> None:
    """AEGIS command-line tool."""
    ctx.obj = build_context(api=api, token=token, data_dir=data_dir, json_mode=json_output,
                            no_color=no_color, quiet=quiet, verbose=verbose, local=local)
    if ctx.invoked_subcommand is None:
        # no command: an interactive terminal opens the menu; anything else (a script, CI, a pipe)
        # gets the help and exit 0 - it must never wait for input.
        if _interactive() and not json_output and not local:
            from aegis.cli.errors import cli_command
            from aegis.cli.ui.menu import run_menu

            raise typer.Exit(cli_command(lambda typer_ctx: run_menu(ctx.obj))(ctx))
        typer.echo(ctx.get_help())
        raise typer.Exit(0)


def _interactive() -> bool:
    import sys

    return bool(getattr(sys.stdin, "isatty", lambda: False)() and getattr(sys.stdout, "isatty", lambda: False)())


# built commands first; every other command of the plan is registered as "arrives in phase …"
_BUILT_MODULES = (scans, scan_run, findings, graph, report, setup, chat, llm)
version.register(app)
_groups = planned.register(app, built=set().union(*(m.BUILT for m in _BUILT_MODULES)))
for _module in _BUILT_MODULES:
    _module.register(app, _groups)


def _tolerant_streams() -> None:
    """Never crash on a character the console cannot show (a Windows pipe or file uses cp1252):
    replace it instead. AEGIS's own output is already made safe in ``ui``; this also covers text
    printed by the framework, such as help screens."""
    import sys

    for stream in (sys.stdout, sys.stderr):
        try:
            if (stream.encoding or "").lower().replace("-", "") != "utf8":
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main() -> None:
    """Console-script entry point."""
    _tolerant_streams()
    app()


if __name__ == "__main__":
    main()
