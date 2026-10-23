"""``aegis doctor`` — is the AEGIS API up, and what can it use? (cli_new_phases.md N0)

Calls ``GET /api/health`` on the running API and reports: the API itself, its database, Ollama and
the model, the scanners it found, repo scans and the offline vulnerability databases. Exit 0 when
the API answers (problems it reports are warnings), 5 when the API cannot be reached.
"""

from __future__ import annotations

import typer

from aegis.cli.context import current
from aegis.cli.errors import cli_command
from aegis.cli.ui.views import doctor_view

__all__ = ["BUILT", "register"]

BUILT = {(None, "doctor")}


def register(app: typer.Typer, groups: dict[str, typer.Typer]) -> None:
    @app.command("doctor", help="Check the running AEGIS API: database, Ollama and model, scanners. Says what to fix.")
    @cli_command
    def doctor(typer_ctx: typer.Context) -> None:
        ctx = current(typer_ctx)
        with ctx.api_client() as api:
            health = api.health()
            report = {"api": api.base_url, "reachable": True, "health": health}
        ctx.out.emit(report, doctor_view(report))
