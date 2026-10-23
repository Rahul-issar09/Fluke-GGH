"""Global options → one context object every command reads (CLI_PHASES.md CLI03).

Built once per run in the root callback: the settings in effect (with ``--data-dir`` applied), the
output layer (``--json``, colour, ``--quiet``), the log level (``-v``/``-vv``; logs always go to
**stderr**), and which backend to use (local now; ``--api`` arrives in CLI12).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, replace
from pathlib import Path

from aegis.cli.ui.output import Output
from aegis.config import AppSettings, get_app_settings

__all__ = ["CliContext", "build_context", "current"]


@dataclass
class CliContext:
    settings: AppSettings
    out: Output
    verbose: int = 0
    api: str | None = None
    token: str | None = None
    local: bool = False

    def backend(self):
        """The backend for this run: the running AEGIS API (default), or ``--local`` data on disk."""
        if self.local:
            from aegis.cli.backend import LocalBackend

            return LocalBackend(self.settings)
        from aegis.cli.remote import RemoteBackend

        return RemoteBackend(self.api_client())

    def api_client(self):
        """An HTTP client for the running AEGIS API (``--api`` / ``AEGIS_API_URL`` / 127.0.0.1:8000)."""
        from aegis.cli.remote import ApiClient, api_url

        return ApiClient(api_url(self.api), self.token)


def _log_level(verbose: int, quiet: bool) -> str:
    if quiet:
        return "ERROR"
    return {0: "WARNING", 1: "INFO"}.get(verbose, "DEBUG")


def build_context(*, api: str | None = None, token: str | None = None, data_dir: str | None = None,
                  json_mode: bool = False, no_color: bool = False, quiet: bool = False, verbose: int = 0,
                  local: bool = False) -> CliContext:
    # logs go to stderr BEFORE anything else can log: structlog's unconfigured default prints to stdout
    from aegis.observability import configure_logging

    json_logs = os.getenv("AEGIS_LOGGING__JSON", "").strip().lower() in ("1", "true", "yes", "on")
    configure_logging(_log_level(verbose, quiet), json_logs, stream=sys.stderr)

    settings = get_app_settings()
    if data_dir:
        settings = replace(settings, data_dir=str(Path(data_dir).expanduser().resolve()))
    color = False if (no_color or "NO_COLOR" in os.environ) else None   # None: colour only on a terminal
    out = Output(json_mode=json_mode, color=color, quiet=quiet)
    return CliContext(settings=settings, out=out, verbose=verbose, api=api, token=token, local=local)


def current(ctx) -> CliContext | None:
    """The :class:`CliContext` of a running command, from its ``typer.Context`` (or ``None``)."""
    while ctx is not None:
        if isinstance(getattr(ctx, "obj", None), CliContext):
            return ctx.obj
        ctx = getattr(ctx, "parent", None)
    return None
