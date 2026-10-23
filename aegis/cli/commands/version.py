"""``aegis version`` — what is installed and which settings are in effect (CLI_PHASES.md CLI03).

Reads only package metadata and settings: no network, no database, no model call, so it works
(and is fast) on any machine, including one without scans.
"""

from __future__ import annotations

import platform
import sys
from importlib import metadata
from pathlib import Path

import typer

from aegis.cli.context import current
from aegis.cli.errors import cli_command
from aegis.cli.ui.output import Output

__all__ = ["register", "version_info"]


def _dist(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def version_info(settings, api: str | None = None, *, local: bool = False) -> dict:
    """Installed versions and what this CLI connects to. Model settings are this machine's and are
    shown for ``--local`` only; with the API, ``aegis doctor`` reports the API's own settings."""
    from aegis.cli.remote import api_url

    return {
        "aegis": _dist("aegis") or "not installed (run: pip install -e .)",
        "python": sys.version.split()[0],
        "platform": platform.platform(terse=True),
        "mcp_sdk": _dist("mcp"),
        "mode": "local" if local else "api",
        "api": None if local else api_url(api),
        "data_dir": str(Path(settings.data_dir).resolve()) if local else None,
        "model": settings.model.name if local else None,
        "ollama_url": settings.model.ollama_url if local else None,
        "embedding_model": settings.chat.embed_model if local else None,
        "embedding_dim": settings.chat.embed_dim if local else None,
    }


def _render(info: dict):
    def render(out: Output) -> None:
        out.heading(f"AEGIS {info['aegis']}")
        rows = [("Python", f"{info['python']} ({info['platform']})"), ("MCP SDK", info["mcp_sdk"] or "not installed")]
        if info["mode"] == "api":
            rows.append(("Connects to", f"AEGIS API at {info['api']}  (check it: aegis doctor)"))
        else:
            rows += [("Connects to", f"local data folder {info['data_dir']}  (--local, read-only)"),
                     ("Model", f"{info['model']} at {info['ollama_url']} (local, Ollama)"),
                     ("Embedding model", f"{info['embedding_model']} ({info['embedding_dim']} dims)")]
        out.kv(rows)

    return render


def register(app: typer.Typer) -> None:
    @app.command("version", help="Installed versions and the settings in effect (no network, no database).")
    @cli_command
    def version(typer_ctx: typer.Context) -> None:
        ctx = current(typer_ctx)
        info = version_info(ctx.settings, ctx.api, local=ctx.local)
        from aegis.observability import get_logger

        get_logger("cli").info("cli.version", mode=info["mode"])
        ctx.out.emit(info, _render(info))
