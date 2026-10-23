"""Shared bits for commands: id checks and opening the backend for one command."""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Iterator

import typer

from aegis.cli.context import CliContext, current

__all__ = ["check_id", "session"]

_PATTERNS = {"scan": r"^S-\d{4,}$", "finding": r"^F-\d{4,}$", "evidence": r"^E-\d{4,}$", "fix": r"^X-\d{4,}$"}
_EXAMPLES = {"scan": "S-0016", "finding": "F-0103", "evidence": "E-0222", "fix": "X-0009"}


def check_id(kind: str, value: str | None) -> str | None:
    """A malformed id is a usage error (exit 2) before anything is opened; ``None`` passes through."""
    if value is None:
        return None
    normalized = value.strip().upper()          # f-0103 → F-0103
    if not re.match(_PATTERNS[kind], normalized):
        raise typer.BadParameter(f"{value!r} is not a {kind} id (like {_EXAMPLES[kind]})")
    return normalized


@contextmanager
def session(typer_ctx: typer.Context) -> Iterator[tuple[CliContext, object]]:
    """``(cli context, backend)`` for one command; the backend is closed afterwards."""
    ctx = current(typer_ctx)
    with ctx.backend() as backend:
        yield ctx, backend
