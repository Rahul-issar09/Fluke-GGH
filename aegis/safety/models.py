"""AEGIS safety contract — the typed tool-call interface (PHASES P0.5).

FROZEN after P0 (STRUCTURE invariant I-8). Every tool invocation is expressed
as a ``ToolCall`` and returns a ``ToolResult``; ``SafetyController.run`` is the
only path to execution (no shell, no arbitrary args).

Conflict C6: the ``tool`` literal follows PHASES (adds trufflehog/git and the
``scan_id`` field). ``gh`` is intentionally absent — enabling PR-commit mode
requires a contract decision before it is added.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

__all__ = ["ToolCall", "ToolResult", "Tool"]

Tool = Literal[
    "httpx",
    "katana",
    "playwright",
    "bola",
    "ssrf",
    "nuclei",
    "schemathesis",
    "semgrep",
    "gitleaks",
    "trufflehog",
    "osv",
    "trivy",
    "syft",
    "treesitter",
    "cbom",
    "sslyze",
    "git",
    "pytest",  # AG11.1: the project's own tests on a fix workspace (approved contract extension)
]


class ToolCall(BaseModel):
    tool: Tool
    scan_id: str
    target_host: str | None = None
    args: dict = Field(default_factory=dict)
    test_input_ids: list[str] = Field(default_factory=list)


class ToolResult(BaseModel):
    ok: bool
    tool: str
    exit_code: int | None = None
    duration_ms: int = 0
    output: dict | list | None = None
    stderr_tail: str | None = None
    blocked_reason: str | None = None
