"""Adapter interface + draft types (PHASES P5.3).

An adapter turns one tool's raw output into draft findings and evidence. The
normalizer fingerprints, dedups and persists them. Adapters never touch the DB
or the LLM.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

__all__ = ["EvidenceDraft", "FindingDraft", "Adapter", "fingerprint"]


@dataclass
class EvidenceDraft:
    kind: str
    tool: str
    payload: dict = field(default_factory=dict)
    tool_version: str = ""
    db_date: str | None = None


@dataclass
class FindingDraft:
    type: str
    owasp: str | None = None
    title: str = ""
    route: str | None = None
    function: str | None = None
    file: str | None = None
    line: int | None = None
    severity: float = 0.0
    source: str = ""  # tool id, e.g. "worker2.semgrep"
    mode: str | None = None
    # Discriminates distinct findings that share type+location (e.g. two
    # vulnerable parameters on one route, or two nuclei templates on one path).
    variant: str = ""


def fingerprint(draft: FindingDraft) -> str:
    """Dedup key: code findings by type|file|line, runtime by type|route."""
    if draft.file:
        key = f"{draft.type}|{draft.file}|{draft.line}"
    elif draft.route:
        key = f"{draft.type}|{draft.route}"
    else:
        key = f"{draft.type}|{draft.title}"
    if draft.variant:  # only appended when set, so existing fingerprints are unchanged
        key += f"|{draft.variant}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


class Adapter:
    """Base class: implement ``parse``."""

    tool: str = ""

    def parse(self, raw: object, scan_id: str) -> list[tuple[FindingDraft, list[EvidenceDraft]]]:
        raise NotImplementedError
