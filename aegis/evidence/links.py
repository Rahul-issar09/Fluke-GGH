"""Finding links — the audit record of correlation merges (AG07).

When a runtime finding is correlated with a code-only finding of the same
weakness in the same handler, the code finding is a *duplicate* of the same
issue: its evidence moves to the runtime (primary) finding and the duplicate is
recorded here, so reports and rankings count the issue once (PHASES P9.4 —
"linked, not double-counted").

This is an **additive** table: ``Finding`` is a frozen contract and has no
``merged_into`` field. Rows are never deleted — the duplicate keeps existing, so
re-running the scanner that produced it finds its fingerprint again instead of
creating a new duplicate every time.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import UniqueConstraint
from sqlmodel import Field, SQLModel, select

from aegis.evidence.models import Finding
from aegis.evidence.store import EvidenceStore

__all__ = [
    "FindingLink",
    "MERGED_DUPLICATE",
    "add_link",
    "links_for_scan",
    "merged_ids",
    "linked_to",
    "visible_findings",
]

MERGED_DUPLICATE = "merged_duplicate"


class FindingLink(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("primary_id", "linked_id", name="uq_finding_link"),)

    id: int | None = Field(default=None, primary_key=True)
    scan_id: str = Field(index=True)
    primary_id: str = Field(index=True)
    linked_id: str = Field(index=True)
    kind: str = MERGED_DUPLICATE
    score: float | None = None
    evidence_ids_json: str = "[]"  # evidence that moved to the primary
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def add_link(
    store: EvidenceStore,
    scan_id: str,
    primary_id: str,
    linked_id: str,
    *,
    score: float | None,
    evidence_ids: list[str],
) -> FindingLink:
    """Record a merge; idempotent for the same (primary, linked) pair."""
    with store.session() as s:
        existing = s.exec(
            select(FindingLink).where(
                FindingLink.primary_id == primary_id, FindingLink.linked_id == linked_id
            )
        ).first()
        if existing is not None:
            return existing
        link = FindingLink(
            scan_id=scan_id,
            primary_id=primary_id,
            linked_id=linked_id,
            score=score,
            evidence_ids_json=json.dumps(evidence_ids),
        )
        s.add(link)
        s.commit()
        return link


def links_for_scan(store: EvidenceStore, scan_id: str) -> list[FindingLink]:
    with store.session() as s:
        return list(s.exec(select(FindingLink).where(FindingLink.scan_id == scan_id)))


def merged_ids(store: EvidenceStore, scan_id: str) -> set[str]:
    """IDs of findings that were absorbed into another (excluded from ranking/reports)."""
    return {link.linked_id for link in links_for_scan(store, scan_id) if link.kind == MERGED_DUPLICATE}


def linked_to(store: EvidenceStore, primary_id: str) -> list[str]:
    with store.session() as s:
        rows = s.exec(select(FindingLink).where(FindingLink.primary_id == primary_id))
        return sorted(link.linked_id for link in rows)


def visible_findings(store: EvidenceStore, scan_id: str, **filters) -> list[Finding]:
    """The scan's findings with merged duplicates removed — what ranking and reports use."""
    hidden = merged_ids(store, scan_id)
    return [f for f in store.list_findings(scan_id, **filters) if f.id not in hidden]
