"""Normalizer (PHASES P5.3).

Turns adapter output into persisted findings + evidence, deduplicating by
fingerprint and merging sources. This and the adapters are the only writers of
findings (STRUCTURE boundary B-5). The LLM is never involved.
"""

from __future__ import annotations

from aegis.evidence import dedup, state_machine
from aegis.evidence.adapters.base import EvidenceDraft, FindingDraft, fingerprint
from aegis.evidence.models import FindingState
from aegis.evidence.store import EvidenceStore
from aegis.observability import get_logger

__all__ = ["ingest", "confirm_with_proof"]

log = get_logger("evidence.normalizer")


def _persist_evidence(
    store: EvidenceStore, scan_id: str, finding_id: str, drafts: list[EvidenceDraft]
) -> list[str]:
    ids: list[str] = []
    for d in drafts:
        ev = store.add_evidence(
            scan_id,
            kind=d.kind,
            tool=d.tool,
            payload=d.payload,
            finding_id=finding_id,
            tool_version=d.tool_version,
            db_date=d.db_date,
        )
        ids.append(ev.id)
    return ids


def ingest(
    store: EvidenceStore,
    scan_id: str,
    results: list[tuple[FindingDraft, list[EvidenceDraft]]],
) -> list[str]:
    """Persist adapter results; return the affected finding IDs."""
    touched: list[str] = []
    for draft, ev_drafts in results:
        fp = fingerprint(draft)
        existing = store.find_by_fingerprint(scan_id, fp)

        if existing is None:
            finding = store.add_finding(
                scan_id,
                type=draft.type,
                owasp=draft.owasp,
                title=draft.title,
                route=draft.route,
                function=draft.function,
                file=draft.file,
                line=draft.line,
                severity=draft.severity,
                mode=draft.mode,
                fingerprint=fp,
                sources=dedup.merge_sources("[]", draft.source),
                state=FindingState.candidate,
            )
            finding_id = finding.id
            log.info("normalizer.new_finding", finding_id=finding_id, type=draft.type)
        else:
            finding_id = existing.id
            merged = dedup.merge_sources(existing.sources, draft.source)
            store.update_finding_fields(finding_id, sources=merged)
            log.info("normalizer.merged", finding_id=finding_id, type=draft.type)

        _persist_evidence(store, scan_id, finding_id, ev_drafts)

        # corroboration: independent signals from ≥ 2 tools
        current = store.get_finding(finding_id)
        if current and current.state == FindingState.candidate:
            if dedup.distinct_tool_count(current.sources) >= 2:
                try:
                    state_machine.transition(
                        store,
                        finding_id,
                        "corroborated",
                        evidence_ids=[e.id for e in store.evidence_for(finding_id)],
                        actor="normalizer",
                        reason="second independent tool",
                    )
                except state_machine.IllegalTransition as exc:
                    log.warning("normalizer.corroborate_skip", finding_id=finding_id, error=str(exc))

        if finding_id not in touched:
            touched.append(finding_id)
    return touched


def confirm_with_proof(
    store: EvidenceStore,
    finding_ids: list[str],
    proof_kinds: set[str],
    *,
    actor: str,
    reason: str,
) -> None:
    """Move candidate findings to ``confirmed`` using their proof evidence.

    The state machine decides whether the evidence is sufficient; findings that
    are not candidates (already confirmed, resolved, …) are left alone, which
    makes re-running a check idempotent.
    """
    for finding_id in finding_ids:
        finding = store.get_finding(finding_id)
        if finding is None or finding.state != FindingState.candidate:
            continue
        proof = [e.id for e in store.evidence_for(finding_id) if e.kind in proof_kinds]
        state_machine.transition(
            store, finding_id, "confirmed", evidence_ids=proof, actor=actor, reason=reason
        )
