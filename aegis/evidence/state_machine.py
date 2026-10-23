"""Evidence state machine (PHASES P5.5).

The ONLY place ``Finding.state`` is assigned (STRUCTURE invariant I-4 / B-6).
State advances on evidence, never on the model's say-so.

    ∅ → candidate            one tool signal (set at creation)
    candidate → corroborated second independent tool/layer
    * → confirmed            http_exchange (replay diff), oob_hit, or verified secret
    confirmed/corroborated → resolved   verified FixAttempt (+ retest if correlated)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlmodel import select

from aegis.evidence.models import Evidence, Finding, FindingState, StateTransition
from aegis.observability import get_logger

__all__ = ["IllegalTransition", "transition", "LEGAL"]

log = get_logger("evidence.state_machine")

CONFIRMING_KINDS = {"http_exchange", "oob_hit"}

LEGAL: dict[FindingState | None, set[FindingState]] = {
    None: {FindingState.candidate},
    FindingState.candidate: {FindingState.corroborated, FindingState.confirmed},
    FindingState.corroborated: {FindingState.confirmed, FindingState.resolved},
    FindingState.confirmed: {FindingState.resolved},
    FindingState.resolved: set(),
}


class IllegalTransition(Exception):
    pass


def _distinct_tools(evs: list[Evidence]) -> set[str]:
    return {e.tool for e in evs}


def _requirement_met(
    session, finding: Finding, to: FindingState, evidence_ids: list[str]
) -> tuple[bool, str]:
    evs = [session.get(Evidence, eid) for eid in evidence_ids]
    evs = [e for e in evs if e is not None]
    all_for_finding = list(
        session.exec(select(Evidence).where(Evidence.finding_id == finding.id))
    )

    if to is FindingState.candidate:
        return (len(evs) >= 1 or len(all_for_finding) >= 1, "needs one signal")

    if to is FindingState.corroborated:
        tools = _distinct_tools(all_for_finding) | _distinct_tools(evs)
        return (len(tools) >= 2, "needs a 2nd independent tool/layer")

    if to is FindingState.confirmed:
        ok = any(e.kind in CONFIRMING_KINDS for e in evs) or any(
            e.kind == "secret" and json.loads(e.payload_json or "{}").get("verified")
            for e in evs
        )
        return (ok, "needs http_exchange/oob_hit or a verified secret")

    if to is FindingState.resolved:
        ok = any(e.kind == "retest" for e in evs)
        return (ok, "needs a passing retest")

    return (False, "unknown target state")


def transition(
    store,
    finding_id: str,
    to_state: str,
    *,
    evidence_ids: list[str],
    actor: str,
    reason: str = "",
) -> Finding:
    """Advance a finding's state if legal and evidence-backed, else raise."""
    to = FindingState(to_state)
    with store.session() as s:
        finding = s.get(Finding, finding_id)
        if finding is None:
            raise IllegalTransition(f"unknown finding {finding_id}")
        current = finding.state
        if to not in LEGAL.get(current, set()):
            raise IllegalTransition(f"{current} -> {to} is not a legal transition")

        met, why = _requirement_met(s, finding, to, evidence_ids)
        if not met:
            raise IllegalTransition(f"{current} -> {to} rejected: {why}")

        finding.state = to  # the single authorized state assignment
        finding.updated_at = datetime.now(timezone.utc)
        s.add(finding)
        s.add(
            StateTransition(
                finding_id=finding_id,
                from_state=current.value,
                to_state=to.value,
                reason=reason,
                evidence_ids=json.dumps(evidence_ids),
                actor=actor,
            )
        )
        s.commit()
        log.info(
            "state.transition",
            finding_id=finding_id,
            from_state=current.value,
            to_state=to.value,
            actor=actor,
        )
        return finding
