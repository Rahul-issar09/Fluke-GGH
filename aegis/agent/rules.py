"""Rules-first next-step policy (PHASES P11.1 / AG09.1) — no LLM.

``valid_steps`` says which next steps are *permissible* for a finding;
``decide`` returns a decision only when exactly one is (an obvious case);
``default`` is the deterministic fallback used when the LLM is not consulted or
its answer is rejected. The LLM (AG09.2) is only ever asked to pick among steps
this module already declared valid.

Decision table (evaluated top to bottom, first match wins)::

    resolved                                              → mark_sufficient
    correlation ≥ threshold and state ≥ corroborated      → mark_sufficient          (P11.1 row 3)
    TLS finding with no crypto asset, source available   → request_crypto_scan      (P11.1 row 4)
    correlated mode, runtime finding, no function:
        confirmed                                         → request_source_evidence  (P11.1 row 1)
        candidate / corroborated                          → request_source_evidence | mark_sufficient   ← LLM judgment
    route + function but no correlation score            → link_and_score           (P11.1 row 2)
    correlated mode, static finding of a runtime-checkable
        type, not runtime-proven, endpoint known          → request_runtime_retest   (P11.1 row 5)
    otherwise (nothing left to request)                   → mark_sufficient

The TLS row sits above the generic runtime row on purpose: "which config sets
this protocol?" is answered by the crypto engine, never by a route → handler
lookup, even if the finding happens to carry a route.

A tool action is offered **once**. If it was already tried and the finding is
still unresolved, the finding is *exhausted*: ``mark_sufficient`` or
``escalate_to_human`` — a judgment call, and ``default`` picks the cautious
``escalate_to_human``.

Reconciling the docs (conflict C41): SYSTEM_DESIGN §5.4's sample prompt shows
``request_source_evidence`` *and* ``escalate_to_human`` both valid for a fresh
confirmed runtime finding, while PHASES P11.1 lists that case as a rule
decision. This module follows P11.1 and the FR-A1 contract ("LLM only when
several steps are valid"): ``escalate_to_human`` becomes valid only after the
obvious action has been tried.

Decisions cite only evidence IDs that belong to the finding, and the summary
holds IDs and normalized fields only — never raw evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from aegis.agent.schemas import NextStep, NextStepDecision, Target
from aegis.evidence.models import Finding
from aegis.evidence.store import EvidenceStore
from aegis.graph.correlator import CORRELATION_THRESHOLD
from aegis.graph.security_graph import SecurityGraph
from aegis.observability import get_logger

__all__ = [
    "FindingSummary",
    "RUNTIME_CHECKABLE_TYPES",
    "ACTION_STEPS",
    "summarize_finding",
    "attempted_steps",
    "valid_steps",
    "decide",
    "default",
]

log = get_logger("agent.rules")

# Weaknesses AEGIS can prove at runtime (a differential replay / out-of-band check exists).
RUNTIME_CHECKABLE_TYPES = frozenset({"broken_access_control", "ssrf"})
TLS_TYPES = frozenset({"weak_tls", "tls"})
# The steps that run a tool; the other two just close the investigation of a finding.
ACTION_STEPS = (
    NextStep.request_source_evidence,
    NextStep.request_runtime_retest,
    NextStep.request_crypto_scan,
    NextStep.link_and_score,
)
_STATE_RANK = {"candidate": 0, "corroborated": 1, "confirmed": 2, "resolved": 3}
_PROOF_KINDS = {"http_exchange", "oob_hit", "retest"}
_MAX_REASON_IDS = 5

# which evidence best supports each step (falls back to all of the finding's evidence)
_REASON_KINDS: dict[NextStep, set[str] | None] = {
    NextStep.request_source_evidence: {"http_exchange", "oob_hit"},
    NextStep.request_runtime_retest: {"code_location", "dataflow_path"},
    NextStep.request_crypto_scan: {"tls_scan"},
    NextStep.link_and_score: {"code_location", "dataflow_path"},
    NextStep.mark_sufficient: None,
    NextStep.escalate_to_human: None,
}
# the cautious pick when several steps are valid and the LLM is not (or cannot be) used
_DEFAULT_PREFERENCE = (
    NextStep.escalate_to_human,
    NextStep.request_source_evidence,
    NextStep.link_and_score,
    NextStep.request_runtime_retest,
    NextStep.request_crypto_scan,
    NextStep.mark_sufficient,
)


@dataclass(frozen=True)
class FindingSummary:
    """Everything the rules (and later the LLM) may know about a finding."""

    finding_id: str
    type: str
    state: str  # candidate | corroborated | confirmed | resolved
    mode: str  # the scan's mode: runtime | code | correlated
    route: str | None = None
    function: str | None = None
    file: str | None = None
    line: int | None = None
    correlation: float | None = None
    risk: float = 0.0
    evidence: tuple[tuple[str, str], ...] = ()  # (evidence_id, kind), sorted by id
    runtime_proven: bool = False
    handler_route: str | None = None  # endpoint that reaches a static finding (from the graph)
    has_crypto_asset: bool = False
    attempted: tuple[str, ...] = field(default_factory=tuple)  # tool steps already dispatched

    @property
    def evidence_ids(self) -> list[str]:
        return [eid for eid, _ in self.evidence]

    @property
    def runtime_origin(self) -> bool:
        return bool(self.route)

    @property
    def is_static(self) -> bool:
        return bool(self.file) and not self.route

    @property
    def is_tls(self) -> bool:
        return self.type in TLS_TYPES or any(kind == "tls_scan" for _, kind in self.evidence)


# --------------------------------------------------------------------------- #
# building the summary from the store / graph
# --------------------------------------------------------------------------- #
def attempted_steps(store: EvidenceStore, scan_id: str, finding_id: str) -> tuple[str, ...]:
    """Tool steps already decided for this finding (from the audit trail of decisions)."""
    action_values = {s.value for s in ACTION_STEPS}
    done: list[str] = []
    for decision in store.list_decisions(scan_id, finding_id):
        if not decision.valid or decision.node != "investigate":
            continue
        try:
            step = json.loads(decision.output_json or "{}").get("next_step")
        except (json.JSONDecodeError, ValueError, AttributeError):
            continue
        if step in action_values and step not in done:
            done.append(step)
    return tuple(done)


def _handler_route(finding_id: str, graph: SecurityGraph | None) -> str | None:
    """The endpoint that reaches the function a static finding sits in."""
    if graph is None or graph.backend.node(finding_id) is None:
        return None
    routes: list[str] = []
    for target in graph.backend.successors(finding_id, "ON"):
        if (graph.backend.node(target) or {}).get("type") == "function":
            routes += graph.backend.predecessors(target, "HANDLED_BY")
    return sorted(routes)[0] if routes else None


def summarize_finding(
    store: EvidenceStore,
    finding: Finding,
    *,
    scan_mode: str,
    graph: SecurityGraph | None = None,
) -> FindingSummary:
    evidence = tuple(sorted((e.id, e.kind) for e in store.evidence_for(finding.id)))
    kinds = {kind for _, kind in evidence}
    state = finding.state.value
    return FindingSummary(
        finding_id=finding.id,
        type=finding.type,
        state=state,
        mode=scan_mode,
        route=finding.route,
        function=finding.function,
        file=finding.file,
        line=finding.line,
        correlation=finding.correlation_score,
        risk=finding.risk,
        evidence=evidence,
        runtime_proven=state in ("confirmed", "resolved") and bool(kinds & _PROOF_KINDS),
        handler_route=_handler_route(finding.id, graph),
        has_crypto_asset="crypto_asset" in kinds,
        attempted=attempted_steps(store, finding.scan_id, finding.id),
    )


# --------------------------------------------------------------------------- #
# the policy
# --------------------------------------------------------------------------- #
def _offer(step: NextStep, s: FindingSummary, *also: NextStep) -> list[NextStep]:
    """Offer a tool step once; after that the finding is exhausted."""
    if step.value in s.attempted:
        return [NextStep.mark_sufficient, NextStep.escalate_to_human]
    return [step, *also]


def valid_steps(s: FindingSummary, threshold: float = CORRELATION_THRESHOLD) -> list[NextStep]:
    """The next steps that are permissible for *s*, in a stable order."""
    rank = _STATE_RANK[s.state]
    correlated_mode = s.mode == "correlated"

    if s.state == "resolved":
        return [NextStep.mark_sufficient]

    # row 3 — already linked to its root cause with enough evidence
    if s.correlation is not None and s.correlation >= threshold and rank >= _STATE_RANK["corroborated"]:
        return [NextStep.mark_sufficient]

    # row 4 (before row 1: a type-specific rule outranks the generic one) — a TLS result that is not tied to any crypto asset.
    # A runtime-only scan has no code to search (TNW-2): its TLS result stands on the live check alone.
    if s.is_tls and not s.has_crypto_asset and s.mode != "runtime":
        return _offer(NextStep.request_crypto_scan, s)

    # row 1 — a runtime finding with no root cause in code yet
    if correlated_mode and s.runtime_origin and not s.function:
        if s.state == "confirmed":
            return _offer(NextStep.request_source_evidence, s)
        # weaker evidence: worth a source lookup, or good enough as it is — a judgment call
        return _offer(NextStep.request_source_evidence, s, NextStep.mark_sufficient)

    # row 2 — located but never scored
    if s.route and s.function and s.correlation is None:
        return _offer(NextStep.link_and_score, s)

    # row 5 — a static finding we can try to prove against the running app
    if (
        correlated_mode
        and s.is_static
        and s.type in RUNTIME_CHECKABLE_TYPES
        and not s.runtime_proven
        and s.handler_route
    ):
        return _offer(NextStep.request_runtime_retest, s)

    return [NextStep.mark_sufficient]


def _reason_ids(s: FindingSummary, step: NextStep) -> list[str]:
    wanted = _REASON_KINDS[step]
    ids = [eid for eid, kind in s.evidence if wanted is None or kind in wanted] or s.evidence_ids
    return ids[:_MAX_REASON_IDS]


def _decision(s: FindingSummary, step: NextStep) -> NextStepDecision | None:
    reasons = _reason_ids(s, step)
    if not reasons:  # a decision must cite evidence (FR-A2); a finding with none cannot be decided
        log.warning("rules.no_evidence_to_cite", finding_id=s.finding_id, step=step.value)
        return None
    return NextStepDecision(
        finding_id=s.finding_id,
        next_step=step,
        target=Target(route=s.route or s.handler_route, function=s.function),
        reason_evidence_ids=reasons,
    )


def decide(s: FindingSummary, threshold: float = CORRELATION_THRESHOLD) -> NextStepDecision | None:
    """A rule decision when exactly one step is valid, else ``None`` (the LLM may choose)."""
    steps = valid_steps(s, threshold)
    if len(steps) != 1:
        return None
    return _decision(s, steps[0])


def default(s: FindingSummary, threshold: float = CORRELATION_THRESHOLD) -> NextStepDecision | None:
    """Deterministic fallback among the valid steps (the cautious one wins)."""
    steps = valid_steps(s, threshold)
    for preferred in _DEFAULT_PREFERENCE:
        if preferred in steps:
            return _decision(s, preferred)
    return None  # unreachable: valid_steps is never empty
