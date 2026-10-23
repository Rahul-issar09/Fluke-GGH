"""Validators for what the LLM is allowed to say (AG09.2 decisions, AG10.1 claims).

``validate_decision`` returns a list of human-readable problems (empty means
valid). The investigation node feeds that list back to the model for one retry
and records it in the audit trail if the answer is ultimately refused. The
messages mention only IDs and enum values — never evidence content.

A decision is accepted only if:

* ``next_step`` is one of the steps the *rules* declared valid for this finding,
* ``finding_id`` is the finding it was asked about,
* every ``reason_evidence_id`` exists **and belongs to that finding** (an ID that
  exists but belongs to another finding is just as invalid as an invented one),
* any ``target`` route / function it names actually exists — in the graph, or as
  the finding's own route / function.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from aegis.agent.explanation import EXPLAIN_FIELDS
from aegis.agent.rules import FindingSummary
from aegis.agent.schemas import Claim, NextStep, NextStepDecision
from aegis.evidence.store import EvidenceStore
from aegis.graph.route_normalize import normalize_route, split_route
from aegis.graph.security_graph import SecurityGraph

__all__ = [
    "validate_decision",
    "ClaimVerdict",
    "validate_claims",
    "unsupported_strong_claim",
    "exploit_established",
    "correlated_evidence_ids",
    "MAX_CLAIMS_PER_FIELD",
]


def _route_known(route: str, summary: FindingSummary, graph: SecurityGraph | None) -> bool:
    if route in (summary.route, summary.handler_route):
        return True
    if graph is None:
        return False
    parts = split_route(route)
    key = normalize_route(*parts) if parts else route
    node = graph.backend.node(key)
    return bool(node and node.get("type") == "endpoint")


def _function_known(function: str, summary: FindingSummary, graph: SecurityGraph | None) -> bool:
    if function == summary.function:
        return True
    if graph is None:
        return False
    return any(
        key == function or attrs.get("label") == function for key, attrs in graph.backend.nodes("function")
    )


def validate_decision(
    decision: NextStepDecision,
    *,
    summary: FindingSummary,
    valid: list[NextStep],
    store: EvidenceStore,
    graph: SecurityGraph | None,
) -> list[str]:
    errors: list[str] = []

    if decision.next_step not in valid:
        allowed = ", ".join(step.value for step in valid)
        errors.append(f"next_step '{decision.next_step.value}' is not allowed; choose one of: {allowed}")

    if decision.finding_id != summary.finding_id:
        errors.append(f"finding_id must be '{summary.finding_id}', not '{decision.finding_id}'")

    own = set(summary.evidence_ids)
    for evidence_id in dict.fromkeys(decision.reason_evidence_ids):
        if evidence_id in own:
            continue
        if store.get_evidence(evidence_id) is None:
            errors.append(f"evidence {evidence_id} does not exist")
        else:
            errors.append(f"evidence {evidence_id} does not belong to {summary.finding_id}")

    target = decision.target
    if target.route is not None and not _route_known(target.route, summary, graph):
        errors.append(f"target route '{target.route}' is not a known endpoint")
    if target.function is not None and not _function_known(target.function, summary, graph):
        errors.append(f"target function '{target.function}' is not a known function")

    return errors


# --------------------------------------------------------------------------- #
# claims (AG10.1)
# --------------------------------------------------------------------------- #
MAX_CLAIMS_PER_FIELD = 3

# Phrases that assert a concrete, high-impact exploitation (code execution, takeover, data theft,
# unauthorised access). A claim may use them only when the finding's exploitability is *established*
# by evidence (runtime-proven, or a data-flow path to the sink). For a finding where only a pattern
# or a vulnerable library version is known, such a claim is dropped — the model must stay
# conservative and traceable to evidence (no hallucinated attack paths).
_STRONG_EXPLOIT = re.compile(
    r"\b("
    r"remote code execution|arbitrary code|execute (?:arbitrary |)code|code execution|rce|"
    r"take over|takeover|full control|complete control|root access|"
    r"exfiltrat\w*|steal(?:s|ing|)? (?:the |)(?:data|credentials|secrets)|data theft|"
    r"unauthenti?cated access|unauthorized access|unauthorised access|"
    r"drop (?:the |)(?:database|tables?)|delete (?:all|the database)|"
    r"gain(?:s|ed|ing|) access to|bypass(?:es|ed|ing|) authentication"
    r")\b",
    re.IGNORECASE,
)


def unsupported_strong_claim(text: str, exploit_established: bool) -> str | None:
    """A reason when *text* asserts concrete exploitation the evidence does not establish, else None."""
    if exploit_established:
        return None
    m = _STRONG_EXPLOIT.search(text)
    if m is None:
        return None
    return (f"the claim asserts '{m.group(0)}', which the evidence does not establish; this "
            "finding's exploitability is not proven, so keep the wording conservative")
_CONTROL_CHARS = re.compile("[" + "".join(map(chr, [*range(0, 9), *range(11, 32), 127])) + "]")  # keeps 	 and 



@dataclass(frozen=True)
class ClaimVerdict:
    """The outcome for one claim; ``claim`` carries the cleaned text when kept."""

    claim: Claim
    kept: bool
    reasons: tuple[str, ...] = ()


def exploit_established(finding) -> bool:
    """Whether the finding's exploitability is backed by evidence: runtime-proven (confirmed/
    resolved) or a data-flow path to the sink. A pattern-only or dependency-version finding is not,
    so its explanation must stay conservative (§ LLM safety)."""
    state = getattr(finding.state, "value", finding.state)
    if state in ("confirmed", "resolved"):
        return True
    return float(getattr(finding, "exploitability", 0.0) or 0.0) >= 0.5


def correlated_evidence_ids(store: EvidenceStore, graph: SecurityGraph | None, finding_id: str) -> set[str]:
    """Evidence a finding's explanation may cite.

    Its own evidence, plus the evidence recorded on the graph edges (data flows, crypto/library
    uses) of the function(s) it sits in — its correlated neighbours. Nothing else: an ID that
    exists but belongs to an unrelated finding is not citable.
    """
    allowed = {e.id for e in store.evidence_for(finding_id)}
    if graph is None or graph.backend.node(finding_id) is None:
        return allowed
    functions = {
        t for t in graph.backend.successors(finding_id, "ON") if (graph.backend.node(t) or {}).get("type") == "function"
    }
    for kind in ("FLOWS_TO", "USES"):
        for source, _target, _k, attrs in graph.backend.edges(kind):
            if source in functions and attrs.get("evidence_id"):
                allowed.add(attrs["evidence_id"])
    return allowed


def validate_claims(
    claims: list[Claim],
    *,
    finding_id: str,
    allowed_evidence_ids: set[str],
    store: EvidenceStore,
    fields: tuple[str, ...] = EXPLAIN_FIELDS,
    max_per_field: int = MAX_CLAIMS_PER_FIELD,
    exploit_established: bool = True,
) -> list[ClaimVerdict]:
    """Decide, claim by claim, what may be shown (FR-A4).

    A claim is kept only if its field is one ``explain`` writes, its text is not empty, and
    **every** cited evidence ID is citable for this finding. Anything else is dropped — never
    repaired — and the reasons are returned so the drop can be logged and audited.
    """
    verdicts: list[ClaimVerdict] = []
    seen: set[tuple[str, str]] = set()
    per_field: Counter[str] = Counter()

    for claim in claims:
        reasons: list[str] = []
        text = _CONTROL_CHARS.sub("", claim.text).strip()

        if claim.field not in fields:
            reasons.append(f"field '{claim.field}' is not written by explain")
        if not text:
            reasons.append("claim text is empty")
        for evidence_id in dict.fromkeys(claim.evidence_ids):
            if evidence_id in allowed_evidence_ids:
                continue
            if store.get_evidence(evidence_id) is None:
                reasons.append(f"evidence {evidence_id} does not exist")
            else:
                reasons.append(f"evidence {evidence_id} does not belong to {finding_id}")
        if not reasons:
            strong = unsupported_strong_claim(text, exploit_established)
            if strong:
                reasons.append(strong)
        if not reasons and (claim.field, text) in seen:
            reasons.append("duplicate claim")
        if not reasons and per_field[claim.field] >= max_per_field:
            reasons.append(f"more than {max_per_field} '{claim.field}' claims")

        if reasons:
            verdicts.append(ClaimVerdict(claim, False, tuple(reasons)))
            continue
        seen.add((claim.field, text))
        per_field[claim.field] += 1
        verdicts.append(ClaimVerdict(claim.model_copy(update={"text": text}), True))
    return verdicts
