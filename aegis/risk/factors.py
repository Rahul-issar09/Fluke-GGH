"""Risk factor calculators (PHASES P10.2) — pure and deterministic.

Each function maps facts already in the store/graph to one factor in [0, 1]. No
LLM, no randomness, no clock: the same evidence and graph always give the same
factor, so a reviewer can recompute any score by hand.

=============  ==========================================================
Confidence     candidate 0.4 · corroborated 0.7 · confirmed 1.0
Exploitability runtime-proven 1.0 · data-flow reaches a sink 0.5 · pattern-only 0.3
Exposure       reproduced without credentials 1.0 · with credentials 0.6 ·
               not reachable from an endpoint 0.2
Criticality    route in ``sensitive_routes`` 1.0 · secrets 0.8 · sensitive
               keywords (admin/payment/user data…) 0.7 · otherwise 0.3
PathFactor     a sensitive endpoint within 3 hops: 1.0 − 0.2 × distance
=============  ==========================================================

"Runtime-proven" means the state machine confirmed it (or it is resolved) AND the
proof is an HTTP replay / out-of-band hit / retest / verified secret — a
candidate whose evidence merely happens to be an HTTP exchange (a Nuclei match)
is *not* runtime-proven.
"""

from __future__ import annotations

import json
import re
from collections import deque

from aegis.evidence.models import Evidence, Finding, FindingState
from aegis.graph.route_normalize import normalize_path, split_route
from aegis.graph.security_graph import SecurityGraph

__all__ = [
    "CONFIDENCE",
    "MAX_HOPS",
    "PATH_DECAY",
    "confidence",
    "dependency_severity",
    "exploitability",
    "exposure",
    "criticality",
    "path_factor",
    "is_sensitive_route",
]

# CVSS-style severity labels advisories carry (OSV database_specific / Trivy Severity), mapped to
# the base-severity factor. Used ONLY for vulnerable_dependency, and only from evidence (TNW):
# a dependency's risk reflects the advisory's own severity instead of one flat class value.
DEPENDENCY_SEVERITY: dict[str, float] = {
    "CRITICAL": 0.9, "HIGH": 0.8, "MODERATE": 0.5, "MEDIUM": 0.5, "LOW": 0.3, "NEGLIGIBLE": 0.2,
}

CONFIDENCE: dict[str, float] = {
    "candidate": 0.4,
    "corroborated": 0.7,
    "confirmed": 1.0,
    "resolved": 1.0,
}

MAX_HOPS = 3
PATH_DECAY = 0.2

_PROOF_KINDS = {"http_exchange", "oob_hit", "retest"}
_SENSITIVE_WORDS = (
    "admin", "payment", "billing", "card", "account", "user", "customer", "profile",
    "auth", "login", "token", "password", "credential", "ssn", "pii",
)


def _state_value(state: FindingState | str) -> str:
    return state.value if isinstance(state, FindingState) else str(state)


def _payload(ev: Evidence) -> dict:
    try:
        data = json.loads(ev.payload_json or "{}")
    except (json.JSONDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# --------------------------------------------------------------------------- #
def confidence(state: FindingState | str) -> float:
    return CONFIDENCE[_state_value(state)]


def dependency_severity(evidence: list[Evidence], default: float) -> float:
    """The base severity for a vulnerable-dependency finding: the highest advisory severity label
    present in its evidence, or *default* (the class base) when no label was recorded. Never
    invents a severity — it reads only what OSV/Trivy reported."""
    best = None
    for ev in evidence:
        for label in _payload(ev).get("severities") or []:
            score = DEPENDENCY_SEVERITY.get(str(label).upper())
            if score is not None and (best is None or score > best):
                best = score
    return best if best is not None else default


def exploitability(finding: Finding, evidence: list[Evidence]) -> float:
    kinds = {e.kind for e in evidence}
    proven_state = _state_value(finding.state) in ("confirmed", "resolved")
    verified_secret = any(e.kind == "secret" and _payload(e).get("verified") for e in evidence)
    if proven_state and (kinds & _PROOF_KINDS or verified_secret):
        return 1.0
    if "dataflow_path" in kinds:
        return 0.5
    return 0.3


def _on_endpoint(finding_id: str, graph: SecurityGraph | None) -> bool:
    if graph is None or graph.backend.node(finding_id) is None:
        return False
    for target in graph.backend.successors(finding_id, "ON"):
        node_type = (graph.backend.node(target) or {}).get("type")
        if node_type == "endpoint":
            return True
        if node_type == "function" and graph.backend.predecessors(target, "HANDLED_BY"):
            return True
    return False


def exposure(finding: Finding, evidence: list[Evidence], graph: SecurityGraph | None = None) -> float:
    contexts = {_payload(e).get("auth_context") for e in evidence}
    if "unauthenticated" in contexts:
        return 1.0
    if "authenticated" in contexts:
        return 0.6
    # no runtime observation: a declared endpoint is assumed to need a login; anything
    # not reachable from an endpoint (config, helpers) is treated as internal
    return 0.6 if _on_endpoint(finding.id, graph) else 0.2


def is_sensitive_route(route_or_path: str, sensitive_routes: tuple[str, ...] | list[str]) -> bool:
    """Segment-aware prefix match on normalized paths (``/api/accounts`` ⊃ ``/api/accounts/{param}``)."""
    split = split_route(route_or_path)
    path = normalize_path(split[1] if split else route_or_path)
    for entry in sensitive_routes:
        prefix = normalize_path(entry)
        if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z]+", text.lower()) if t]


def criticality(finding: Finding, sensitive_routes: tuple[str, ...] | list[str]) -> float:
    if finding.route and is_sensitive_route(finding.route, sensitive_routes):
        return 1.0
    best = 0.3
    if finding.type == "secret":
        best = max(best, 0.8)  # a credential protects everything behind it
    text = " ".join(filter(None, [finding.route, finding.function, finding.file]))
    if any(tok.startswith(word) for tok in _tokens(text) for word in _SENSITIVE_WORDS):
        best = max(best, 0.7)
    return best


def path_factor(
    finding_id: str, graph: SecurityGraph | None, sensitive_routes: tuple[str, ...] | list[str]
) -> float:
    """Distance (in graph hops, either direction) to the nearest sensitive endpoint."""
    if graph is None or graph.backend.node(finding_id) is None:
        return 0.0
    seen = {finding_id}
    queue: deque[tuple[str, int]] = deque([(finding_id, 0)])
    while queue:
        key, distance = queue.popleft()
        node = graph.backend.node(key) or {}
        if node.get("type") == "endpoint" and is_sensitive_route(key, sensitive_routes):
            return round(1.0 - PATH_DECAY * distance, 2)
        if distance == MAX_HOPS:
            continue
        neighbours = set(graph.backend.successors(key)) | set(graph.backend.predecessors(key))
        for nxt in sorted(neighbours - seen):
            seen.add(nxt)
            queue.append((nxt, distance + 1))
    return 0.0
