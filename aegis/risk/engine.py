"""Risk engine (PHASES P10.3) — one transparent, hand-recomputable score.

    Risk = Severity × Confidence × (1 + Exploitability + Exposure + Criticality + PathFactor) / Kmax
    Kmax = 5   (the largest the bracket can be, so Risk ∈ [0, 1])

Pure Python over the evidence store and the security graph. The formula and every
factor value are printed in each report (``risk_breakdown``) so a reviewer can
redo the arithmetic.

Worked example (the demo access-control bug, authenticated, on a sensitive route
one hop from the endpoint)::

    0.9 × 1.0 × (1 + 1.0 + 0.6 + 1.0 + 0.8) / 5 = 0.792

(The PRD's illustrative 0.86 uses Exposure = 1.0; that bug needs a login, so the
factor table gives 0.6. See conflict C7.)
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from pathlib import Path

import yaml

from aegis.evidence.links import merged_ids
from aegis.evidence.models import Finding, FindingState
from aegis.evidence.store import EvidenceStore
from aegis.graph.security_graph import SecurityGraph
from aegis.observability import get_logger
from aegis.risk import factors

__all__ = [
    "KMAX",
    "RISK_FORMULA",
    "DEFAULT_SEVERITY_PATH",
    "SeverityTable",
    "load_severity",
    "compute_risk",
    "score_finding",
    "score_scan",
    "rank_findings",
    "risk_breakdown",
]

log = get_logger("risk.engine")

KMAX = 5.0
RISK_FORMULA = "Risk = Severity × Confidence × (1 + Exploitability + Exposure + Criticality + PathFactor) / 5"
DEFAULT_SEVERITY_PATH = Path(__file__).with_name("severity.yaml")
_MIN_SEVERITY, _MAX_SEVERITY = 0.1, 1.0


@dataclass(frozen=True)
class SeverityTable:
    default: float
    types: dict[str, float]

    def for_type(self, type_: str) -> float:
        if type_ in self.types:
            return self.types[type_]
        log.warning("risk.unknown_type_default_severity", type=type_, severity=self.default)
        return self.default


@functools.lru_cache(maxsize=4)
def _load(path: str) -> SeverityTable:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    table = SeverityTable(default=float(data["default"]), types={k: float(v) for k, v in data["types"].items()})
    for name, value in {"default": table.default, **table.types}.items():
        if not _MIN_SEVERITY <= value <= _MAX_SEVERITY:
            raise ValueError(f"severity '{name}'={value} is outside [{_MIN_SEVERITY}, {_MAX_SEVERITY}]")
    return table


def load_severity(path: str | Path | None = None) -> SeverityTable:
    return _load(str(path or DEFAULT_SEVERITY_PATH))


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def compute_risk(
    severity: float,
    confidence: float,
    exploitability: float,
    exposure: float,
    criticality: float,
    path_factor: float,
) -> float:
    """The formula, rounded to 3 places. Inputs are clamped so Risk stays in [0, 1]."""
    bracket = 1 + sum(_clamp01(v) for v in (exploitability, exposure, criticality, path_factor))
    return round(_clamp01(severity) * _clamp01(confidence) * bracket / KMAX, 3)


@dataclass(frozen=True)
class Scores:
    severity: float
    confidence: float
    exploitability: float
    exposure: float
    criticality: float
    path_factor: float
    risk: float


def score_finding(
    finding: Finding,
    evidence: list,
    graph: SecurityGraph | None,
    *,
    sensitive_routes: tuple[str, ...] | list[str],
    severity_table: SeverityTable,
) -> Scores:
    severity = severity_table.for_type(finding.type)
    if finding.type == "vulnerable_dependency":
        severity = factors.dependency_severity(evidence, default=severity)
    conf = factors.confidence(finding.state)
    expl = factors.exploitability(finding, evidence)
    expo = factors.exposure(finding, evidence, graph)
    crit = factors.criticality(finding, sensitive_routes)
    path = factors.path_factor(finding.id, graph, sensitive_routes)
    return Scores(severity, conf, expl, expo, crit, path, compute_risk(severity, conf, expl, expo, crit, path))


def score_scan(
    store: EvidenceStore,
    scan_id: str,
    graph: SecurityGraph | None,
    *,
    sensitive_routes: tuple[str, ...] | list[str],
    severity_table: SeverityTable | None = None,
) -> dict[str, Scores]:
    """Score every visible finding and store the factors + risk on it.

    Merged duplicates are skipped (they are absorbed into their primary issue).
    Resolved findings are still scored (their record stays complete) but never ranked.
    """
    table = severity_table or load_severity()
    hidden = merged_ids(store, scan_id)
    results: dict[str, Scores] = {}
    for finding in sorted(store.list_findings(scan_id), key=lambda f: f.id):
        if finding.id in hidden:
            continue
        scores = score_finding(
            finding,
            store.evidence_for(finding.id),
            graph,
            sensitive_routes=sensitive_routes,
            severity_table=table,
        )
        store.update_finding_fields(
            finding.id,
            severity=scores.severity,
            exploitability=scores.exploitability,
            exposure=scores.exposure,
            criticality=scores.criticality,
            path_factor=scores.path_factor,
            risk=scores.risk,
        )
        results[finding.id] = scores
        log.debug("risk.scored", finding_id=finding.id, risk=scores.risk)
    log.info("risk.scan_scored", scan_id=scan_id, findings=len(results))
    return results


def rank_findings(store: EvidenceStore, scan_id: str) -> list[Finding]:
    """Open, de-duplicated findings by risk, highest first (ties: severity, then id)."""
    hidden = merged_ids(store, scan_id)
    open_findings = [
        f for f in store.list_findings(scan_id) if f.id not in hidden and f.state != FindingState.resolved
    ]
    return sorted(open_findings, key=lambda f: (-f.risk, -f.severity, f.id))


def _g(value: float) -> str:
    return f"{value:g}"


def risk_breakdown(finding: Finding) -> dict:
    """Every factor plus the arithmetic, for the report's "recompute it yourself" section."""
    conf = factors.confidence(finding.state)
    parts = {
        "severity": finding.severity,
        "confidence": conf,
        "exploitability": finding.exploitability,
        "exposure": finding.exposure,
        "criticality": finding.criticality,
        "path_factor": finding.path_factor,
    }
    risk = compute_risk(**parts)
    expression = (
        f"{_g(finding.severity)} × {_g(conf)} × (1 + {_g(finding.exploitability)} + {_g(finding.exposure)}"
        f" + {_g(finding.criticality)} + {_g(finding.path_factor)}) / {_g(KMAX)} = {_g(risk)}"
    )
    return {"formula": RISK_FORMULA, "factors": parts, "expression": expression, "risk": risk}
