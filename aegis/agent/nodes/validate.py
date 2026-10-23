"""validate node (PHASES P12.2 + P12.3 / AG10.1) — the only writer of explanation fields.

Reads what ``explain`` recorded, keeps a claim only if every evidence ID it cites exists
and belongs to the finding (or is a correlated neighbour in the graph), and writes the
result:

* every claim — kept or dropped — is saved as a ``Claim`` row (``kept`` says which), and
  each drop is logged as a WARNING with the reason (FR-A4);
* ``what`` / ``impact`` / ``exploit`` on the finding are assembled from the **kept** claims
  only, through :class:`ExplanationWriter` — nothing the model said that failed validation
  can reach the finding;
* a part with no valid claim is filled from the fixed templates in ``explanation.py``
  (recorded in the audit log), so every finding is fully explained even if the model was
  down. ``where`` is never stored here: it is built from the real source when shown.

The model never writes a finding; this node is the single, narrow gate.
"""

from __future__ import annotations

import json
import time
from typing import Any

from langchain_core.runnables import RunnableConfig
from pydantic import ValidationError

from aegis.agent.deps import get_deps
from aegis.agent.explanation import EXPLAIN_FIELDS, template_claims
from aegis.agent.schemas import Claim
from aegis.agent.validator import correlated_evidence_ids, exploit_established, validate_claims
from aegis.evidence.links import visible_findings
from aegis.evidence.store import EvidenceStore
from aegis.graph.correlator import build_graph, load_handlers
from aegis.observability import get_logger

log = get_logger("agent.node.validate")


class ExplanationWriter:
    """The single path by which text reaches a finding's explanation fields."""

    FIELDS = EXPLAIN_FIELDS

    def __init__(self, store: EvidenceStore):
        self._store = store

    def write(self, finding_id: str, parts: dict[str, str]) -> None:
        unexpected = set(parts) - set(self.FIELDS)
        if unexpected:
            raise ValueError(f"ExplanationWriter may only write {self.FIELDS}, not {sorted(unexpected)}")
        self._store.update_finding_fields(finding_id, **parts)


def _proposed_claims(store: EvidenceStore, scan_id: str, finding_id: str) -> list[Claim]:
    """The model's latest proposal for this finding (empty if none / unusable)."""
    latest: list[dict[str, Any]] = []
    for decision in store.list_decisions(scan_id, finding_id):
        if decision.node != "explain" or not decision.valid:
            continue
        try:
            latest = json.loads(decision.output_json or "{}").get("claims") or []
        except (ValueError, AttributeError):
            latest = []
    claims: list[Claim] = []
    for raw in latest:
        try:
            claims.append(Claim(**raw))
        except (ValidationError, TypeError):
            log.warning("validate.unreadable_claim", finding_id=finding_id)
    return claims


def validate(state: dict, config: RunnableConfig) -> dict:
    scan_id = state["scan_id"]
    log.info("node.enter", node="validate", scan_id=scan_id)
    started = time.monotonic()
    deps = get_deps(config)
    store = deps.store
    writer = ExplanationWriter(store)
    graph = build_graph(store, scan_id, load_handlers(store, scan_id))

    kept_total = dropped_total = filled_total = 0
    for finding in sorted(visible_findings(store, scan_id), key=lambda f: (-f.risk, f.id)):
        allowed = correlated_evidence_ids(store, graph, finding.id)
        verdicts = validate_claims(
            _proposed_claims(store, scan_id, finding.id),
            finding_id=finding.id, allowed_evidence_ids=allowed, store=store,
            exploit_established=exploit_established(finding),
        )
        kept = [v.claim for v in verdicts if v.kept]
        dropped = [v for v in verdicts if not v.kept]
        for v in dropped:
            log.warning(
                "claim.dropped", finding_id=finding.id, field=v.claim.field,
                evidence_ids=list(v.claim.evidence_ids), reasons=list(v.reasons),
            )

        missing = [f for f in EXPLAIN_FIELDS if not any(c.field == f for c in kept)]
        filled = template_claims(finding, sorted(e.id for e in store.evidence_for(finding.id)), missing)
        if missing and not filled:
            log.warning("validate.cannot_fill_without_evidence", finding_id=finding.id, parts=missing)
        kept += filled

        store.replace_claims(
            finding.id,
            [(c.field, c.text, list(c.evidence_ids), True) for c in kept]
            + [(v.claim.field, v.claim.text, list(v.claim.evidence_ids), False) for v in dropped],
        )
        writer.write(
            finding.id,
            {f: " ".join(c.text for c in kept if c.field == f) for f in EXPLAIN_FIELDS if any(c.field == f for c in kept)},
        )
        store.add_decision(
            scan_id, "validate", "rule", finding_id=finding.id,
            input_summary={"proposed": len(verdicts), "allowed_evidence": sorted(allowed)},
            output={
                "kept": len(kept) - len(filled),
                "dropped": [
                    {"field": v.claim.field, "evidence_ids": list(v.claim.evidence_ids), "reasons": list(v.reasons)}
                    for v in dropped
                ],
                "filled_from_template": [c.field for c in filled],
            },
            valid=True, error=None,
        )
        kept_total += len(kept) - len(filled)
        dropped_total += len(dropped)
        filled_total += len(filled)

    log.info(
        "node.exit", node="validate", scan_id=scan_id, kept=kept_total, dropped=dropped_total,
        filled_from_template=filled_total, duration_ms=int((time.monotonic() - started) * 1000),
    )
    return {"completed_stages": ["validate"]}
