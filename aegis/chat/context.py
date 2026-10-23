"""Assemble the generator's context from reranked chunks (RAG07).

Groups the reranked chunks by finding (highest-ranked first), keeps at most ``max_findings``
findings within a token budget — always keeping the top finding's top chunk — and attaches each
kept finding's **evidence digests** (never payloads) as its citable evidence. The whole thing is
built through the prompt guard (AG01.3), so only whitelisted, safe fields reach the model.

It also returns the **allowed citation set** — the finding and evidence IDs actually present in the
context. The explain validator (RAG11) accepts an answer only if every cited ID is in this set, so
the model can't cite something it was never shown.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.agent.prompt_guard import build_payload
from aegis.chat.chunker import estimate_tokens
from aegis.chat.schemas import RetrievedChunk
from aegis.evidence.digest import digest
from aegis.observability import get_logger

__all__ = ["Context", "build_context", "FIELD_ORDER"]

log = get_logger("chat.context")

# the order fields are presented to the model (RAG_PHASES RAG07)
FIELD_ORDER = ("what", "impact", "exploit", "where", "fix", "summary")
_PAYLOAD_MAX_BYTES = 16000


@dataclass
class Context:
    payload: dict
    finding_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)

    @property
    def allowed_citations(self) -> set[str]:
        """Every finding and evidence id the model is allowed to cite (RAG11 enforces this)."""
        return set(self.finding_ids) | set(self.evidence_ids)

    @property
    def is_empty(self) -> bool:
        return not self.finding_ids


def _field_key(rc: RetrievedChunk) -> tuple[int, int]:
    f = rc.chunk.metadata.field
    return (FIELD_ORDER.index(f) if f in FIELD_ORDER else len(FIELD_ORDER), rc.chunk.metadata.chunk_index)


def build_context(store, question: str, reranked: list[RetrievedChunk], *, max_findings: int = 5,
                  token_budget: int = 3000) -> Context:
    """Build the context payload and the allowed citation set from the reranked chunks."""
    # finding order = first appearance in the reranked list; cap to max_findings
    groups: dict[str, list[RetrievedChunk]] = {}
    order: list[str] = []
    for rc in reranked:
        fid = rc.chunk.metadata.finding_id
        if fid not in groups:
            groups[fid] = []
            order.append(fid)
        groups[fid].append(rc)
    order = order[:max_findings]

    kept_fields: dict[str, dict] = {}   # fid -> {"meta", "digests", "eids", <field>: [texts]}
    kept_order: list[str] = []
    used = 0

    for fid in order:
        chunks = sorted(groups[fid], key=_field_key)
        eids = sorted({e for rc in groups[fid] for e in rc.chunk.metadata.evidence_ids})
        digests = [digest(ev) for ev in (store.get_evidence(e) for e in eids) if ev is not None]
        digest_cost = estimate_tokens(" ".join(digests))
        opened = False
        for rc in chunks:
            tokens = rc.chunk.metadata.tokens or estimate_tokens(rc.chunk.text)
            extra = tokens + (0 if opened else digest_cost)
            # always keep the very first chunk of the top-ranked finding, budget or not
            must_keep = not kept_order and not opened
            if used + extra > token_budget and not must_keep:
                continue
            used += extra
            if not opened:
                opened = True
                kept_order.append(fid)
                kept_fields[fid] = {"meta": rc.chunk.metadata, "digests": digests, "eids": eids}
            kept_fields[fid].setdefault(rc.chunk.metadata.field, []).append(rc.chunk.text)
        if not opened:
            log.info("context.finding_dropped_over_budget", finding_id=fid)

    findings: list[dict] = []
    evidence_ids: list[str] = []
    for fid in kept_order:
        data = kept_fields[fid]
        meta = data["meta"]
        fdict: dict = {
            "finding_id": fid, "type": meta.type, "owasp": meta.owasp,
            "state": meta.state, "risk": meta.risk, "evidence_digests": data["digests"],
        }
        for f in FIELD_ORDER:
            if f in data:
                fdict[f] = " ".join(data[f])
        findings.append(fdict)
        evidence_ids += [e for e in data["eids"] if e not in evidence_ids]

    payload = build_payload({"question": question, "findings": findings}, max_bytes=_PAYLOAD_MAX_BYTES)
    log.info("context.built", findings=len(findings), evidence=len(evidence_ids), tokens=used)
    return Context(payload=payload, finding_ids=list(kept_order), evidence_ids=evidence_ids)
