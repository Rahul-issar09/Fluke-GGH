"""Deterministic feature reranker (RAG06).

Fusion (RAG05) ordered candidates by rank alone. The reranker reorders them by relevance **and**
security signal, using only reproducible features — no model, no randomness (RAG invariant R-5):

* the fused score (the baseline),
* the question's intent → preferred field ("how to fix" prefers the ``fix`` chunk, "where" the
  ``where`` chunk, "why/explain" the ``what``/``impact``/``exploit`` chunks),
* exact overlap between the question's tokens and a chunk's metadata (a named function, file,
  route, type or OWASP code is a strong, precise signal),
* finding state (confirmed > corroborated > candidate),
* risk and correlation score,
* a diversity penalty, so later chunks of the same finding don't crowd out other findings.

Weights have safe defaults and can be overridden. The result is the top ``final_k`` candidates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.chat.schemas import RetrievedChunk
from aegis.chat.sparse import tokenize

__all__ = ["RerankWeights", "rerank", "preferred_fields"]


@dataclass(frozen=True)
class RerankWeights:
    fused: float = 10.0          # fused score is ~0.016–0.033; scaled up to be the baseline
    field_match: float = 0.5     # the chunk's field matches the question's intent
    overlap: float = 0.5         # per query token that exactly matches a metadata field (capped)
    overlap_cap: int = 3
    risk: float = 0.3
    correlation: float = 0.2
    diversity: float = 0.5       # subtracted once per earlier chunk of the same finding


_STATE_BOOST = {"confirmed": 0.4, "resolved": 0.35, "corroborated": 0.25, "candidate": 0.1}

_FIX_CUES = re.compile(r"\b(fix|remediat\w*|patch|mitigat\w*|upgrade|resolve|how (?:do|to|can)\b.*\bfix)\b", re.I)
_WHERE_CUES = re.compile(r"\b(where|which (?:file|line|function|route|endpoint)|located|location|what file)\b", re.I)


def preferred_fields(query: str) -> set[str]:
    """The chunk fields this question is best answered from."""
    if _FIX_CUES.search(query):
        return {"fix"}
    if _WHERE_CUES.search(query):
        return {"where"}
    return {"what", "impact", "exploit"}  # the default "why / explain / what" intent


def _metadata_tokens(rc: RetrievedChunk) -> set[str]:
    m = rc.chunk.metadata
    text = " ".join(x for x in (m.function, m.file, m.route, m.type, m.owasp) if x)
    return set(tokenize(text))


def _feature_score(rc: RetrievedChunk, query_tokens: set[str], fields: set[str], w: RerankWeights) -> float:
    m = rc.chunk.metadata
    score = w.fused * (rc.fused_score or 0.0)
    if m.field in fields:
        score += w.field_match
    overlap = len(query_tokens & _metadata_tokens(rc))
    score += w.overlap * min(overlap, w.overlap_cap)
    score += _STATE_BOOST.get(m.state, 0.1)
    score += w.risk * m.risk
    score += w.correlation * (m.correlation_score or 0.0)
    return score


def rerank(query: str, candidates: list[RetrievedChunk], final_k: int, *, weights: RerankWeights | None = None) -> list[RetrievedChunk]:
    """Reorder *candidates* and return the top *final_k* (fewer if there aren't that many)."""
    if not candidates:
        return []
    w = weights or RerankWeights()
    fields = preferred_fields(query)
    query_tokens = set(tokenize(query))

    base = [(rc, _feature_score(rc, query_tokens, fields, w)) for rc in candidates]
    # order to apply the diversity penalty fairly: by feature score, then the fusion tie-break
    base.sort(key=lambda it: (-it[1], -it[0].chunk.metadata.risk, it[0].chunk.metadata.finding_id, it[0].chunk.chunk_id))

    seen: dict[str, int] = {}
    for rc, feature in base:
        fid = rc.chunk.metadata.finding_id
        rc.rerank_score = feature - w.diversity * seen.get(fid, 0)
        seen[fid] = seen.get(fid, 0) + 1

    ranked = [rc for rc, _ in base]
    ranked.sort(key=lambda rc: (-rc.rerank_score, -rc.chunk.metadata.risk, rc.chunk.metadata.finding_id, rc.chunk.chunk_id))
    return ranked[: max(0, final_k)]
