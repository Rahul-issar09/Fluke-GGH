"""Explain answer path (RAG11) — hybrid retrieve → generate → validate citations.

The one path that calls the model. It embeds the question, retrieves with dense + sparse, fuses and
reranks, builds the context (RAG07), then asks ``qwen2.5`` for a cited :class:`Answer`. Every cited
id is checked against the context's allowed set (R-2): an answer that cites something it was not
shown is rejected and retried once, and if it still fails, a deterministic **extractive** answer is
built from the top finding's own claims and real ids — never a fabricated one. Nothing retrieved
(or everything below the similarity floor) → ``"No finding matches."`` with no citations.

If the embedding model is down the path degrades instead of failing: with an index it uses keyword
search alone; with no index (it was down at finalize) it runs keyword search over chunks built from
the findings themselves; and if even that finds nothing it says retrieval is unavailable
(``RETRIEVAL_UNAVAILABLE``) rather than claiming the scan has no matching finding.

A scope gate (RAG15) runs first: a question whose subject words are not in this scan's findings is
out of scope and gets ``"No finding matches."`` without touching the embedder or the model.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from aegis.agent.llm import structured_call
from aegis.chat.chunker import chunk_from_store
from aegis.chat.context import build_context
from aegis.chat.embedder import EmbeddingUnavailable
from aegis.chat.fusion import fuse
from aegis.chat.reranker import rerank
from aegis.chat.schemas import Answer, FindingFilter
from aegis.chat.scope import term_coverage
from aegis.chat.sparse import SparseRetriever
from aegis.chat.structured import NO_MATCH
from aegis.evidence.links import visible_findings
from aegis.observability import get_logger

__all__ = ["answer_explain", "RETRIEVAL_UNAVAILABLE"]

log = get_logger("chat.retriever")

_PROMPT = Path(__file__).resolve().parent / "prompts" / "answer.txt"


@lru_cache(maxsize=1)
def _system_prompt() -> str:
    return _PROMPT.read_text(encoding="utf-8")


# said when the embedding model is down AND keyword search found nothing: that is a retrieval
# outage, not "this scan has no matching finding", and the user should be told which it is.
RETRIEVAL_UNAVAILABLE = (
    "Semantic search is unavailable (the embedding model could not be reached) and no keyword match "
    "was found. Counts, lists and look-ups by severity, file, route or OWASP code still work."
)


class _Rows:
    """An in-memory stand-in for the vector store's ``all_for_scan`` (keyword search only)."""

    def __init__(self, rows):
        self._rows = rows

    def all_for_scan(self, scan_id: str):
        return self._rows


def _local_rows(store, scan_id: str):
    """Chunks built straight from the scan's visible findings — what the indexer would have stored.

    Used when nothing is indexed (the embedding model was down at finalize), so keyword search can
    still ground an answer in real findings. Same chunker as the indexer: ids and validated text only.
    """
    rows = []
    for finding in sorted(visible_findings(store, scan_id), key=lambda f: f.id):
        rows.extend((c.chunk_id, c.metadata, c.text) for c in chunk_from_store(store, finding))
    return rows


def _extractive_fallback(ctx, reranked) -> Answer:
    """A grounded answer built from the top finding's own claims and real ids (no model)."""
    top = ctx.payload["findings"][0]
    fid = ctx.finding_ids[0]
    text = " ".join(top[f] for f in ("what", "impact", "exploit", "fix", "summary") if top.get(f)).strip()
    eids = sorted({e for rc in reranked if rc.chunk.metadata.finding_id == fid for e in rc.chunk.metadata.evidence_ids})
    return Answer(text=text or NO_MATCH, finding_ids=[fid], evidence_ids=[e for e in eids if e in set(ctx.evidence_ids)])


async def answer_explain(
    store,
    chroma,
    embedder,
    sparse,
    scan_id: str,
    question: str,
    *,
    filt: FindingFilter | None = None,   # reserved for future scoping; retrieval is already scan-scoped
    settings=None,
    llm=None,
    model_settings=None,
    manager=None,
) -> Answer:
    from aegis.config import ChatSettings

    cfg = settings or ChatSettings()

    # the lexicon for this scan: its indexed chunks, or — when nothing is indexed (the embedding model
    # was down at finalize) — chunks built straight from its findings, so the chat still answers.
    local = None
    lexicon = sparse
    if not sparse.vocabulary(scan_id):
        local = _local_rows(store, scan_id)
        if local:
            lexicon = SparseRetriever(_Rows(local))

    # scope gate (RAG15): answer only questions about THIS scan's findings. Deterministic and before any
    # embedding or model call, so "what is k8s?" never reaches the generator.
    if cfg.min_term_coverage > 0:
        cov = term_coverage(question, lexicon.vocabulary(scan_id))
        if cov.ratio < cfg.min_term_coverage:
            log.info("explain.out_of_scope", scan_id=scan_id, coverage=round(cov.ratio, 2),
                     unmatched=list(cov.unmatched)[:8])
            return Answer(text=NO_MATCH)

    embed_failed = False
    try:
        qvec = await embedder.embed_query(question)
        dense = chroma.query_dense(scan_id, qvec, cfg.dense_k)
    except EmbeddingUnavailable as exc:
        log.warning("explain.embeddings_unavailable", scan_id=scan_id, error=str(exc)[:160])
        dense, embed_failed = [], True
    dense = [row for row in dense if (1.0 - row[1]) >= cfg.min_dense_similarity]  # similarity floor
    # when a floor is set and nothing clears it, there is no semantic match: don't answer from
    # lexical noise alone (common words) — say so. (The default floor is 0, so production keeps
    # full hybrid retrieval and lets the model decide.) Not applied when embeddings are down.
    if cfg.min_dense_similarity > 0 and not dense and not embed_failed:
        log.info("explain.below_similarity_floor", scan_id=scan_id, floor=cfg.min_dense_similarity)
        return Answer(text=NO_MATCH)

    if local:
        sparse_hits = lexicon.query_sparse(scan_id, question, cfg.sparse_k, drop_stopwords=True)
        by_id = {cid: (cid, meta, doc) for cid, meta, doc in local}
        resolve = lambda ids: [by_id[i] for i in ids if i in by_id]  # noqa: E731
        log.info("explain.keyword_only", scan_id=scan_id, chunks=len(local), hits=len(sparse_hits))
    else:
        sparse_hits = sparse.query_sparse(scan_id, question, cfg.sparse_k)
        resolve = lambda ids: chroma.get_by_ids(ids)  # noqa: E731

    fused = fuse(dense, sparse_hits, rrf_k=cfg.rrf_k, resolve=resolve)
    reranked = rerank(question, fused, cfg.final_k)
    if not reranked:
        log.info("explain.no_retrieval", scan_id=scan_id, embeddings_down=embed_failed)
        return Answer(text=RETRIEVAL_UNAVAILABLE if embed_failed else NO_MATCH)

    ctx = build_context(store, question, reranked, max_findings=cfg.max_findings_in_context,
                        token_budget=cfg.context_token_budget)
    if ctx.is_empty:
        return Answer(text=NO_MATCH)
    allowed = ctx.allowed_citations

    def validate(ans: Answer) -> list[str]:
        bad = [cid for cid in dict.fromkeys([*ans.finding_ids, *ans.evidence_ids]) if cid not in allowed]
        return [f"cited id(s) not in the retrieved context: {bad}"] if bad else []

    trace: list = []
    try:
        # a question is answered by the model active *now* (not the scan's pinned one)
        ans, source = await structured_call(
            Answer, _system_prompt(), ctx.payload, validate, llm=llm, settings=model_settings, trace=trace,
            manager=manager, scope="chat" if manager is not None else None,
        )
    except Exception as exc:  # noqa: BLE001 - the model being down must never fail a question
        log.warning("explain.llm_unavailable", scan_id=scan_id, error=type(exc).__name__)
        ans, source = None, "fallback"

    if ans is None:
        log.info("explain.fallback", scan_id=scan_id, rejected=[a.get("error") for a in trace][:2])
        return _extractive_fallback(ctx, reranked)

    log.info("explain.answered", scan_id=scan_id, source=source,
             findings=ans.finding_ids, evidence=len(ans.evidence_ids))
    return ans
