"""In-house BM25 sparse retrieval (RAG04).

Dense vectors capture meaning; lexical search captures exact terms that embeddings blur — an
identifier (``get_account``), an OWASP code (``A01``), a file (``auth.py``), a CWE (``CWE-89``).
This module adds a small, deterministic BM25 over the **same** chunks, with a security-aware
tokenizer, and no external library (so it stays offline and reproducible — RAG invariants R-4/R-5).

The index for a scan is built from the store's chunks (document text plus a few searchable metadata
fields), and cached per scan, keyed by the chunk count and newest ``indexed_at`` so a re-index
rebuilds it.
"""

from __future__ import annotations

import math
import re

from aegis.chat.schemas import ChunkMetadata
from aegis.observability import get_logger

__all__ = ["tokenize", "BM25Index", "SparseRetriever", "STOPWORDS", "K1", "B"]

log = get_logger("chat.sparse")

K1 = 1.5
B = 0.75

# question filler that matches every finding. Dropped from the query only when keyword search is the
# sole signal (no embeddings), where a match on "the" or "is" would otherwise pass for relevance.
STOPWORDS = frozenset(
    "a an the is are was were be been being of to in on for and or not no why how what which who whom "
    "when where does do did can could would should may might will it its this that these those with "
    "without by as at from than then there their they them i we you me my our your about into over "
    "any some all if so".split()
)

# a run of alphanumerics possibly joined by . _ - (keeps get_account, cwe-89, auth.py, a01 whole)
_RUN = re.compile(r"[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*")
# camelCase / PascalCase pieces: "getAccount" -> get, Account ; "HTTPError" -> HTTP, Error
_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")


def tokenize(text: str) -> list[str]:
    """Security-aware tokens: the whole identifier **and** its sub-parts, lowercased.

    ``get_account`` → ``get_account, get, account``; ``A01`` → ``a01``; ``CWE-89`` → ``cwe-89, cwe,
    89``; ``getAccount`` → ``getaccount, get, account``. Sub-parts shorter than two characters are
    dropped (they are noise), but a whole token is always kept.
    """
    tokens: list[str] = []
    for run in _RUN.findall(text or ""):
        whole = run.lower()
        tokens.append(whole)
        subs: list[str] = []
        for part in re.split(r"[._-]+", run):
            if part.lower() != whole and len(part) >= 2:
                subs.append(part.lower())
            for piece in _CAMEL.findall(part):
                subs.append(piece.lower())
        tokens.extend(s for s in subs if len(s) >= 2 and s != whole)
    return tokens


def _searchable(meta: ChunkMetadata, document: str) -> str:
    """The chunk text plus the metadata fields worth matching on exactly."""
    # finding_id: the chunk text never names its finding, so "why is F-0020 exploitable?" needs it here
    extra = [meta.finding_id, meta.type, meta.owasp, meta.route, meta.function, meta.file]
    return document + " " + " ".join(x for x in extra if x)


class BM25Index:
    """A standard BM25 index over a fixed set of ``(chunk_id, tokens)`` documents."""

    def __init__(self, documents: list[tuple[str, list[str]]], *, k1: float = K1, b: float = B):
        self.k1 = k1
        self.b = b
        self.ids = [cid for cid, _ in documents]
        self.tokens = [toks for _, toks in documents]
        self.doc_len = [len(toks) for toks in self.tokens]
        self.n = len(documents)
        self.avgdl = (sum(self.doc_len) / self.n) if self.n else 0.0
        self.tf: list[dict[str, int]] = []
        self.df: dict[str, int] = {}
        for toks in self.tokens:
            counts: dict[str, int] = {}
            for t in toks:
                counts[t] = counts.get(t, 0) + 1
            self.tf.append(counts)
            for t in counts:
                self.df[t] = self.df.get(t, 0) + 1

    def _idf(self, term: str) -> float:
        df = self.df.get(term, 0)
        if df == 0:
            return 0.0
        return math.log(1 + (self.n - df + 0.5) / (df + 0.5))

    def search(self, query_tokens: list[str], k: int) -> list[tuple[str, float]]:
        """Top-*k* ``(chunk_id, score)`` for the query, scores descending, deterministic ties."""
        if self.n == 0 or k <= 0 or not query_tokens:
            return []
        terms = set(query_tokens)
        scored: list[tuple[str, float]] = []
        for i, cid in enumerate(self.ids):
            counts, dl = self.tf[i], self.doc_len[i]
            score = 0.0
            for term in terms:
                tf = counts.get(term, 0)
                if tf == 0:
                    continue
                denom = tf + self.k1 * (1 - self.b + self.b * dl / self.avgdl) if self.avgdl else 1.0
                score += self._idf(term) * (tf * (self.k1 + 1)) / denom
            if score > 0:
                scored.append((cid, score))
        scored.sort(key=lambda r: (-r[1], r[0]))  # higher score first; chunk_id breaks ties
        return scored[:k]


class SparseRetriever:
    """Builds and caches a per-scan BM25 index from the vector store's chunks."""

    def __init__(self, store, *, k1: float = K1, b: float = B):
        self._store = store
        self._k1 = k1
        self._b = b
        self._cache: dict[str, tuple[tuple, BM25Index]] = {}

    def _index(self, scan_id: str) -> BM25Index:
        rows = self._store.all_for_scan(scan_id)  # (chunk_id, metadata, document)
        signature = (len(rows), max((m.indexed_at for _c, m, _d in rows), default=""))
        cached = self._cache.get(scan_id)
        if cached and cached[0] == signature:
            return cached[1]
        index = BM25Index([(cid, tokenize(_searchable(meta, doc))) for cid, meta, doc in rows], k1=self._k1, b=self._b)
        self._cache[scan_id] = (signature, index)
        log.info("sparse.index_built", scan_id=scan_id, chunks=index.n)
        return index

    def vocabulary(self, scan_id: str) -> frozenset[str]:
        """Every token in the scan's indexed chunks (empty when nothing is indexed) — the scope gate's lexicon."""
        return frozenset(self._index(scan_id).df)

    def query_sparse(self, scan_id: str, text: str, k: int, *, drop_stopwords: bool = False) -> list[tuple[str, float]]:
        """Top-*k* lexical matches within one scan (empty when the scan has no chunks)."""
        tokens = tokenize(text)
        if drop_stopwords:
            tokens = [t for t in tokens if t not in STOPWORDS]
        return self._index(scan_id).search(tokens, k)
