"""Deterministic, offline embedder for tests (STRUCTURE ST05.3).

No Ollama, no network, no GPU. A vector is derived from the text's tokens so that related texts
(a query and the chunk it should match) land near each other, and identical text always gives an
identical vector — the RAG tests depend on both. Vectors are L2-normalized, like the real one.

Token prefixes (``search_document:`` / ``search_query:``) are stripped before hashing, so a query
and its document are compared on content, not on the prefix.
"""

from __future__ import annotations

import hashlib
import math
import re

from aegis.chat.embedder import DOC_PREFIX, QUERY_PREFIX

_TOKEN = re.compile(r"[a-z0-9]+")


class FakeEmbedder:
    def __init__(self, dim: int = 768):
        self.dim = dim
        self.model = "fake-embed"

    def _vector(self, text: str) -> list[float]:
        body = text
        for prefix in (DOC_PREFIX, QUERY_PREFIX):
            if body.startswith(prefix):
                body = body[len(prefix):]
        vec = [0.0] * self.dim
        tokens = _TOKEN.findall(body.lower()) or ["_empty_"]
        for tok in tokens:  # a bag-of-words hashing embedding: shared words → similar vectors
            h = hashlib.sha256(tok.encode("utf-8")).digest()
            idx = int.from_bytes(h[:4], "big") % self.dim
            sign = 1.0 if h[4] & 1 else -1.0
            vec[idx] += sign
        norm = math.sqrt(sum(x * x for x in vec))
        return [x / norm for x in vec] if norm else vec

    async def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._vector(DOC_PREFIX + t) for t in texts]

    async def embed_query(self, text: str) -> list[float]:
        return self._vector(QUERY_PREFIX + text)
