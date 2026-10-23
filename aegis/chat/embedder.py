"""Dense embeddings via a local Ollama model (RAG02).

Offline and deterministic: embeddings come from a local Ollama embedding model (default
``nomic-embed-text``). Documents and queries get the model's asymmetric prefixes
(``search_document:`` / ``search_query:``) so a query retrieves the matching chunk, and every
vector is L2-normalized so cosine distance behaves. A transient Ollama error is retried once, then
raised as :class:`EmbeddingUnavailable` — the indexer treats that as a soft failure (R-6), never a
crash. Ollama is AEGIS's own infrastructure, so this uses a plain HTTP client, not the scan egress
guard (conflict C33). Text is never logged.
"""

from __future__ import annotations

import math

import httpx

from aegis.observability import get_logger

__all__ = ["EmbeddingUnavailable", "OllamaEmbedder", "l2_normalize", "DOC_PREFIX", "QUERY_PREFIX"]

log = get_logger("chat.embedder")

DOC_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "


class EmbeddingUnavailable(RuntimeError):
    """The embedding model could not be reached or returned nothing usable."""


def l2_normalize(vec: list[float]) -> list[float]:
    norm = math.sqrt(sum(x * x for x in vec))
    if norm == 0.0:
        return list(vec)  # a zero vector stays zero (no division); callers treat it as "no signal"
    return [x / norm for x in vec]


class OllamaEmbedder:
    """Calls Ollama's ``/api/embeddings`` once per text (a batch is a loop — deterministic order)."""

    def __init__(self, model: str, base_url: str, *, dim: int | None = None, timeout: float = 30.0,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.model = model
        self.dim = dim
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout, transport=self._transport)

    async def _embed_one(self, client: httpx.AsyncClient, text: str) -> list[float]:
        last: Exception | None = None
        for attempt in (1, 2):  # one retry on a transient error, then give up (R-6)
            try:
                resp = await client.post("/api/embeddings", json={"model": self.model, "prompt": text})
                if resp.status_code >= 500:
                    raise httpx.HTTPStatusError("server error", request=resp.request, response=resp)
                resp.raise_for_status()
                vec = (resp.json() or {}).get("embedding")
                if not isinstance(vec, list) or not vec:
                    raise EmbeddingUnavailable(f"the embedding model '{self.model}' returned no vector")
                if self.dim is not None and len(vec) != self.dim:
                    raise EmbeddingUnavailable(f"expected {self.dim}-dim vectors, got {len(vec)} from '{self.model}'")
                return l2_normalize([float(x) for x in vec])
            except EmbeddingUnavailable:
                raise
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                last = exc
                log.warning("embedder.retry", attempt=attempt, error=type(exc).__name__)
        raise EmbeddingUnavailable(f"could not reach the embedding model '{self.model}': {type(last).__name__}")

    async def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """One normalized vector per text, each prefixed as a document."""
        log.debug("embedder.documents", model=self.model, count=len(texts))
        async with self._client() as client:
            return [await self._embed_one(client, DOC_PREFIX + t) for t in texts]

    async def embed_query(self, text: str) -> list[float]:
        """A normalized vector for a query (query prefix)."""
        log.debug("embedder.query", model=self.model)
        async with self._client() as client:
            return await self._embed_one(client, QUERY_PREFIX + text)


def make_embedder(chat_settings, ollama_url: str, *, transport: httpx.AsyncBaseTransport | None = None) -> OllamaEmbedder:
    """Build the embedder from the chat settings (model, dim) and the Ollama host."""
    return OllamaEmbedder(chat_settings.embed_model, ollama_url, dim=chat_settings.embed_dim, transport=transport)
