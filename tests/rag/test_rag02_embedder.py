"""RAG02 — the dense embedder (Ollama) and the deterministic test fake."""

from __future__ import annotations

import math

import httpx
import pytest

from aegis.chat.embedder import DOC_PREFIX, QUERY_PREFIX, EmbeddingUnavailable, OllamaEmbedder, l2_normalize
from fakes.fake_embedder import FakeEmbedder

pytestmark = pytest.mark.phase("RAG02")


def _recorder(vector, *, fail_times=0, status=200):
    """A MockTransport that records the prompts it was sent and returns *vector* (after optionally
    failing the first *fail_times* calls with a 500)."""
    seen = {"prompts": [], "calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["calls"] += 1
        import json

        seen["prompts"].append(json.loads(request.content)["prompt"])
        if seen["calls"] <= fail_times:
            return httpx.Response(500, json={"error": "loading"})
        return httpx.Response(status, json={"embedding": list(vector)})

    return httpx.MockTransport(handler), seen


def embedder(vector, **kw):
    transport, seen = _recorder(vector, **kw)
    return OllamaEmbedder("nomic-embed-text", "http://ollama:11434", transport=transport), seen


async def test_prefixes_applied():
    emb, seen = embedder([3.0, 4.0])
    await emb.embed_documents(["the endpoint leaks data"])
    await emb.embed_query("why does it leak")
    assert seen["prompts"][0] == DOC_PREFIX + "the endpoint leaks data"
    assert seen["prompts"][1] == QUERY_PREFIX + "why does it leak"


async def test_vectors_are_l2_normalized():
    emb, _ = embedder([3.0, 4.0])                       # norm 5 → (0.6, 0.8)
    (vec,) = await emb.embed_documents(["x"])
    assert vec == [0.6, 0.8] and abs(math.sqrt(sum(v * v for v in vec)) - 1.0) < 1e-9


async def test_batch_matches_individual():
    emb, _ = embedder([1.0, 2.0, 2.0])
    batch = await emb.embed_documents(["a", "b", "c"])
    assert len(batch) == 3 and all(v == batch[0] for v in batch)  # same input vector → same output


async def test_one_transient_error_is_retried_then_succeeds():
    emb, seen = embedder([1.0, 0.0], fail_times=1)
    (vec,) = await emb.embed_documents(["x"])
    assert vec == [1.0, 0.0] and seen["calls"] == 2            # failed once, retried, then ok


async def test_two_failures_raise_embedding_unavailable():
    emb, seen = embedder([1.0], fail_times=2)
    with pytest.raises(EmbeddingUnavailable):
        await emb.embed_query("x")
    assert seen["calls"] == 2                                   # one try, one retry, then give up


async def test_an_empty_vector_is_unavailable_not_a_silent_zero():
    emb, _ = embedder([])
    with pytest.raises(EmbeddingUnavailable):
        await emb.embed_documents(["x"])


async def test_a_wrong_dimension_is_rejected():
    emb = OllamaEmbedder("nomic-embed-text", "http://ollama:11434", dim=768,
                         transport=_recorder([0.1, 0.2])[0])
    with pytest.raises(EmbeddingUnavailable, match="768-dim"):
        await emb.embed_query("x")


def test_l2_normalize_handles_zero_vector():
    assert l2_normalize([0.0, 0.0]) == [0.0, 0.0]               # no division by zero


# --- the deterministic fake used by later phases --------------------------------------------- #
async def test_fake_is_deterministic_and_normalized():
    fake = FakeEmbedder(dim=64)
    a = await fake.embed_query("broken access control on accounts")
    b = await fake.embed_query("broken access control on accounts")
    assert a == b and len(a) == 64 and abs(math.sqrt(sum(x * x for x in a)) - 1.0) < 1e-9


async def test_fake_related_text_is_closer_than_unrelated():
    fake = FakeEmbedder(dim=256)
    (doc,) = await fake.embed_documents(["the account endpoint returns other users data"])
    near = await fake.embed_query("account endpoint returns other users data")
    far = await fake.embed_query("transport layer certificate cipher configuration")
    dot = lambda u, v: sum(x * y for x, y in zip(u, v))
    assert dot(doc, near) > dot(doc, far)                      # shared words → higher cosine
