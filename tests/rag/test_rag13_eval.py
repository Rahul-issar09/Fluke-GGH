"""RAG13 — golden-question eval: routing, grounded citations, cross-scan isolation.

Deterministic and offline (FakeEmbedder; explain uses the model-down extractive fallback, which
cites whatever retrieval surfaced). The eval therefore checks the parts that must not regress:
the router's path, that each question's required findings are retrieved and cited, that another
scan's findings are never cited, and that an out-of-scope question yields "no finding matches".
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aegis.chat.chroma_store import ChromaStore
from aegis.chat.indexer import index_scan
from aegis.chat.retriever import answer_explain
from aegis.chat.router import route
from aegis.chat.schemas import Answer
from aegis.chat.structured import NO_MATCH, answer_structured
from aegis.config import ChatSettings
from fakes.fake_embedder import FakeEmbedder
from fakes.demo_apps import ROOT

pytestmark = pytest.mark.phase("RAG13")

DIM = 64
CFG = ChatSettings(embed_dim=DIM, min_dense_similarity=0.35)  # separates in-scope (0.47+) from out-of-scope (<0.3) for the fake embedder
GOLDEN = yaml.safe_load((ROOT / "tests" / "fixtures" / "rag" / "golden_questions.yaml").read_text(encoding="utf-8"))

_SCAN_A = [
    ("broken_access_control", "A01", 0.9, 0.79, "app/routes/accounts.py", "GET /api/accounts/{id}",
     "The accounts endpoint returns any account by id without an ownership check.",
     "A signed-in user can read another user's account balance."),
    ("sqli", "A03", 0.9, 0.40, "app/routes/users.py", None,
     "User search builds a sql query by concatenating the name parameter.",
     "An attacker can alter the sql query to read unintended rows."),
    ("secret", None, 0.8, 0.26, "app/config.py", None,
     "A hardcoded stripe api key is stored in the configuration source.",
     "Anyone reading the repository can use the leaked key."),
    ("weak_tls", "A02", 0.6, 0.30, "app/tls.py", None,
     "The server accepts the outdated tls protocol version 1.0.",
     "Network traffic can be downgraded and intercepted."),
]


@pytest.fixture
async def world(store, tmp_path):
    sid_a = store.add_scan(mode="correlated").id
    for t, owasp, sev, risk, file, route_, what, impact in _SCAN_A:
        f = store.add_finding(sid_a, type=t, owasp=owasp, route=route_, file=file, line=10, source="w")
        store.add_evidence(sid_a, "code_location", "semgrep", finding_id=f.id, payload={"file": file, "line": 10})
        store.update_finding_fields(f.id, severity=sev, risk=risk, what=what, impact=impact)
    # a second scan whose finding must never be cited when answering scan A
    sid_b = store.add_scan(mode="runtime").id
    fb = store.add_finding(sid_b, type="misconfig", owasp="A05", route="GET /dashboard", source="w")
    store.add_evidence(sid_b, "http_exchange", "httpx", finding_id=fb.id, payload={"method": "GET", "route": "/dashboard", "status": 200})
    store.update_finding_fields(fb.id, what="A kubernetes ingress dashboard is exposed without authentication.")

    chroma = ChromaStore(str(tmp_path / "chroma"))
    await index_scan(store, chroma, FakeEmbedder(DIM), sid_a)
    await index_scan(store, chroma, FakeEmbedder(DIM), sid_b)   # both scans share the collection
    return store, chroma, sid_a, sid_b, fb.id


class _CiteAll:
    """A stand-in model that cites every finding the retrieval surfaced, so the eval measures what
    retrieval put in the context (the validator still enforces every id is in the allowed set)."""

    def with_structured_output(self, *a, **k):
        return self

    async def ainvoke(self, messages):
        import json

        payload = json.loads(messages[-1].content)
        fids = [f["finding_id"] for f in payload["findings"]]
        return Answer(text="grounded in the retrieved findings", finding_ids=fids, evidence_ids=[])


async def _answer(world, scan_id, question, path):
    store, chroma, *_ = world
    if path == "structured":
        return answer_structured(store, route(question, scan_id).filter)
    from aegis.chat.sparse import SparseRetriever
    return await answer_explain(store, chroma, FakeEmbedder(DIM), SparseRetriever(chroma),
                                scan_id, question, settings=CFG, llm=_CiteAll())


@pytest.mark.parametrize("case", GOLDEN, ids=[c["q"][:40] for c in GOLDEN])
async def test_golden_question(world, case):
    _s, _c, sid_a, _sid_b, scan_b_finding = world
    decision = route(case["q"], sid_a)
    assert decision.path == case["path"], f"{case['q']!r} routed to {decision.path}"

    ans = await _answer(world, sid_a, case["q"], case["path"])

    if case.get("expect_no_match"):
        assert ans.text == NO_MATCH and ans.finding_ids == []
        return

    cited = set(ans.finding_ids)
    assert set(case.get("must_cite", [])) <= cited, f"{case['q']!r}: missing {set(case['must_cite']) - cited}"
    forbidden = set(case.get("must_not_cite", [])) | {scan_b_finding}
    assert cited.isdisjoint(forbidden), f"{case['q']!r}: cited forbidden {cited & forbidden}"


async def test_cross_scan_isolation_on_the_explain_path(world):
    _s, _c, sid_a, _sid_b, scan_b_finding = world
    # an A-scan question that lexically resembles scan B's dashboard finding must still not cite it
    ans = await _answer(world, sid_a, "why is the dashboard endpoint a risk?", "explain")
    assert scan_b_finding not in ans.finding_ids


async def test_citation_recall_is_perfect_on_the_golden_set(world):
    # a visible summary metric: every must_cite id is retrieved/returned across the golden set
    store, chroma, sid_a, _sid_b, _fb = world
    hit = total = 0
    for case in GOLDEN:
        if case.get("expect_no_match"):
            continue
        ans = await _answer(world, sid_a, case["q"], case["path"])
        want = set(case.get("must_cite", []))
        hit += len(want & set(ans.finding_ids))
        total += len(want)
    recall = hit / total if total else 1.0
    print(f"RAG13 citation recall on the golden set: {hit}/{total} = {recall:.2f}")
    assert recall == 1.0
