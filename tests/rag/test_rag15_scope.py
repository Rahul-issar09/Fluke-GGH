"""RAG15 — scope gate: answer only questions about this scan's findings."""

from __future__ import annotations

import pytest

from aegis.chat.chroma_store import ChromaStore
from aegis.chat.indexer import index_scan
from aegis.chat.retriever import answer_explain
from aegis.chat.schemas import Answer
from aegis.chat.scope import stem, term_coverage
from aegis.chat.sparse import SparseRetriever
from aegis.chat.structured import NO_MATCH
from aegis.config import ChatSettings
from fakes.fake_embedder import FakeEmbedder
from fakes.fake_llm import FakeLLM

pytestmark = pytest.mark.phase("RAG15")

DIM = 64
CFG = ChatSettings(embed_dim=DIM, min_dense_similarity=0.0)

VOCAB = set(
    "the endpoint returns any account by id without ownership check signed in user can read other users "
    "accounts hardcoded stripe api key configuration source swagger redoc publicly accessible exposing "
    "internal documentation misconfig a05 broken access control a01 tls outdated protocol".split()
)


# ---- the gate itself (pure) -------------------------------------------------------------------

@pytest.mark.parametrize("question", [
    "what is k8s",
    "what is the capital of france",
    "how do i make coffee",
    "hello",
    "tell me a joke",
    "why does the kubernetes ingress get exposed?",     # a false premise: only "exposed" is in the scan
])
def test_unrelated_questions_fall_below_the_threshold(question):
    assert term_coverage(question, VOCAB).ratio < CFG.min_term_coverage


@pytest.mark.parametrize("question", [
    "why is the broken access control on accounts a risk?",
    "is there a hardcoded secret and how do I fix it?",
    "why is the stripe api key a problem?",
    "is the swagger documentation publicly accessible?",
    "explain the A01 finding",
    "why is the account leak a risk?",                   # "leak" ~ unauthorized read
    "can a user read someone else's account?",
])
def test_questions_about_the_findings_pass(question):
    assert term_coverage(question, VOCAB).ratio >= CFG.min_term_coverage


@pytest.mark.parametrize("question", [
    "what should I fix first?", "summarize the scan", "what are the top risks?", "why?", "is it serious?",
])
def test_overview_questions_with_no_subject_words_pass(question):
    cov = term_coverage(question, VOCAB)
    assert cov.ratio == 1.0 and cov.unmatched == ()


def test_nothing_indexed_means_nothing_to_check():
    assert term_coverage("what is k8s", frozenset()).ratio == 1.0     # empty vocabulary: no basis to refuse


def test_stemming_matches_inflections():
    assert stem("exposed") == stem("exposes") == stem("expose")
    assert stem("accounts") == stem("account")
    assert term_coverage("is the account exposing?", {"account", "exposes"}).ratio == 1.0


def test_an_identifier_counts_once_and_compound_names_match_by_parts():
    assert term_coverage("explain A01", {"a01"}).unmatched == ()
    assert term_coverage("what does get_account do?", {"get", "account"}).ratio == 1.0
    assert term_coverage("what does get_account do?", {"get"}).ratio == 0.0


def test_it_is_deterministic():
    a = term_coverage("why does the kubernetes ingress get exposed?", VOCAB)
    b = term_coverage("why does the kubernetes ingress get exposed?", VOCAB)
    assert a == b and a.unmatched == ("kubernetes", "ingress")


# ---- through the explain path -----------------------------------------------------------------

class SpyEmbedder(FakeEmbedder):
    def __init__(self):
        super().__init__(DIM)
        self.calls = 0

    async def embed_query(self, text):
        self.calls += 1
        return await super().embed_query(text)


class SpyLLM:
    def __init__(self):
        self.calls = 0

    def with_structured_output(self, *a, **k):
        return self

    async def ainvoke(self, messages):
        self.calls += 1
        return Answer(text="should not be reached", finding_ids=[], evidence_ids=[])


@pytest.fixture
async def world(store, tmp_path):
    scan = store.add_scan(mode="correlated").id
    f = store.add_finding(scan, type="broken_access_control", owasp="A01", route="GET /api/accounts/{id}",
                          file="app/routes/accounts.py", line=37, source="w")
    e = store.add_evidence(scan, "http_exchange", "httpx", finding_id=f.id,
                           payload={"method": "GET", "route": "/api/accounts/1", "status": 200})
    store.update_finding_fields(f.id, risk=0.79, severity=0.9,
                                what="The application allows unauthorized users to access and view sensitive account details.",
                                impact="Attackers can steal personal information or manipulate account data.")
    chroma = ChromaStore(str(tmp_path / "chroma"))
    await index_scan(store, chroma, FakeEmbedder(DIM), scan)
    return store, chroma, scan, f.id, e.id


async def _ask(world, question, *, llm, embedder=None, settings=CFG):
    store, chroma, scan, *_ = world
    return await answer_explain(store, chroma, embedder or FakeEmbedder(DIM), SparseRetriever(chroma), scan,
                                question, settings=settings, llm=llm)


async def test_an_unrelated_question_gets_no_match_without_calling_the_embedder_or_model(world):
    embedder, llm = SpyEmbedder(), SpyLLM()
    ans = await _ask(world, "what is k8s", llm=llm, embedder=embedder)
    assert ans.text == NO_MATCH and ans.finding_ids == [] and ans.evidence_ids == []
    assert embedder.calls == 0 and llm.calls == 0


async def test_a_false_premise_question_gets_no_match(world):
    llm = SpyLLM()
    ans = await _ask(world, "why does the kubernetes ingress get exposed?", llm=llm)
    assert ans.text == NO_MATCH and llm.calls == 0


async def test_a_question_about_the_findings_is_answered(world):
    _s, _c, _scan, fid, eid = world
    good = Answer(text="Users can view other accounts.", finding_ids=[fid], evidence_ids=[eid])
    ans = await _ask(world, "why is the broken access control on accounts a risk?", llm=FakeLLM([good]))
    assert ans.finding_ids == [fid] and ans.text == "Users can view other accounts."


async def test_a_question_naming_a_finding_id_is_answered(world):
    _s, _c, _scan, fid, eid = world
    good = Answer(text="Any signed-in user can read any account.", finding_ids=[fid], evidence_ids=[eid])
    ans = await _ask(world, f"Why is {fid} exploitable?", llm=FakeLLM([good]))
    assert ans.text != NO_MATCH and ans.finding_ids == [fid]


async def test_an_overview_question_is_answered(world):
    _s, _c, _scan, fid, _e = world
    good = Answer(text="Fix the access control first.", finding_ids=[fid], evidence_ids=[])
    ans = await _ask(world, "what should I fix first?", llm=FakeLLM([good]))
    assert ans.finding_ids == [fid]


async def test_the_gate_can_be_disabled(world):
    embedder = SpyEmbedder()
    await _ask(world, "what is k8s", llm=SpyLLM(), embedder=embedder,
               settings=ChatSettings(embed_dim=DIM, min_dense_similarity=0.0, min_term_coverage=0.0))
    assert embedder.calls == 1                      # 0 turns the gate off: retrieval ran


async def test_the_gate_uses_this_scans_vocabulary_not_another_scans(world):
    store, chroma, scan_a, _fid, _e = world
    other = store.add_scan(mode="runtime").id
    f = store.add_finding(other, type="misconfig", owasp="A05", route="GET /dashboard", source="w")
    store.add_evidence(other, "http_exchange", "httpx", finding_id=f.id, payload={"method": "GET", "route": "/dashboard", "status": 200})
    store.update_finding_fields(f.id, what="A kubernetes ingress dashboard is exposed without authentication.")
    await index_scan(store, chroma, FakeEmbedder(DIM), other)
    ans = await _ask(world, "why does the kubernetes ingress dashboard get exposed?", llm=SpyLLM())
    assert ans.text == NO_MATCH                     # "kubernetes" exists only in the OTHER scan


async def test_the_gate_also_applies_when_nothing_is_indexed(store, tmp_path):
    scan = store.add_scan(mode="correlated").id
    f = store.add_finding(scan, type="secret", file="app/config.py", line=3, source="w")
    store.add_evidence(scan, "code_location", "semgrep", finding_id=f.id, payload={"file": "app/config.py", "line": 3})
    store.update_finding_fields(f.id, severity=0.8, risk=0.3, what="A hardcoded stripe api key is in the configuration source.")
    chroma = ChromaStore(str(tmp_path / "chroma"))      # never indexed
    out = await answer_explain(store, chroma, FakeEmbedder(DIM), SparseRetriever(chroma), scan, "what is k8s",
                               settings=CFG, llm=SpyLLM())
    assert out.text == NO_MATCH
