"""RAG06 — the deterministic feature reranker."""

from __future__ import annotations

import pytest

from aegis.chat.reranker import RerankWeights, preferred_fields, rerank
from aegis.chat.schemas import Chunk, ChunkMetadata, RetrievedChunk

pytestmark = pytest.mark.phase("RAG06")


def rc(cid, *, field="what", fused=0.02, state="confirmed", risk=0.5, finding=None,
       function=None, file=None, route=None, type="broken_access_control", owasp=None, corr=None):
    fid = finding or cid.split(":")[0]
    meta = ChunkMetadata(chunk_id=cid, finding_id=fid, scan_id="S-1", field=field, chunk_index=0,
                         type=type, state=state, risk=risk, function=function, file=file, route=route,
                         owasp=owasp, correlation_score=corr)
    return RetrievedChunk(chunk=Chunk(chunk_id=cid, text=f"doc {cid}", metadata=meta), fused_score=fused)


def ids(ranked):
    return [r.chunk.chunk_id for r in ranked]


def test_preferred_fields_by_intent():
    assert preferred_fields("how do I fix this?") == {"fix"}
    assert preferred_fields("which file is it in?") == {"where"}
    assert preferred_fields("why is this a risk?") == {"what", "impact", "exploit"}


def test_a_fix_query_prefers_the_fix_chunk():
    cands = [rc("F-1:what:0", field="what", fused=0.03), rc("F-1:fix:0", field="fix", fused=0.02)]
    assert ids(rerank("how do I fix the account leak?", cands, 2))[0] == "F-1:fix:0"


def test_a_why_query_prefers_what_over_fix_when_fused_is_equal():
    cands = [rc("F-1:fix:0", field="fix", fused=0.02), rc("F-1:what:0", field="what", fused=0.02)]
    assert ids(rerank("why is this exploitable?", cands, 2))[0] == "F-1:what:0"


def test_exact_function_name_in_the_query_boosts_its_chunk():
    cands = [rc("F-2:what:0", finding="F-2", function="list_users", fused=0.03),
             rc("F-1:what:0", finding="F-1", function="get_account", fused=0.02)]
    # F-1 has the lower fused score, but the query names its function → it should win
    assert ids(rerank("is get_account vulnerable?", cands, 2))[0] == "F-1:what:0"


def test_owasp_code_and_file_overlap_boosts():
    cands = [rc("F-2:what:0", finding="F-2", file="users.py", fused=0.03),
             rc("F-1:what:0", finding="F-1", file="auth.py", owasp="A01", fused=0.02)]
    assert ids(rerank("show the A01 issue in auth.py", cands, 2))[0] == "F-1:what:0"


def test_confirmed_outranks_candidate_when_otherwise_tied():
    cands = [rc("F-2:what:0", finding="F-2", state="candidate", risk=0.5, fused=0.02),
             rc("F-1:what:0", finding="F-1", state="confirmed", risk=0.5, fused=0.02)]
    assert ids(rerank("why is this a risk?", cands, 2))[0] == "F-1:what:0"


def test_diversity_penalty_lets_a_second_finding_through():
    # three strong chunks of F-1 and one weaker chunk of F-2; F-2 should not be buried last
    cands = [
        rc("F-1:what:0", finding="F-1", field="what", fused=0.030, risk=0.9),
        rc("F-1:impact:0", finding="F-1", field="impact", fused=0.029, risk=0.9),
        rc("F-1:exploit:0", finding="F-1", field="exploit", fused=0.028, risk=0.9),
        rc("F-2:what:0", finding="F-2", field="what", fused=0.020, risk=0.3),
    ]
    order = ids(rerank("why are these risks?", cands, 4))
    assert order.index("F-2:what:0") < 3            # F-2 beats at least one later F-1 chunk
    assert order[0] == "F-1:what:0"                 # the top F-1 chunk still leads


def test_returns_at_most_final_k_but_not_more_than_exist():
    cands = [rc(f"F-{i}:what:0", finding=f"F-{i}") for i in range(5)]
    assert len(rerank("why?", cands, 3)) == 3
    assert len(rerank("why?", cands, 10)) == 5
    assert rerank("why?", [], 3) == []


def test_order_is_deterministic():
    cands = [rc("F-2:what:0", finding="F-2"), rc("F-1:what:0", finding="F-1"), rc("F-1:fix:0", finding="F-1")]
    assert ids(rerank("how to fix?", cands, 3)) == ids(rerank("how to fix?", cands, 3))


def test_weights_are_overridable():
    cands = [rc("F-1:what:0", field="what", fused=0.03), rc("F-1:fix:0", field="fix", fused=0.02)]
    # with field_match weight 0, the higher fused what-chunk wins even for a fix query
    assert ids(rerank("how to fix?", cands, 2, weights=RerankWeights(field_match=0.0)))[0] == "F-1:what:0"
