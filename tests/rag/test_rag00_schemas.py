"""RAG00.1 — chat schemas and the Chroma metadata contract."""

from __future__ import annotations

import pytest

from aegis.api.schemas import AskOut
from aegis.chat.schemas import (
    FIELDS,
    Answer,
    Chunk,
    ChunkMetadata,
    FindingFilter,
    RetrievedChunk,
    RouteDecision,
    decode_list,
    encode_list,
)

pytestmark = pytest.mark.phase("RAG00")


def _meta(**over) -> ChunkMetadata:
    base = dict(chunk_id="F-0012:what:0", finding_id="F-0012", scan_id="S-0001", field="what",
                chunk_index=0, type="broken_access_control", evidence_ids=["E-0041", "E-0057"])
    base.update(over)
    return ChunkMetadata(**base)


def test_filter_defaults():
    f = FindingFilter(scan_id="S-0001")
    assert f.count is False
    assert (f.owasp, f.state, f.type, f.file, f.function, f.route, f.severity_min) == (None,) * 7


def test_route_decision_carries_an_optional_filter():
    assert RouteDecision(path="explain").filter is None
    d = RouteDecision(path="structured", filter=FindingFilter(scan_id="S-0001", count=True))
    assert d.path == "structured" and d.filter.count is True


def test_chroma_metadata_is_all_scalar_and_round_trips():
    meta = _meta(owasp="A01", risk=0.79, severity=0.9, route="GET /api/accounts/{id}",
                 function="get_account", file="app/routes/accounts.py", line=37,
                 correlation_score=1.0, tokens=42, indexed_at="2026-10-09T00:00:00Z", content_sha="abc")
    chroma = meta.to_chroma()
    assert all(isinstance(v, (str, int, float, bool)) for v in chroma.values())  # Chroma requires scalars
    assert chroma["evidence_ids"] == "E-0041,E-0057"                              # list → sorted delimited string
    assert ChunkMetadata.from_chroma(chroma) == meta                              # lossless round-trip


def test_none_optionals_are_omitted_then_restored_as_none():
    meta = _meta()  # owasp/route/function/file/line/correlation_score all default to None
    chroma = meta.to_chroma()
    for key in ("owasp", "route", "function", "file", "line", "correlation_score"):
        assert key not in chroma                                                  # Chroma rejects None
    assert None not in chroma.values()
    restored = ChunkMetadata.from_chroma(chroma)
    assert restored == meta and restored.owasp is None and restored.line is None


@pytest.mark.parametrize("values", [
    [],
    ["E-1"],
    ["E-2", "E-1"],                       # unsorted in → sorted out
    ["a,b", "c"],                         # a value containing the delimiter
    ["back\\slash", "plain"],             # a value containing the escape char
    ["x,y", "a\\b", "z,\\,"],             # both, together
])
def test_list_encoding_round_trips_even_with_delimiters(values):
    encoded = encode_list(values)
    assert isinstance(encoded, str)
    assert decode_list(encoded) == sorted(values)


def test_a_comma_in_an_evidence_value_does_not_split_into_two_ids():
    meta = _meta(evidence_ids=["E-1", "weird,id"])
    restored = ChunkMetadata.from_chroma(meta.to_chroma())
    assert restored.evidence_ids == ["E-1", "weird,id"]                           # still two ids, comma intact


def test_answer_maps_to_askout():
    ans = Answer(text="The endpoint returns other users' accounts.", finding_ids=["F-0012"], evidence_ids=["E-0041"])
    out = ans.to_askout()
    assert isinstance(out, AskOut)
    assert (out.answer, out.finding_ids, out.evidence_ids) == (ans.text, ["F-0012"], ["E-0041"])


def test_empty_answer_maps_cleanly():
    out = Answer(text="no finding matches").to_askout()
    assert out.answer == "no finding matches" and out.finding_ids == [] and out.evidence_ids == []


def test_chunk_and_retrieved_chunk_shapes():
    chunk = Chunk(chunk_id="F-0012:what:0", text="the handler returns any account by id", metadata=_meta())
    rc = RetrievedChunk(chunk=chunk, dense_score=0.8)
    assert rc.chunk.metadata.finding_id == "F-0012"
    assert rc.sparse_score is None and rc.dense_score == 0.8


def test_fields_cover_the_five_parts_plus_summary():
    assert set(FIELDS) == {"what", "impact", "exploit", "fix", "where", "summary"}
