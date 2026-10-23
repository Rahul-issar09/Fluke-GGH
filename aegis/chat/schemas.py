"""Typed models for the findings chatbot (RAG00.1).

These are the objects the RAG pipeline passes around: the parsed question filter, the router's
decision, a finding chunk and its Chroma metadata, a retrieved chunk with its scores, and the final
answer. They are **not** frozen contracts (the chat layer is additive), but :class:`Answer` maps
one-to-one onto the API's ``AskOut`` and that parity is tested.

Chroma metadata values must be scalar (str / int / float / bool), so list fields (``evidence_ids``)
are flattened to a delimited string by :meth:`ChunkMetadata.to_chroma` and restored by
:meth:`ChunkMetadata.from_chroma`. The encoding escapes the delimiter and the escape character, so a
value containing a comma round-trips losslessly. Optional fields that are ``None`` are omitted from
the Chroma dict (Chroma rejects ``None``) and restored as ``None`` on read.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from aegis.api.schemas import AskOut

__all__ = [
    "FindingFilter",
    "RouteDecision",
    "ChunkMetadata",
    "Chunk",
    "RetrievedChunk",
    "Answer",
    "FIELDS",
    "encode_list",
    "decode_list",
]

# the finding text fields a chunk can come from (RAG01); used for field-aware reranking (RAG06)
FIELDS = ("what", "impact", "exploit", "fix", "where", "summary")

_DELIM = ","
_ESC = "\\"


def encode_list(items: list[str]) -> str:
    """Sorted, delimiter-joined string for a Chroma metadata list field, escaping the delimiter
    and the escape char so any value (even one containing the delimiter) round-trips."""
    out = []
    for item in sorted(items):
        out.append(str(item).replace(_ESC, _ESC + _ESC).replace(_DELIM, _ESC + _DELIM))
    return _DELIM.join(out)


def decode_list(text: str) -> list[str]:
    """Inverse of :func:`encode_list`."""
    if text == "":
        return []
    out: list[str] = []
    cur: list[str] = []
    escaped = False
    for ch in text:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == _ESC:
            escaped = True
        elif ch == _DELIM:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


class FindingFilter(BaseModel):
    """A structured query over a scan's findings (the router parses a question into this)."""

    scan_id: str
    severity_min: float | None = None
    owasp: str | None = None
    state: str | None = None
    type: str | None = None
    file: str | None = None
    function: str | None = None
    route: str | None = None
    count: bool = False  # the question asks "how many", not "which"


class RouteDecision(BaseModel):
    """Which path answers the question, and the filter parsed from it (if any)."""

    path: Literal["structured", "explain"]
    filter: FindingFilter | None = None


class ChunkMetadata(BaseModel):
    """Everything that rides alongside a chunk's embedding in Chroma (RAG_PHASES §1).

    ``chunk_id`` is the Chroma primary id. Optional fields are ``None`` when the finding lacks them.
    """

    chunk_id: str
    finding_id: str
    scan_id: str
    field: str
    chunk_index: int
    type: str
    owasp: str | None = None
    state: str = "candidate"
    risk: float = 0.0
    severity: float = 0.0
    route: str | None = None
    function: str | None = None
    file: str | None = None
    line: int | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    correlation_score: float | None = None
    tokens: int = 0
    indexed_at: str = ""
    content_sha: str = ""

    # fields that are optional (may be None) and so are omitted from Chroma when absent
    _OPTIONAL = ("owasp", "route", "function", "file", "line", "correlation_score")

    def to_chroma(self) -> dict:
        """A flat dict of only scalar, non-``None`` values, safe to store as Chroma metadata."""
        data = self.model_dump()
        data["evidence_ids"] = encode_list(self.evidence_ids)
        return {k: v for k, v in data.items() if not (k in self._OPTIONAL and v is None)}

    @classmethod
    def from_chroma(cls, data: dict) -> "ChunkMetadata":
        """Rebuild from a Chroma metadata dict (missing optional keys become ``None``)."""
        fields = {**data}
        fields["evidence_ids"] = decode_list(data.get("evidence_ids", ""))
        return cls(**fields)


class Chunk(BaseModel):
    """One citable slice of a finding's validated text, plus its metadata."""

    chunk_id: str
    text: str
    metadata: ChunkMetadata


class RetrievedChunk(BaseModel):
    """A chunk returned by retrieval, carrying the scores each stage assigned it."""

    chunk: Chunk
    dense_score: float | None = None
    sparse_score: float | None = None
    fused_score: float | None = None
    rerank_score: float | None = None


class Answer(BaseModel):
    """The chatbot's answer: prose plus the finding and evidence IDs it is grounded in."""

    text: str
    finding_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)

    def to_askout(self) -> AskOut:
        """Map to the API's response shape (``AskOut``)."""
        return AskOut(answer=self.text, finding_ids=list(self.finding_ids), evidence_ids=list(self.evidence_ids))
