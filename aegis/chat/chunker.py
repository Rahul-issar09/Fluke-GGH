"""Turn one finding into small, citable chunks (RAG01).

A chunk is one slice of a finding's **validated, safe** text — the kept explanation claims
(``what`` / ``impact`` / ``exploit``), a fix *description* (never the diff), a code-free ``where``
line, and a one-line ``summary`` built from structured fields. Raw evidence payloads, HTTP bodies,
source code and secret values never enter a chunk (invariant R-3): the chunker only reads the
finding's own scalar fields and the fix attempt's description, never evidence payloads or files.

One chunk per field; a field longer than the token ceiling is split on sentence boundaries with a
one-sentence overlap, so a cited sentence keeps its context. A finding with no kept claims
(nothing to explain) yields no chunks.
"""

from __future__ import annotations

import hashlib
import json
import re

from aegis.agent.explanation import render_where
from aegis.chat.schemas import Chunk, ChunkMetadata
from aegis.evidence.models import Finding
from aegis.observability import get_logger

__all__ = ["estimate_tokens", "finding_fields", "chunk_finding", "chunk_from_store", "MAX_FIELD_TOKENS"]

log = get_logger("chat.chunker")

MAX_FIELD_TOKENS = 256
_CLAIM_FIELDS = ("what", "impact", "exploit")  # the model-written parts; "fix" is a description
_TOKEN = re.compile(r"\w+|[^\w\s]")
_SENTENCE = re.compile(r"(?<=[.!?])\s+")


def estimate_tokens(text: str) -> int:
    """A deterministic token estimate (words + punctuation). The context manager (RAG07) uses the
    same function, so chunk sizes and the context budget are measured the same way."""
    return len(_TOKEN.findall(text or ""))


def _state(finding: Finding) -> str:
    return getattr(finding.state, "value", finding.state) or "candidate"


def _summary(finding: Finding) -> str:
    """A one-line description from structured fields only (no raw content)."""
    where = finding.route or (f"{finding.file}:{finding.line}" if finding.line else finding.file) or "the codebase"
    owasp = f" {finding.owasp}" if finding.owasp else ""
    return (f"{finding.type}{owasp} at {where}: {_state(finding)}, "
            f"risk {finding.risk:.2f}, severity {finding.severity:.2f}.")


def finding_fields(finding: Finding, fix_description: str | None = None) -> dict[str, str]:
    """The field → text map a finding contributes, in field order, skipping empty fields.

    ``where`` is built **without** a source path, so it is just the location (``file:line
    (function)`` or the route) and never a code snippet.
    """
    raw = {
        "what": finding.what,
        "impact": finding.impact,
        "exploit": finding.exploit,
        "fix": fix_description,
        "where": render_where(finding, None),  # None source_path → location only, no code
        "summary": _summary(finding),
    }
    return {field: text.strip() for field, text in raw.items() if text and text.strip()}


def _split_field(text: str, max_tokens: int) -> list[str]:
    """One piece if it fits; else sentence-boundary pieces with a one-sentence overlap.

    A single sentence longer than the ceiling is kept whole (we never cut mid-sentence), so the
    loop always makes progress."""
    if estimate_tokens(text) <= max_tokens:
        return [text]
    sentences = [s.strip() for s in _SENTENCE.split(text) if s.strip()]
    if len(sentences) <= 1:
        return [text]
    pieces: list[str] = []
    i = 0
    while i < len(sentences):
        current = [sentences[i]]  # always take at least one, even if it alone exceeds the ceiling
        i += 1
        while i < len(sentences) and estimate_tokens(" ".join(current + [sentences[i]])) <= max_tokens:
            current.append(sentences[i])
            i += 1
        pieces.append(" ".join(current))
        if i < len(sentences) and len(current) > 1:
            i -= 1  # overlap: the last sentence of this piece starts the next one
    return pieces


def chunk_finding(
    finding: Finding,
    *,
    evidence_ids: list[str],
    fix_description: str | None = None,
    indexed_at: str = "",
    max_tokens: int = MAX_FIELD_TOKENS,
) -> list[Chunk]:
    """The chunks for *finding*. Empty when the finding has no kept claims (nothing to explain)."""
    fields = finding_fields(finding, fix_description)
    if not any(fields.get(f) for f in _CLAIM_FIELDS + ("fix",)):
        log.info("chunk.skip_no_claims", finding_id=finding.id)
        return []

    chunks: list[Chunk] = []
    for field, text in fields.items():
        for n, piece in enumerate(_split_field(text, max_tokens)):
            chunk_id = f"{finding.id}:{field}:{n}"
            meta = ChunkMetadata(
                chunk_id=chunk_id,
                finding_id=finding.id,
                scan_id=finding.scan_id,
                field=field,
                chunk_index=n,
                type=finding.type,
                owasp=finding.owasp,
                state=_state(finding),
                risk=finding.risk,
                severity=finding.severity,
                route=finding.route,
                function=finding.function,
                file=finding.file,
                line=finding.line,
                evidence_ids=sorted(evidence_ids),
                correlation_score=finding.correlation_score,
                tokens=estimate_tokens(piece),
                indexed_at=indexed_at,
                content_sha=hashlib.sha256(piece.encode("utf-8")).hexdigest(),
            )
            chunks.append(Chunk(chunk_id=chunk_id, text=piece, metadata=meta))
    return chunks


def _fix_description(store, finding_id: str) -> str | None:
    """The latest fix attempt's recommendation/description (safe text), never its diff."""
    attempt = store.latest_fix_attempt(finding_id)
    if attempt is None:
        return None
    try:
        return (json.loads(attempt.verify_report_json or "{}").get("draft") or {}).get("description")
    except (ValueError, AttributeError):
        return None


def chunk_from_store(store, finding: Finding, *, indexed_at: str = "", max_tokens: int = MAX_FIELD_TOKENS) -> list[Chunk]:
    """Chunk a finding, reading its citable evidence ids and fix description from the store.

    This is what the indexer (RAG08) calls. Only ids and the fix description are read — never
    evidence payloads or source files."""
    evidence_ids = [e.id for e in store.evidence_for(finding.id)]
    return chunk_finding(
        finding,
        evidence_ids=evidence_ids,
        fix_description=_fix_description(store, finding.id),
        indexed_at=indexed_at,
        max_tokens=max_tokens,
    )
