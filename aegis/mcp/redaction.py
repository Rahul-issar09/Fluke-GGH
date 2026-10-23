"""Evidence exposure policy for MCP clients (MCP_PHASES MCP05.1, invariant M-3).

The one place that decides what an external agent sees of an evidence record:

* default (``expose_raw=False``): a digest — a one-line summary built from structured fields
  only (``aegis.evidence.digest``), never the payload;
* ``expose_raw=True``: the payload, passed through two redaction passes — the report redaction
  (credential-named fields) and a string scrub (credentials embedded in text, such as an
  ``Authorization:`` header inside a stored request).

There is no path that returns an unredacted payload.
"""

from __future__ import annotations

import re
from typing import Any

from aegis.evidence.digest import digest
from aegis.evidence.models import Evidence
from aegis.mcp.schemas import EvidenceDigestOut, EvidenceOut
from aegis.reports.json_report import REDACTED, evidence_out

__all__ = ["project_evidence", "scrub_payload", "scrub_text"]

# credentials that appear *inside* text: headers, key=value pairs, bearer tokens, private keys
_PATTERNS = (
    re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*).+$"),
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|session(?:id)?)\s*[=:]\s*)[\"']?[^\s\"'&,;]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
)


def scrub_text(text: str) -> str:
    out = _PATTERNS[0].sub(lambda m: m.group(1) + REDACTED, text)
    out = _PATTERNS[1].sub(lambda m: m.group(1) + " " + REDACTED, out)
    out = _PATTERNS[2].sub(lambda m: m.group(1) + REDACTED, out)
    return _PATTERNS[3].sub(REDACTED, out)


def scrub_payload(value: Any) -> Any:
    """Scrub credentials embedded in every string of a JSON-like value."""
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        return {k: scrub_payload(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub_payload(v) for v in value]
    return value


def project_evidence(evidence: Evidence, *, expose_raw: bool) -> EvidenceOut | EvidenceDigestOut:
    if expose_raw:
        out = evidence_out(evidence, redacted=True)
        return out.model_copy(update={"payload": scrub_payload(out.payload)})
    return EvidenceDigestOut(
        id=evidence.id, finding_id=evidence.finding_id, scan_id=evidence.scan_id,
        kind=evidence.kind, tool=evidence.tool, digest=digest(evidence),
    )
