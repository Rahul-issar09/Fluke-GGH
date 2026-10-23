"""MCP tool shapes (MCP_PHASES MCP01.1).

Outputs reuse the REST API's models (``aegis.api.schemas``) so MCP and REST cannot drift (M-2).
The only MCP-specific shapes are the safe evidence projection and two small wrappers.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from aegis.api.schemas import AskOut, EvidenceOut, FindingDetail, FindingOut, ScanOut

__all__ = [
    "SCAN_ID", "FINDING_ID", "EVIDENCE_ID", "OWASP",
    "AskOut", "AttackPathsOut", "EvidenceDigestOut", "EvidenceOut", "FindingDetail", "FindingOut",
    "FindingsOut", "ScanOut",
]

# the same id patterns the REST routers enforce
SCAN_ID = r"^S-\d{4,}$"
FINDING_ID = r"^F-\d{4,}$"
EVIDENCE_ID = r"^E-\d{4,}$"
OWASP = r"^A\d{2}$"


class EvidenceDigestOut(BaseModel):
    """The safe view of an evidence record: a one-line digest built from structured fields only —
    never the raw payload (M-3)."""

    id: str
    finding_id: str | None = None
    scan_id: str
    kind: str
    tool: str
    digest: str
    raw_payload_available: bool = Field(False, description="True only when the server exposes raw evidence")


class FindingsOut(BaseModel):
    scan_id: str
    total: int = Field(description="Findings matching the filters, before the limit")
    findings: list[FindingOut]


class AttackPathsOut(BaseModel):
    scan_id: str
    paths: list[list[str]] = Field(description="Chains like [endpoint, function, sink, finding]")
