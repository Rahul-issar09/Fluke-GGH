"""MCP tool shapes (MCP_PHASES MCP01.1).

Outputs reuse the REST API's models (``aegis.api.schemas``) so MCP and REST cannot drift (M-2).
The only MCP-specific shapes are the safe evidence projection and two small wrappers.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from aegis.api.schemas import AskOut, EvidenceOut, FindingDetail, FindingOut, ScanOut

__all__ = [
    "SCAN_ID", "FINDING_ID", "EVIDENCE_ID", "OWASP",
    "AnsweredBy", "AskOut", "AttackPathsOut", "EvidenceDigestOut", "EvidenceOut", "FindingDetail", "FindingOut",
    "FindingsOut", "LlmStatusOut", "McpAskOut", "ScanOut",
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


class AnsweredBy(BaseModel):
    provider: str
    model: str
    location: str = Field(description="local (this machine) or cloud")


class McpAskOut(AskOut):
    """The REST answer plus which model answered (LLM_PROVIDER_PHASES LP10). ``AskOut`` itself is a
    frozen REST contract, so the addition lives here."""

    answered_by: AnsweredBy | None = None
    note: str | None = Field(None, description="Why the answer did not come from the configured model, if so")


class LlmStatusOut(BaseModel):
    """The model AEGIS reasons with, as configured in AEGIS (an MCP client cannot change it).
    Carries nothing about the API key — not even whether one exists."""

    provider: str
    model: str
    location: str = Field(description="local (this machine) or cloud (Google Gemini)")
    online_model: str | None = Field(None, description="The Gemini model chosen for Online mode")
    online_chosen_but_inactive: bool = Field(False, description="Online mode is chosen but this server cannot use it now")
    note: str | None = None
    consent_given: bool = False
    allow_source_code: bool = False
    embeddings: dict = Field(default_factory=dict, description="The embedding model: always local")
