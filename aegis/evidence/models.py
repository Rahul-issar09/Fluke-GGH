"""AEGIS data contract — SQLModel tables + enums (PHASES P0.3).

FROZEN after P0 (STRUCTURE invariant I-8). Any change here is caught by the
ST03 contract-snapshot test and requires explicit approval.

Source: SYSTEM_DESIGN §4.1 + PRD §8. Store is SQLite (conflict C1: the SD
header's "postgress" is disregarded — every other section says SQLite).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from sqlmodel import Field, SQLModel

__all__ = [
    "Mode",
    "FindingState",
    "ScanStatus",
    "EvidenceKind",
    "Scan",
    "Finding",
    "Evidence",
    "StateTransition",
    "AgentDecision",
    "Claim",
    "FixAttempt",
    "ToolCallLog",
    "Counter",
]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Mode(str, Enum):
    runtime = "runtime"
    code = "code"
    correlated = "correlated"


class FindingState(str, Enum):
    candidate = "candidate"
    corroborated = "corroborated"
    confirmed = "confirmed"
    resolved = "resolved"


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    awaiting_approval = "awaiting_approval"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class EvidenceKind(str, Enum):
    http_exchange = "http_exchange"
    code_location = "code_location"
    dataflow_path = "dataflow_path"
    dependency = "dependency"
    secret = "secret"
    crypto_asset = "crypto_asset"
    tls_scan = "tls_scan"
    retest = "retest"
    oob_hit = "oob_hit"
    tool_error = "tool_error"


# --------------------------------------------------------------------------- #
# Tables
# --------------------------------------------------------------------------- #
class Scan(SQLModel, table=True):
    id: str = Field(primary_key=True)  # S-0001
    mode: Mode
    status: ScanStatus = ScanStatus.queued
    target_url: str | None = None
    source_path: str | None = None  # folder or temp clone dir
    repo_url: str | None = None
    config_json: str = "{}"  # frozen scan config/policy
    db_snapshot_dates: str = "{}"  # {"osv": "...", "trivy": "...", "nuclei": "..."}
    created_at: datetime = Field(default_factory=_utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None


class Finding(SQLModel, table=True):
    id: str = Field(primary_key=True)  # F-0012
    scan_id: str = Field(index=True)
    type: str  # broken_access_control, sqli, secret, weak_crypto, ...
    owasp: str | None = None  # A01..A10
    title: str = ""
    state: FindingState = FindingState.candidate
    mode: Mode | None = None
    route: str | None = None  # "GET /api/accounts/{id}"
    function: str | None = None
    file: str | None = None
    line: int | None = None
    severity: float = 0.0  # 0.1–1.0
    exploitability: float = 0.0
    exposure: float = 0.0
    criticality: float = 0.0
    path_factor: float = 0.0
    correlation_score: float | None = None
    risk: float = 0.0
    # written by the explain node AFTER validation; never by the raw LLM output
    what: str | None = None
    impact: str | None = None
    exploit: str | None = None
    fix_diff: str | None = None
    sources: str = "[]"  # JSON list of tool ids
    fingerprint: str = Field(default="", index=True)  # dedup key
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Evidence(SQLModel, table=True):
    id: str = Field(primary_key=True)  # E-0041
    finding_id: str | None = Field(default=None, index=True)
    scan_id: str = Field(index=True)
    kind: str  # EvidenceKind value
    tool: str
    tool_version: str = ""
    db_date: str | None = None
    payload_json: str = "{}"  # raw request/response, code snippet — NEVER sent to the LLM
    created_at: datetime = Field(default_factory=_utcnow)


class StateTransition(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    finding_id: str = Field(index=True)
    from_state: str | None = None
    to_state: str
    reason: str = ""
    evidence_ids: str = "[]"  # JSON list
    actor: str = "rule"  # rule | worker | verifier
    at: datetime = Field(default_factory=_utcnow)


class AgentDecision(SQLModel, table=True):
    id: str = Field(primary_key=True)  # D-0001
    scan_id: str = Field(index=True)
    finding_id: str | None = None
    node: str = ""
    input_summary_json: str = "{}"
    output_json: str = "{}"
    source: str = "rule"  # rule | llm | llm_retry | fallback
    valid: bool = True
    error: str | None = None
    at: datetime = Field(default_factory=_utcnow)


class Claim(SQLModel, table=True):
    """Explanation sentence (DB table). Distinct from the agent-schema ``Claim``
    pydantic model used for LLM output (conflict C27: same name, different
    module and purpose)."""

    id: int | None = Field(default=None, primary_key=True)
    finding_id: str = Field(index=True)
    field: str  # what | impact | exploit | fix
    text: str = ""
    evidence_ids_json: str = "[]"
    kept: bool = True


class FixAttempt(SQLModel, table=True):
    id: str = Field(primary_key=True)  # X-0003
    finding_id: str = Field(index=True)
    diff: str = ""
    workspace_path: str | None = None
    status: str = "drafted"  # drafted | verified | failed | committed
    verify_report_json: str = "{}"
    commit_mode: str | None = None  # patch | apply | pr
    at: datetime = Field(default_factory=_utcnow)


class ToolCallLog(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    scan_id: str = Field(index=True)
    tool: str
    target_host: str | None = None
    args_hash: str = ""
    duration_ms: int | None = None
    exit_code: int | None = None
    blocked_reason: str | None = None
    at: datetime = Field(default_factory=_utcnow)


class Counter(SQLModel, table=True):
    """Monotonic per-prefix counter for human-readable IDs (S/F/E/X/D)."""

    prefix: str = Field(primary_key=True)
    value: int = 0
