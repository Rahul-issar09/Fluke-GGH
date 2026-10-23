"""AEGIS API request/response contract (PHASES P0.6 + FASTAPI FA00.2).

FROZEN after P0 (STRUCTURE invariant I-8). These are the shapes the REST API
and (by reuse) the MCP server return.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ScanRequest",
    "ScanOut",
    "Scores",
    "FindingOut",
    "FindingDetail",
    "EvidenceOut",
    "ProgressEvent",
    "GateOut",
    "FixOut",
    "CommitRequest",
    "AskRequest",
    "AskOut",
    "ErrorOut",
]


class ScanRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"url": "http://demo-app:5000", "identities": "/app/identities.yml"},
                {"folder": "/scan"},
                {
                    "url": "http://demo-app:5000",
                    "folder": "/scan",
                    "identities": "/app/identities.yml",
                },
            ]
        }
    )
    url: str | None = None
    folder: str | None = None
    repo: str | None = None
    identities: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)


class ScanOut(BaseModel):
    id: str
    mode: str
    status: str
    stages: list[str] = Field(default_factory=list)
    completed_stages: list[str] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    started_at: str | None = None
    finished_at: str | None = None


class Scores(BaseModel):
    confidence: float = 0.0
    exploitability: float = 0.0
    exposure: float = 0.0
    criticality: float = 0.0
    path_factor: float = 0.0
    risk: float = 0.0
    correlation: float | None = None


class FindingOut(BaseModel):
    id: str
    type: str
    owasp: str | None = None
    title: str = ""
    severity: float = 0.0
    state: str
    mode: str | None = None
    route: str | None = None
    function: str | None = None
    file: str | None = None
    line: int | None = None
    risk: float = 0.0
    correlation_score: float | None = None


class FindingDetail(FindingOut):
    # 5-part explanation: where is derived deterministically from file:line
    what: str | None = None
    where: str | None = None
    impact: str | None = None
    exploit: str | None = None
    fix: dict[str, Any] | None = None
    scores: Scores = Field(default_factory=Scores)
    claims: list[dict[str, Any]] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class EvidenceOut(BaseModel):
    id: str
    finding_id: str | None = None
    scan_id: str
    kind: str
    tool: str
    tool_version: str = ""
    db_date: str | None = None
    payload: dict[str, Any] | list[Any] | None = None
    created_at: str | None = None


class ProgressEvent(BaseModel):
    scan_id: str
    stage: str
    node: str
    status: str
    ms: int | None = None
    at: str


class GateOut(BaseModel):
    passed: bool
    exit_code: int  # 0 clean · 1 above threshold · 2 error
    blocking_findings: list[str] = Field(default_factory=list)


class FixOut(BaseModel):
    fix_id: str
    finding_id: str
    status: str
    diff: str | None = None
    verify_report: dict[str, Any] | None = None


class CommitRequest(BaseModel):
    mode: Literal["patch", "apply", "pr"]


class AskRequest(BaseModel):
    scan_id: str
    question: str


class AskOut(BaseModel):
    answer: str
    finding_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class ErrorOut(BaseModel):
    error: str
    detail: str | None = None
    ids: list[str] | None = None
