"""Registry of the frozen contract objects (STRUCTURE ST03).

One place lists every enum, model and TypedDict that is frozen after P0, so
the snapshot test and the golden generator agree.
"""

from __future__ import annotations

from aegis.agent import schemas as agent_schemas
from aegis.agent import state as agent_state
from aegis.api import schemas as api_schemas
from aegis.evidence import models as ev
from aegis.safety import models as safety

CONTRACTS: dict[str, list] = {
    "evidence.models": [
        ev.Mode,
        ev.FindingState,
        ev.ScanStatus,
        ev.EvidenceKind,
        ev.Scan,
        ev.Finding,
        ev.Evidence,
        ev.StateTransition,
        ev.AgentDecision,
        ev.Claim,
        ev.FixAttempt,
        ev.ToolCallLog,
        ev.Counter,
    ],
    "agent.schemas": [
        agent_schemas.NextStep,
        agent_schemas.Target,
        agent_schemas.NextStepDecision,
        agent_schemas.Claim,
        agent_schemas.Explanation,
        agent_schemas.FixDraft,
    ],
    "agent.state": [
        agent_state.ScanInputs,
        agent_state.AegisState,
        agent_state.FixState,
    ],
    "safety.models": [
        safety.ToolCall,
        safety.ToolResult,
    ],
    "api.schemas": [
        api_schemas.ScanRequest,
        api_schemas.ScanOut,
        api_schemas.Scores,
        api_schemas.FindingOut,
        api_schemas.FindingDetail,
        api_schemas.EvidenceOut,
        api_schemas.ProgressEvent,
        api_schemas.GateOut,
        api_schemas.FixOut,
        api_schemas.CommitRequest,
        api_schemas.AskRequest,
        api_schemas.AskOut,
        api_schemas.ErrorOut,
    ],
}
