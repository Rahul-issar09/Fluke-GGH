"""P0.5 — safety models (contract)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.safety import models as sm

pytestmark = pytest.mark.phase("AG00")


def test_valid_toolcall_defaults():
    c = sm.ToolCall(tool="semgrep", scan_id="S-0001")
    assert c.args == {} and c.test_input_ids == [] and c.target_host is None


def test_unknown_tool_rejected():
    with pytest.raises(ValidationError):
        sm.ToolCall(tool="rm-rf", scan_id="S-0001")


def test_gh_not_in_tool_literal():
    # Conflict C6: pr-commit mode's `gh` must not be a valid tool yet.
    with pytest.raises(ValidationError):
        sm.ToolCall(tool="gh", scan_id="S-0001")


def test_toolresult_shape():
    r = sm.ToolResult(ok=False, tool="semgrep", blocked_reason="off-allowlist")
    assert r.ok is False and r.blocked_reason == "off-allowlist"
    assert r.exit_code is None and r.duration_ms == 0
