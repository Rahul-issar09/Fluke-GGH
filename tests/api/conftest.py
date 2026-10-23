"""API tests reuse the agent tests' world builders (demo source, seeded evidence, scripted model)."""

from __future__ import annotations

import os
import sys

_AGENT_TESTS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent")
if _AGENT_TESTS not in sys.path:
    sys.path.insert(0, _AGENT_TESTS)
