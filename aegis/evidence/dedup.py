"""Deduplication helper (PHASES P5.3).

Same fingerprint → one finding; merge evidence and sources. When a finding
gathers independent signals from ≥ 2 distinct tools it becomes a candidate for
corroboration (the normalizer calls the state machine to make that move).
"""

from __future__ import annotations

import json

__all__ = ["merge_sources", "distinct_tool_count"]


def merge_sources(existing_sources_json: str, new_source: str) -> str:
    try:
        sources = json.loads(existing_sources_json or "[]")
    except (json.JSONDecodeError, ValueError):
        sources = []
    if new_source and new_source not in sources:
        sources.append(new_source)
    return json.dumps(sources)


def distinct_tool_count(sources_json: str) -> int:
    try:
        sources = json.loads(sources_json or "[]")
    except (json.JSONDecodeError, ValueError):
        return 0
    # source ids look like "worker2.semgrep" — the suffix is the tool
    tools = {s.split(".")[-1] for s in sources}
    return len(tools)
