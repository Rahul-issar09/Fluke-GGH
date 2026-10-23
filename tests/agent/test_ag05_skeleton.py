"""AG05.1 — main graph runs to END with correct node order per mode.

Runs against a real Scan row (AG05.2 nodes are real); ``mode`` is derived by
``route_mode`` from the inputs, not pre-seeded.
"""

from __future__ import annotations

import pytest

from _graph_helpers import make_run
from aegis.agent.graph import build_aegis_graph, next_stage
from aegis.evidence.models import Mode

pytestmark = pytest.mark.phase("AG05")


async def _run(store, tmp_path, mode: Mode) -> list[str]:
    _, state, config = make_run(store, tmp_path, mode)
    final = await build_aegis_graph().ainvoke(state, config)
    return final["completed_stages"]


async def test_runtime_mode_order(store, tmp_path):
    assert await _run(store, tmp_path, Mode.runtime) == [
        "route_mode", "prepare", "plan", "runtime",
        "normalize", "score", "investigate",
        "explain", "validate", "remediate", "finalize",
    ]


async def test_code_mode_order(store, tmp_path):
    assert await _run(store, tmp_path, Mode.code) == [
        "route_mode", "prepare", "plan", "code", "crypto",
        "normalize", "score", "investigate",
        "explain", "validate", "remediate", "finalize",
    ]


async def test_correlated_mode_runs_correlate(store, tmp_path):
    assert await _run(store, tmp_path, Mode.correlated) == [
        "route_mode", "prepare", "plan", "runtime", "code", "crypto",
        # no handler map yet, so the runtime findings ask for source evidence once (investigate -> dispatch),
        # then the second pass finds them exhausted and closes them
        "normalize", "correlate", "score", "investigate", "dispatch", "investigate",
        "explain", "validate", "remediate", "finalize",
    ]


async def test_correlate_only_in_correlated_mode(store, tmp_path):
    assert "correlate" not in await _run(store, tmp_path, Mode.runtime)
    assert "correlate" not in await _run(store, tmp_path, Mode.code)


def test_next_stage_picks_unfinished():
    state = {"plan": ["runtime", "code", "crypto"], "completed_stages": ["runtime"]}
    assert next_stage(state) == "code"
    state["completed_stages"] = ["runtime", "code", "crypto"]
    assert next_stage(state) == "normalize"


async def test_graph_reaches_end_all_modes(store, tmp_path):
    for mode in (Mode.runtime, Mode.code, Mode.correlated):
        assert (await _run(store, tmp_path, mode))[-1] == "finalize"
