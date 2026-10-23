"""AEGIS main LangGraph graph (PHASES P3.2 / AG05.1).

Wires the full investigation graph (SYSTEM_DESIGN §5.2):

    route_mode → prepare → plan
      → [runtime | code | crypto]  (sequential, chosen by next_stage)
      → normalize → correlate? → score
      → investigate ⇄ dispatch
      → explain → validate → remediate → finalize → END

In AG05.1 the nodes are stubs; real implementations land in AG05.2+ (first
nodes), AG06–AG08 (workers/correlation/risk) and AG09–AG12 (investigation,
explain, remediate, finalize). ``correlate`` runs only in correlated mode.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from aegis.agent.nodes.correlate import correlate
from aegis.agent.nodes.code_subgraph import code_subgraph
from aegis.agent.nodes.crypto_subgraph import crypto_subgraph
from aegis.agent.nodes.dispatch import dispatch
from aegis.agent.nodes.explain import explain
from aegis.agent.nodes.finalize import finalize
from aegis.agent.nodes.investigate import investigate
from aegis.agent.nodes.normalize import normalize
from aegis.agent.nodes.plan import plan
from aegis.agent.nodes.prepare import prepare
from aegis.agent.nodes.remediate import remediate
from aegis.agent.nodes.route_mode import route_mode
from aegis.agent.nodes.runtime_subgraph import runtime_subgraph
from aegis.agent.nodes.score import score
from aegis.agent.nodes.validate import validate
from aegis.agent.state import AegisState
from aegis.evidence.models import Mode

__all__ = ["build_aegis_graph", "next_stage"]

_WORKER_STAGES = {"runtime": runtime_subgraph, "code": code_subgraph, "crypto": crypto_subgraph}


def next_stage(state: AegisState) -> str:
    """Next unfinished stage from the plan, else 'normalize'.

    Sequential execution keeps memory under the hardware budget (SD §5.2).
    """
    completed = set(state.get("completed_stages", []))
    for stage in state.get("plan", []):
        if stage not in completed:
            return stage
    return "normalize"


def _after_normalize(state: AegisState) -> str:
    mode = state.get("mode")
    is_correlated = mode == Mode.correlated or mode == "correlated"
    return "correlate" if is_correlated else "score"


def _after_investigate(state: AegisState) -> str:
    return "dispatch" if state.get("pending_actions") else "explain"


def _after_dispatch(state: AegisState) -> str:
    return "investigate" if state.get("iterations", 0) < state.get("max_iterations", 3) else "explain"


def build_aegis_graph(checkpointer=None, *, interrupt_before: list[str] | None = None):
    """Compile the main graph.

    ``interrupt_before`` is a test/ops hook for pausing ahead of named nodes
    (used to prove checkpoint resume); normal scans never set it.
    """
    g = StateGraph(AegisState)

    for name, fn in [
        ("route_mode", route_mode),
        ("prepare", prepare),
        ("plan", plan),
        ("runtime", runtime_subgraph),
        ("code", code_subgraph),
        ("crypto", crypto_subgraph),
        ("normalize", normalize),
        ("correlate", correlate),
        ("score", score),
        ("investigate", investigate),
        ("dispatch", dispatch),
        ("explain", explain),
        ("validate", validate),
        ("remediate", remediate),
        ("finalize", finalize),
    ]:
        g.add_node(name, fn)

    g.add_edge(START, "route_mode")
    g.add_edge("route_mode", "prepare")
    g.add_edge("prepare", "plan")

    stage_map = {"runtime": "runtime", "code": "code", "crypto": "crypto", "normalize": "normalize"}
    g.add_conditional_edges("plan", next_stage, stage_map)
    for stage in _WORKER_STAGES:
        g.add_conditional_edges(stage, next_stage, stage_map)

    g.add_conditional_edges("normalize", _after_normalize, {"correlate": "correlate", "score": "score"})
    g.add_edge("correlate", "score")
    g.add_edge("score", "investigate")

    g.add_conditional_edges("investigate", _after_investigate, {"dispatch": "dispatch", "explain": "explain"})
    g.add_conditional_edges("dispatch", _after_dispatch, {"investigate": "investigate", "explain": "explain"})

    g.add_edge("explain", "validate")
    g.add_edge("validate", "remediate")
    g.add_edge("remediate", "finalize")
    g.add_edge("finalize", END)

    return g.compile(checkpointer=checkpointer, interrupt_before=interrupt_before)
