"""AG10.1 — explain + validate against the real local model (opt-in: ``pytest -m ollama``).

A scripted model cannot show whether the prompt works. This runs the real nodes with
qwen2.5:7b on the demo's correlated access-control finding and checks what matters:
the finished explanation is complete, every kept claim is backed by real evidence, and
the model — not only the fixed templates — contributed.
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

from _corr_helpers import seed_handlers, seed_runtime_bac, seed_static
from _graph_helpers import make_run
import aegis.agent.nodes.explain as explain_node
from aegis.agent.nodes.explain import explain
from aegis.agent.nodes.validate import validate
from aegis.agent.validator import correlated_evidence_ids
from aegis.config import ModelSettings
from aegis.evidence.models import Mode
from aegis.graph.correlator import build_graph, correlate_scan, load_handlers

pytestmark = [pytest.mark.phase("AG10"), pytest.mark.ollama, pytest.mark.slow]

_URL = os.getenv("AEGIS_OLLAMA_URL", "http://localhost:11434")
_MODEL = os.getenv("AEGIS_MODEL", "qwen2.5:7b")


def _reachable() -> bool:
    try:
        httpx.get(f"{_URL}/api/tags", timeout=2.0)
        return True
    except Exception:
        return False


async def test_the_real_model_writes_an_explanation_that_survives_validation(store, tmp_path, monkeypatch):
    if not _reachable():
        pytest.skip(f"Ollama not reachable at {_URL}")

    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)
    seed_handlers(store, scan_id)
    seed_static(store, scan_id)
    runtime = seed_runtime_bac(store, scan_id)
    correlate_scan(store, scan_id, load_handlers(store, scan_id))
    deps = config["configurable"]["deps"]
    deps.llm = None  # the real model
    deps.llm_settings = ModelSettings(name=_MODEL, ollama_url=_URL, temperature=0.1, num_ctx=8192)

    # explain only the finding we care about, to keep the run short
    original = explain_node.visible_findings
    monkeypatch.setattr(explain_node, "visible_findings", lambda st, sid: [f for f in original(st, sid) if f.id == runtime])
    await explain(state, config)
    validate(state, config)

    rows = [d for d in store.list_decisions(scan_id, runtime) if d.node == "explain"]
    detail = [(d.source, d.valid, d.error) for d in rows]
    proposal = rows[-1]
    assert proposal.valid and proposal.source in ("llm", "llm_retry"), f"the model was set aside: {detail}"

    finding = store.get_finding(runtime)
    assert finding.what and finding.impact and finding.exploit            # a complete explanation

    graph = build_graph(store, scan_id, load_handlers(store, scan_id))
    allowed = correlated_evidence_ids(store, graph, runtime)
    kept = store.list_claims(runtime, kept=True)
    assert kept and all(set(json.loads(c.evidence_ids_json)) <= allowed for c in kept)  # every claim backed

    verdict = next(d for d in store.list_decisions(scan_id, runtime) if d.node == "validate")
    out = json.loads(verdict.output_json)
    assert out["kept"] >= 1, f"nothing the model wrote survived validation: {out}"       # the model contributed
