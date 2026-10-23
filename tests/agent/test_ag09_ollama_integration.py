"""AG09.2 — the investigate node against the real local model (opt-in: ``pytest -m ollama``).

Proves what a scripted model cannot: that qwen2.5:7b, given the real prompt and the guarded
payload, returns an answer that passes ``validate_decision`` — a real enum value among the
allowed steps, citing evidence that actually belongs to the finding.
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

from _corr_helpers import seed_runtime_bac
from _graph_helpers import make_run
from aegis.agent.nodes.investigate import investigate
from aegis.config import ModelSettings
from aegis.evidence.models import Mode

pytestmark = [pytest.mark.phase("AG09"), pytest.mark.ollama, pytest.mark.slow]

_URL = os.getenv("AEGIS_OLLAMA_URL", "http://localhost:11434")
_MODEL = os.getenv("AEGIS_MODEL", "qwen2.5:7b")


def _reachable() -> bool:
    try:
        httpx.get(f"{_URL}/api/tags", timeout=2.0)
        return True
    except Exception:
        return False


async def test_the_real_model_makes_a_valid_judgment_call(store, tmp_path):
    if not _reachable():
        pytest.skip(f"Ollama not reachable at {_URL}")

    scan_id, state, config = make_run(store, tmp_path, Mode.correlated)
    runtime = seed_runtime_bac(store, scan_id)
    # the source lookup was already tried and did not help: [mark_sufficient, escalate_to_human]
    store.add_decision(scan_id, "investigate", "rule", finding_id=runtime, output={"next_step": "request_source_evidence"})
    deps = config["configurable"]["deps"]
    deps.llm = None  # use the real model, not the test stand-in
    deps.llm_settings = ModelSettings(name=_MODEL, ollama_url=_URL, temperature=0.1, num_ctx=8192)

    await investigate(state, config)

    rows = [d for d in store.list_decisions(scan_id, runtime) if d.node == "investigate"][1:]
    final = rows[-1]
    detail = [(d.source, d.valid, d.error) for d in rows]
    assert final.valid, detail
    assert final.source in ("llm", "llm_retry"), f"the model was set aside: {detail}"
    out = json.loads(final.output_json)
    assert out["next_step"] in ("mark_sufficient", "escalate_to_human")
    assert set(out["reason_evidence_ids"]) <= {e.id for e in store.evidence_for(runtime)}
