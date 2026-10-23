"""Runtime dependencies for graph nodes (AG05.2, extended in AG06.1).

``AegisState`` is a frozen contract that holds IDs and small summaries only, so
nodes get their collaborators (the evidence store, the git clone callable, the
default allowlist, offline DB location) through LangGraph's per-run config:

    graph.invoke(state, {"configurable": {"deps": AgentDeps(store=...)}})

Nodes fetch them with :func:`get_deps`.

``scratch`` is per-scan, per-stage, **in-memory** working space for things that
must never be persisted or shown to the LLM — e.g. login sessions and the HTTP
client. It is closed and discarded when the stage ends (``close_scratch``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from aegis.config import ModelSettings
from aegis.evidence.store import EvidenceStore

__all__ = ["AgentDeps", "MissingDeps", "get_deps"]


class MissingDeps(RuntimeError):
    """A node ran without ``configurable.deps`` in the run config."""


@dataclass
class AgentDeps:
    store: EvidenceStore
    # clone_fn(repo_url, dest, scan_id) → info dict, sync or async — the real one is
    # ``workers.code.clone.make_clone_fn`` (a SafetyController "git" call to the configured git
    # hosts). None means repo scans fail with a clear reason instead of cloning.
    clone_fn: Callable[..., Any] | None = None
    # Mirrors safety.allowlist in .aegis.yml (SD §13); the target URL host is added per scan.
    default_allowlist: tuple[str, ...] = ("demo-app:5000", "callback:8080")
    offline_db_dir: str = "offline-db"
    tmp_root: str | None = None  # where repo clones go (the backend uses <data_dir>/clones)
    clone_keep_hours: float = 24.0  # a finished scan's clone is kept this long, for its fixes
    # Runtime data root; per-scan graphs are written to <data_dir>/graphs/<scan_id>.json.
    data_dir: str = "data"
    # Minimum link score for correlation (.aegis.yml correlation.threshold).
    correlation_threshold: float = 0.70
    # Routes whose data is sensitive (.aegis.yml risk.sensitive_routes) — drives Criticality / PathFactor.
    sensitive_routes: tuple[str, ...] = ("/api/accounts", "/admin")
    # The structured LLM runnable used by the investigation loop. None → build the local
    # Ollama model from ``llm_settings`` (env defaults). Tests inject a deterministic fake.
    llm: Any | None = None
    llm_settings: ModelSettings | None = None
    # Inner transport under the egress guard. None → real network (allowlisted
    # hosts only); tests inject an in-process ASGI/mock transport.
    http_transport: httpx.AsyncBaseTransport | None = None
    rate_limit_rps: float = 5.0
    rate_limit_burst: int = 10
    # SafetyController executor for external tools; None → the real one
    # (``workers.executor.execute_tool``). Tests inject a fake.
    tool_executor: Callable[..., Any] | None = None
    # How long to wait for an out-of-band callback before calling a probe negative.
    oob_wait_s: float = 5.0
    # The self-hosted out-of-band listener (safety.callback_url). AEGIS's own infrastructure, so
    # prepare adds it to every scan's allowlist; the SSRF probe value is built from it.
    callback_url: str = "http://callback:8080"
    # Fix verification (AG11): where the patched build answers for the runtime re-test.
    # ``patched_target(workspace) -> PatchedTarget | None`` builds/starts it from the fix workspace;
    # otherwise ``patched_target_url`` names a pre-staged patched build (SD §5.7). Its host must be
    # in the scan's allowlist — it is never added automatically.
    patched_target: Callable[..., Any] | None = None
    patched_target_url: str | None = None
    # Builds the chat index for a finished scan (RAG phases). Started by ``finalize`` without
    # waiting for it; None → no chat index yet.
    chat_indexer: Callable[[str], Any] | None = None
    background_tasks: set = field(default_factory=set)  # keeps fire-and-forget tasks alive
    scratch: dict[str, dict[str, Any]] = field(default_factory=dict)

    def scratch_for(self, scan_id: str, stage: str) -> dict[str, Any]:
        return self.scratch.setdefault(f"{scan_id}:{stage}", {"closers": []})

    async def close_scratch(self, scan_id: str, stage: str) -> None:
        """Run the stage's closers (e.g. close the HTTP client) and drop its scratch."""
        data = self.scratch.pop(f"{scan_id}:{stage}", None)
        if not data:
            return
        for closer in reversed(data.get("closers", [])):
            try:
                await closer()
            except Exception:  # noqa: BLE001 - cleanup must never fail the scan
                pass


def get_deps(config: Any) -> AgentDeps:
    deps = ((config or {}).get("configurable") or {}).get("deps")
    if not isinstance(deps, AgentDeps):
        raise MissingDeps("graph run config is missing configurable.deps (AgentDeps)")
    return deps
