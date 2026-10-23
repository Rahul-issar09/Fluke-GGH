"""Helpers for running the main graph against a real Scan row (AG05/AG06)."""

from __future__ import annotations

from aegis.agent.deps import AgentDeps
from aegis.agent.state import ScanInputs
from aegis.api.schemas import ScanRequest
from aegis.evidence.models import Mode
from aegis.services.scan_service import create_scan
from aegis.workers.executor import no_tools_executor
from fakes.demo_apps import demo_stack, identities_path
from fakes.fake_llm import PickFirstLLM

_URL = "http://demo-app:5000"


def make_run(store, tmp_path, mode: Mode, *, demo: str = "vulnerable", identities: str | None = None, **dep_overrides):
    """Create a scan for *mode* and return ``(scan_id, init_state, config)``.

    ``mode`` is deliberately left out of the initial state so ``route_mode``
    has to derive it from the inputs. Runtime stages run against the in-process
    scan network (demo target + callback listener; ``demo="vulnerable"`` or
    ``"patched"``) — no real network and no real scanner binaries.
    """
    folder = tmp_path / "scan"
    folder.mkdir(exist_ok=True)
    kwargs: dict = {}
    if mode in (Mode.runtime, Mode.correlated):
        kwargs.update(url=_URL, identities=identities or identities_path(demo))
    if mode in (Mode.code, Mode.correlated):
        kwargs.update(folder=str(folder))

    scan_id = create_scan(store, ScanRequest(**kwargs), allowed_source_roots=(str(folder),))
    state = {
        "scan_id": scan_id,
        "inputs": ScanInputs(**kwargs),
        "plan": [],
        "completed_stages": [],
        "open_findings": [],
        "pending_actions": [],
        "iterations": 0,
        "max_iterations": 3,
        "errors": [],
    }
    options = {
        "offline_db_dir": str(tmp_path / "offline-db"),
        "tmp_root": str(tmp_path / "tmp"),
        "data_dir": str(tmp_path / "data"),
        "http_transport": demo_stack(demo)[0],
        "rate_limit_rps": 1000.0,
        "rate_limit_burst": 1000,
        "tool_executor": no_tools_executor,  # external scanners are exercised in their own tests
        "oob_wait_s": 0.3,
        "llm": PickFirstLLM(),  # the real model is only used in the opt-in -m ollama tests
    }
    options.update(dep_overrides)
    deps = AgentDeps(store=store, **options)
    return scan_id, state, {"configurable": {"deps": deps}}
