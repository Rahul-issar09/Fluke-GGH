"""code worker stage (Worker 2, AG14.1): a subgraph of registered steps.

Steps (``worker_stage.STAGE_STEPS["code"]``): inventory → extract_routes → semgrep → gitleaks
→ trufflehog → osv → trivy.

* **inventory** — Syft SBOM as ``dependency`` evidence (optional tool).
* **extract_routes** — route → handler map (``code_location`` evidence, ``role: route_handler``),
  parsed with ``ast`` in a thread; what correlation links runtime findings to.
* **semgrep** — the local rules; findings with ``code_location`` (+ ``dataflow_path``) evidence.
* **gitleaks** — hard-coded secrets; the value is never stored.
* **trufflehog** — a second secret scanner (never verifies a secret); agreeing with gitleaks on the
  same file and line corroborates that finding.
* **osv** / **trivy** — vulnerable dependency versions against the pre-staged offline databases
  (``<offline_db_dir>/osv``, ``<offline_db_dir>/trivy``); Trivy also checks configuration files.
  Without a staged database the step is skipped with a warning.

Every tool runs through the SafetyController. A tool that is not installed is skipped with a
warning; a tool that fails becomes a ``tool_error`` (the stage records it and carries on). When
the investigation loop narrows a run to one file (``state["target"]["file"]``, re-derived from
the store by dispatch), semgrep and gitleaks scan only that file.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from langchain_core.runnables import RunnableConfig

from aegis.agent.deps import get_deps
from aegis.agent.nodes.worker_stage import StageAbort, make_stage_node, register_step
from aegis.evidence.adapters.gitleaks import GitleaksAdapter
from aegis.evidence.adapters.osv import OsvAdapter
from aegis.evidence.adapters.semgrep import SemgrepAdapter
from aegis.evidence.adapters.trivy import TrivyAdapter
from aegis.evidence.adapters.trufflehog import TrufflehogAdapter
from aegis.evidence.normalizer import ingest
from aegis.observability import get_logger
from aegis.safety.allowlist import Allowlist
from aegis.safety.controller import SafetyController
from aegis.safety.rate_limiter import RateLimiter
from aegis.safety.test_inputs import TestInputLibrary
from aegis.workers.code.dependencies import DependencyScanUnavailable, run_osv, run_trivy
from aegis.workers.code.gitleaks import GitleaksUnavailable, run_gitleaks
from aegis.workers.code.inventory import InventoryUnavailable, run_inventory
from aegis.workers.code.routes_fastapi import extract_routes
from aegis.workers.code.semgrep import SemgrepUnavailable, run_semgrep
from aegis.workers.code.trufflehog import TrufflehogUnavailable, run_trufflehog
from aegis.workers.executor import execute_tool

log = get_logger("agent.node.code")


def _source(state: dict, config: RunnableConfig) -> Path:
    scan = get_deps(config).store.get_scan(state["scan_id"])
    if scan is None or not scan.source_path or not Path(scan.source_path).is_dir():
        raise StageAbort("the scan has no source folder")
    return Path(scan.source_path)


def _target_file(state: dict, source: Path) -> str | None:
    """The one file an investigation follow-up asked about — only if it is inside the source."""
    file = (state.get("target") or {}).get("file")
    if not file:
        return None
    path = (source / file).resolve()
    return file if path.is_relative_to(source.resolve()) and path.is_file() else None


def _mode(config: RunnableConfig, scan_id: str) -> str | None:
    scan = get_deps(config).store.get_scan(scan_id)
    return getattr(scan.mode, "value", scan.mode) if scan else None


def _controller(state: dict, config: RunnableConfig) -> SafetyController:
    deps = get_deps(config)
    scratch = deps.scratch_for(state["scan_id"], "code")
    if "controller" not in scratch:
        scan = deps.store.get_scan(state["scan_id"])
        scan_cfg = json.loads(scan.config_json or "{}")
        scratch["controller"] = SafetyController(
            Allowlist(scan_cfg.get("allowlist") or deps.default_allowlist),
            TestInputLibrary.load(callback_url=deps.callback_url),
            RateLimiter(deps.rate_limit_rps, deps.rate_limit_burst),
            executor=deps.tool_executor or execute_tool,
            audit_sink=deps.store.add_tool_call_log,
        )
    return scratch["controller"]


def _not_installed(exc: Exception) -> bool:
    return str(exc).startswith("tool not installed")


@register_step("code", "inventory")
async def inventory_step(state: dict, config: RunnableConfig) -> None:
    scan_id, source = state["scan_id"], _source(state, config)
    try:
        found = await run_inventory(_controller(state, config), scan_id, source)
    except InventoryUnavailable as exc:
        if _not_installed(exc):
            log.warning("inventory.skipped", scan_id=scan_id, reason=str(exc))
            return
        raise RuntimeError(str(exc)) from exc
    get_deps(config).store.add_evidence(scan_id, "dependency", "syft", {"components": found, "count": len(found)})


@register_step("code", "extract_routes")
async def extract_routes_step(state: dict, config: RunnableConfig) -> None:
    store, scan_id, source = get_deps(config).store, state["scan_id"], _source(state, config)
    routes, skipped = await asyncio.to_thread(extract_routes, source)
    known = {
        (p.get("qualname"), p.get("path"))
        for p in (json.loads(e.payload_json or "{}") for e in store.list_evidence(scan_id, kind="code_location"))
        if p.get("role") == "route_handler"
    }
    added = 0
    for row in routes:
        if (row["qualname"], row["path"]) in known:  # a re-run (investigation follow-up) adds nothing twice
            continue
        store.add_evidence(scan_id, "code_location", "route_extractor", {"role": "route_handler", **row})
        added += 1
    for skip in skipped:
        store.add_tool_error(scan_id, "route_extractor", f"{skip['file']}: {skip['reason']}")
    log.info("extract_routes.done", scan_id=scan_id, routes=len(routes), added=added, skipped=len(skipped))


@register_step("code", "semgrep")
async def semgrep_step(state: dict, config: RunnableConfig) -> None:
    scan_id, source = state["scan_id"], _source(state, config)
    only = _target_file(state, source)
    try:
        results = await run_semgrep(_controller(state, config), scan_id, source, only_file=only)
    except SemgrepUnavailable as exc:
        if _not_installed(exc):
            log.warning("semgrep.skipped", scan_id=scan_id, reason=str(exc))
            return
        raise RuntimeError(str(exc)) from exc
    drafts = SemgrepAdapter(mode=_mode(config, scan_id)).parse({"results": results}, scan_id)
    finding_ids = ingest(get_deps(config).store, scan_id, drafts)
    log.info("semgrep_step.done", scan_id=scan_id, file=only, findings=finding_ids)


@register_step("code", "gitleaks")
async def gitleaks_step(state: dict, config: RunnableConfig) -> None:
    scan_id, source = state["scan_id"], _source(state, config)
    only = _target_file(state, source)
    try:
        report = await run_gitleaks(_controller(state, config), scan_id, source, only_file=only)
    except GitleaksUnavailable as exc:
        if _not_installed(exc):
            log.warning("gitleaks.skipped", scan_id=scan_id, reason=str(exc))
            return
        raise RuntimeError(str(exc)) from exc
    drafts = GitleaksAdapter(mode=_mode(config, scan_id)).parse(report, scan_id)
    finding_ids = ingest(get_deps(config).store, scan_id, drafts)
    log.info("gitleaks_step.done", scan_id=scan_id, file=only, findings=finding_ids)


@register_step("code", "trufflehog")
async def trufflehog_step(state: dict, config: RunnableConfig) -> None:
    scan_id, source = state["scan_id"], _source(state, config)
    try:
        found = await run_trufflehog(_controller(state, config), scan_id, source)
    except TrufflehogUnavailable as exc:
        if _not_installed(exc):
            log.warning("trufflehog.skipped", scan_id=scan_id, reason=str(exc))
            return
        raise RuntimeError(str(exc)) from exc
    finding_ids = ingest(get_deps(config).store, scan_id, TrufflehogAdapter(mode=_mode(config, scan_id)).parse(found, scan_id))
    log.info("trufflehog_step.done", scan_id=scan_id, findings=finding_ids)


def _db(config: RunnableConfig, scan_id: str, name: str) -> tuple[Path, str | None]:
    deps = get_deps(config)
    scan = deps.store.get_scan(scan_id)
    dates = json.loads(scan.db_snapshot_dates or "{}") if scan else {}
    return Path(deps.offline_db_dir) / name, dates.get(name)


async def _dependency_step(state: dict, config: RunnableConfig, tool: str) -> None:
    scan_id, source = state["scan_id"], _source(state, config)
    db_dir, db_date = _db(config, scan_id, tool)
    if not db_dir.is_dir():
        log.warning(f"{tool}.skipped", scan_id=scan_id, reason=f"offline database not staged: {db_dir}")
        return
    runner, adapter = (run_osv, OsvAdapter) if tool == "osv" else (run_trivy, TrivyAdapter)
    try:
        found = await runner(_controller(state, config), scan_id, source, db_dir)
    except DependencyScanUnavailable as exc:
        if _not_installed(exc):
            log.warning(f"{tool}.skipped", scan_id=scan_id, reason=str(exc))
            return
        raise RuntimeError(str(exc)) from exc
    drafts = adapter(mode=_mode(config, scan_id), db_date=db_date).parse(found, scan_id)
    finding_ids = ingest(get_deps(config).store, scan_id, drafts)
    log.info(f"{tool}_step.done", scan_id=scan_id, findings=finding_ids, db_date=db_date)


@register_step("code", "osv")
async def osv_step(state: dict, config: RunnableConfig) -> None:
    await _dependency_step(state, config, "osv")


@register_step("code", "trivy")
async def trivy_step(state: dict, config: RunnableConfig) -> None:
    await _dependency_step(state, config, "trivy")


code_subgraph = make_stage_node("code")
