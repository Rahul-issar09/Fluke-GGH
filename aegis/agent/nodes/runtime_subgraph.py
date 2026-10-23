"""runtime worker stage (AG05.3 wiring + AG06.1 steps).

The stage is a subgraph of steps (``worker_stage.STAGE_STEPS["runtime"]``).
This module registers the Worker 1 steps that exist; the rest (ssrf,
misconfig, api conformance) are skipped with a warning until they are built.

Layering: the worker modules (``aegis.workers.runtime.*``) are plain async
functions with no graph dependency. These adapters fetch the scan's context,
call them, persist evidence, and translate ``RuntimeStageError`` into
``StageAbort`` (the stage stops, the scan reports it and carries on).

No LLM is used here. Sessions and the HTTP client live in the stage's in-memory
scratch space and are closed when the stage ends.
"""

from __future__ import annotations

import json
from pathlib import Path

from langchain_core.runnables import RunnableConfig

from aegis.agent.deps import get_deps
from aegis.agent.nodes.crypto_subgraph import scan_tls, tls_targets, write_scan_cbom
from aegis.agent.nodes.worker_stage import StageAbort, make_stage_node, register_step
from aegis.observability import get_logger
from aegis.evidence.adapters.nuclei import NucleiAdapter
from aegis.evidence.adapters.schemathesis import SchemathesisAdapter
from aegis.evidence.normalizer import ingest
from aegis.safety.allowlist import Allowlist
from aegis.safety.controller import SafetyController
from aegis.safety.egress import make_client
from aegis.safety.models import ToolResult
from aegis.safety.rate_limiter import RateLimiter
from aegis.safety.test_inputs import TestInputLibrary
from aegis.workers.executor import execute_tool
from aegis.workers.runtime.auth import authenticate, browser_authenticate, load_identities
from aegis.workers.runtime.crawl import routes_from_crawl, run_katana
from aegis.workers.runtime.bola import check_bola, record_bola_findings
from aegis.workers.runtime import coverage
from aegis.workers.runtime.context import RuntimeContext, RuntimeStageError, auth_headers, verify_tls
from aegis.workers.runtime.discover import discover_routes
from aegis.workers.runtime.model import build_model
from aegis.workers.runtime.nuclei import run_nuclei
from aegis.workers.runtime.schemathesis import run_schemathesis
from aegis.workers.runtime.ssrf import check_ssrf, find_ssrf_candidates, record_ssrf_findings
from aegis.workers.runtime.validate import validate_target
from aegis.graph.route_normalize import normalize_path

log = get_logger("agent.node.runtime")


def _context(state: dict, config: RunnableConfig) -> RuntimeContext:
    """Build (once per scan/stage) the in-memory runtime context."""
    deps = get_deps(config)
    scan_id = state["scan_id"]
    scratch = deps.scratch_for(scan_id, "runtime")
    if "ctx" in scratch:
        return scratch["ctx"]

    scan = deps.store.get_scan(scan_id)
    if scan is None or not scan.target_url:
        raise StageAbort("scan has no target URL")
    scan_cfg = json.loads(scan.config_json or "{}")
    allowlist = Allowlist(scan_cfg.get("allowlist") or deps.default_allowlist)
    client = make_client(
        allowlist,
        rate_limiter=RateLimiter(deps.rate_limit_rps, deps.rate_limit_burst),
        inner=deps.http_transport,
        verify=verify_tls(scan_cfg),
        timeout=10.0,
        follow_redirects=False,
    )
    ctx = RuntimeContext(
        scan_id=scan_id,
        base_url=scan.target_url,
        client=client,
        identities_path=scan_cfg.get("identities"),
    )
    scratch["ctx"] = ctx
    scratch["closers"].append(client.aclose)
    return ctx


@register_step("runtime", "tls_scan")
async def tls_scan_step(state: dict, config: RunnableConfig) -> None:
    """The TLS check for a scan without source code (TNW-2). With source code it runs in the crypto
    stage instead, where each issue is linked to the TLS setting in the code that causes it."""
    deps, scan_id = get_deps(config), state["scan_id"]
    scan = deps.store.get_scan(scan_id)
    if scan is None or scan.source_path:
        log.info("tls_scan.in_crypto_stage", scan_id=scan_id)
        return
    if not tls_targets(scan):
        log.info("tls_scan.nothing_to_scan", scan_id=scan_id)
        return
    before = len([f for f in deps.store.list_findings(scan_id) if f.type == "weak_tls"])
    try:
        await scan_tls(deps, scan_id, _controller(state, config), _scan_mode(deps, scan_id))
        after = len([f for f in deps.store.list_findings(scan_id) if f.type == "weak_tls"])
        coverage.record(deps.store, scan_id, "tls", coverage.FAILED if after > before else coverage.PASS, "sslyze checked the TLS endpoint(s)")
    finally:  # the CBOM lists the endpoints that were checked (no code assets without source)
        write_scan_cbom(deps, scan_id)


@register_step("runtime", "validate_target")
async def validate_target_step(state: dict, config: RunnableConfig) -> None:
    ctx = _context(state, config)
    try:
        await validate_target(ctx.client, ctx.base_url)
    except RuntimeStageError as exc:
        raise StageAbort(str(exc)) from exc


@register_step("runtime", "discover_routes")
async def discover_routes_step(state: dict, config: RunnableConfig) -> None:
    ctx = _context(state, config)
    try:
        ctx.routes, payload = await discover_routes(ctx.client, ctx.base_url)
    except RuntimeStageError as exc:
        coverage.record(get_deps(config).store, ctx.scan_id, "discovery", coverage.BLOCKED, str(exc)[:160])
        raise StageAbort(str(exc)) from exc
    if ctx.routes:
        ctx.spec_path = payload["route"]
    store = get_deps(config).store
    store.add_evidence(ctx.scan_id, kind="http_exchange", tool="httpx", payload=payload)
    if ctx.routes:
        coverage.record(store, ctx.scan_id, "discovery", coverage.PASS, f"{len(ctx.routes)} routes from the OpenAPI document")
    elif payload.get("status") in (401, 403):
        coverage.record(store, ctx.scan_id, "discovery", coverage.BLOCKED, f"the API description was refused (HTTP {payload['status']})")
    else:
        coverage.record(store, ctx.scan_id, "discovery", coverage.NOT_TESTED, "no OpenAPI document; relying on the crawler")


@register_step("runtime", "authenticate")
async def authenticate_step(state: dict, config: RunnableConfig) -> None:
    ctx = _context(state, config)
    try:
        cfg = load_identities(ctx.identities_path)
        if cfg.type == "browser":
            deps = get_deps(config)
            scan_cfg = json.loads(deps.store.get_scan(ctx.scan_id).config_json or "{}")
            ctx.sessions = await browser_authenticate(
                _controller(state, config), ctx.scan_id, ctx.base_url, cfg, ctx.identities_path,
                list(scan_cfg.get("allowlist") or deps.default_allowlist), verify_tls=verify_tls(scan_cfg),
            )
        else:
            ctx.sessions = await authenticate(ctx.client, ctx.base_url, cfg)
        coverage.record(get_deps(config).store, ctx.scan_id, "authentication", coverage.PASS, f"signed in {', '.join(sorted(ctx.sessions))}")
    except RuntimeStageError as exc:
        detail = "login refused (HTTP 403)" if "403" in str(exc) else str(exc)[:160]
        coverage.record(get_deps(config).store, ctx.scan_id, "authentication", coverage.BLOCKED, detail)
        raise StageAbort(str(exc)) from exc


@register_step("runtime", "crawl")
async def crawl_step(state: dict, config: RunnableConfig) -> None:
    """Katana, when the target published no OpenAPI document: its routes feed the request model."""
    ctx = _context(state, config)
    if ctx.routes:
        log.info("crawl.not_needed", scan_id=ctx.scan_id, routes=len(ctx.routes))
        return
    deps = get_deps(config)
    result = await run_katana(
        _controller(state, config), ctx.scan_id, ctx.base_url,
        rate_limit=deps.rate_limit_rps, headers=auth_headers(ctx.sessions.get("A")),
    )
    if _unavailable(result, "crawl", ctx.scan_id):
        return
    _failed(result, "katana")
    ctx.routes = routes_from_crawl(result.output, ctx.base_url)
    deps.store.add_evidence(ctx.scan_id, kind="http_exchange", tool="katana", payload={
        "method": "GET", "route": "/", "status": None, "routes_found": len(ctx.routes),
        "routes": [r.template for r in ctx.routes], "source": "crawl",
        "auth_context": "A" if "A" in ctx.sessions else "unauthenticated",
    })
    log.info("crawl.done", scan_id=ctx.scan_id, routes=[r.template for r in ctx.routes])
    if ctx.routes:
        deps.store and coverage.record(deps.store, ctx.scan_id, "discovery", coverage.PASS, f"{len(ctx.routes)} routes by crawling")


@register_step("runtime", "build_request_model")
async def build_request_model_step(state: dict, config: RunnableConfig) -> None:
    ctx = _context(state, config)
    if not ctx.sessions:
        raise StageAbort("no authenticated sessions to build the request model")
    ctx.model = await build_model(ctx.client, ctx.base_url, ctx.routes, ctx.sessions)


@register_step("runtime", "check_bola")
async def check_bola_step(state: dict, config: RunnableConfig) -> None:
    ctx = _context(state, config)
    model = ctx.model
    if _target_route(state):  # a focused retest: only the route the loop asked about
        model = [m for m in model if _same_route(m.route.template, _target_route(state))]
    if not model:
        log.info("check_bola.nothing_to_check", scan_id=ctx.scan_id, target=_target_route(state))
        coverage.record(get_deps(config).store, ctx.scan_id, "access_control", coverage.NOT_TESTED, "no object route with a sibling list route to compare owners")
        return
    results = await check_bola(ctx.client, ctx.base_url, model, ctx.sessions)
    deps = get_deps(config)
    finding_ids = record_bola_findings(deps.store, ctx.scan_id, _scan_mode(deps, ctx.scan_id), results)
    coverage.record(deps.store, ctx.scan_id, "access_control", coverage.FAILED if finding_ids else coverage.PASS,
                    f"compared {len(results)} object(s) across identities")
    log.info(
        "check_bola.done",
        scan_id=ctx.scan_id,
        checked=len(results),
        vulnerable=sum(1 for r in results if r["vulnerable"]),
        findings=finding_ids,
    )


def _target_route(state: dict) -> str | None:
    """The route a dispatch narrowed this run to (``"GET /api/x/{param}"``), if any."""
    return (state.get("target") or {}).get("route")


def _same_route(template: str, target: str) -> bool:
    """Compare ``"GET /api/accounts/{id}"`` with ``"GET /api/accounts/{param}"`` by normalized path."""
    t_method, _, t_path = template.partition(" ")
    g_method, _, g_path = target.partition(" ")
    return t_method.upper() == g_method.upper() and normalize_path(t_path) == normalize_path(g_path)


def _scan_mode(deps, scan_id: str) -> str | None:
    scan = deps.store.get_scan(scan_id)
    return scan.mode.value if scan is not None and hasattr(scan.mode, "value") else None


def _controller(state: dict, config: RunnableConfig) -> SafetyController:
    """The scan's SafetyController for external tools (built once per stage)."""
    deps = get_deps(config)
    ctx = _context(state, config)
    scratch = deps.scratch_for(ctx.scan_id, "runtime")
    if "controller" not in scratch:
        scan = deps.store.get_scan(ctx.scan_id)
        scan_cfg = json.loads(scan.config_json or "{}")
        scratch["controller"] = SafetyController(
            Allowlist(scan_cfg.get("allowlist") or deps.default_allowlist),
            TestInputLibrary.load(),
            RateLimiter(deps.rate_limit_rps, deps.rate_limit_burst),
            executor=deps.tool_executor or execute_tool,
            audit_sink=deps.store.add_tool_call_log,
        )
    return scratch["controller"]


def _unavailable(result: ToolResult, step: str, scan_id: str) -> bool:
    """True when an optional tool simply isn't installed (skip, don't fail the scan)."""
    if result.blocked_reason and result.blocked_reason.startswith("tool not installed"):
        log.warning(f"{step}.skipped", scan_id=scan_id, reason=result.blocked_reason)
        return True
    return False


def _failed(result: ToolResult, tool: str) -> None:
    if not result.ok:
        reason = result.blocked_reason or result.stderr_tail or "no output"
        raise RuntimeError(f"{tool} failed: {str(reason)[:200]}")


@register_step("runtime", "check_ssrf")
async def check_ssrf_step(state: dict, config: RunnableConfig) -> None:
    ctx = _context(state, config)
    candidates = find_ssrf_candidates(ctx.routes)
    if _target_route(state):
        candidates = [(r, p) for r, p in candidates if _same_route(r.template, _target_route(state))]
    if not candidates or "A" not in ctx.sessions:
        log.info("check_ssrf.nothing_to_check", scan_id=ctx.scan_id)
        coverage.record(get_deps(config).store, ctx.scan_id, "ssrf", coverage.NOT_TESTED, "no URL-taking endpoint to probe")
        return
    deps = get_deps(config)
    results = await check_ssrf(
        ctx.client,
        ctx.base_url,
        candidates,
        ctx.sessions["A"],
        TestInputLibrary.load(callback_url=deps.callback_url),
        ctx.scan_id,
        wait_s=deps.oob_wait_s,
    )
    finding_ids = record_ssrf_findings(deps.store, ctx.scan_id, _scan_mode(deps, ctx.scan_id), results)
    coverage.record(deps.store, ctx.scan_id, "ssrf", coverage.FAILED if finding_ids else coverage.PASS, f"probed {len(results)} parameter(s)")
    log.info("check_ssrf.done", scan_id=ctx.scan_id, probed=len(results), findings=finding_ids)


@register_step("runtime", "check_misconfig")
async def check_misconfig_step(state: dict, config: RunnableConfig) -> None:
    ctx = _context(state, config)
    deps = get_deps(config)
    templates = Path(deps.offline_db_dir) / "nuclei-templates"
    if not templates.is_dir():
        log.warning("check_misconfig.templates_not_staged", scan_id=ctx.scan_id, path=str(templates))
        coverage.record(deps.store, ctx.scan_id, "misconfig", coverage.NOT_TESTED, "nuclei templates are not staged")
        return
    result = await run_nuclei(_controller(state, config), ctx.scan_id, ctx.base_url, str(templates), rate_limit=deps.rate_limit_rps)
    if _unavailable(result, "check_misconfig", ctx.scan_id):
        coverage.record(deps.store, ctx.scan_id, "misconfig", coverage.NOT_TESTED, "nuclei is not installed")
        return
    _failed(result, "nuclei")
    drafts = NucleiAdapter(mode=_scan_mode(deps, ctx.scan_id)).parse(result.output, ctx.scan_id)
    finding_ids = ingest(deps.store, ctx.scan_id, drafts)
    coverage.record(deps.store, ctx.scan_id, "misconfig", coverage.FAILED if finding_ids else coverage.PASS, "nuclei templates run")
    log.info("check_misconfig.done", scan_id=ctx.scan_id, findings=finding_ids)


@register_step("runtime", "check_api")
async def check_api_step(state: dict, config: RunnableConfig) -> None:
    ctx = _context(state, config)
    if not ctx.spec_path:
        log.info("check_api.no_openapi", scan_id=ctx.scan_id)
        coverage.record(get_deps(config).store, ctx.scan_id, "api_conformance", coverage.NOT_TESTED, "no OpenAPI document to test against")
        return
    deps = get_deps(config)
    result = await run_schemathesis(
        _controller(state, config),
        ctx.scan_id,
        ctx.base_url,
        ctx.base_url.rstrip("/") + ctx.spec_path,
        session=ctx.sessions.get("A"),
        tls_verify=verify_tls(json.loads(deps.store.get_scan(ctx.scan_id).config_json or "{}")),
    )
    if _unavailable(result, "check_api", ctx.scan_id):
        coverage.record(deps.store, ctx.scan_id, "api_conformance", coverage.NOT_TESTED, "schemathesis is not installed")
        return
    _failed(result, "schemathesis")
    drafts = SchemathesisAdapter(
        mode=_scan_mode(deps, ctx.scan_id), authenticated="A" in ctx.sessions
    ).parse(result.output, ctx.scan_id)
    finding_ids = ingest(deps.store, ctx.scan_id, drafts)
    coverage.record(deps.store, ctx.scan_id, "api_conformance", coverage.FAILED if finding_ids else coverage.PASS, "schemathesis run against the spec")
    log.info("check_api.done", scan_id=ctx.scan_id, findings=finding_ids)


runtime_subgraph = make_stage_node("runtime")
