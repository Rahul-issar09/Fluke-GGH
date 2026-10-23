"""One runtime builder for every AEGIS front end (CLI_PHASES.md CLI02).

The REST API and the ``aegis`` CLI build AEGIS the same way, through :func:`open_runtime`:

    ensure_dirs (and prove the data folder is writable) → SQLite store → report interrupted scans
    → model check (logged, never blocking) → checkpointer (data/checkpoints.db)
    → AgentDeps (+ chat indexer, repo cloning) → main graph + fix graph
    → JobRunner(max_concurrent_scans) + EventBus → Fix / Scan / Query / Chat services

and shuts it down in reverse (cancel running scans, stop fix verifications, close the checkpointer
and the database). It does not configure logging — the caller decides where logs go (the API logs
to its console; the CLI to stderr, so stdout stays clean for output).

(The read-only MCP server uses the lighter :mod:`aegis.services.read_services` instead.)
"""

from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator

from sqlmodel import select

from aegis.agent.deps import AgentDeps
from aegis.agent.fix_graph import build_fix_graph
from aegis.agent.graph import build_aegis_graph
from aegis.chat.indexer import make_chat_indexer
from aegis.config import AppSettings, ChatSettings, resolve_chat_settings
from aegis.evidence.db import init_db, make_engine
from aegis.evidence.models import Scan, ScanStatus
from aegis.evidence.store import EvidenceStore
from aegis.llm.manager import ProviderManager
from aegis.observability import get_logger
from aegis.services.chat_service import ChatService
from aegis.services.event_bus import EventBus
from aegis.services.fix_service import FixService
from aegis.services.job_runner import JobRunner, open_checkpointer
from aegis.services.query_service import QueryService
from aegis.services.scan_service import ScanService
from aegis.workers.code.clone import make_clone_fn, prune_clones

__all__ = ["DATA_SUBDIRS", "Runtime", "StartupError", "check_model", "ensure_dirs", "open_runtime"]

# same logger name the API startup always used, so existing log consumers see the same events
log = get_logger("api")

DATA_SUBDIRS = ("reports", "workspaces", "patches", "graphs", "clones")


class StartupError(RuntimeError):
    """AEGIS cannot start safely (e.g. its data folder is not writable)."""


@dataclass
class Runtime:
    """Everything long-lived that a front end needs, built once."""

    settings: AppSettings
    data_dir: Path
    store: EvidenceStore
    checkpointer: Any
    graph: Any
    fix_graph: Any
    agent_deps: AgentDeps
    bus: EventBus
    runner: JobRunner
    fix_service: FixService
    scan_service: ScanService
    query_service: QueryService
    chat_service: ChatService
    chat_settings: ChatSettings
    llm_manager: ProviderManager


def ensure_dirs(data_dir: str | Path) -> Path:
    """Create the data folders and prove they can be written — or fail with a clear reason."""
    root = Path(data_dir)
    try:
        for sub in ("", *DATA_SUBDIRS):
            (root / sub).mkdir(parents=True, exist_ok=True)
        probe = root / ".write-test"
        probe.write_bytes(b"ok")
        probe.unlink()
    except OSError as exc:
        raise StartupError(f"the data folder {root.resolve()} is not writable ({type(exc).__name__}: {exc.strerror or exc})") from exc
    return root


def _report_interrupted_scans(store: EvidenceStore) -> None:
    with store.session() as s:
        stuck = [scan.id for scan in s.exec(select(Scan)) if scan.status == ScanStatus.running]
    if stuck:  # their checkpoints are kept; the scans can be resumed
        log.warning("startup.interrupted_scans", scans=stuck)


async def check_model(settings: AppSettings) -> dict:
    """Log whether the configured model can be used. Never stops startup: without the model, scans
    still run on rules and templates."""
    from aegis.api.routers.health import probe_ollama

    probe = await probe_ollama(settings.model.ollama_url, settings.model.name)
    if probe["model_present"]:
        log.info("startup.model_ok", url=probe["url"], model=probe["model"])
    elif probe["reachable"]:
        log.warning(
            "startup.model_missing",
            url=probe["url"],
            model=probe["model"],
            available=probe.get("models", []),
            hint="set AEGIS_MODEL to one of the available models, or point AEGIS_OLLAMA_URL at an Ollama that has it "
            "(on Windows use http://127.0.0.1:11434: 'localhost' can reach a different Ollama, e.g. one in Docker, over IPv6)",
        )
    else:
        log.warning(
            "startup.ollama_unreachable",
            url=probe["url"],
            error=probe.get("error"),
            hint="start Ollama or set AEGIS_OLLAMA_URL (locally: http://127.0.0.1:11434); scans fall back to templates",
        )
    return probe


def chat_settings_for(settings: AppSettings, data: Path) -> ChatSettings:
    """The chat settings with a relative chat-index path placed under the data folder and the
    embedding URL filled in (LP4: embeddings are configured apart from the LLM)."""
    return resolve_chat_settings(settings, str(data))


@asynccontextmanager
async def open_runtime(settings: AppSettings, *, agent_overrides: dict[str, Any] | None = None) -> AsyncIterator[Runtime]:
    """Build AEGIS from *settings*; ``agent_overrides`` replace ``AgentDeps`` fields (tests inject fakes)."""
    agent_overrides = dict(agent_overrides or {})
    data = ensure_dirs(settings.data_dir)
    engine = make_engine(f"sqlite:///{(data / 'aegis.db').resolve().as_posix()}")
    init_db(engine)
    store = EvidenceStore(engine)
    _report_interrupted_scans(store)
    await check_model(settings)
    # which model answers: environment → data/config/llm.json → offline default (never creates files)
    llm_manager = agent_overrides.get("llm_manager") or ProviderManager(settings, data)

    try:
        async with AsyncExitStack() as stack:
            saver = await stack.enter_async_context(open_checkpointer(data / "checkpoints.db"))
            options: dict[str, Any] = {
                "data_dir": str(data),
                "offline_db_dir": settings.offline_db_dir,
                "default_allowlist": tuple(settings.allowlist),
                "llm_settings": settings.model,
                "llm_manager": llm_manager,
                "patched_target_url": settings.patched_target_url,
                "callback_url": settings.callback_url,
                "tmp_root": str(data / "clones"),
                "rate_limit_rps": settings.rate_limit_rps,
                "clone_keep_hours": settings.clone_keep_hours,
            }
            chat_cfg = chat_settings_for(settings, data)
            if chat_cfg.enabled:  # RAG: index findings at finalize, answer questions
                options["chat_indexer"] = make_chat_indexer(store, chat_cfg, guard=True)
            if settings.git_hosts:  # repo scans (TNW-1): clones only from these hosts
                options["clone_fn"] = make_clone_fn(
                    settings.git_hosts,
                    executor=agent_overrides.get("tool_executor"),
                    audit_sink=store.add_tool_call_log,
                    max_bytes=settings.clone_max_mb * 1024 * 1024,
                )
            options.update(agent_overrides)
            agent_deps = AgentDeps(store=store, **options)
            prune_clones(data / "clones", store, keep_hours=settings.clone_keep_hours)
            bus = EventBus()
            runner = JobRunner(store, bus, agent_deps, max_concurrent_scans=settings.max_concurrent_scans)
            fix_graph = build_fix_graph(saver)
            graph = build_aegis_graph(saver)
            fix_service = FixService(agent_deps, fix_graph)

            runtime = Runtime(
                settings=settings,
                data_dir=data,
                store=store,
                checkpointer=saver,
                graph=graph,
                fix_graph=fix_graph,
                agent_deps=agent_deps,
                bus=bus,
                runner=runner,
                fix_service=fix_service,
                scan_service=ScanService(store, runner, graph, settings),
                query_service=QueryService(store, data),
                chat_service=ChatService(store, chat_cfg, ollama_url=settings.model.ollama_url, model_settings=settings.model,
                                         llm_manager=llm_manager),
                chat_settings=chat_cfg,
                llm_manager=llm_manager,
            )
            log.info(
                "startup.ready",
                data_dir=str(data.resolve()),
                model=settings.model.name,
                llm=llm_manager.snapshot.to_dict(),
                allowlist=list(settings.allowlist),
                git_hosts=list(settings.git_hosts),
                auth=settings.api.auth_token is not None,
                max_concurrent_scans=settings.max_concurrent_scans,
            )
            try:
                yield runtime
            finally:
                await runner.shutdown()
                await fix_service.shutdown()
                log.info("shutdown.done")
    finally:
        engine.dispose()
