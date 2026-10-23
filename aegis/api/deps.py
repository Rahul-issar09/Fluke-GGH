"""Dependency providers for the routers (AG13.1, FASTAPI FA00.1).

Everything long-lived is built once in the lifespan and kept on ``app.state``; routes get it
through these providers (``Depends(get_store)`` …), so tests can swap any of them with
``app.dependency_overrides``.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request

from aegis.agent.deps import AgentDeps
from aegis.config import AppSettings
from aegis.evidence.store import EvidenceStore
from aegis.services.event_bus import EventBus
from aegis.services.fix_service import FixService
from aegis.services.job_runner import JobRunner
from aegis.services.query_service import QueryService
from aegis.services.scan_service import ScanService

__all__ = [
    "get_agent_deps",
    "get_event_bus",
    "get_fix_service",
    "get_graph",
    "get_job_runner",
    "get_llm_manager",
    "get_query_service",
    "get_scan_service",
    "get_settings",
    "get_store",
]


def get_settings(request: Request) -> AppSettings:
    return request.app.state.settings


def get_store(request: Request) -> EvidenceStore:
    return request.app.state.store


def get_agent_deps(request: Request) -> AgentDeps:
    return request.app.state.agent_deps


def get_graph(request: Request) -> Any:
    return request.app.state.graph


def get_job_runner(request: Request) -> JobRunner:
    return request.app.state.runner


def get_event_bus(request: Request) -> EventBus:
    return request.app.state.bus


def get_fix_service(request: Request) -> FixService:
    return request.app.state.fix_service


def get_scan_service(request: Request) -> ScanService:
    return request.app.state.scan_service


def get_query_service(request: Request) -> QueryService:
    return request.app.state.query_service


def get_chat_service(request: Request):
    return request.app.state.chat_service


def get_llm_manager(request: Request):
    """The provider manager, or ``None`` for an app state built without one (older tests)."""
    return getattr(request.app.state, "llm_manager", None)
