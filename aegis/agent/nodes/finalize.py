"""finalize node (AG12.1) — the end of every scan.

* Writes the JSON and HTML reports (``<data_dir>/reports/<scan_id>/``) and logs their paths.
* Does **not** set the scan's status: the job runner is its single owner (AG06) and marks the
  scan ``completed`` — with its finish time and the terminal SSE event — once the graph ends.
  This node's own update is streamed as the ``finalize`` stage's ``done`` event.
* Starts the chat index build without waiting for it, when one is configured.

A report that cannot be written is recorded as an error, never a failed scan: the findings
and evidence are already safe in the store and the API can still serve them.
"""

from __future__ import annotations

import asyncio
import inspect

from langchain_core.runnables import RunnableConfig

from aegis.agent.deps import AgentDeps, get_deps
from aegis.observability import get_logger
from aegis.services.report_service import write_reports

log = get_logger("agent.node.finalize")


def _start_chat_index(deps: AgentDeps, scan_id: str) -> None:
    if deps.chat_indexer is None:
        log.info("chat.index_skipped", scan_id=scan_id, reason="no chat indexer configured")
        return

    async def build() -> None:
        try:
            result = deps.chat_indexer(scan_id)
            if inspect.isawaitable(result):
                await result
            log.info("chat.index_built", scan_id=scan_id)
        except Exception as exc:  # noqa: BLE001 - chat is optional; it never affects the scan
            log.warning("chat.index_failed", scan_id=scan_id, error=f"{type(exc).__name__}: {str(exc)[:200]}")

    task = asyncio.get_running_loop().create_task(build(), name=f"chat-index-{scan_id}")
    deps.background_tasks.add(task)
    task.add_done_callback(deps.background_tasks.discard)
    log.info("chat.index_started", scan_id=scan_id)


async def finalize(state: dict, config: RunnableConfig) -> dict:
    deps = get_deps(config)
    scan_id = state["scan_id"]
    log.info("node.enter", node="finalize", scan_id=scan_id)

    errors: list[str] = []
    try:
        paths = write_reports(deps.store, scan_id, deps.data_dir)
        log.info("finalize.reports", scan_id=scan_id, json=str(paths["json"]), html=str(paths["html"]))
    except Exception as exc:  # noqa: BLE001 - see module docstring
        reason = f"report not written: {type(exc).__name__}: {str(exc)[:200]}"
        log.error("finalize.report_failed", scan_id=scan_id, reason=reason)
        errors.append(f"finalize: {reason}")

    _start_chat_index(deps, scan_id)
    log.info("node.exit", node="finalize", scan_id=scan_id, errors=len(errors))
    return {"completed_stages": ["finalize"], "errors": errors}
