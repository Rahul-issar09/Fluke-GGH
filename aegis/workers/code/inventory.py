"""Component inventory (Worker 2, AG14.1, PHASES P7.1) — what the source is built from.

Runs ``syft dir:<source> -o cyclonedx-json`` through the SafetyController and keeps a compact
component list (name, version, purl, type) as ``dependency`` evidence for the scan; later
phases add the components as ``library`` nodes in the security graph. Syft is optional: when it
is not installed the step is skipped and the scan goes on.
"""

from __future__ import annotations

from pathlib import Path

from aegis.observability import get_logger
from aegis.safety.models import ToolCall

__all__ = ["InventoryUnavailable", "components", "run_inventory"]

log = get_logger("workers.code.inventory")

MAX_COMPONENTS = 2000


class InventoryUnavailable(RuntimeError):
    pass


def components(sbom: dict) -> list[dict]:
    out = []
    for c in (sbom or {}).get("components") or []:
        if isinstance(c, dict) and c.get("name") and c.get("type") != "file":  # syft also lists the manifests it read
            out.append({k: c.get(k) for k in ("name", "version", "purl", "type") if c.get(k) is not None})
    return sorted(out, key=lambda c: (c["name"].lower(), c.get("version") or ""))[:MAX_COMPONENTS]


async def run_inventory(controller, scan_id: str, source_root: str | Path) -> list[dict]:
    result = await controller.run(ToolCall(tool="syft", scan_id=scan_id, args={"path": str(Path(source_root))}))
    if result.blocked_reason:
        raise InventoryUnavailable(result.blocked_reason)
    if not result.ok or not isinstance(result.output, dict):
        raise InventoryUnavailable(f"syft failed: {(result.stderr_tail or '').strip()[:200]}")
    found = components(result.output)
    log.info("inventory.done", scan_id=scan_id, components=len(found))
    return found
