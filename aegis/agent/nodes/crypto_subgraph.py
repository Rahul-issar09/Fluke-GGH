"""crypto worker stage (Worker 3 / Engine 3, AG15.1): a subgraph of registered steps.

Steps (``worker_stage.STAGE_STEPS["crypto"]``): discover → classical_rules → quantum_rules →
tls_scan → build_cbom.

* **discover** — the crypto rules (semgrep) + ``ast`` read every crypto asset; each is stored once
  as an inventory ``crypto_asset`` evidence record (not tied to a finding).
* **classical_rules** — weak by today's standards → ``weak_crypto`` findings.
* **quantum_rules** — public-key crypto broken by Shor's algorithm → ``quantum_risk`` findings.
* **tls_scan** — sslyze on the scan's TLS endpoints (an ``https`` target URL, plus
  ``options.tls_targets``; each must be on the scan's allowlist) → ``weak_tls`` findings, linked
  to the TLS setting in the code that causes them. A scan without source code (runtime only)
  runs the same check in the runtime stage instead (TNW-2, :func:`scan_tls`).
* **build_cbom** — the CycloneDX 1.6 CBOM, written to ``<data_dir>/cbom/<scan_id>.json``.

No LLM is involved. An investigation follow-up (``request_crypto_scan``) narrows discovery to one
file.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from langchain_core.runnables import RunnableConfig

from aegis.agent.deps import get_deps
from aegis.agent.nodes.code_subgraph import _controller as code_controller
from aegis.agent.nodes.code_subgraph import _mode, _not_installed, _source, _target_file
from aegis.agent.nodes.worker_stage import make_stage_node, register_step
from aegis.evidence.adapters.cbom import CryptoAdapter, TlsAdapter
from aegis.evidence.normalizer import ingest
from aegis.observability import get_logger
from aegis.workers.code.semgrep import SemgrepUnavailable
from aegis.workers.crypto.cbom import build_cbom, write_cbom
from aegis.workers.crypto.discover import run_discovery
from aegis.workers.crypto.rules_classical import classical_risk
from aegis.workers.crypto.rules_quantum import quantum_risk
from aegis.workers.crypto.tls import TlsUnavailable, link_issue, run_sslyze, tls_issues

log = get_logger("agent.node.crypto")

_ASSET_KEY = ("file", "line", "algo", "setting")


def _inventory(store, scan_id: str, only_file: str | None = None) -> list[dict]:
    """The discovered assets (inventory records, not the copies attached to findings)."""
    out = []
    for ev in store.list_evidence(scan_id, kind="crypto_asset"):
        payload = json.loads(ev.payload_json or "{}")
        if ev.finding_id is None and payload.get("role") == "inventory" and (only_file is None or payload.get("file") == only_file):
            out.append({k: v for k, v in payload.items() if k != "role"})
    return out


@register_step("crypto", "discover")
async def discover_step(state: dict, config: RunnableConfig) -> None:
    deps, scan_id, source = get_deps(config), state["scan_id"], _source(state, config)
    only = _target_file(state, source)
    try:
        assets = await run_discovery(code_controller(state, config), scan_id, source, only_file=only)
    except SemgrepUnavailable as exc:
        if _not_installed(exc):
            log.warning("crypto.discover_skipped", scan_id=scan_id, reason=str(exc))
            return
        raise RuntimeError(str(exc)) from exc
    known = {tuple(a.get(k) for k in _ASSET_KEY) for a in _inventory(deps.store, scan_id)}
    added = 0
    for asset in assets:
        if tuple(asset.get(k) for k in _ASSET_KEY) in known:  # a follow-up re-run adds nothing twice
            continue
        deps.store.add_evidence(scan_id, "crypto_asset", "crypto-discovery", {**asset, "role": "inventory"})
        added += 1
    log.info("crypto.assets", scan_id=scan_id, found=len(assets), added=added,
             assets=[f"{a['algo']}@{a['file']}:{a['line']}" for a in assets])


def _flag(state: dict, config: RunnableConfig, kind: str, rule) -> None:
    deps, scan_id = get_deps(config), state["scan_id"]
    only = _target_file(state, _source(state, config))
    flagged = [(a, reason) for a in _inventory(deps.store, scan_id, only) if (reason := rule(a))]
    finding_ids = ingest(deps.store, scan_id, CryptoAdapter(kind, mode=_mode(config, scan_id)).parse(flagged, scan_id))
    log.info(f"crypto.{kind}", scan_id=scan_id, flagged=[f"{a['algo']}@{a['file']}:{a['line']}" for a, _ in flagged], findings=finding_ids)


@register_step("crypto", "classical_rules")
async def classical_rules_step(state: dict, config: RunnableConfig) -> None:
    _flag(state, config, "weak_crypto", classical_risk)


@register_step("crypto", "quantum_rules")
async def quantum_rules_step(state: dict, config: RunnableConfig) -> None:
    _flag(state, config, "quantum_risk", quantum_risk)


def tls_targets(scan) -> list[str]:
    """``host:port`` of each TLS endpoint: an https target URL, plus ``options.tls_targets``."""
    cfg = json.loads(scan.config_json or "{}")
    targets: list[str] = []
    if scan.target_url and urlparse(scan.target_url).scheme == "https":
        parsed = urlparse(scan.target_url)
        targets.append(f"{parsed.hostname}:{parsed.port or 443}")
    for t in (cfg.get("options") or {}).get("tls_targets") or []:
        if isinstance(t, str) and t not in targets:
            targets.append(t)
    return targets


async def scan_tls(deps, scan_id: str, controller, mode: str | None) -> list[str]:
    """sslyze on each of the scan's TLS endpoints → ``weak_tls`` findings (their ids).

    Each issue is linked to the TLS setting in the code that causes it when the crypto discovery
    found one (none in a runtime-only scan: the finding then rests on the live check alone).
    Raises ``RuntimeError`` naming every endpoint that could not be checked."""
    scan = deps.store.get_scan(scan_id)
    targets = tls_targets(scan)
    if not targets:
        log.info("tls_scan.nothing_to_scan", scan_id=scan_id)
        return []
    assets = _inventory(deps.store, scan_id)
    linked_rows, errors = [], []
    for target in targets:
        try:
            endpoints = await run_sslyze(controller, scan_id, target)
        except TlsUnavailable as exc:
            if _not_installed(exc):
                log.warning("tls_scan.skipped", scan_id=scan_id, reason=str(exc))
                return []
            errors.append(f"{target}: {exc}")  # e.g. not on the allowlist, or no TLS there
            continue
        for endpoint in endpoints:
            deps.store.add_evidence(scan_id, "tls_scan", "sslyze", {**endpoint, "role": "inventory"})
            for issue in tls_issues(endpoint):
                linked_rows.append((endpoint, issue, link_issue(issue, assets)))
    finding_ids = ingest(deps.store, scan_id, TlsAdapter(mode=mode).parse(linked_rows, scan_id))
    log.info("tls_scan.done", scan_id=scan_id, targets=targets, findings=finding_ids,
             linked=[f"{i['issue']} -> {l['file']}:{l['line']}" for _, i, l in linked_rows if l])
    if errors:
        raise RuntimeError("; ".join(errors))
    return finding_ids


@register_step("crypto", "tls_scan")
async def tls_scan_step(state: dict, config: RunnableConfig) -> None:
    deps, scan_id = get_deps(config), state["scan_id"]
    await scan_tls(deps, scan_id, code_controller(state, config), _mode(config, scan_id))


def write_scan_cbom(deps, scan_id: str):
    """Write the scan's CBOM from its crypto assets and checked TLS endpoints; return its path."""
    scan = deps.store.get_scan(scan_id)
    assets = _inventory(deps.store, scan_id)
    endpoints = []
    for ev in deps.store.list_evidence(scan_id, kind="tls_scan"):
        payload = json.loads(ev.payload_json or "{}")
        if ev.finding_id is None and payload.get("role") == "inventory":
            endpoint = {k: v for k, v in payload.items() if k != "role"}
            endpoints.append((endpoint, tls_issues(endpoint)))
    subject = Path(scan.source_path).name if scan and scan.source_path else (scan.target_url if scan else scan_id)
    path = write_cbom(deps.data_dir, scan_id, build_cbom(scan_id, subject, assets, endpoints))
    flags = sum(1 for a in assets if classical_risk(a)), sum(1 for a in assets if quantum_risk(a))
    log.info("cbom.written", scan_id=scan_id, path=str(path), components=len(assets) + len(endpoints), classical_flags=flags[0], quantum_flags=flags[1])
    return path


@register_step("crypto", "build_cbom")
async def build_cbom_step(state: dict, config: RunnableConfig) -> None:
    write_scan_cbom(get_deps(config), state["scan_id"])


crypto_subgraph = make_stage_node("crypto")
