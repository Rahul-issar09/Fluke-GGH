"""prepare node (AG05.2).

* loads the source (folder in place, or shallow clone via the injected
  ``clone_fn`` — the only networked moment of a scan; TNW-1), and records the cloned commit,
* registers the scan's allowlist (configured hosts + the target URL's host + the callback listener),
* snapshots the offline DB dates (printed on every report),
* persists all of it on the ``Scan`` row — ``AegisState`` is a frozen contract
  that holds IDs only, so later nodes read these from the store.

On failure a partially created temp clone is removed (see
``router.prepare_source``) and the error propagates so the job runner marks the
scan failed with a logged reason.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from langchain_core.runnables import RunnableConfig

from aegis.agent.deps import get_deps
from aegis.agent.nodes.route_mode import _inputs
from aegis.observability import get_logger
from aegis.router import prepare_source
from aegis.workers.code.clone import prune_clones

log = get_logger("agent.node.prepare")

# Convention for the staged offline assets (STRUCTURE §4.3): one entry per feed,
# the date is the entry's last-modified day.
_DB_PATHS = {"osv": "osv", "trivy": "trivy", "nuclei": "nuclei-templates"}


def snapshot_db_dates(offline_db_dir: str) -> dict[str, str | None]:
    base = Path(offline_db_dir)
    dates: dict[str, str | None] = {}
    for name, rel in _DB_PATHS.items():
        p = base / rel
        if p.exists():
            dates[name] = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).date().isoformat()
        else:
            dates[name] = None
    return dates


def _target_allowlist_entry(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.hostname:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.hostname}:{port}"


async def prepare(state: dict, config: RunnableConfig) -> dict:
    scan_id = state["scan_id"]
    log.info("node.enter", node="prepare", scan_id=scan_id)
    deps = get_deps(config)
    inputs = _inputs(state)

    update: dict = {}
    cleanup = False
    repo_info: dict | None = None
    if inputs.repo and deps.tmp_root:
        prune_clones(deps.tmp_root, deps.store, keep_hours=deps.clone_keep_hours)
    if inputs.folder or inputs.repo:
        prep = await prepare_source(
            folder=inputs.folder,
            repo=inputs.repo,
            scan_id=scan_id,
            clone_fn=deps.clone_fn,
            tmp_root=deps.tmp_root,
        )
        update["source_path"] = prep["source_path"]
        cleanup = prep["cleanup"]
        repo_info = prep.get("repo")

    allowlist = list(deps.default_allowlist)
    # the target, and AEGIS's own out-of-band listener (set by the operator, never by the agent)
    for entry in (_target_allowlist_entry(inputs.url), _target_allowlist_entry(deps.callback_url)):
        if entry and entry not in allowlist:
            allowlist.append(entry)

    db_dates = snapshot_db_dates(deps.offline_db_dir)

    scan = deps.store.get_scan(scan_id)
    config_json = json.loads(scan.config_json) if scan and scan.config_json else {}
    config_json["allowlist"] = allowlist
    config_json["source_cleanup"] = cleanup  # temp clones are removed after the scan/fixes (C13)
    if repo_info is not None:
        config_json["repo_clone"] = repo_info  # url, commit, branch, size — shown in the report
    deps.store.update_scan(
        scan_id,
        db_snapshot_dates=json.dumps(db_dates),
        config_json=json.dumps(config_json),
        **update,
    )

    log.info(
        "node.exit",
        node="prepare",
        scan_id=scan_id,
        source_path=update.get("source_path"),
        cleanup=cleanup,
        allowlist=allowlist,
        db_dates=db_dates,
    )
    return {"completed_stages": ["prepare"]}
