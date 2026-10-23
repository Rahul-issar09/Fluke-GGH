"""Runtime step 5 — differential access-control check (PHASES P6.5, flagship).

For every object the owner identity (A) legitimately has, replay the *same*
request as the attacker identity (B). If B receives a successful response that
contains A's identifying fields, the two responses are the proof and the route
is vulnerable.

* The check chooses nothing itself: routes and object IDs come from the request
  model; no payloads are involved (the replay is the owner's own, valid request).
* A baseline that does not succeed is skipped — there is nothing to compare.
* Findings are written only via the adapter + normalizer, and confirmed through
  the state machine because the replay is reproducible runtime proof.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import httpx

from aegis.evidence.adapters.bola import BolaAdapter
from aegis.evidence.normalizer import confirm_with_proof, ingest
from aegis.evidence.store import EvidenceStore
from aegis.observability import get_logger
from aegis.workers.runtime.context import ObjectRoute, Session, request_as

log = get_logger("workers.runtime.bola")

# Person-identifying fields; deliberately excludes generic ones (name, type, id)
# that two different objects could legitimately share.
OWNER_KEYS = ("owner", "owner_id", "user_id", "username", "email", "account_number", "phone", "ssn")
_EXCERPT_CHARS = 2000


def _scalar_leaves(obj: Any, out: dict[str, Any] | None = None) -> dict[str, Any]:
    out = {} if out is None else out
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, (dict, list)):
                _scalar_leaves(value, out)
            else:
                out.setdefault(str(key).lower(), value)
    elif isinstance(obj, list):
        for item in obj:
            _scalar_leaves(item, out)
    return out


def owner_fields_present(baseline: Any, replay: Any) -> bool:
    """True if the replay response repeats the baseline's owner-identifying values."""
    base, other = _scalar_leaves(baseline), _scalar_leaves(replay)
    for key in OWNER_KEYS:
        value = base.get(key)
        if value not in (None, "") and other.get(key) == value:
            return True
    return False


def _concrete(path_template: str, param: str, object_id: Any) -> str:
    return path_template.replace("{" + param + "}", quote(str(object_id), safe=""))


async def check_bola(
    client: httpx.AsyncClient,
    base_url: str,
    model: list[ObjectRoute],
    sessions: dict[str, Session],
    owner: str = "A",
    attacker: str = "B",
) -> list[dict]:
    results: list[dict] = []
    for obj in model:
        param = obj.route.params[0]
        for object_id in obj.owner_ids:
            path = _concrete(obj.route.path, param, object_id)
            base = await request_as(client, base_url, sessions[owner], "GET", path)
            if not 200 <= base.status < 300:
                log.info("bola.skip_baseline", route=obj.route.template, status=base.status)
                continue
            replay = await request_as(client, base_url, sessions[attacker], "GET", path)
            leaked = owner_fields_present(base.json, replay.json)
            vulnerable = 200 <= replay.status < 300 and leaked
            results.append(
                {
                    "route": obj.route.template,
                    "path": path,
                    "object_id": object_id,
                    "baseline": {"identity": owner, "status": base.status, "timing_ms": base.timing_ms},
                    "replay": {
                        "identity": attacker,
                        "status": replay.status,
                        "timing_ms": replay.timing_ms,
                        "contains_owner_fields": leaked,
                        "response_excerpt": (
                            json.dumps(replay.json)[:_EXCERPT_CHARS]
                            if replay.json is not None
                            else replay.text[:_EXCERPT_CHARS]
                        ),
                    },
                    "vulnerable": vulnerable,
                }
            )
            log.info(
                "bola.checked",
                route=obj.route.template,
                object_id=object_id,
                baseline=base.status,
                replay=replay.status,
                vulnerable=vulnerable,
            )
    return results


def record_bola_findings(
    store: EvidenceStore, scan_id: str, mode: str | None, results: list[dict]
) -> list[str]:
    """Persist vulnerable results as confirmed findings; return their IDs."""
    drafts = BolaAdapter(mode=mode).parse(results, scan_id)
    finding_ids = ingest(store, scan_id, drafts)
    confirm_with_proof(
        store,
        finding_ids,
        {"http_exchange"},
        actor="worker",
        reason="differential replay: the second identity received the first identity's record",
    )
    return finding_ids
