"""Evidence digests (PHASES P5.6).

A digest is a short, safe one-line summary built ONLY from structured payload
fields — never by copying HTTP bodies, code, comments or secret values. These
are the only evidence strings the LLM is ever shown, so target-controlled text
(including injection attempts) can never ride into a prompt (FR-S6).
"""

from __future__ import annotations

import json

from aegis.evidence.models import Evidence

__all__ = ["digest"]


def _payload(ev: Evidence) -> dict:
    try:
        data = json.loads(ev.payload_json or "{}")
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def digest(ev: Evidence) -> str:
    """Return a one-line, injection-safe digest of *ev*."""
    p = _payload(ev)
    eid = ev.id or "E-????"

    if ev.kind == "http_exchange":
        method = str(p.get("method", "")).upper()
        route = p.get("route") or p.get("path") or ""
        status = p.get("status")
        identity = p.get("identity")
        owner = "contains owner fields" if p.get("contains_owner_fields") else ""
        bits = [b for b in [f"identity {identity}" if identity else "", f"{method} {route}".strip(), f"→ {status}" if status is not None else "", owner] if b]
        return f"{eid}: " + ", ".join(bits)

    if ev.kind in ("code_location", "dataflow_path"):
        fn = p.get("function") or ""
        file = p.get("file") or ""
        line = p.get("line")
        note = p.get("note") or p.get("rule") or ""
        where = f"{fn} ({file}:{line})".strip()
        return f"{eid}: {where}" + (f" — {note}" if note else "")

    if ev.kind == "dependency":
        return f"{eid}: {p.get('package', '')}@{p.get('version', '')} {p.get('advisory', '')}".rstrip()

    if ev.kind == "secret":
        return f"{eid}: secret '{p.get('rule', 'secret')}' at {p.get('file', '')}:{p.get('line', '')} (value redacted)"

    if ev.kind == "crypto_asset":
        return f"{eid}: {p.get('algo', '')} at {p.get('file', '')}:{p.get('line', '')} ({p.get('usage', '')})".rstrip()

    if ev.kind == "tls_scan":
        return f"{eid}: TLS {p.get('protocol', '')} {p.get('grade', '')}".rstrip()

    if ev.kind == "oob_hit":
        return f"{eid}: out-of-band callback hit for {p.get('param', '')}"

    if ev.kind == "retest":
        return f"{eid}: retest {'passed' if p.get('passed') else 'failed'}"

    if ev.kind == "tool_error":
        return f"{eid}: tool '{ev.tool}' error"

    return f"{eid}: {ev.kind}"
