"""Out-of-band SSRF adapter (PHASES P6.7).

An out-of-band callback hit is reproducible runtime proof, so the finding is
created as a candidate with one ``oob_hit`` evidence and then confirmed by the
state machine. The evidence names the approved test input *by ID* — the probe
value itself is never copied in — and carries no credentials.
"""

from __future__ import annotations

from aegis.evidence.adapters.base import Adapter, EvidenceDraft, FindingDraft

__all__ = ["SsrfAdapter"]

_TOOL_VERSION = "0.1.0"


class SsrfAdapter(Adapter):
    tool = "ssrf"

    def __init__(self, mode: str | None = None):
        self._mode = mode

    def parse(self, raw, scan_id):
        results = raw if isinstance(raw, list) else [raw]
        out: list[tuple[FindingDraft, list[EvidenceDraft]]] = []
        for result in results:
            if not result or not result.get("vulnerable"):
                continue
            template = result["route"]
            param = result["param"]
            draft = FindingDraft(
                type="ssrf",
                owasp="A10",
                title=f"Server-side request forgery via '{param}' on {template}",
                route=template,
                severity=0.8,
                source="worker1.ssrf",
                mode=self._mode,
                variant=param,
            )
            evidence = EvidenceDraft(
                kind="oob_hit",
                tool="ssrf",
                tool_version=_TOOL_VERSION,
                payload={
                    "method": template.split(" ", 1)[0],
                    "route": result.get("path", template),
                    "route_template": template,
                    "param": param,
                    "auth_context": "authenticated",  # the probe ran as a logged-in identity
                    "test_input_id": result["test_input_id"],
                    "probe_status": result.get("probe_status"),
                    "hits": result.get("hits", 1),
                    "request": (
                        f"{template.split(' ', 1)[0]} {result.get('path', '')}"
                        f"?{param}=<approved test input {result['test_input_id']}>"
                    ),
                },
            )
            out.append((draft, [evidence]))
        return out
