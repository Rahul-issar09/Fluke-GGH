"""Schemathesis adapter (PHASES P6.8).

Maps Schemathesis' JUnit XML report to ``api_conformance`` **candidate**
findings — one per failing operation. Verified against schemathesis 4.29.x: a
``<testcase name="GET /api/accounts/{id}">`` with a ``<failure>`` child whose
text lists numbered cases, bullet-pointed failure titles, ``Received: <status>``
and a ``Reproduce with:`` curl block.

Only the failure titles and the received status are kept. The ``Reproduce
with`` block and the echoed response body are dropped on purpose: a repro line
can contain request headers (an authenticated run carries a session cookie) and
the body is target-controlled text.

``<error>`` elements are tool/runtime errors, not findings, and are ignored
here (the caller logs them).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from aegis.evidence.adapters.base import Adapter, EvidenceDraft, FindingDraft

__all__ = ["SchemathesisAdapter", "JunitRejected"]

_TOOL_VERSION = "schemathesis-4"
_RECEIVED = re.compile(r"^\s*Received:\s*(\d{3})\b", re.MULTILINE)
_TITLE = re.compile(r"^-\s+(.+?)\s*$", re.MULTILINE)
_MAX_TITLES = 8


class JunitRejected(ValueError):
    """The report is not a plain JUnit document (DTD/entities are refused)."""


def _parse_xml(xml_text: str) -> ET.Element:
    lowered = xml_text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise JunitRejected("DTD/entity declarations are not accepted")
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise JunitRejected(f"invalid JUnit XML: {exc}") from exc


class SchemathesisAdapter(Adapter):
    tool = "schemathesis"

    def __init__(self, mode: str | None = None, authenticated: bool = False):
        self._mode = mode
        self._auth = "authenticated" if authenticated else "unauthenticated"

    def parse(self, raw, scan_id):
        xml_text = raw.get("junit_xml") if isinstance(raw, dict) else None
        if not xml_text:
            return []
        root = _parse_xml(xml_text)

        out: list[tuple[FindingDraft, list[EvidenceDraft]]] = []
        for case in root.iter("testcase"):
            failures = case.findall("failure")
            name = (case.get("name") or "").strip()
            if not failures or " " not in name:
                continue
            method, path = name.split(" ", 1)
            text = "\n".join((f.text or "") for f in failures)

            titles: list[str] = []
            for title in _TITLE.findall(text):
                if title not in titles:
                    titles.append(title)
            statuses = [int(s) for s in _RECEIVED.findall(text)]
            status = statuses[0] if statuses else None
            server_error = any(s >= 500 for s in statuses)

            template = f"{method.upper()} {path}"
            draft = FindingDraft(
                type="api_conformance",
                owasp="A05",
                title=f"API conformance failure on {template}: {titles[0] if titles else 'check failed'}",
                route=template,
                severity=0.5 if server_error else 0.3,
                source="worker1.schemathesis",
                mode=self._mode,
            )
            evidence = EvidenceDraft(
                kind="http_exchange",
                tool="schemathesis",
                tool_version=_TOOL_VERSION,
                payload={
                    "method": method.upper(),
                    "route": path,
                    "route_template": template,
                    "status": status,
                    "auth_context": self._auth,
                    "checks": titles[:_MAX_TITLES],
                    "request": template,
                },
            )
            out.append((draft, [evidence]))
        return out
