"""Query router (RAG09) — rules and keywords only, no model (SD §10).

Decides whether a question is answered by the **structured** path (counts, lists, look-ups from the
findings table) or the **explain** path (a cited natural-language answer), and parses any filter the
question implies (an OWASP code, a weakness type, a severity, a state, a file/function/route). The
decision is deterministic. When it is unclear, it defaults to **explain** (the richer answer) while
still keeping the parsed filter to scope retrieval.
"""

from __future__ import annotations

import re

from aegis.chat.schemas import FindingFilter, RouteDecision
from aegis.observability import get_logger

__all__ = ["route"]

log = get_logger("chat.router")

_OWASP = re.compile(r"\bA(0[1-9]|10)\b", re.IGNORECASE)
_PATH = re.compile(r"(?:^|[\s(])(/[A-Za-z0-9_{}/.-]+)")  # a slash at a boundary, not inside a filename like app/config.py
_FILE = re.compile(r"\b([\w./-]+\.(?:py|js|ts|mjs|cjs|java|rb|go|php|yml|yaml|json|txt|cfg|ini|toml))\b", re.IGNORECASE)
_FUNCTION = re.compile(r"\bfunction\s+([A-Za-z_]\w+)|\bin\s+([A-Za-z_]\w+)\s*\(\)|\b([a-z_][a-z0-9_]*_[a-z0-9_]+)\b")

_SEVERITY = {"critical": 0.9, "high": 0.7, "medium": 0.5, "moderate": 0.5, "low": 0.3}
_STATES = ("confirmed", "corroborated", "candidate", "resolved")
# weakness keywords → finding type (multiword phrases first so they win over their substrings)
_TYPES: tuple[tuple[str, str], ...] = (
    ("broken access control", "broken_access_control"), ("access control", "broken_access_control"), ("idor", "broken_access_control"),
    ("sql injection", "sqli"), ("sqli", "sqli"),
    ("command injection", "command_injection"), ("code injection", "code_injection"),
    ("path traversal", "path_traversal"), ("deserialization", "insecure_deserialization"),
    ("server-side request", "ssrf"), ("ssrf", "ssrf"),
    ("vulnerable dependency", "vulnerable_dependency"), ("dependencies", "vulnerable_dependency"),
    ("dependency", "vulnerable_dependency"), ("cve", "vulnerable_dependency"),
    ("api key", "secret"), ("hardcoded", "secret"), ("credential", "secret"), ("secret", "secret"),
    ("weak crypto", "weak_crypto"), ("weak hash", "weak_crypto"), ("md5", "weak_crypto"), ("sha1", "weak_crypto"), ("sha-1", "weak_crypto"),
    ("weak tls", "weak_tls"), ("tls", "weak_tls"),
    ("misconfiguration", "misconfig"), ("misconfig", "misconfig"),
    ("quantum", "quantum_risk"), ("api conformance", "api_conformance"),
)

# explanatory cues → explain; counting/listing cues → structured
_EXPLAIN_CUES = re.compile(
    r"\b(why|explain|elaborate|describe|walk me through|tell me about|what about|what does\b.*\bmean|"
    r"how (?:do|does|can|could|would|is|are)\b|is it (?:serious|exploitable|risky|dangerous|bad|safe|real)|"
    r"should (?:i|we)|what is the (?:impact|risk|exploit)|how to fix|how do i fix)\b",
    re.IGNORECASE,
)
_COUNT_CUES = re.compile(r"\b(how many|how much|number of|count)\b", re.IGNORECASE)
_LIST_CUES = re.compile(
    r"\b(list|show|which|what are|what's in|whats in|are there|do we have|find all|give me (?:all|the)|"
    r"any .* (?:findings|issues|vulnerabilities))\b",
    re.IGNORECASE,
)


def _parse_filter(question: str, scan_id: str) -> FindingFilter:
    q = question.lower()
    owasp = _OWASP.search(question)
    severity = next((v for word, v in _SEVERITY.items() if re.search(rf"\b{word}\b", q)), None)
    state = next((s for s in _STATES if re.search(rf"\b{s}\b", q)), None)
    ftype = next((t for phrase, t in _TYPES if phrase in q), None)
    file_match = _FILE.search(question)

    function = None
    fm = _FUNCTION.search(question)
    if fm:
        function = next((g for g in fm.groups() if g), None)

    route = None
    pm = _PATH.search(question)
    if pm and "/" in pm.group(1).strip("/") + "/":  # a real path like /api/accounts, not a bare "/"
        candidate = pm.group(1)
        route = candidate if len(candidate) > 1 else None

    return FindingFilter(
        scan_id=scan_id,
        severity_min=severity,
        owasp=owasp.group(0).upper() if owasp else None,
        state=state,
        type=ftype,
        file=file_match.group(1) if file_match else None,
        function=function,
        route=route,
        count=bool(_COUNT_CUES.search(question)),
    )


def route(question: str, scan_id: str) -> RouteDecision:
    """Pick the path and parse the filter for *question* (deterministic, no model)."""
    text = (question or "").strip()
    filt = _parse_filter(text, scan_id)

    if _EXPLAIN_CUES.search(text):
        path = "explain"
    elif _COUNT_CUES.search(text) or _LIST_CUES.search(text):
        path = "structured"
    elif any((filt.owasp, filt.type, filt.severity_min, filt.state, filt.file, filt.function, filt.route)):
        path = "structured"  # a bare filter ("A01?", "sqli findings") with no explanatory verb
    else:
        path = "explain"  # default: the richer answer, still scoped by whatever was parsed

    log.info("router.decided", path=path, owasp=filt.owasp, type=filt.type, count=filt.count,
             severity_min=filt.severity_min, state=filt.state, file=filt.file)
    return RouteDecision(path=path, filter=filt)
