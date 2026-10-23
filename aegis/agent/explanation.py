"""The parts of a finding's explanation that are never the model's (AG10.1).

PRD §4.2 gives every finding a 5-part explanation: **what / where / impact / exploit / fix**.

* ``what`` / ``impact`` / ``exploit`` come from *validated* claims (the model proposes,
  ``validate`` disposes). When a part ends up with no valid claim — the model was down,
  or every claim it made was dropped — it is filled from the fixed per-weakness text in
  :data:`TEMPLATES`, citing the finding's real evidence. Those texts are conceptual: no
  payloads, no steps beyond what the evidence already shows.
* ``where`` is built here from ``file:line`` and the actual source text — deterministic, never
  written by the model, and never sent to it (code can carry injected comments).
* ``fix`` is the drafted diff from the remediation step (AG10.2); empty until then.

Everything here is pure and deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegis.agent.schemas import Claim
from aegis.evidence.models import Finding

__all__ = [
    "EXPLAIN_FIELDS",
    "TEMPLATES",
    "template_claims",
    "render_where",
    "five_parts",
]

EXPLAIN_FIELDS = ("what", "impact", "exploit")

_MAX_SOURCE_BYTES = 1_000_000
_MAX_LINE_CHARS = 200
_DEFAULT_CONTEXT = 2

# {weakness type: {part: sentence}} — each ≤ 400 characters (the Claim limit).
TEMPLATES: dict[str, dict[str, str]] = {
    "broken_access_control": {
        "what": "The endpoint does not check that the requested object belongs to the person asking for it.",
        "impact": "Any signed-in user can read, and possibly change, other users' data.",
        "exploit": "A signed-in user asks for another user's object by its identifier and the server returns it.",
    },
    "sqli": {
        "what": "Input from the request is placed directly into a database query.",
        "impact": "An attacker can read or alter data in the database well beyond what the application intends.",
        "exploit": "Specially shaped input reaches the query unchanged and changes what the query means.",
    },
    "ssrf": {
        "what": "The server fetches a web address supplied by the caller without limiting where it may point.",
        "impact": "The server can be made to reach internal systems or services on the caller's behalf.",
        "exploit": "The caller supplies an address they control and the server connects to it.",
    },
    "command_injection": {
        "what": "Input from the request becomes part of an operating-system command.",
        "impact": "An attacker can run commands on the server with the application's permissions.",
        "exploit": "Input containing shell syntax is passed to the command and runs alongside it.",
    },
    "code_injection": {
        "what": "Input from the request is evaluated as program code.",
        "impact": "An attacker can run arbitrary code inside the application.",
        "exploit": "The attacker sends code as input and the application executes it.",
    },
    "insecure_deserialization": {
        "what": "Data is loaded with a deserializer that can run code embedded in the data.",
        "impact": "Whoever controls that data can run code in the application.",
        "exploit": "Crafted serialized data runs code while it is being loaded.",
    },
    "path_traversal": {
        "what": "Input from the request decides which file the server opens.",
        "impact": "An attacker can read files outside the intended folder, such as configuration or keys.",
        "exploit": "A file name containing \"../\" walks out of the intended folder.",
    },
    "insecure_tls": {
        "what": "Certificate verification is turned off for an outgoing encrypted connection.",
        "impact": "Traffic to that service can be intercepted or altered without detection.",
        "exploit": "A network attacker presents their own certificate and the application accepts it.",
    },
    "secret": {
        "what": "A credential is stored in the source code.",
        "impact": "Anyone who can read the code can use the credential until it is replaced.",
        "exploit": "The credential is read from the repository and used against the service it protects.",
    },
    "weak_crypto": {
        "what": "A weak or outdated cryptographic algorithm is in use.",
        "impact": "Protected data or passwords can be recovered or forged far more easily than intended.",
        "exploit": "An attacker who obtains the protected values can defeat the weak protection offline.",
    },
    "weak_tls": {
        "what": "The service accepts an outdated or weak transport-encryption configuration.",
        "impact": "Traffic between clients and the service is easier to intercept or downgrade.",
        "exploit": "A network attacker negotiates the weak configuration and reads or alters the traffic.",
    },
    "quantum_risk": {
        "what": "Data is protected by public-key cryptography that future quantum computers are expected to break.",
        "impact": "Traffic or data recorded today could be decrypted later.",
        "exploit": "An attacker stores the protected data now and decrypts it once the capability exists.",
    },
    "vulnerable_dependency": {
        "what": "The application uses a library version with a publicly known vulnerability.",
        "impact": "The known weakness may be reachable through the application, with the library's own impact.",
        "exploit": "An attacker uses the published details of the vulnerability against the affected component.",
    },
    "misconfig": {
        "what": "A security-relevant setting is missing or unsafe.",
        "impact": "The protection that setting is meant to provide is absent.",
        "exploit": "An attacker relies on the missing protection, which the application does not enforce.",
    },
    "api_conformance": {
        "what": "The API behaves differently from its own documented contract.",
        "impact": "Clients and security controls that trust the documentation can be misled or bypassed.",
        "exploit": "A request outside the documented behaviour gets a response the documentation does not describe.",
    },
    "code_issue": {
        "what": "Static analysis flagged a risky pattern in the code.",
        "impact": "Depending on how the code is reached, the pattern may weaken the application's security.",
        "exploit": "Whether it can be exploited depends on how the flagged code is reached; see the evidence.",
    },
}

_MAX_EVIDENCE_PER_CLAIM = 2


def template_claims(finding: Finding, evidence_ids: list[str], fields: list[str] | tuple[str, ...]) -> list[Claim]:
    """Fixed-text claims for *fields*, citing the finding's own evidence. Empty if it has none."""
    if not evidence_ids:
        return []
    text = TEMPLATES.get(finding.type, TEMPLATES["code_issue"])
    cited = sorted(evidence_ids)[:_MAX_EVIDENCE_PER_CLAIM]
    return [Claim(field=f, text=text[f], evidence_ids=cited) for f in fields]


# --------------------------------------------------------------------------- #
# where — deterministic, from the real source
# --------------------------------------------------------------------------- #
def _snippet(source_path: str | None, file: str, line: int | None, context: int) -> str | None:
    if not source_path or line is None or line < 1:
        return None
    try:
        root = Path(source_path).resolve()
        target = (root / file).resolve()
        if not target.is_relative_to(root) or not target.is_file() or target.stat().st_size > _MAX_SOURCE_BYTES:
            return None  # outside the source tree (path traversal), missing, or too big to display
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None
    if line > len(lines):
        return None
    first, last = max(1, line - context), min(len(lines), line + context)
    return "\n".join(
        f"{'>' if n == line else ' '} {n:>4} | {lines[n - 1].rstrip()[:_MAX_LINE_CHARS]}"
        for n in range(first, last + 1)
    )


def render_where(finding: Finding, source_path: str | None, context: int = _DEFAULT_CONTEXT) -> str | None:
    """``file:line (function)`` plus the code around it; the endpoint for runtime-only findings."""
    if not finding.file:
        return finding.route
    location = f"{finding.file}:{finding.line}" if finding.line else finding.file
    if finding.function:
        location += f" ({finding.function})"
    snippet = _snippet(source_path, finding.file, finding.line, context)
    return f"{location}\n{snippet}" if snippet else location


def _fix_part(finding: Finding, fix: Any | None) -> dict[str, Any] | None:
    """The drafted fix (a ``FixAttempt``), shown as ``{fix_id, status, description, diff}``."""
    if fix is not None:
        try:
            draft = json.loads(fix.verify_report_json or "{}").get("draft", {})
        except (ValueError, AttributeError):
            draft = {}
        return {
            "fix_id": fix.id,
            "status": fix.status,
            "description": draft.get("description"),
            "diff": fix.diff,
            "secret_masked": bool(draft.get("secret_masked")),
        }
    if finding.fix_diff:
        return {"description": None, "diff": finding.fix_diff}
    return None


def five_parts(finding: Finding, source_path: str | None = None, fix: Any | None = None) -> dict[str, Any]:
    """What / where / impact / exploit / fix, as the API and the reports show them.

    ``fix`` is the finding's latest ``FixAttempt`` (``store.latest_fix_attempt``), if any.
    """
    return {
        "what": finding.what,
        "where": render_where(finding, source_path),
        "impact": finding.impact,
        "exploit": finding.exploit,
        "fix": _fix_part(finding, fix),
    }
