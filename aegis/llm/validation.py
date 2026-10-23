"""Proving a model works before it is activated (LLM_PROVIDER_PHASES §7.3).

* **Probe** — one tiny structured call (``{"ok": true, "echo": "aegis"}``) on a fixed, harmless
  prompt: it proves the key works, the model generates, and schema-constrained output parses.
* **Deep probe** (optional) — each of AEGIS's four real answer schemas (investigate, explain,
  remediate, chat) on a *synthetic* payload, with the real system prompts. It catches a schema the
  provider cannot handle before a real scan meets it. Nothing from a real scan is ever sent.
* **ValidationCache** — a validated candidate (model + key) is held **in memory only**, under a
  random id, for 10 minutes, and can be used once: activation (LP6) consumes it, so the key is
  never sent twice and never written anywhere before the user has agreed to cloud processing.
"""

from __future__ import annotations

import json
import secrets as pysecrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, SecretStr

__all__ = ["DEEP_PROBES", "Probe", "ValidationCache", "ValidationEntry", "run_deep_probe", "run_probe"]

_ROOT = Path(__file__).resolve().parents[1]


class Probe(BaseModel):
    ok: bool
    echo: Literal["aegis"]


PROBE_SYSTEM = 'This is a connectivity check. Reply with JSON only: {"ok": true, "echo": "aegis"}.'


def _schemas() -> list[tuple[str, type[BaseModel], Path, dict[str, Any]]]:
    from aegis.agent.schemas import Explanation, NextStepDecision
    from aegis.chat.schemas import Answer
    from aegis.fix.draft import FixEdit

    finding = {"finding_id": "F-0001", "type": "sqli", "owasp": "A03", "title": "SQL injection (synthetic check)",
               "state": "candidate", "file": "app/search.py", "line": 3, "evidence_ids": ["E-0001"],
               "evidence_digests": ["E-0001 semgrep sqli app/search.py:3 (synthetic)"]}
    return [
        ("investigate", NextStepDecision, _ROOT / "agent" / "prompts" / "investigate.txt",
         {**finding, "valid_next_steps": ["mark_sufficient", "escalate_to_human"]}),
        ("explain", Explanation, _ROOT / "agent" / "prompts" / "explain.txt", finding),
        ("remediate", FixEdit, _ROOT / "agent" / "prompts" / "remediate.txt",
         {**finding, "fix_hint": "use a parameterized query",
          "handler_source": "1 def search(db, q):\n2     sql = f\"SELECT * FROM items WHERE name = '{q}'\"\n"
                            "3     return db.execute(sql).fetchall()\n"}),
        ("chat", Answer, _ROOT / "chat" / "prompts" / "answer.txt",
         {"question": "why is F-0001 a risk?", "findings": [{"finding_id": "F-0001", "what": "SQL injection",
                                                             "evidence_digests": finding["evidence_digests"]}]}),
    ]


DEEP_PROBES = ("investigate", "explain", "remediate", "chat")


async def run_probe(runnable: Any) -> None:
    """Raises if the model cannot produce the probe schema."""
    out = await runnable.ainvoke([SystemMessage(content=PROBE_SYSTEM), HumanMessage(content='{"check": "aegis"}')])
    if not isinstance(out, Probe) or not out.ok:
        raise ValueError("the probe answer did not match its schema")


async def run_deep_probe(structured_for) -> list[str]:
    """Each AEGIS schema on a synthetic payload; returns the names that failed (``[]`` = all good).
    *structured_for(schema)* builds the runnable."""
    failed: list[str] = []
    for name, schema, prompt, payload in _schemas():
        try:
            out = await structured_for(schema).ainvoke([
                SystemMessage(content=prompt.read_text(encoding="utf-8")),
                HumanMessage(content=json.dumps(payload)),
            ])
            if not isinstance(out, schema):
                failed.append(name)
        except Exception:  # noqa: BLE001 - reported by name; the caller decides
            failed.append(name)
    return failed


@dataclass(frozen=True)
class ValidationEntry:
    provider: str
    model: str
    key: SecretStr | None          # the candidate key, memory only
    capabilities: frozenset[str]
    expires_at: float


class ValidationCache:
    def __init__(self, ttl_s: float = 600.0, max_entries: int = 32, clock=time.monotonic):
        self.ttl_s = ttl_s
        self.max_entries = max_entries
        self._clock = clock
        self._entries: dict[str, ValidationEntry] = {}
        self._lock = threading.Lock()

    def put(self, provider: str, model: str, key: str | None, capabilities: frozenset[str]) -> str:
        vid = pysecrets.token_urlsafe(18)
        entry = ValidationEntry(provider, model, SecretStr(key) if key else None, frozenset(capabilities),
                                self._clock() + self.ttl_s)
        with self._lock:
            self._purge()
            while len(self._entries) >= self.max_entries:
                self._entries.pop(next(iter(self._entries)))
            self._entries[vid] = entry
        return vid

    def consume(self, vid: str) -> ValidationEntry | None:
        """The entry, once; ``None`` if unknown, already used or expired."""
        with self._lock:
            self._purge()
            return self._entries.pop(vid, None)

    def _purge(self) -> None:
        now = self._clock()
        for vid in [v for v, e in self._entries.items() if e.expires_at <= now]:
            del self._entries[vid]
