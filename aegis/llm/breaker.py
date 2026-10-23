"""Stop calling a model that cannot answer, for the rest of a scan (LLM_PROVIDER_PHASES §7.5).

Some failures will not fix themselves within a scan: the model is not installed, the key is
invalid, the quota is spent, cloud processing was revoked. After the first one, every later call
in the same scope (a scan id, or ``"chat"``) for the same snapshot generation is refused at once
with the same error, instead of failing again per finding. Callers already fall back to rules and
templates, so the scan result is unchanged — it is just faster, and the audit shows the cause once.

Transient failures (server errors, timeouts, connection refused) do not open the breaker: the
model may be back for the next finding. A new configuration (a new ``generation``) starts closed.
"""

from __future__ import annotations

import threading

from aegis.llm.base import LlmError, LlmSnapshot

__all__ = ["FATAL_KINDS", "CircuitBreaker"]

FATAL_KINDS = frozenset({
    "invalid_api_key", "permission_denied", "billing_required", "model_not_found", "quota_exhausted",
    "revoked", "provider_unavailable", "config_error",
})


class CircuitBreaker:
    def __init__(self) -> None:
        self._open: dict[tuple[str, str, str, int], LlmError] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(scope: str, snapshot: LlmSnapshot) -> tuple[str, str, str, int]:
        return (scope, snapshot.provider.value, snapshot.model, snapshot.generation)

    def check(self, scope: str, snapshot: LlmSnapshot) -> None:
        """Raise the stored error if the breaker is open for *scope* and *snapshot*."""
        err = self._open.get(self._key(scope, snapshot))
        if err is not None:
            raise LlmError(err.kind, f"{err} (skipped: the model already failed this way in this run)",
                           provider=err.provider, status_code=err.status_code)

    def record(self, scope: str, snapshot: LlmSnapshot, err: LlmError) -> bool:
        """Open the breaker if *err* is fatal; returns whether it opened just now."""
        if err.kind not in FATAL_KINDS:
            return False
        key = self._key(scope, snapshot)
        with self._lock:
            if key in self._open:
                return False
            self._open[key] = err
        return True

    def is_open(self, scope: str, snapshot: LlmSnapshot) -> bool:
        return self._key(scope, snapshot) in self._open

    def reset(self, scope: str) -> None:
        with self._lock:
            for key in [k for k in self._open if k[0] == scope]:
                del self._open[key]
