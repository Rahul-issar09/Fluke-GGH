"""Secure Prompt service: one gated, validated model call.

Only Gemini Online mode may serve it (the feature's rule): any other active model is refused with
``online_required`` and nothing is sent anywhere. The request goes through the same
``structured_call`` every other AEGIS model call uses, so it gets the manager's gate before each
attempt, one corrective retry, the rate limiter and the circuit breaker. Only the user's request
text is sent, with any known secret scrubbed out of it first; no code or findings leave the machine.
"""

from __future__ import annotations

from typing import Any

from aegis.agent.llm import structured_call
from aegis.llm.base import ProviderId
from aegis.observability import get_logger
from aegis.secret_scrub import scrub
from aegis.secure_prompt.prompts import SYSTEM
from aegis.secure_prompt.schemas import (
    OWASP_2021, BulletOut, CoverageRow, ModelResult, SecurePromptOut, SecurePromptRequest,
)

__all__ = ["SecurePromptUnavailable", "generate", "validate_result"]

log = get_logger("secure_prompt")

_OVERCLAIMS = ("100% secure", "completely secure", "fully secure", "unhackable", "guaranteed secure")


class SecurePromptUnavailable(Exception):
    """The request cannot be served; ``code`` is the stable reason and ``status`` the HTTP status."""

    def __init__(self, code: str, message: str, status: int):
        super().__init__(message)
        self.code, self.status = code, status


def validate_result(result: ModelResult) -> list[str]:
    """What is wrong with the model's answer; ``[]`` means usable (a failure triggers one retry)."""
    problems: list[str] = []
    if not result.code.strip():
        problems.append("code is empty")
    if len(result.bullets) < 3:
        problems.append("give at least 3 bullets, each with an OWASP id, an action and a reason")
    clash = sorted({b.owasp for b in result.bullets} & set(result.not_applicable))
    if clash:
        problems.append(f"{', '.join(clash)} has a bullet, so it cannot also be in not_applicable")
    if not result.not_covered:
        problems.append("not_covered must list at least one honest limit")
    text = " ".join(f"{b.action} {b.why}" for b in result.bullets).lower()
    if any(phrase in text for phrase in _OVERCLAIMS):
        problems.append("do not claim the code is fully or 100% secure")
    return problems


def _require_online(manager: Any) -> Any:
    if manager is None:
        raise SecurePromptUnavailable("online_required", "no AI model is configured on this server", 409)
    snap = manager.snapshot
    if snap.provider is not ProviderId.gemini or snap.location != "cloud":
        waiting = bool(manager.status().get("awaiting_key"))
        why = ("Online mode is chosen but this run's Gemini key has not been entered yet"
               if waiting else "the active model is offline")
        raise SecurePromptUnavailable(
            "online_required", f"Secure Prompt needs Gemini Online mode: {why}. Switch on the AI model page.", 409)
    return snap


def _present(result: ModelResult, request: SecurePromptRequest, snap: Any) -> SecurePromptOut:
    covered = {b.owasp for b in result.bullets}
    coverage = [
        CoverageRow(id=oid, name=name,   # type: ignore[arg-type]
                    status="covered" if oid in covered else "not_applicable" if oid in result.not_applicable else "not_covered")
        for oid, name in OWASP_2021.items()
    ]
    bullets = [BulletOut(**b.model_dump(), category=OWASP_2021[b.owasp])
               for b in sorted(result.bullets, key=lambda b: b.owasp)]
    return SecurePromptOut(language=result.language or request.language, code=result.code, bullets=bullets,
                           coverage=coverage, not_covered=result.not_covered,
                           provider=snap.provider.value, model=snap.model)


async def generate(manager: Any, request: SecurePromptRequest) -> SecurePromptOut:
    snap = _require_online(manager)
    prompt = scrub(request.prompt)
    payload = {"user_request": prompt, "language": request.language, "owasp_version": "2021",
               "allowed_owasp_ids": list(OWASP_2021)}
    trace: list[dict[str, Any]] = []
    result, source = await structured_call(ModelResult, SYSTEM, payload, validate_result, manager=manager,
                                           snapshot=snap, scope="secure_prompt", trace=trace)
    if result is None:
        log.warning("secure_prompt.failed", attempts=len(trace))
        manager.audit.record("secure_prompt", provider=snap.provider.value, model=snap.model,
                             prompt_chars=len(prompt), outcome="invalid_output")
        raise SecurePromptUnavailable("generation_failed",
                                      "The model did not return usable secure code. Try again or rephrase.", 502)
    out = _present(result, request, snap)
    manager.audit.record("secure_prompt", provider=snap.provider.value, model=snap.model,
                         prompt_chars=len(prompt), bullets=len(out.bullets), outcome="ok" if source == "llm" else "ok_retry")
    log.info("secure_prompt.ok", model=snap.model, bullets=len(out.bullets), source=source)
    return out
