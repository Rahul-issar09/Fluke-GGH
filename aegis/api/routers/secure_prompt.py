"""``POST /api/secure-prompt`` — a code request in, secure code and OWASP-mapped reasons out.

Gemini Online mode only: with any other active model the answer is 409 ``online_required`` and
nothing is sent anywhere. Model-side failures (key refused, rate limit, provider down) use the same
error codes as the rest of ``/api``. The code is neither run nor scanned, and the response says so
(``verified: false``).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from aegis.api.deps import get_llm_manager
from aegis.api.errors import error_response
from aegis.api.schemas import ErrorOut
from aegis.secure_prompt import SecurePromptOut, SecurePromptRequest, SecurePromptUnavailable, generate

router = APIRouter(prefix="/api", tags=["secure-prompt"])


@router.post(
    "/secure-prompt",
    summary="Write secure code for a request, explained against the OWASP Top 10 (Gemini Online mode only)",
    response_model=SecurePromptOut,
    responses={
        409: {"model": ErrorOut, "description": "Not in Gemini Online mode (online_required)"},
        429: {"model": ErrorOut, "description": "The provider's rate limit or quota"},
        502: {"model": ErrorOut, "description": "The model did not return usable output (generation_failed)"},
        503: {"model": ErrorOut, "description": "Gemini cannot be reached"},
    },
)
async def secure_prompt(body: SecurePromptRequest, manager=Depends(get_llm_manager)):
    try:
        return await generate(manager, body)
    except SecurePromptUnavailable as exc:
        return error_response(exc.status, exc.code, str(exc))
