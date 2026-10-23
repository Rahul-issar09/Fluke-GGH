"""``/api/llm/*`` — choose and inspect the model AEGIS reasons with (LLM_PROVIDER_PHASES LP7, §8).

    GET    /api/llm/providers              which providers exist, are installed and allowed
    GET    /api/llm/config                 the active model, consent, key status (never the key)
    GET    /api/llm/models?provider=…      models of a provider (Gemini: with this session's key)
    POST   /api/llm/discover               Gemini models for a key given in the body
    POST   /api/llm/validate               prove a model works; returns a single-use validation id
    PUT    /api/llm/config                 switch: {"provider": "ollama"} = go offline now;
                                           Gemini needs a validation id (+ consent, unless on record)
    DELETE /api/llm/credentials/gemini     forget this session's key (goes offline first)
    POST   /api/llm/test                   one small check of the active model (rate-limited)

The key arrives only in a request body, never a URL, and is never returned. It is kept in this
process's memory (decision Q-4): every run asks for it again.

**Protection (§9.6).** Every request that changes something or carries a key needs the header
``X-AEGIS-Intent: llm-config`` — a custom header that a web page on another site cannot send
without a CORS preflight, which this API never grants. Without an API token, such requests are
also only accepted from this machine (client, ``Host`` and ``Origin`` all loopback), so a key can
never be set from the network on an open API. With ``AEGIS_API__AUTH_TOKEN`` the bearer token
(checked by the middleware for all of ``/api``) is required instead.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Query, Request

from aegis.api.deps import get_llm_manager, get_settings
from aegis.api.llm_schemas import (
    ActivateRequest, DiscoverRequest, LlmConfigOut, ModelOut, ModelsOut, ProviderOut, TestOut, ValidateOut,
    ValidateRequest,
)
from aegis.api.schemas import ErrorOut
from aegis.api.security import host_is_local
from aegis.config import AppSettings
from aegis.llm.base import LlmError, ProviderId
from aegis.llm.consent import ConsentInput, disclosure
from aegis.llm.policy import ConfigRefused
from aegis.llm.secrets import fingerprint
from aegis.observability import get_logger

router = APIRouter(prefix="/api/llm", tags=["llm"])
log = get_logger("api.llm")

INTENT_HEADER = "x-aegis-intent"
INTENT_VALUE = "llm-config"
TEST_INTERVAL_S = 10.0

_ERRORS: dict[int | str, dict[str, Any]] = {
    403: {"model": ErrorOut, "description": "Not allowed from here, or cloud processing is disabled"},
    409: {"model": ErrorOut, "description": "Conflicts with the configuration (environment, consent, …)"},
    410: {"model": ErrorOut, "description": "The validation expired or was already used"},
    422: {"model": ErrorOut, "description": "Invalid request, key or model"},
    429: {"model": ErrorOut, "description": "The provider's rate limit or quota"},
    503: {"model": ErrorOut, "description": "The provider cannot be reached"},
}


# ------------------------------------------------------------------ protection
class _Forbidden(Exception):
    """Mapped to 403 ``config_api_forbidden`` by the API error handlers."""


def require_config_intent(request: Request, settings: AppSettings = Depends(get_settings)) -> str:
    """Guard for changing requests; returns who is asking (``ui`` / ``cli`` / ``api``) for the audit."""
    headers = request.headers
    if headers.get(INTENT_HEADER) != INTENT_VALUE:
        raise ConfigRefused("invalid_request", f"send the header 'X-AEGIS-Intent: {INTENT_VALUE}' to change the model "
                                               "configuration")
    if settings.api.auth_token is None:   # an open API: only this machine may change the model or send a key
        client = request.client.host if request.client else None
        host = urlsplit(f"//{headers.get('host', '')}").hostname
        origin = headers.get("origin")
        if (not host_is_local(client) or not host_is_local(host)
                or (origin and not host_is_local(urlsplit(origin).hostname))
                or headers.get("sec-fetch-site") == "cross-site"):
            log.warning("llm.config_api_refused", client=client, host=host, origin=origin)
            raise _Forbidden()
    actor = headers.get("x-aegis-client", "api").lower()
    return actor if actor in ("ui", "cli", "api") else "api"


def _client(request: Request) -> str | None:
    return request.client.host if request.client else None


def _manager(request: Request):
    manager = get_llm_manager(request)
    if manager is None:
        raise ConfigRefused("provider_unavailable", "model configuration is not available in this process")
    return manager


# ------------------------------------------------------------------ reads
@router.get("/providers", summary="Model providers and whether they can be used", response_model=list[ProviderOut])
def providers(request: Request) -> list[ProviderOut]:
    mgr = _manager(request)
    llm, active = mgr.settings.llm, mgr.snapshot.provider
    out = [ProviderOut(id="ollama", name="Ollama (offline, this machine)", location="local", installed=True,
                       allowed=True, active=active is ProviderId.ollama, needs_key=False)]
    installed = mgr.registry.available(ProviderId.gemini)
    reason = None if installed else 'not installed: pip install -e ".[gemini]"'
    if installed and not llm.allow_cloud:
        reason = "disabled on this install (AEGIS_LLM__ALLOW_CLOUD=false)"
    out.append(ProviderOut(id="gemini", name="Google Gemini (online)", location="cloud", installed=installed,
                           allowed=installed and llm.allow_cloud, active=active is ProviderId.gemini,
                           needs_key=True, reason=reason))
    return out


@router.get("/config", summary="The active model, consent and key status (never the key)", response_model=LlmConfigOut)
def get_config(request: Request, settings: AppSettings = Depends(get_settings)) -> LlmConfigOut:
    return _config_out(_manager(request), settings)


def _config_out(mgr, settings: AppSettings) -> LlmConfigOut:
    from aegis.config import resolve_chat_settings

    status = mgr.status()
    chat = resolve_chat_settings(settings)
    return LlmConfigOut(
        **{k: status[k] for k in ("provider", "model", "location", "generation", "managed_by", "allow_cloud",
                                  "config_error", "awaiting_key", "online_model", "key", "consent",
                                  "allow_source_code")},
        disclosure=disclosure(),
        embeddings={"provider": "ollama", "location": "local", "model": chat.embed_model, "dim": chat.embed_dim,
                    "note": "embeddings and the search index always stay on this machine"},
    )


@router.get("/models", summary="Models of a provider", response_model=ModelsOut, responses=_ERRORS)
async def models(request: Request, provider: str = Query("ollama", pattern="^(ollama|gemini)$")) -> ModelsOut:
    mgr = _manager(request)
    pid = ProviderId(provider)
    return ModelsOut(provider=provider, models=[ModelOut(**m.to_dict()) for m in await mgr.list_models(pid)])


# ------------------------------------------------------------------ changes (guarded)
@router.post("/discover", summary="Models a Gemini key can use (the key stays in memory only)",
             response_model=ModelsOut, responses=_ERRORS)
async def discover(body: DiscoverRequest, request: Request, actor: str = Depends(require_config_intent)) -> ModelsOut:
    mgr = _manager(request)
    pid = ProviderId(body.provider)
    _cloud_allowed(mgr, pid)
    key = body.api_key.get_secret_value() if body.api_key else None
    found = await mgr.list_models(pid, key)
    log.info("llm.discovered", provider=pid.value, count=len(found), actor=actor)
    return ModelsOut(provider=body.provider, models=[ModelOut(**m.to_dict()) for m in found])


@router.post("/validate", summary="Prove a model works before switching to it", response_model=ValidateOut,
             responses=_ERRORS)
async def validate(body: ValidateRequest, request: Request, actor: str = Depends(require_config_intent)) -> ValidateOut:
    mgr = _manager(request)
    pid = ProviderId(body.provider)
    _cloud_allowed(mgr, pid)
    key = body.api_key.get_secret_value() if body.api_key else None
    result, vid = await mgr.validate(pid, body.model, key, deep=body.deep)
    if not result.ok:
        raise LlmError(result.error_kind or "invalid_request", result.error or "the model cannot be used",
                       provider=pid.value)
    on_record = False
    if pid is ProviderId.gemini:
        candidate = fingerprint(key) if key else (mgr.secrets.get().fingerprint if mgr.secrets.get() else None)
        on_record = mgr.consent_on_record(candidate)
    return ValidateOut(ok=True, validation_id=vid, capabilities=sorted(result.capabilities),
                       warnings=list(result.warnings), consent_on_record=on_record,
                       disclosure=disclosure() if pid is ProviderId.gemini else {})


@router.put("/config", summary="Switch the model ({'provider': 'ollama'} goes offline now)",
            response_model=LlmConfigOut, responses=_ERRORS)
async def put_config(body: ActivateRequest, request: Request, actor: str = Depends(require_config_intent),
                     settings: AppSettings = Depends(get_settings)) -> LlmConfigOut:
    mgr = _manager(request)
    pid = ProviderId(body.provider)
    consent = (ConsentInput(disclosure_version=body.consent.disclosure_version, accepted=body.consent.accepted,
                            allow_source_code=body.consent.allow_source_code) if body.consent else None)
    if pid is ProviderId.ollama:
        await mgr.activate(pid, body.model, actor=actor, client=_client(request))
    else:
        await mgr.activate(pid, body.model, validation_id=body.validation_id, consent=consent, actor=actor,
                           client=_client(request))
    return _config_out(mgr, settings)


@router.delete("/credentials/gemini", summary="Forget this session's Gemini key (goes offline first)",
               response_model=LlmConfigOut, responses=_ERRORS)
async def forget_key(request: Request, actor: str = Depends(require_config_intent),
                     settings: AppSettings = Depends(get_settings)) -> LlmConfigOut:
    mgr = _manager(request)
    await mgr.forget_key(actor=actor, client=_client(request))
    return _config_out(mgr, settings)


@router.post("/test", summary="One small check of the active model", response_model=TestOut, responses=_ERRORS)
async def test_active(request: Request, actor: str = Depends(require_config_intent)) -> TestOut:
    mgr = _manager(request)
    last = getattr(request.app.state, "llm_last_test", 0.0)
    if time.monotonic() - last < TEST_INTERVAL_S:
        raise LlmError("rate_limited", f"wait {TEST_INTERVAL_S:.0f} s between checks", retry_after=TEST_INTERVAL_S)
    request.app.state.llm_last_test = time.monotonic()
    snap = mgr.snapshot
    result = await mgr.provider_for(snap).validate(snap.model)
    log.info("llm.tested", provider=snap.provider.value, model=snap.model, ok=result.ok, actor=actor)
    return TestOut(ok=result.ok, provider=snap.provider.value, model=snap.model, error_kind=result.error_kind,
                   error=result.error)


def _cloud_allowed(mgr, pid: ProviderId) -> None:
    if pid is ProviderId.ollama:
        return
    if not mgr.registry.available(pid):
        raise ConfigRefused("provider_unavailable", 'the Gemini provider is not installed: pip install -e ".[gemini]"')
    if not mgr.settings.llm.allow_cloud:
        raise ConfigRefused("cloud_disabled", "cloud processing is disabled on this install (AEGIS_LLM__ALLOW_CLOUD=false)")
