"""The one object that knows which model AEGIS uses right now (LLM_PROVIDER_PHASES LP2, LP6).

``ProviderManager`` resolves the configuration (environment → ``<data_dir>/config/llm.json`` →
defaults), applies the cloud policy (kill-switch, consent to the current privacy notice, the key
it was given with), keeps the active :class:`LlmSnapshot`, and hands out structured runnables.
Anything that fails a check falls back to Offline and says why — never to another cloud model.

    runnable = manager.structured(Explanation)               # the active model
    runnable = manager.structured(Explanation, snapshot=s)   # a model pinned earlier (a scan's)

``authorize`` is the gate every call passes. A local snapshot is always allowed. A cloud snapshot
only while cloud processing is still allowed and that provider is still the active one — so
"go offline" (or the kill-switch) stops cloud calls at once, even for a scan already running.

Changes (LP6) — ``activate`` (needs a validation from ``validate`` and consent), ``go_offline``,
``forget_key`` — write the config atomically, roll back on failure, and leave one audit line each
in ``<data_dir>/audit/llm.jsonl``. A ``read_only`` manager (the MCP server) refuses every change.
"""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from aegis.config import AppSettings
from aegis.llm.audit import LlmAudit
from aegis.llm.base import (
    LlmError, LlmProvider, LlmSnapshot, ModelInfo, ProviderHealth, ProviderId, ValidationResult,
)
from aegis.llm.breaker import CircuitBreaker
from aegis.llm.config_store import (
    ConsentRecord, GeminiSection, KeyRef, LlmConfigFile, OllamaSection, ResolvedLlmConfig, config_path,
    read_config, resolve, write_config,
)
from aegis.llm.consent import DISCLOSURE_VERSION, ConsentInput
from aegis.llm.policy import CloudDecision, CloudPolicy, ConfigRefused
from aegis.llm.registry import ProviderRegistry
from aegis.llm.secrets import SecretStore, fingerprint
from aegis.llm.validation import ValidationCache
from aegis.observability import get_logger

__all__ = ["ProviderManager"]

log = get_logger("llm")

_LOCAL = CloudDecision(allowed=True)


def _norm(model: str | None) -> str:
    model = (model or "").strip()
    return model[len("models/"):] if model.startswith("models/") else model


def _via(actor: str) -> str:
    return actor if actor in ("ui", "cli", "api") else "api"


class ProviderManager:
    def __init__(self, settings: AppSettings, data_dir: str | Path | None = None, *, read_only: bool = False,
                 registry: ProviderRegistry | None = None, environ: dict[str, str] | None = None,
                 secrets: SecretStore | None = None):
        self.settings = settings
        self.data_dir = Path(data_dir if data_dir is not None else settings.data_dir)
        self.read_only = read_only
        self._environ = environ
        # one key store per process: a key entered this session must reach the provider that uses it
        self.secrets = secrets or SecretStore()
        self.registry = registry or ProviderRegistry(settings, secrets=self.secrets)
        self.policy = CloudPolicy(settings, self.secrets)
        self.audit = LlmAudit(self.data_dir / "audit" / "llm.jsonl")
        self.breaker = CircuitBreaker()
        self.validations = ValidationCache()
        self._lock = threading.RLock()
        self._mtime: float | None = None
        self._last_block: str | None = None
        self._resolved: ResolvedLlmConfig
        self._snapshot: LlmSnapshot
        self._cloud: CloudDecision = _LOCAL
        self._awaiting_key = False
        self.reload()

    # ------------------------------------------------------------------ configuration
    @property
    def config_path(self) -> Path:
        return config_path(self.data_dir)

    def _file_mtime(self) -> float | None:
        try:
            return self.config_path.stat().st_mtime
        except OSError:
            return None

    def _resolve_once(self) -> tuple[ResolvedLlmConfig, CloudDecision]:
        resolved = resolve(self.settings, read_config(self.config_path), environ=self._environ,
                           available=self.registry.available)
        if resolved.provider is ProviderId.ollama:
            return resolved, _LOCAL
        decision = self.policy.evaluate(resolved)
        if decision.allowed:
            return resolved, decision
        errors = [e for e in (resolved.config_error, f"{decision.reason}; using the offline provider") if e]
        return replace(resolved, provider=ProviderId.ollama, model=resolved.ollama_model,
                       managed_by={**resolved.managed_by, "provider": "default"},
                       config_error="; ".join(errors)), decision

    def reload(self) -> ResolvedLlmConfig:
        """Re-read the config file and environment, apply the cloud policy, and make the result active."""
        with self._lock:
            resolved, decision = self._resolve_once()
            if self._kill_switch_left_consent(resolved):
                self._revoke_for_kill_switch(resolved.file)
                resolved, decision = self._resolve_once()
            snapshot = self.registry.get(resolved.provider).snapshot(resolved.model, generation=resolved.generation)
            self._resolved, self._snapshot, self._mtime = resolved, snapshot, self._file_mtime()
            self._cloud = decision if snapshot.location == "cloud" else _LOCAL
            self._awaiting_key = decision.missing_key   # Online chosen, this run's key not entered yet
            blocked = None if decision.allowed else decision.reason
            if blocked and blocked != self._last_block and not self.read_only:
                self.audit.record("cloud_blocked_by_policy", actor="system", reason=blocked)
            self._last_block = blocked
        if resolved.config_error:
            log.warning("llm.config_error", error=resolved.config_error, provider=snapshot.provider.value)
        log.info("llm.active", provider=snapshot.provider.value, model=snapshot.model, location=snapshot.location,
                 generation=snapshot.generation, managed_by=resolved.managed_by)
        return resolved

    def _kill_switch_left_consent(self, resolved: ResolvedLlmConfig) -> bool:
        cfg = resolved.file
        return (not self.read_only and not self.settings.llm.allow_cloud and cfg is not None
                and cfg.consent is not None)

    def _revoke_for_kill_switch(self, cfg: LlmConfigFile) -> None:
        """The kill-switch is on: recorded consent stops counting (turning cloud on again needs new consent)."""
        write_config(self.config_path, cfg.model_copy(update={
            "generation": cfg.generation + 1, "provider": ProviderId.ollama, "consent": None,
            "updated_at": datetime.now(timezone.utc)}))
        self.audit.record("consent_revoked", actor="system", reason="kill_switch", generation=cfg.generation + 1)
        log.warning("llm.consent_revoked", reason="kill_switch")

    def reload_if_changed(self) -> bool:
        """Reload when the config file changed on disk (how a separate process picks up a switch)."""
        if self._file_mtime() == self._mtime:
            return False
        self.reload()
        return True

    @property
    def snapshot(self) -> LlmSnapshot:
        """The active snapshot. Pin it (store it) to keep using the same model later."""
        return self._snapshot

    @property
    def resolved(self) -> ResolvedLlmConfig:
        return self._resolved

    def _consent_status(self) -> dict[str, Any] | None:
        llm = self.settings.llm
        consent = self._resolved.file.consent if self._resolved.file is not None else None
        if consent is not None:
            return {"granted": True, "via": consent.accepted_via, "disclosure_version": consent.disclosure_version,
                    "accepted_at": consent.accepted_at.isoformat(), "allow_source_code": consent.allow_source_code}
        if llm.cloud_consent:
            return {"granted": True, "via": "env", "disclosure_version": llm.cloud_consent, "accepted_at": None,
                    "allow_source_code": llm.cloud_source_consent}
        return None

    def consent_on_record(self, key_fingerprint: str | None) -> bool:
        """Was consent to the current notice already recorded for the key with this fingerprint?
        Then re-entering that key (every run asks for it) needs no new consent."""
        consent = self._resolved.file.consent if self._resolved.file is not None else None
        return bool(key_fingerprint and consent is not None and consent.disclosure_version == DISCLOSURE_VERSION
                    and consent.key_fingerprint == key_fingerprint)

    def status(self) -> dict[str, Any]:
        """What is active and why — safe to show anywhere: the key appears only as fingerprint + last 4."""
        snap, res = self._snapshot, self._resolved
        stored = self.secrets.get()
        return {
            **snap.to_dict(),
            "managed_by": dict(res.managed_by),
            "allow_cloud": res.allow_cloud,
            "config_error": res.config_error,
            "config_path": str(self.config_path),
            "consent": self._consent_status(),
            "awaiting_key": self._awaiting_key,
            # the Gemini model chosen for Online mode (also while it waits for this run's key)
            "online_model": res.file.gemini.model if res.file is not None else None,
            "allow_source_code": self.allows_source_code(snap),
            "key": stored.describe() if stored is not None else {"configured": False},
            "disclosure_version": DISCLOSURE_VERSION,
        }

    # ------------------------------------------------------------------ calls
    def provider_for(self, snapshot: LlmSnapshot | None = None) -> LlmProvider:
        return self.registry.get((snapshot or self._snapshot).provider)

    def authorize(self, snapshot: LlmSnapshot) -> None:
        """Raise ``LlmError("revoked")`` if *snapshot* may no longer be used."""
        if snapshot.location == "local":
            return
        active = self._snapshot
        if not self._cloud.allowed or active.location != "cloud" or active.provider is not snapshot.provider:
            raise LlmError("revoked", "cloud processing is no longer enabled", provider=snapshot.provider.value)

    def allows_source_code(self, snapshot: LlmSnapshot) -> bool:
        """May the user's (masked) source code be sent to *snapshot*'s model? Always for a local model;
        for a cloud model only with the separate source-code consent (decision Q-3)."""
        if snapshot.location == "local":
            return True
        active = self._snapshot
        return (self._cloud.allowed and self._cloud.allow_source_code and active.location == "cloud"
                and active.provider is snapshot.provider)

    def structured(self, schema: type[BaseModel], snapshot: LlmSnapshot | None = None) -> Any:
        """A runnable producing *schema* from the active (or the given, pinned) model."""
        snap = snapshot or self._snapshot
        self.authorize(snap)
        return self.provider_for(snap).structured(snap, schema)

    def classify(self, exc: BaseException, snapshot: LlmSnapshot | None = None) -> LlmError:
        return self.provider_for(snapshot).classify(exc)

    async def health(self, snapshot: LlmSnapshot | None = None) -> ProviderHealth:
        snap = snapshot or self._snapshot
        return await self.provider_for(snap).health(snap)

    async def list_models(self, provider: ProviderId | None = None, credential: str | None = None) -> list[ModelInfo]:
        """The provider's models; *credential* is a candidate key (held in memory only), else the stored one."""
        return await self.registry.get(provider or self._snapshot.provider).list_models(credential)

    async def validate(self, provider: ProviderId, model: str, credential: str | None = None, *,
                       deep: bool = False) -> tuple[ValidationResult, str | None]:
        """Validate *model* (with a candidate key, if given). A success is remembered in memory for
        10 minutes under the returned id, which ``activate`` consumes once; nothing is written."""
        result = await self.registry.get(provider).validate(model, credential, deep=deep)
        if not result.ok:
            log.info("llm.validation_failed", provider=provider.value, model=model, kind=result.error_kind)
            if not self.read_only:
                self.audit.record("validation_failed", provider=provider.value, model=_norm(model), kind=result.error_kind)
            return result, None
        vid = self.validations.put(provider.value, _norm(model), credential, result.capabilities)
        log.info("llm.validated", provider=provider.value, model=model, capabilities=sorted(result.capabilities))
        return result, vid

    # ------------------------------------------------------------------ changes (LP6)
    def _check_writable(self) -> None:
        if self.read_only:
            raise ConfigRefused("read_only", "this AEGIS process may only read the model configuration")

    def _check_env(self, provider: ProviderId, model: str | None) -> None:
        llm, managed = self.settings.llm, self._resolved.managed_by
        if llm.provider is not None and llm.provider != provider.value:
            raise ConfigRefused("managed_by_environment",
                                f"the provider is set by AEGIS_LLM__PROVIDER={llm.provider}; change it there")
        if provider is ProviderId.gemini and llm.gemini_model and model and _norm(model) != _norm(llm.gemini_model):
            raise ConfigRefused("managed_by_environment",
                                f"the Gemini model is set by AEGIS_LLM__GEMINI__MODEL={llm.gemini_model}")
        if (provider is ProviderId.ollama and model and managed.get("ollama_model") == "env"
                and model != self.settings.model.name):
            raise ConfigRefused("managed_by_environment",
                                f"the local model is set by AEGIS_MODEL={self.settings.model.name}")

    def _base(self) -> LlmConfigFile:
        return read_config(self.config_path).config or LlmConfigFile()

    def _restore(self, cfg: LlmConfigFile | None) -> None:
        if cfg is None:
            self.config_path.unlink(missing_ok=True)
        else:
            write_config(self.config_path, cfg)

    async def activate(self, provider: ProviderId, model: str | None = None, *, validation_id: str | None = None,
                       consent: ConsentInput | None = None, actor: str = "api", client: str | None = None,
                       reason: str = "user") -> dict[str, Any]:
        """Make *provider*/*model* the active model. A cloud provider needs a fresh validation
        (``validation_id``, consumed once) and consent to the current privacy notice."""
        self._check_writable()
        if provider is ProviderId.ollama:
            return await self._activate_local(model, actor=actor, client=client, reason=reason)
        with self._lock:
            return self._activate_cloud(provider, model, validation_id, consent, actor, client)

    async def go_offline(self, *, actor: str = "api", client: str | None = None, reason: str = "user") -> dict[str, Any]:
        """Switch to the local model now. Needs nothing; revokes recorded consent."""
        self._check_writable()
        return await self._activate_local(None, actor=actor, client=client, reason=reason)

    async def _activate_local(self, model: str | None, *, actor: str, client: str | None, reason: str) -> dict[str, Any]:
        self._check_env(ProviderId.ollama, model)
        if model:
            result = await self.registry.get(ProviderId.ollama).validate(model)
            if not result.ok:
                raise ConfigRefused("invalid_request", result.error or f"{model} cannot be used")
        with self._lock:
            old = read_config(self.config_path).config
            base = old or LlmConfigFile()
            previous = self._snapshot
            write_config(self.config_path, base.model_copy(update={
                "generation": base.generation + 1, "provider": ProviderId.ollama,
                "ollama": OllamaSection(model=model or base.ollama.model), "consent": None,
                "updated_at": datetime.now(timezone.utc)}))
            self.reload()
            gen = self._snapshot.generation
            if base.consent is not None:
                self.audit.record("consent_revoked", actor=actor, client=client, reason=reason, generation=gen)
            if previous.location == "cloud":
                self.audit.record("provider_deactivated", actor=actor, client=client, reason=reason, generation=gen,
                                  provider="ollama", model=self._snapshot.model,
                                  previous_provider=previous.provider.value, previous_model=previous.model)
            else:
                self.audit.record("provider_activated", actor=actor, client=client, generation=gen, provider="ollama",
                                  model=self._snapshot.model, previous_provider=previous.provider.value,
                                  previous_model=previous.model)
        log.info("llm.offline" if previous.location == "cloud" else "llm.local_model", model=self._snapshot.model,
                 actor=actor, reason=reason)
        return self.status()

    def _activate_cloud(self, provider: ProviderId, model: str | None, validation_id: str | None,
                        consent: ConsentInput | None, actor: str, client: str | None) -> dict[str, Any]:
        self._check_env(provider, model)
        if not self.settings.llm.allow_cloud:
            raise ConfigRefused("cloud_disabled", "cloud processing is disabled on this install (AEGIS_LLM__ALLOW_CLOUD=false)")
        if not self.registry.available(provider):
            raise ConfigRefused("provider_unavailable", f"the {provider.value} provider is not installed "
                                                        "(pip install -e \".[gemini]\")")
        entry = self.validations.consume(validation_id) if validation_id else None
        if entry is None:
            raise ConfigRefused("validation_expired", "validate the model and key again "
                                                      "(a validation can be used once, within 10 minutes)")
        model = _norm(model or entry.model)
        if entry.provider != provider.value or _norm(entry.model) != model:
            raise ConfigRefused("invalid_request", f"that validation was for {entry.provider} {entry.model}")
        previous_key = self.secrets.get()
        if entry.key is not None:
            candidate_fp = fingerprint(entry.key.get_secret_value())
        else:
            candidate_fp = previous_key.fingerprint if previous_key is not None else None
        reused = None
        if consent is None and self.consent_on_record(candidate_fp):
            reused = self._resolved.file.consent   # the same key again (every run asks for it): consent stands
        elif consent is None or not consent.accepted:
            raise ConfigRefused("consent_required", "Online mode needs your agreement to the privacy notice")
        elif consent.disclosure_version != DISCLOSURE_VERSION:
            raise ConfigRefused("consent_required", f"the privacy notice changed: show version {DISCLOSURE_VERSION} "
                                                    "and ask again")

        key_changed, restore = False, None
        if entry.key is not None:
            candidate = entry.key.get_secret_value()
            if previous_key is None or previous_key.value.get_secret_value() != candidate:
                if self.secrets.managed_by_environment():
                    raise ConfigRefused("managed_by_environment", "the API key comes from AEGIS_LLM__GEMINI__API_KEY "
                                                                  "(or _FILE); change it there")
                try:
                    self.secrets.put(candidate)
                except LlmError as exc:
                    raise ConfigRefused("invalid_request", str(exc)) from None
                key_changed = True
                restore = previous_key if previous_key is not None and previous_key.source == "session" else None
        current = self.secrets.get()
        if current is None:
            raise ConfigRefused("invalid_request", "enter the Gemini API key for this session")

        def rollback_key() -> None:
            if key_changed:
                if restore is not None:
                    self.secrets.put(restore.value.get_secret_value())
                else:
                    self.secrets.delete()

        old = read_config(self.config_path).config
        base = old or LlmConfigFile()
        previous = self._snapshot
        now = datetime.now(timezone.utc)
        new = base.model_copy(update={
            "generation": base.generation + 1,
            "provider": provider,
            "gemini": GeminiSection(model=model, validated_at=now, capabilities=sorted(entry.capabilities),
                                    key_ref=KeyRef(source=current.source, fingerprint=current.fingerprint,
                                                   last4=current.last4)),
            "consent": reused or ConsentRecord(disclosure_version=DISCLOSURE_VERSION, accepted_at=now,
                                               accepted_via=_via(actor), allow_source_code=consent.allow_source_code,
                                               key_fingerprint=current.fingerprint),
            "updated_at": now,
        })
        try:
            write_config(self.config_path, new)
        except Exception:
            rollback_key()
            raise
        self.reload()
        if self._snapshot.provider is not provider:   # the policy refused what was just written: undo all of it
            problem = self._resolved.config_error
            self._restore(old)
            rollback_key()
            self.reload()
            raise ConfigRefused("invalid_request", f"Online mode could not be switched on: {problem}")

        gen = self._snapshot.generation
        if key_changed:
            self.audit.record("key_rotated" if previous_key is not None else "key_stored", actor=actor, client=client,
                              key_source=current.source, key_fingerprint=current.fingerprint,
                              previous_key_fingerprint=previous_key.fingerprint if previous_key else None)
        if reused is None:
            self.audit.record("consent_granted", actor=actor, client=client, generation=gen,
                              disclosure_version=DISCLOSURE_VERSION, allow_source_code=consent.allow_source_code,
                              key_fingerprint=current.fingerprint)
        self.audit.record("provider_activated", actor=actor, client=client, generation=gen, provider=provider.value,
                          model=model, previous_provider=previous.provider.value, previous_model=previous.model,
                          key_fingerprint=current.fingerprint)
        log.warning("llm.cloud_activated", provider=provider.value, model=model, actor=actor,
                    consent="reused" if reused is not None else "given", key=current.fingerprint)
        return self.status()

    async def forget_key(self, *, actor: str = "api", client: str | None = None) -> dict[str, Any]:
        """Forget this session's key (going offline first if it is in use)."""
        self._check_writable()
        if self.secrets.managed_by_environment():
            raise ConfigRefused("managed_by_environment", "the API key comes from AEGIS_LLM__GEMINI__API_KEY "
                                                          "(or _FILE); remove it there")
        if self._snapshot.location == "cloud":
            await self.go_offline(actor=actor, client=client, reason="key forgotten")
        with self._lock:
            stored = self.secrets.get()
            deleted = self.secrets.delete()
            cfg = read_config(self.config_path).config
            if cfg is not None and cfg.gemini.key_ref is not None:
                write_config(self.config_path, cfg.model_copy(update={
                    "generation": cfg.generation + 1, "gemini": cfg.gemini.model_copy(update={"key_ref": None}),
                    "updated_at": datetime.now(timezone.utc)}))
            self.reload()
            if deleted:
                self.audit.record("key_deleted", actor=actor, client=client,
                                  key_fingerprint=stored.fingerprint if stored else None)
        return self.status()
