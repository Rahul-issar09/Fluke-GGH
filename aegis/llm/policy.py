"""May AEGIS use a cloud model right now? (LLM_PROVIDER_PHASES §9.2, §9.5)

``CloudPolicy.evaluate`` is consulted every time the configuration is (re)loaded. A cloud provider
stays active only while **all** of these hold, otherwise AEGIS falls back to Offline and says why:

* the kill-switch allows cloud processing (``AEGIS_LLM__ALLOW_CLOUD``, default true);
* consent was given **to the current privacy notice** (``DISCLOSURE_VERSION``) — recorded by
  activation, or given by the operator through ``AEGIS_LLM__CLOUD_CONSENT=<version>``;
* an API key is available, and — for recorded consent — it is **the same key** the consent was
  given with (its fingerprint): a key swapped outside AEGIS needs a new validation and consent.

Whether source code may be sent is part of the same decision (``allow_source_code``).

:class:`ConfigRefused` is how a configuration *change* is refused (activation, forgetting a key);
its ``code`` is the machine-readable reason the API maps to an HTTP status.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.config import AppSettings
from aegis.llm.config_store import ResolvedLlmConfig
from aegis.llm.consent import DISCLOSURE_VERSION
from aegis.llm.secrets import SecretStore

__all__ = ["CloudDecision", "CloudPolicy", "ConfigRefused"]


class ConfigRefused(Exception):
    """A configuration change that is not allowed (the message says what to do instead)."""

    CODES = ("managed_by_environment", "cloud_disabled", "consent_required", "validation_expired",
             "read_only", "provider_unavailable", "invalid_request")

    def __init__(self, code: str, message: str):
        if code not in self.CODES:
            raise ValueError(f"unknown refusal code {code!r}")
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CloudDecision:
    allowed: bool
    reason: str | None = None
    allow_source_code: bool = False
    consent_via: str | None = None        # "ui" / "cli" / "api" (recorded) or "env" (operator)
    key_fingerprint: str | None = None
    missing_key: bool = False             # Online mode is chosen, but this run's key was not entered yet


class CloudPolicy:
    def __init__(self, settings: AppSettings, secrets: SecretStore):
        self.settings = settings
        self.secrets = secrets

    def evaluate(self, resolved: ResolvedLlmConfig) -> CloudDecision:
        llm = self.settings.llm
        if not llm.allow_cloud:
            return CloudDecision(False, "cloud processing is disabled (AEGIS_LLM__ALLOW_CLOUD=false)")
        key = self.secrets.get()
        if key is None:   # decision Q-4: the key is asked for every run and never saved
            return CloudDecision(False, "enter the Gemini API key for this session (AEGIS asks for it every run "
                                        "and never saves it)", missing_key=True)

        if llm.cloud_consent:   # the operator agreed for this install (headless use)
            if llm.cloud_consent != DISCLOSURE_VERSION:
                return CloudDecision(False, f"AEGIS_LLM__CLOUD_CONSENT agrees to notice {llm.cloud_consent!r}, but the "
                                            f"current notice is {DISCLOSURE_VERSION!r}: read it and set the new version")
            return CloudDecision(True, allow_source_code=llm.cloud_source_consent, consent_via="env",
                                 key_fingerprint=key.fingerprint)

        consent = resolved.file.consent if resolved.file is not None else None
        if consent is None:
            return CloudDecision(False, "cloud processing needs recorded consent, and none has been given")
        if consent.disclosure_version != DISCLOSURE_VERSION:
            return CloudDecision(False, f"the privacy notice changed since consent was given "
                                        f"({consent.disclosure_version} -> {DISCLOSURE_VERSION}): agree again")
        if consent.key_fingerprint != key.fingerprint:
            return CloudDecision(False, "the API key changed since consent was given: validate it and agree again")
        return CloudDecision(True, allow_source_code=consent.allow_source_code, consent_via=consent.accepted_via,
                             key_fingerprint=key.fingerprint)
