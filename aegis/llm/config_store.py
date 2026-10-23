"""The persisted LLM configuration and how it combines with the environment (LLM_PROVIDER_PHASES §6).

``<data_dir>/config/llm.json`` holds the **non-secret** choice: which provider is active, the
model per provider, the consent record and a reference to where the key lives (its source and
fingerprint — never the key: the schema has no field that could hold one, and unknown fields are
refused).

Precedence, highest first: environment variables → this file → built-in defaults. A field set
by the environment is reported as ``managed_by: "env"`` and the API will refuse to change it.

Fail-closed: a file that cannot be read, is not valid JSON, has an unknown ``schema_version``
or fails validation is ignored as a whole; the result is the offline provider plus a
``config_error`` explaining why. A broken file never selects a cloud provider. Validation
messages never echo values from the file (in case something secret was pasted into it).

Writes are atomic (temp file → fsync → ``os.replace``) so a reader — the MCP server, another
process — never sees half a file. The ``config/`` folder is created on the first write only, so
read-only users (the MCP server) never create anything.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegis.config import AppSettings
from aegis.llm.base import ProviderId

__all__ = [
    "CONFIG_FILE",
    "SCHEMA_VERSION",
    "ConsentRecord",
    "GeminiSection",
    "KeyRef",
    "LlmConfigFile",
    "OllamaSection",
    "ReadResult",
    "ResolvedLlmConfig",
    "config_path",
    "read_config",
    "resolve",
    "write_config",
]

SCHEMA_VERSION = 1
CONFIG_FILE = Path("config") / "llm.json"
MODEL_PATTERN = r"^[A-Za-z0-9._:/-]{1,128}$"

# environment names that pin the Ollama model (``get_model_settings`` reads the same two)
_OLLAMA_MODEL_ENV = ("AEGIS_MODEL", "AEGIS_MODEL__NAME")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OllamaSection(_Strict):
    model: str | None = Field(None, pattern=MODEL_PATTERN)


class KeyRef(_Strict):
    """Where the Gemini key lives and how to recognise it — never the key itself."""

    source: Literal["session", "env", "file"]   # never stored: "session" means "entered this run"
    fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{8,64}$")
    last4: str | None = Field(None, pattern=r"^[A-Za-z0-9_-]{4}$")


class GeminiSection(_Strict):
    model: str | None = Field(None, pattern=MODEL_PATTERN)
    validated_at: datetime | None = None
    capabilities: list[str] = Field(default_factory=list)
    key_ref: KeyRef | None = None


class ConsentRecord(_Strict):
    disclosure_version: str = Field(min_length=1, max_length=64)
    accepted_at: datetime
    accepted_via: Literal["ui", "cli", "api"]
    allow_source_code: bool = False
    # the key the consent was given with (LP6): a different key needs a new validation and consent
    key_fingerprint: str | None = Field(None, pattern=r"^sha256:[0-9a-f]{8,64}$")


class LlmConfigFile(_Strict):
    schema_version: Literal[1] = SCHEMA_VERSION
    generation: int = Field(0, ge=0)
    provider: ProviderId = ProviderId.ollama
    ollama: OllamaSection = Field(default_factory=OllamaSection)
    gemini: GeminiSection = Field(default_factory=GeminiSection)
    consent: ConsentRecord | None = None
    updated_at: datetime | None = None


@dataclass(frozen=True)
class ReadResult:
    config: LlmConfigFile | None = None   # None: no file, or a file that was refused
    error: str | None = None              # why the file was refused (no values from it)


@dataclass(frozen=True)
class ResolvedLlmConfig:
    """The configuration in effect after precedence and fail-closed rules."""

    provider: ProviderId
    model: str
    generation: int
    allow_cloud: bool
    managed_by: dict[str, str] = field(default_factory=dict)  # field -> "env" | "file" | "default"
    config_error: str | None = None
    file: LlmConfigFile | None = None
    ollama_model: str = ""   # the offline model, so a later refusal can always fall back to it


def config_path(data_dir: str | Path) -> Path:
    return Path(data_dir) / CONFIG_FILE


def _describe(exc: ValidationError) -> str:
    """Field paths and messages only — ``include_input=False`` keeps file values out of the text."""
    parts = []
    for err in exc.errors(include_input=False, include_url=False)[:3]:
        loc = ".".join(str(p) for p in err.get("loc", ())) or "(file)"
        parts.append(f"{loc}: {err.get('msg')}")
    return "; ".join(parts)


def read_config(path: str | Path) -> ReadResult:
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ReadResult()
    except OSError as exc:
        return ReadResult(error=f"cannot read {path.name} ({type(exc).__name__})")
    try:
        data = json.loads(raw)
    except ValueError:
        return ReadResult(error=f"{path.name} is not valid JSON")
    if not isinstance(data, dict):
        return ReadResult(error=f"{path.name} must hold a JSON object")
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        shown = version if isinstance(version, int) else type(version).__name__
        return ReadResult(error=f"{path.name} has unsupported schema_version {shown} (expected {SCHEMA_VERSION})")
    try:
        return ReadResult(config=LlmConfigFile.model_validate(data))
    except ValidationError as exc:
        return ReadResult(error=f"{path.name} is invalid: {_describe(exc)}")


def write_config(path: str | Path, cfg: LlmConfigFile, *, attempts: int = 5) -> None:
    """Atomically replace *path* with *cfg*. Creates the folder if needed (the first write)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    body = cfg.model_dump_json(indent=2) + "\n"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)
        fh.flush()
        os.fsync(fh.fileno())
    if os.name == "posix":
        os.chmod(tmp, 0o600)
    for attempt in range(attempts):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:  # Windows: a reader has the file open for a moment
            if attempt == attempts - 1:
                tmp.unlink(missing_ok=True)
                raise
            time.sleep(0.05 * (attempt + 1))


def _env_set(environ: Mapping[str, str], *names: str) -> bool:
    return any((environ.get(n) or "").strip() for n in names)


def resolve(settings: AppSettings, read: ReadResult, *, environ: Mapping[str, str] | None = None,
            available: Callable[[ProviderId], bool] | None = None) -> ResolvedLlmConfig:
    """Combine environment, file and defaults (§6.2), failing closed to the offline provider.

    *available* says whether a provider can be built in this install (the Gemini extra may be
    missing); an unavailable provider falls back to offline like any other refusal.
    """
    env = os.environ if environ is None else environ
    llm = settings.llm
    cfg = read.config
    managed: dict[str, str] = {}
    errors: list[str] = [read.error] if read.error else []

    if llm.provider is not None:
        provider, managed["provider"] = ProviderId(llm.provider), "env"
    elif cfg is not None:
        provider, managed["provider"] = cfg.provider, "file"
    else:
        provider, managed["provider"] = ProviderId.ollama, "default"

    if _env_set(env, *_OLLAMA_MODEL_ENV):
        ollama_model, managed["ollama_model"] = settings.model.name, "env"
    elif cfg is not None and cfg.ollama.model:
        ollama_model, managed["ollama_model"] = cfg.ollama.model, "file"
    else:
        ollama_model, managed["ollama_model"] = settings.model.name, "default"

    gemini_model: str | None = None
    if llm.gemini_model:
        gemini_model, managed["gemini_model"] = llm.gemini_model, "env"
    elif cfg is not None and cfg.gemini.model:
        gemini_model, managed["gemini_model"] = cfg.gemini.model, "file"

    model = ollama_model
    if provider is ProviderId.gemini:
        refusal = None
        if available is not None and not available(provider):
            refusal = "the gemini provider is not available in this install"
        elif not llm.allow_cloud:
            refusal = "cloud processing is disabled (AEGIS_LLM__ALLOW_CLOUD=false)"
        elif not gemini_model:
            refusal = "Gemini is selected but no Gemini model is configured"
        elif not llm.cloud_consent and (cfg is None or cfg.consent is None):
            # sending findings to a cloud model needs consent (§9.2) — recorded by activation, or the
            # operator's AEGIS_LLM__CLOUD_CONSENT; its details are checked by aegis.llm.policy
            refusal = "cloud processing needs recorded consent, and none has been given"
        if refusal:
            errors.append(f"{refusal}; using the offline provider")
            provider, managed["provider"] = ProviderId.ollama, "default"
        else:
            model = gemini_model

    return ResolvedLlmConfig(
        provider=provider,
        model=model,
        generation=cfg.generation if cfg is not None else 0,
        allow_cloud=llm.allow_cloud,
        managed_by=managed,
        config_error="; ".join(errors) or None,
        file=cfg,
        ollama_model=ollama_model,
    )
