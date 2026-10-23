"""Request/response models of ``/api/llm/*`` (LLM_PROVIDER_PHASES §8.2).

Kept out of :mod:`aegis.api.schemas` on purpose: that module is a frozen contract (ST03). A key is
only ever *received* — as ``SecretStr``, so it never appears in a ``repr``, a log line or a
validation-error message — and never returned: responses carry a fingerprint and the last four
characters at most.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

__all__ = [
    "ActivateRequest", "ConsentIn", "DiscoverRequest", "LlmConfigOut", "ModelOut", "ModelsOut",
    "ProviderOut", "TestOut", "ValidateOut", "ValidateRequest",
]

MODEL = Field(pattern=r"^[A-Za-z0-9._:/-]{1,128}$", description="Model id, e.g. qwen2.5:7b or gemini-2.5-flash")
API_KEY = Field(None, min_length=20, max_length=200, json_schema_extra={"format": "password"},
                description="A Gemini API key for this request only; omit to use the key entered in this session")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class ProviderOut(BaseModel):
    id: Literal["ollama", "gemini"]
    name: str
    location: Literal["local", "cloud"]
    installed: bool
    allowed: bool
    active: bool
    needs_key: bool
    reason: str | None = None


class ModelOut(BaseModel):
    id: str
    display_name: str
    stage: str
    thinking: bool | None = None
    input_token_limit: int | None = None
    output_token_limit: int | None = None
    capabilities: list[str] = Field(default_factory=list)


class ModelsOut(BaseModel):
    provider: Literal["ollama", "gemini"]
    models: list[ModelOut]


class DiscoverRequest(_Strict):
    provider: Literal["ollama", "gemini"] = "gemini"
    api_key: SecretStr | None = API_KEY


class ValidateRequest(_Strict):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True,
                              json_schema_extra={"examples": [{"provider": "gemini", "model": "gemini-2.5-flash",
                                                               "api_key": "<your Gemini API key>"}]})

    provider: Literal["ollama", "gemini"]
    model: str = MODEL
    api_key: SecretStr | None = API_KEY
    deep: bool = Field(False, description="Also try every AEGIS answer format (a few more calls)")


class ValidateOut(BaseModel):
    ok: bool
    validation_id: str | None = Field(None, description="Use once, within 10 minutes, to activate")
    capabilities: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    consent_on_record: bool = Field(False, description="Consent was already given for this key and the current "
                                                       "privacy notice: activation may omit it")
    disclosure: dict[str, Any] = Field(default_factory=dict, description="The privacy notice to show before activating")


class ConsentIn(_Strict):
    disclosure_version: str = Field(min_length=1, max_length=64)
    accepted: bool
    allow_source_code: bool = False


class ActivateRequest(_Strict):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True,
                              json_schema_extra={"examples": [{"provider": "ollama"},
                                                              {"provider": "gemini", "model": "gemini-2.5-flash",
                                                               "validation_id": "<from POST /api/llm/validate>",
                                                               "consent": {"disclosure_version": "<shown version>",
                                                                           "accepted": True}}]})

    provider: Literal["ollama", "gemini"]
    model: str | None = Field(None, pattern=r"^[A-Za-z0-9._:/-]{1,128}$")
    validation_id: str | None = Field(None, max_length=64)
    consent: ConsentIn | None = None


class LlmConfigOut(BaseModel):
    provider: str
    model: str
    location: Literal["local", "cloud"]
    generation: int
    managed_by: dict[str, str]
    allow_cloud: bool
    config_error: str | None = None
    awaiting_key: bool
    online_model: str | None = Field(None, description="The Gemini model chosen for Online mode")
    key: dict[str, Any]
    consent: dict[str, Any] | None = None
    allow_source_code: bool
    disclosure: dict[str, Any]
    embeddings: dict[str, Any]


class TestOut(BaseModel):
    __test__ = False   # not a pytest test class
    ok: bool
    provider: str
    model: str
    error_kind: str | None = None
    error: str | None = None
