"""AEGIS configuration.

AG00.1 provides only the **logging section** needed by
:mod:`aegis.observability`. The full ``Settings`` object (model / scan /
safety / correlation / risk / gate / api / chat / mcp) is built in ST02
(PHASES P0.2 / STRUCTURE ST02) and will fold ``LoggingSettings`` into it.

Config keys (AG00.1): ``logging.level`` (default ``INFO``),
``logging.json`` (default ``true``). Env overrides follow the nested
delimiter convention used by the full settings:
``AEGIS_LOGGING__LEVEL`` and ``AEGIS_LOGGING__JSON``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = [
    "LoggingSettings",
    "get_logging_settings",
    "ModelSettings",
    "get_model_settings",
    "ApiSettings",
    "get_api_settings",
    "AppSettings",
    "get_app_settings",
    "GateSettings",
    "get_gate_settings",
    "ChatSettings",
    "get_chat_settings",
    "McpSettings",
    "get_mcp_settings",
]

_FALSEY = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class LoggingSettings:
    level: str = "INFO"
    json: bool = True


def get_logging_settings() -> LoggingSettings:
    """Read logging settings from the environment, with AG00.1 defaults."""
    level = os.getenv("AEGIS_LOGGING__LEVEL", "INFO")
    json_env = os.getenv("AEGIS_LOGGING__JSON")
    json = True if json_env is None else json_env.strip().lower() not in _FALSEY
    return LoggingSettings(level=level, json=json)


@dataclass(frozen=True)
class ModelSettings:
    """LLM (Ollama) settings. AG01.1 minimal slice; ST02 folds this into the
    full ``Settings.model`` section. Values match PRD §6.1 / SD §13."""

    name: str = "qwen2.5:7b"
    ollama_url: str = "http://ollama:11434"
    temperature: float = 0.1
    num_ctx: int = 8192


def get_model_settings() -> ModelSettings:
    """Read model settings from the environment, with AG01.1 defaults.

    Honours the SD §5.9 swap-the-model aliases ``AEGIS_MODEL`` and
    ``AEGIS_OLLAMA_URL`` as well as the nested-delimiter forms.
    """
    name = os.getenv("AEGIS_MODEL") or os.getenv("AEGIS_MODEL__NAME", "qwen2.5:7b")
    url = os.getenv("AEGIS_OLLAMA_URL") or os.getenv(
        "AEGIS_MODEL__OLLAMA_URL", "http://ollama:11434"
    )
    temp = float(os.getenv("AEGIS_MODEL__TEMPERATURE", "0.1"))
    num_ctx = int(os.getenv("AEGIS_MODEL__NUM_CTX", "8192"))
    return ModelSettings(name=name, ollama_url=url, temperature=temp, num_ctx=num_ctx)


@dataclass(frozen=True)
class ApiSettings:
    """REST surface settings. AG02.1 needs ``allowed_source_roots`` (GAP C35);
    ST02 folds this into the full ``Settings.api`` section."""

    allowed_source_roots: tuple[str, ...] = ("/scan",)
    max_body_bytes: int = 65536
    auth_token: str | None = None


def get_api_settings() -> ApiSettings:
    """Read API settings from the environment, with GAP defaults."""
    roots_env = os.getenv("AEGIS_API__ALLOWED_SOURCE_ROOTS")
    roots = (
        tuple(p for p in roots_env.split(os.pathsep) if p.strip())
        if roots_env
        else ("/scan",)
    )
    max_body = int(os.getenv("AEGIS_API__MAX_BODY_BYTES", "65536"))
    token = os.getenv("AEGIS_API__AUTH_TOKEN") or None
    return ApiSettings(allowed_source_roots=roots, max_body_bytes=max_body, auth_token=token)


@dataclass(frozen=True)
class GateSettings:
    """CI gate (SYSTEM_DESIGN §13 ``gate``): an open finding blocks when its OWASP category is
    in ``block_owasp`` and its risk is at least ``severity_threshold``."""

    severity_threshold: float = 0.7
    block_owasp: tuple[str, ...] = ("A01", "A02", "A03", "A10")
    warn_owasp: tuple[str, ...] = ("A04", "A09")


def get_gate_settings() -> GateSettings:
    block = os.getenv("AEGIS_GATE__BLOCK_OWASP")
    warn = os.getenv("AEGIS_GATE__WARN_OWASP")
    return GateSettings(
        severity_threshold=float(os.getenv("AEGIS_GATE__SEVERITY_THRESHOLD", "0.7")),
        block_owasp=_split_list(block) if block else GateSettings.block_owasp,
        warn_owasp=_split_list(warn) if warn else GateSettings.warn_owasp,
    )


@dataclass(frozen=True)
class ChatSettings:
    """Findings chatbot (RAG_PHASES Appendix B). Offline: a local embed model + a local Chroma
    index. All read-only; indexing runs in the background at finalize and never delays a scan."""

    enabled: bool = True
    embed_model: str = "nomic-embed-text"      # Ollama embedding model (RAG02)
    embed_dim: int = 768                        # nomic-embed-text = 768; bge-m3 = 1024
    chroma_path: str = "data/chroma"            # PersistentClient directory (RAG03)
    collection: str = "aegis_findings"          # one shared collection, isolated by scan_id
    dense_k: int = 10                           # dense candidates before fusion
    sparse_k: int = 10                          # sparse (BM25) candidates before fusion
    rrf_k: int = 60                             # reciprocal-rank-fusion constant (RAG05)
    final_k: int = 8                            # candidates kept after rerank (RAG06)
    max_findings_in_context: int = 5            # distinct findings in the generator context (RAG07)
    context_token_budget: int = 3000            # token ceiling for the context (RAG07)
    min_dense_similarity: float = 0.0           # below this, treat as "no match" (RAG11)
    min_term_coverage: float = 0.6              # share of a question's subject words found in the scan, else "no match" (RAG15); 0 disables
    index_timeout_s: float = 120.0              # bound on a background index job (RAG08)


def get_chat_settings() -> ChatSettings:
    enabled = os.getenv("AEGIS_CHAT__ENABLED")
    return ChatSettings(
        enabled=ChatSettings.enabled if enabled is None else enabled.strip().lower() not in _FALSEY,
        embed_model=os.getenv("AEGIS_CHAT__EMBED_MODEL", ChatSettings.embed_model),
        embed_dim=int(os.getenv("AEGIS_CHAT__EMBED_DIM", str(ChatSettings.embed_dim))),
        chroma_path=os.getenv("AEGIS_CHAT__CHROMA_PATH", ChatSettings.chroma_path),
        collection=os.getenv("AEGIS_CHAT__COLLECTION", ChatSettings.collection),
        dense_k=int(os.getenv("AEGIS_CHAT__DENSE_K", str(ChatSettings.dense_k))),
        sparse_k=int(os.getenv("AEGIS_CHAT__SPARSE_K", str(ChatSettings.sparse_k))),
        rrf_k=int(os.getenv("AEGIS_CHAT__RRF_K", str(ChatSettings.rrf_k))),
        final_k=int(os.getenv("AEGIS_CHAT__FINAL_K", str(ChatSettings.final_k))),
        max_findings_in_context=int(os.getenv("AEGIS_CHAT__MAX_FINDINGS", str(ChatSettings.max_findings_in_context))),
        context_token_budget=int(os.getenv("AEGIS_CHAT__CONTEXT_BUDGET", str(ChatSettings.context_token_budget))),
        min_dense_similarity=float(os.getenv("AEGIS_CHAT__MIN_SIMILARITY", str(ChatSettings.min_dense_similarity))),
        min_term_coverage=float(os.getenv("AEGIS_CHAT__MIN_TERM_COVERAGE", str(ChatSettings.min_term_coverage))),
        index_timeout_s=float(os.getenv("AEGIS_CHAT__INDEX_TIMEOUT_S", str(ChatSettings.index_timeout_s))),
    )


@dataclass(frozen=True)
class McpSettings:
    """The read-only MCP server (MCP_PHASES MCP00.1). ``AEGIS_MCP__ENABLED`` (the HTTP mount) stays
    on ``AppSettings.mcp_enabled``; these are the server's own knobs."""

    expose_raw_evidence: bool = False   # M-3: digests by default; raw payloads (still redacted) only when true
    max_list_limit: int = 100           # cap on list_findings results
    audit_path: str = "audit/mcp.jsonl"  # relative paths live under the data directory (M-4)
    ask_timeout_s: float = 120.0        # bound on one `ask` call (a local model can be slow)


def get_mcp_settings() -> McpSettings:
    raw = os.getenv("AEGIS_MCP__EXPOSE_RAW_EVIDENCE")
    return McpSettings(
        expose_raw_evidence=False if raw is None else raw.strip().lower() not in _FALSEY,
        max_list_limit=max(1, int(os.getenv("AEGIS_MCP__MAX_LIST_LIMIT", str(McpSettings.max_list_limit)))),
        audit_path=os.getenv("AEGIS_MCP__AUDIT_PATH", McpSettings.audit_path),
        ask_timeout_s=float(os.getenv("AEGIS_MCP__ASK_TIMEOUT_S", str(McpSettings.ask_timeout_s))),
    )


@dataclass(frozen=True)
class AppSettings:
    """What the backend process needs at startup (AG13.1). ST02 folds this into the full
    ``Settings`` object; until then each value has an ``AEGIS_*`` environment override."""

    data_dir: str = "data"  # SQLite DB, checkpoints, reports, fix workspaces, patches
    offline_db_dir: str = "offline-db"  # pre-staged OSV / Trivy / nuclei snapshots
    allowlist: tuple[str, ...] = ("demo-app:5000", "callback:8080")  # safety.allowlist
    callback_url: str = "http://callback:8080"  # safety.callback_url: the out-of-band listener
    # safety.git_hosts: hosts a repo scan may clone from (TNW-1); empty → repo scans are off
    git_hosts: tuple[str, ...] = ()
    clone_max_mb: int = 500  # a cloned repo's working tree larger than this is refused
    clone_keep_hours: float = 24.0  # a finished scan's clone is kept this long (for its fixes)
    patched_target_url: str | None = None  # pre-staged patched build for fix re-tests (SD §5.7)
    mcp_enabled: bool = False
    max_concurrent_scans: int = 1
    # requests per second to a scan target (AEGIS's own probes and Nuclei); raise it for your own
    # local test targets — a polite 5 makes Nuclei's profile take about 12 minutes
    rate_limit_rps: float = 5.0
    logging: LoggingSettings = LoggingSettings()
    model: ModelSettings = ModelSettings()
    api: ApiSettings = ApiSettings()
    gate: GateSettings = GateSettings()
    chat: ChatSettings = ChatSettings()


def _split_list(value: str) -> tuple[str, ...]:
    return tuple(p.strip() for p in value.replace(";", ",").split(",") if p.strip())


def get_app_settings() -> AppSettings:
    allow = os.getenv("AEGIS_SAFETY__ALLOWLIST")
    return AppSettings(
        data_dir=os.getenv("AEGIS_DATA_DIR", "data"),
        offline_db_dir=os.getenv("AEGIS_OFFLINE_DB_DIR", "offline-db"),
        allowlist=_split_list(allow) if allow else AppSettings.allowlist,
        callback_url=os.getenv("AEGIS_SAFETY__CALLBACK_URL", "http://callback:8080"),
        git_hosts=_split_list(os.getenv("AEGIS_SAFETY__GIT_HOSTS", "")),
        clone_max_mb=int(os.getenv("AEGIS_SAFETY__CLONE_MAX_MB", "500")),
        clone_keep_hours=float(os.getenv("AEGIS_SAFETY__CLONE_KEEP_HOURS", "24")),
        patched_target_url=os.getenv("AEGIS_FIX__PATCHED_TARGET_URL") or None,
        mcp_enabled=os.getenv("AEGIS_MCP__ENABLED", "false").strip().lower() not in _FALSEY,
        max_concurrent_scans=int(os.getenv("AEGIS_SCAN__MAX_CONCURRENT", "1")),
        rate_limit_rps=float(os.getenv("AEGIS_SCAN__RATE_LIMIT_RPS", "5")),
        logging=get_logging_settings(),
        model=get_model_settings(),
        api=get_api_settings(),
        gate=get_gate_settings(),
        chat=get_chat_settings(),
    )
