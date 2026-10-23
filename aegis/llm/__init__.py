"""Model providers behind AEGIS's LLM calls (LLM_PROVIDER_PHASES.md).

``base`` (the contract), ``config_store`` (the persisted, non-secret choice and its precedence),
``registry`` (which providers this install can build), ``manager`` (the active model) and
``providers/`` (the adapters — the only code that builds a chat-model client).
"""
