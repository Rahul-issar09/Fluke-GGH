"""Trivy wrapper — see ``workers.code.dependencies`` (shared with OSV-Scanner)."""

from aegis.workers.code.dependencies import run_trivy

__all__ = ["run_trivy"]
