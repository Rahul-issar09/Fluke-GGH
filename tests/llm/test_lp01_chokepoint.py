"""LP1 — the architecture stays honest: one place builds model clients, one place imports a cloud SDK.

Inventory (LLM_PROVIDER_PHASES §3.1, after LP2–LP10): every model call goes through
``aegis.agent.llm.structured_call`` → ``ProviderManager.structured`` → a provider in
``aegis/llm/providers/``. These guards fail if new code builds a chat client somewhere else (which
would bypass the provider choice, consent and the kill-switch) or imports the Google SDK outside the
Gemini provider (which would put it on the offline path).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.phase("LP1")

AEGIS = Path(__file__).resolve().parents[2] / "aegis"
CLIENT_CLASSES = {"ChatOllama", "ChatGoogleGenerativeAI", "OllamaLLM", "GenerativeModel"}
CLOUD_SDKS = ("google.genai", "google.generativeai", "langchain_google_genai", "google.ai")


def _modules():
    for py in sorted(AEGIS.rglob("*.py")):
        if "__pycache__" not in py.parts:
            yield py, ast.parse(py.read_text(encoding="utf-8"))


def _rel(py: Path) -> str:
    return py.relative_to(AEGIS.parent).as_posix()


def test_only_providers_build_chat_clients():
    offenders = []
    for py, tree in _modules():
        if _rel(py).startswith("aegis/llm/providers/"):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
                if name in CLIENT_CLASSES or (name == "Client" and "genai" in ast.unparse(node.func)):
                    offenders.append(f"{_rel(py)}:{node.lineno} {name}(...)")
    assert offenders == [], offenders


def test_only_the_gemini_provider_imports_a_cloud_sdk():
    offenders = []
    for py, tree in _modules():
        if _rel(py) == "aegis/llm/providers/gemini.py":
            continue
        for node in ast.walk(tree):
            names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                     else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            offenders += [f"{_rel(py)}:{node.lineno} {n}" for n in names if n.startswith(CLOUD_SDKS)]
    assert offenders == [], offenders


def test_every_model_call_goes_through_structured_call_with_a_manager_route():
    """The call sites pass the route (llm/settings/manager/snapshot/scope) — never a bare client."""
    sites = {"aegis/agent/nodes/explain.py", "aegis/agent/nodes/investigate.py", "aegis/agent/nodes/remediate.py",
             "aegis/chat/retriever.py", "aegis/secure_prompt/service.py"}
    found = set()
    for py, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "structured_call":
                found.add(_rel(py))
                keywords = {k.arg for k in node.keywords}
                assert None in keywords or "manager" in keywords, f"{_rel(py)}:{node.lineno} has no manager route"
    assert found == sites, found ^ sites
