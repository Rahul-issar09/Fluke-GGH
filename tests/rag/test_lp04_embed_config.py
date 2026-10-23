"""LP4 — embeddings are configured on their own, stay local, and an LLM switch never touches the index."""

from __future__ import annotations

import hashlib
import pathlib

import pytest
from fastapi.testclient import TestClient

from aegis.api.main import create_app
from aegis.chat.chroma_store import ChromaStore
from aegis.chat.embedder import EmbeddingUnavailable, OllamaEmbedder, make_embedder
from aegis.chat.indexer import index_scan
from aegis.config import AppSettings, ChatSettings, ModelSettings, get_app_settings, get_chat_settings, resolve_chat_settings
from aegis.llm.config_store import LlmConfigFile, OllamaSection, config_path, write_config
from aegis.llm.manager import ProviderManager
from aegis.services.chat_service import ChatService
from fakes.fake_embedder import FakeEmbedder
from fakes.fake_llm import FakeLLM

pytestmark = pytest.mark.phase("LP4")

DIM = 64
ENV = ("AEGIS_CHAT__EMBED_MODEL", "AEGIS_CHAT__EMBED_DIM", "AEGIS_CHAT__EMBED_URL", "AEGIS_OLLAMA_URL",
       "AEGIS_MODEL__OLLAMA_URL")


@pytest.fixture
def clean_env(monkeypatch):
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


# ---------------------------------------------------------------- defaults (decision Q-8)
def test_defaults_are_bge_m3_on_this_machine(clean_env):
    chat, model = get_chat_settings(), get_app_settings().model
    assert (chat.embed_model, chat.embed_dim, chat.embed_url) == ("bge-m3", 1024, None)
    assert model.ollama_url == "http://127.0.0.1:11434" == ModelSettings().ollama_url


def test_the_embedding_url_follows_the_ollama_url_unless_set(clean_env, tmp_path):
    settings = AppSettings(data_dir=str(tmp_path), model=ModelSettings(ollama_url="http://10.0.0.5:11434"))
    chat = resolve_chat_settings(settings)
    assert chat.embed_url == "http://10.0.0.5:11434"
    assert chat.chroma_path == str(tmp_path / "chroma")
    clean_env.setenv("AEGIS_CHAT__EMBED_URL", "http://10.0.0.9:11434")
    settings = AppSettings(data_dir=str(tmp_path), model=ModelSettings(ollama_url="http://10.0.0.5:11434"),
                           chat=get_chat_settings())
    assert resolve_chat_settings(settings).embed_url == "http://10.0.0.9:11434"


def test_the_embedder_uses_the_embedding_url_not_the_llm_url():
    emb = make_embedder(ChatSettings(embed_url="http://10.0.0.9:11434"), "http://10.0.0.5:11434")
    assert isinstance(emb, OllamaEmbedder) and emb._base_url == "http://10.0.0.9:11434"
    legacy = make_embedder(ChatSettings(), "http://10.0.0.5:11434")   # no embedding URL: the old argument
    assert legacy._base_url == "http://10.0.0.5:11434"


async def test_a_public_embedding_url_is_refused_and_nothing_is_sent():
    emb = make_embedder(ChatSettings(embed_url="http://8.8.8.8:11434"), "", guard=True)
    with pytest.raises(EmbeddingUnavailable, match="local"):
        await emb.embed_query("anything")
    with pytest.raises(EmbeddingUnavailable):
        await emb.embed_documents(["anything"])


# ---------------------------------------------------------------- switching the LLM leaves the index alone
def _fingerprint(chroma_dir: pathlib.Path, chroma: ChromaStore, scan_id: str) -> tuple:
    manifest = (chroma_dir / "aegis_index.json").read_bytes()
    rows = chroma._col.get(where={"scan_id": scan_id}, include=["embeddings"])
    vectors = hashlib.sha256(repr([list(map(float, v)) for v in rows["embeddings"]]).encode()).hexdigest()
    return manifest, chroma.count(), sorted(rows["ids"]), vectors


async def test_switching_the_llm_never_touches_the_embedding_index(store, tmp_path):
    s = store.add_scan("code")
    f = store.add_finding(s.id, type="sqli", owasp="A03", title="SQL injection in search", file="app/search.py", line=3)
    store.add_evidence(s.id, "code_location", "semgrep", payload={"file": "app/search.py", "line": 3}, finding_id=f.id)
    store.update_finding_fields(f.id, what="SQL injection in search", impact="the database can be read")
    chroma_dir = tmp_path / "chroma"
    chroma = ChromaStore(str(chroma_dir))
    embedder = FakeEmbedder(DIM)
    await index_scan(store, chroma, embedder, s.id)
    before = _fingerprint(chroma_dir, chroma, s.id)

    manager = ProviderManager(AppSettings(data_dir=str(tmp_path)), tmp_path, environ={})
    write_config(config_path(tmp_path), LlmConfigFile(generation=1, ollama=OllamaSection(model="llama3")))
    svc = ChatService(store, ChatSettings(embed_dim=DIM, min_dense_similarity=0.0, min_term_coverage=0.0),
                      embedder=embedder, chroma=chroma, llm=FakeLLM([ConnectionError("down")]), llm_manager=manager)
    await svc.ask(s.id, "why is the SQL injection a risk?")

    assert manager.snapshot.model == "llama3"            # the LLM did switch
    assert _fingerprint(chroma_dir, chroma, s.id) == before


# ---------------------------------------------------------------- health
def test_health_has_an_embeddings_block(tmp_path, clean_env):
    settings = AppSettings(data_dir=str(tmp_path / "data"), offline_db_dir=str(tmp_path / "offline-db"),
                           model=ModelSettings(ollama_url="http://127.0.0.1:9"))
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8000", raise_server_exceptions=False) as c:
        emb = c.get("/api/health").json()["embeddings"]
    assert (emb["provider"], emb["location"], emb["model"], emb["dim"]) == ("ollama", "local", "bge-m3", 1024)
    assert emb["url"] == "http://127.0.0.1:9" and emb["reachable"] is False
    assert emb["index"] == {"model": None, "dim": None, "adopted": None, "compatible": None,
                            "reason": "no index record yet (written by the next index or reindex)"}
