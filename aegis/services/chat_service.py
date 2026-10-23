"""ChatService (RAG12) — the one read-only entry point for the findings chatbot.

Routes each question (RAG09) to the structured path (RAG10, no model) or the explain path (RAG11,
model + retrieval), and maps the result to the API's ``AskOut``. Read-only: it only reads the store
and its own Chroma index. The retrieval stack (Chroma + embedder + sparse) is built lazily on the
first explain question and reused; if chat is disabled, or the vector store can't be opened, it
degrades to the structured answer or a plain "no finding matches" rather than failing.
"""

from __future__ import annotations

from aegis.api.schemas import AskOut
from aegis.chat.router import route
from aegis.chat.schemas import Answer
from aegis.chat.structured import NO_MATCH, answer_structured
from aegis.observability import get_logger

__all__ = ["ChatService"]

log = get_logger("chat.service")


class ChatService:
    def __init__(self, store, chat_settings, *, ollama_url: str = "", model_settings=None,
                 embedder=None, chroma=None, sparse=None, llm=None):
        self._store = store
        self._settings = chat_settings
        self._ollama_url = ollama_url
        self._model_settings = model_settings
        self._llm = llm
        self._cache = {"embedder": embedder, "chroma": chroma, "sparse": sparse}

    def _retrieval(self):
        """(chroma, embedder, sparse) — built once; ``(None, …)`` if the vector store can't open."""
        if self._cache["chroma"] is None:
            try:
                from aegis.chat.chroma_store import ChromaStore

                self._cache["chroma"] = ChromaStore(self._settings.chroma_path, self._settings.collection)
            except Exception as exc:  # noqa: BLE001 - chromadb missing / corrupt dir: chat degrades, never 500s
                log.warning("chat.retrieval_unavailable", error=f"{type(exc).__name__}: {str(exc)[:160]}")
                return None, None, None
        if self._cache["embedder"] is None:
            from aegis.chat.embedder import make_embedder

            self._cache["embedder"] = make_embedder(self._settings, self._ollama_url)
        if self._cache["sparse"] is None:
            from aegis.chat.sparse import SparseRetriever

            self._cache["sparse"] = SparseRetriever(self._cache["chroma"])
        return self._cache["chroma"], self._cache["embedder"], self._cache["sparse"]

    async def ask(self, scan_id: str, question: str) -> AskOut:
        """Answer one question about one scan's findings (read-only)."""
        if not self._settings.enabled:
            return Answer(text=NO_MATCH).to_askout()

        decision = route(question, scan_id)
        if decision.path == "structured":
            ans = answer_structured(self._store, decision.filter)
            log.info("chat.ask", scan_id=scan_id, path="structured", findings=len(ans.finding_ids))
            return ans.to_askout()

        chroma, embedder, sparse = self._retrieval()
        if chroma is None:  # retrieval not available → best-effort structured answer
            ans = answer_structured(self._store, decision.filter)
            log.info("chat.ask", scan_id=scan_id, path="structured_fallback", findings=len(ans.finding_ids))
            return ans.to_askout()

        from aegis.chat.retriever import answer_explain

        ans = await answer_explain(
            self._store, chroma, embedder, sparse, scan_id, question,
            filt=decision.filter, settings=self._settings, llm=self._llm, model_settings=self._model_settings,
        )
        log.info("chat.ask", scan_id=scan_id, path="explain", findings=len(ans.finding_ids), evidence=len(ans.evidence_ids))
        return ans.to_askout()
