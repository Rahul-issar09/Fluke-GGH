"""``POST /api/ask`` (FASTAPI FA07.1, RAG12.2) — ask about a scan's findings.

Read-only. Delegates to :class:`ChatService`, which routes the question to the structured path
(counts / lists / look-ups, no model) or the explain path (hybrid retrieval + a cited answer). The
scan must exist (404 otherwise); a question with no matching findings returns the stable
"no finding matches" answer with empty citations, never an error.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from aegis.api.deps import get_chat_service, get_scan_service
from aegis.api.schemas import AskOut, AskRequest, ErrorOut
from aegis.services.chat_service import ChatService
from aegis.services.scan_service import ScanService

router = APIRouter(prefix="/api", tags=["ask"])


@router.post(
    "/ask",
    summary="Ask about a scan's findings",
    response_model=AskOut,
    responses={404: {"model": ErrorOut}},
)
async def ask(
    body: AskRequest,
    scans: ScanService = Depends(get_scan_service),
    chat: ChatService = Depends(get_chat_service),
) -> AskOut:
    scans.is_finished(body.scan_id)  # 404 for an unknown scan
    return await chat.ask(body.scan_id, body.question)
