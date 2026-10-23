"""Account routes — INTENTIONALLY VULNERABLE (planted IDOR / broken access control)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..auth import current_user

router = APIRouter()

_SELECT = (
    "SELECT a.id, a.owner_id, u.username AS owner, a.account_number, a.balance "
    "FROM accounts a JOIN users u ON u.id = a.owner_id"
)


def _row(r) -> dict:
    return {
        "id": r["id"],
        "owner_id": r["owner_id"],
        "owner": r["owner"],
        "account_number": r["account_number"],
        "balance": r["balance"],
    }


@router.get("/api/accounts")
def list_accounts(request: Request):
    user = current_user(request)
    rows = request.app.state.db.execute(_SELECT + " WHERE a.owner_id = ?", (user["id"],)).fetchall()
    return [_row(r) for r in rows]


@router.get("/api/accounts/{id}")
def get_account(id: int, request: Request):
    current_user(request)  # authenticated, but...
    # PLANTED WEAKNESS (IDOR): no check that the account belongs to the caller.
    row = request.app.state.db.execute(_SELECT + " WHERE a.id = ?", (id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="account not found")
    return _row(row)
