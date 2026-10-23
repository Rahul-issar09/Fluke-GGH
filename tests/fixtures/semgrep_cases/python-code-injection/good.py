import ast

from fastapi import APIRouter

router = APIRouter()


@router.get("/calc")
def calc(expr: str):
    # literal_eval only accepts literals, never code
    return {"result": ast.literal_eval(expr)}


def constant():
    return eval("1 + 1")
