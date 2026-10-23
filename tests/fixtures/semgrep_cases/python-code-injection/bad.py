from fastapi import APIRouter

router = APIRouter()


@router.get("/calc")
def calc(expr: str):
    return {"result": eval(expr)}  # ruleid: python-code-injection


@router.post("/run")
def run(script: str):
    code = "result = " + script
    exec(code)  # ruleid: python-code-injection
