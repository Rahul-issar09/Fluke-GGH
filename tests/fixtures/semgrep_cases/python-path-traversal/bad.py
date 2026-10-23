from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()

BASE = "/srv/files/"


@router.get("/download")
def download(name: str):
    return FileResponse(BASE + name)  # ruleid: python-path-traversal


@router.get("/read")
def read(path: str):
    with open(path) as fh:  # ruleid: python-path-traversal
        return fh.read()
