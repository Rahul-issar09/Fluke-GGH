import os

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()

BASE = "/srv/files/"


@router.get("/download")
def download(name: str):
    # only the bare file name is used, so "../" cannot leave the folder
    return FileResponse(BASE + os.path.basename(name))


@router.get("/readme")
def readme():
    with open("README.md") as fh:
        return fh.read()
