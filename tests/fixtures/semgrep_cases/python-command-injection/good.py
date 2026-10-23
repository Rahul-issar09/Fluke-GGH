import os
import subprocess

from fastapi import APIRouter

router = APIRouter()


@router.get("/ping")
def ping(host: str):
    # an argument list without a shell: the input is one argument, never a command
    return subprocess.run(["ping", "-c", "1", host], capture_output=True)


@router.get("/uptime")
def uptime():
    return os.system("uptime")
