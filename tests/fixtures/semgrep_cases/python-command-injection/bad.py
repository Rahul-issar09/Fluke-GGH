import os
import subprocess

from fastapi import APIRouter

router = APIRouter()


@router.get("/ping")
def ping(host: str):
    return os.system("ping -c 1 " + host)  # ruleid: python-command-injection


@router.get("/lookup")
def lookup(name: str):
    cmd = f"nslookup {name}"
    return subprocess.run(cmd, shell=True, capture_output=True)  # ruleid: python-command-injection
