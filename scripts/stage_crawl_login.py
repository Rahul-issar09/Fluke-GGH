"""Stage Katana and Playwright for offline scans (TNW-4). Run ONCE, while online.

* Katana (the crawler for apps without an OpenAPI document): the pinned release for this platform
  into ``.tools/katana``, checked against the SHA-256 published with the release before unpacking.
* Playwright (browser logins): the pinned Python package into the running interpreter (run this
  with the project's ``.venv`` Python) and its headless Chromium into ``.tools/ms-playwright``,
  where AEGIS looks for it.

    .venv\\Scripts\\python.exe scripts\\stage_crawl_login.py
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

KATANA_VERSION = "1.8.0"
KATANA_SHA256 = {
    "windows_amd64": "8013253e3092e08524527a5c3f7ebd70747acc4bb51414858f8e6dffeb17f907",
    "linux_amd64": "cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2",
    "linux_arm64": "80e269210727a855511ffac8dfb01297b2344742acec71a35e8ba4a67a90f0f2",
    "macOS_amd64": "806256316dd45e0fe0e3985fd7283ddffc376c95cbaa3dcfd14cde6e1de61aaf",
    "macOS_arm64": "52e9802e9f83012a089fe57fb1ac476b936f181ac033c71bfa55f913c07cede6",
}
PLAYWRIGHT_VERSION = "1.63.0"

ROOT = Path(__file__).resolve().parent.parent


def _platform() -> str:
    system = {"Windows": "windows", "Linux": "linux", "Darwin": "macOS"}[platform.system()]
    arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "amd64"
    key = f"{system}_{arch}"
    if key not in KATANA_SHA256:
        sys.exit(f"no pinned Katana build for {key}")
    return key


def stage_katana(dest: Path) -> None:
    key = _platform()
    name = f"katana_{KATANA_VERSION}_{key}.zip"
    with tempfile.TemporaryDirectory(prefix="aegis-stage-katana-") as tmp:
        archive = Path(tmp) / name
        url = f"https://github.com/projectdiscovery/katana/releases/download/v{KATANA_VERSION}/{name}"
        print(f"downloading {url}")
        with urllib.request.urlopen(url, timeout=120) as resp, open(archive, "wb") as out:
            shutil.copyfileobj(resp, out)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != KATANA_SHA256[key]:
            sys.exit(f"checksum mismatch for {name}: got {digest}")
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True)
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                target = (dest / info.filename).resolve()
                if info.is_dir() or not target.is_relative_to(dest.resolve()):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(info))
                if info.external_attr >> 16 & 0o111:
                    target.chmod(0o755)
    print(f"katana v{KATANA_VERSION} -> {dest} (sha256 ok)")


def stage_playwright(browsers: Path) -> None:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", f"playwright=={PLAYWRIGHT_VERSION}"], check=True)
    env = {**os.environ, "PLAYWRIGHT_BROWSERS_PATH": str(browsers)}
    subprocess.run([sys.executable, "-m", "playwright", "install", "chromium-headless-shell"], check=True, env=env)
    print(f"playwright {PLAYWRIGHT_VERSION} + headless Chromium -> {browsers}")


if __name__ == "__main__":
    stage_katana(ROOT / ".tools" / "katana")
    stage_playwright(ROOT / ".tools" / "ms-playwright")
