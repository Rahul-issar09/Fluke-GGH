"""Stage Nuclei and its templates for offline scans (TNW-3). Run ONCE, while online.

Downloads the pinned Nuclei release for this platform into ``.tools/nuclei`` and the pinned
``nuclei-templates`` release into ``offline-db/nuclei-templates``. Each download is checked against
the SHA-256 published with its release before anything is unpacked; a mismatch stops the script.
Scans never download templates or updates (Nuclei runs with ``-duc -ni``).

    python scripts/stage_nuclei.py [--tools-dir DIR] [--db-dir DIR]

To move to newer releases, change the versions and checksums below (from each release's
``*_checksums.txt``) and re-run.
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

NUCLEI_VERSION = "3.11.1"
NUCLEI_SHA256 = {
    "windows_amd64": "bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2",
    "linux_amd64": "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
    "linux_arm64": "8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07",
    "macOS_amd64": "75c47ce11e9dbd4288a1c895ed85e3c4df9f4acb8237d6d178da6dccd1628f2a",
    "macOS_arm64": "7d7e291addd1fc29a9bf8d089afe878a9799b20229cbea2fb1693fc40fd4c5f0",
}
TEMPLATES_VERSION = "10.5.0"
TEMPLATES_SHA256 = "dd836a827b4147d7d8294ca6a89526288ccb1a4bcc895dceac7af3563bc61775"

ROOT = Path(__file__).resolve().parent.parent


def _platform() -> str:
    system = {"Windows": "windows", "Linux": "linux", "Darwin": "macOS"}[platform.system()]
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    key = f"{system}_{arch}"
    if key not in NUCLEI_SHA256:
        sys.exit(f"no pinned Nuclei build for {key}")
    return key


def _download(url: str, dest: Path, sha256: str) -> None:
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as resp, open(dest, "wb") as out:
        shutil.copyfileobj(resp, out)
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    if digest != sha256:
        sys.exit(f"checksum mismatch for {dest.name}: got {digest}, expected {sha256}")
    print(f"  sha256 ok ({dest.stat().st_size // (1024 * 1024)} MB)")


def _extract(archive: Path, dest: Path, strip: int) -> int:
    """Unpack *archive* into *dest*, dropping *strip* leading path parts; refuse paths that escape."""
    dest = dest.resolve()
    count = 0
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            parts = Path(info.filename).parts[strip:]
            if info.is_dir() or not parts:
                continue
            target = (dest / Path(*parts)).resolve()
            if not target.is_relative_to(dest):
                sys.exit(f"unsafe path in {archive.name}: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(info))
            if info.external_attr >> 16 & 0o111:
                target.chmod(0o755)
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tools-dir", default=str(ROOT / ".tools" / "nuclei"))
    parser.add_argument("--db-dir", default=str(ROOT / "offline-db"))
    args = parser.parse_args()
    tools, db = Path(args.tools_dir), Path(args.db_dir)
    key = _platform()

    with tempfile.TemporaryDirectory(prefix="aegis-stage-nuclei-") as tmp:
        tmp = Path(tmp)
        binary_zip = tmp / f"nuclei_{NUCLEI_VERSION}_{key}.zip"
        _download(
            f"https://github.com/projectdiscovery/nuclei/releases/download/v{NUCLEI_VERSION}/{binary_zip.name}",
            binary_zip, NUCLEI_SHA256[key],
        )
        templates_zip = tmp / f"nuclei-templates-{TEMPLATES_VERSION}.zip"
        _download(
            f"https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v{TEMPLATES_VERSION}.zip",
            templates_zip, TEMPLATES_SHA256,
        )
        shutil.rmtree(tools, ignore_errors=True)
        print(f"nuclei: {_extract(binary_zip, tools, 0)} files -> {tools}")
        templates = db / "nuclei-templates"
        shutil.rmtree(templates, ignore_errors=True)
        print(f"templates: {_extract(templates_zip, templates, 1)} files -> {templates}")

    (db / "nuclei_stage.log").write_text(
        f"nuclei v{NUCLEI_VERSION} {key} sha256 {NUCLEI_SHA256[key]}\n"
        f"nuclei-templates v{TEMPLATES_VERSION} sha256 {TEMPLATES_SHA256}\n",
        encoding="utf-8",
    )
    print("done")


if __name__ == "__main__":
    main()
