"""Vulnerable dependencies and misconfiguration (Worker 2, AG14 / PHASES P7.6): OSV-Scanner + Trivy.

Both read the project's manifests (``requirements.txt``, lockfiles, …) and match the pinned
versions against a **pre-staged offline database** (``<offline_db_dir>/osv``,
``<offline_db_dir>/trivy`` — see ``scripts/stage_offline``); neither touches the network. Trivy
also checks configuration files such as Dockerfiles with its built-in checks.

Results are normalized to one record per vulnerable *package version* (advisory IDs grouped) and
one per misconfiguration, with paths relative to the source and the manifest line of the package,
so the two scanners' findings for the same package land on the same finding.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePath

from aegis.observability import get_logger
from aegis.safety.models import ToolCall

__all__ = ["DependencyScanUnavailable", "normalize_osv", "normalize_trivy", "package_line", "run_osv", "run_trivy"]

log = get_logger("workers.code.dependencies")


class DependencyScanUnavailable(RuntimeError):
    pass


def _relative(path: str, root: Path) -> str:
    p = PurePath(path)
    if p.is_absolute():
        try:
            return Path(p).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return p.as_posix()
    rel = p.as_posix()
    return rel[2:] if rel.startswith("./") else rel


def _norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def package_line(root: Path, manifest: str, package: str) -> int | None:
    """The line of *manifest* that declares *package* (PEP 503 name matching), if any."""
    try:
        lines = (root / manifest).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    want = _norm_name(package)
    for n, line in enumerate(lines, 1):
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if m and not line.lstrip().startswith("#") and _norm_name(m.group(1)) == want:
            return n
    return None


_SEVERITY_LABELS = {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"}


def _osv_severity_labels(vuln: dict) -> set[str]:
    """Severity labels OSV records for a vulnerability, as written (no CVSS parsing, no invention)."""
    labels: set[str] = set()
    specific = vuln.get("database_specific") or {}
    if isinstance(specific.get("severity"), str) and specific["severity"].upper() in _SEVERITY_LABELS:
        labels.add(specific["severity"].upper())
    for affected in vuln.get("affected") or []:
        eco = (affected.get("database_specific") or {}).get("severity")
        if isinstance(eco, str) and eco.upper() in _SEVERITY_LABELS:
            labels.add(eco.upper())
    return labels


def _fixed_versions(vuln: dict) -> list[str]:
    fixed = []
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            fixed += [e["fixed"] for e in rng.get("events") or [] if e.get("fixed")]
    return sorted(set(fixed))


def normalize_osv(report: dict, root: Path) -> list[dict]:
    out = []
    for result in (report or {}).get("results") or []:
        manifest = _relative(((result.get("source") or {}).get("path")) or "", root)
        for pkg in result.get("packages") or []:
            vulns = pkg.get("vulnerabilities") or []
            if not vulns:
                continue
            name, version = pkg["package"]["name"], pkg["package"].get("version")
            out.append({
                "package": name,
                "version": version,
                "ecosystem": pkg["package"].get("ecosystem"),
                "manifest": manifest,
                "line": package_line(root, manifest, name),
                "advisories": sorted({v["id"] for v in vulns}),
                "aliases": sorted({a for v in vulns for a in v.get("aliases") or []}),
                "fixed_in": sorted({f for v in vulns for f in _fixed_versions(v)}),
                "severities": sorted({s for v in vulns for s in _osv_severity_labels(v)}),
                "summaries": sorted({(v.get("summary") or "").strip() for v in vulns} - {""})[:5],
            })
    return out


def normalize_trivy(report: dict, root: Path) -> tuple[list[dict], list[dict]]:
    """``(vulnerable packages, misconfigurations)``."""
    packages: dict[tuple[str, str, str], dict] = {}
    misconfigs: list[dict] = []
    for result in (report or {}).get("Results") or []:
        target = _relative(result.get("Target") or "", root)
        for v in result.get("Vulnerabilities") or []:
            key = (target, v.get("PkgName", ""), v.get("InstalledVersion", ""))
            row = packages.setdefault(key, {
                "package": key[1], "version": key[2], "ecosystem": result.get("Type"), "manifest": target,
                "line": package_line(root, target, key[1]), "advisories": set(), "fixed_in": set(), "severities": set(),
            })
            row["advisories"].add(v.get("VulnerabilityID"))
            if v.get("FixedVersion"):
                row["fixed_in"].update(x.strip() for x in str(v["FixedVersion"]).split(","))
            if v.get("Severity"):
                row["severities"].add(v["Severity"])
        for m in result.get("Misconfigurations") or []:
            if (m.get("Status") or "FAIL") != "FAIL":
                continue
            misconfigs.append({
                "check": m.get("ID") or m.get("AVDID"),
                "title": m.get("Title"),
                "severity": m.get("Severity"),
                "message": m.get("Message"),
                "resolution": m.get("Resolution"),
                "file": target,
                "line": (m.get("CauseMetadata") or {}).get("StartLine") or None,
            })
    vulns = [{**r, "advisories": sorted(r["advisories"] - {None}), "fixed_in": sorted(r["fixed_in"]), "severities": sorted(r["severities"])} for r in packages.values()]
    return vulns, misconfigs


async def _run(controller, tool: str, scan_id: str, root: Path, db_dir: Path):
    result = await controller.run(ToolCall(tool=tool, scan_id=scan_id, args={"path": str(root), "db_dir": str(db_dir)}))
    if result.blocked_reason:
        raise DependencyScanUnavailable(result.blocked_reason)
    if not result.ok:
        tail = (result.stderr_tail or "").strip()
        # osv exits non-zero when the repo has no dependency manifest it recognises — that is
        # "nothing to scan", not a failure (common for repos without a lockfile; TNW-7)
        if tool == "osv" and "No package sources found" in tail:
            log.info("osv.no_manifests", scan_id=scan_id)
            return {}
        raise DependencyScanUnavailable(f"{tool} failed: {tail[:200]}")
    return result.output if isinstance(result.output, dict) else {}


async def run_osv(controller, scan_id: str, source_root: str | Path, db_dir: str | Path) -> list[dict]:
    root = Path(source_root)
    found = normalize_osv(await _run(controller, "osv", scan_id, root, Path(db_dir)), root)
    log.info("osv.done", scan_id=scan_id, vulnerable_packages=[f"{f['package']}@{f['version']}" for f in found])
    return found


async def run_trivy(controller, scan_id: str, source_root: str | Path, db_dir: str | Path) -> tuple[list[dict], list[dict]]:
    root = Path(source_root)
    vulns, misconfigs = normalize_trivy(await _run(controller, "trivy", scan_id, root, Path(db_dir)), root)
    log.info("trivy.done", scan_id=scan_id, vulnerable_packages=len(vulns), misconfigs=[m["check"] for m in misconfigs])
    return vulns, misconfigs
