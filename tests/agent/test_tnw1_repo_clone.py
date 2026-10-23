"""TNW-1 — scanning a GitHub repo: a shallow https clone through the SafetyController.

* the repo URL rules (https only, no credentials, no query, no odd paths),
* the git policy and the controller (the clone must declare the repo's host, which must be an
  allowed git host),
* the fixed ``git clone`` command line (no hooks, no user/system config, no submodules),
* the clone worker (commit recorded, ``.git`` removed, size limit, readable errors),
* pruning old clones, request validation, and a whole repo scan over HTTP.

No network: ``git clone`` is replaced by a stand-in that writes a repository folder (with the
``.git`` files a real shallow clone has). ``test_real_clone_of_a_public_repo`` clones for real
when ``AEGIS_TEST_NETWORK=1`` is set.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.api.main import create_app
from aegis.api.schemas import ScanRequest
from aegis.config import ApiSettings, AppSettings, ModelSettings
from aegis.evidence.models import ScanStatus
from aegis.router import RequestInvalid, prepare_source, validate_request
from aegis.safety.allowlist import Allowlist
from aegis.safety.controller import SafetyController
from aegis.safety.models import ToolCall, ToolResult
from aegis.safety.policies import PolicyError, required_target, validate_args
from aegis.safety.repo_url import parse_repo_url
from aegis.safety.test_inputs import TestInputLibrary
from aegis.workers.code.clone import CloneError, clone_repo, make_clone_fn, prune_clones, read_commit
from aegis.workers.executor import BUILDERS, execute_tool
from fakes.demo_apps import ROOT
from fakes.tool_executors import fix_executor

pytestmark = pytest.mark.phase("TNW-1")

REPO = "https://github.com/acme/demo-app"
SHA = "3f2c" + "a" * 36


# --------------------------------------------------------------------------------------------- #
# a stand-in for `git clone`: writes what a real shallow clone leaves on disk
# --------------------------------------------------------------------------------------------- #
def write_clone(dest: Path, files: dict[str, str] | None = None, source: Path | None = None) -> None:
    if source is not None:
        shutil.copytree(source, dest)
    else:
        dest.mkdir()
        for name, text in (files or {"README.md": "hello\n"}).items():
            (dest / name).parent.mkdir(parents=True, exist_ok=True)
            (dest / name).write_text(text, encoding="utf-8")
    git = dest / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "objects" / "pack").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git / "refs" / "heads" / "main").write_text(SHA + "\n", encoding="utf-8")
    (git / "shallow").write_text(SHA + "\n", encoding="utf-8")
    pack = git / "objects" / "pack" / "pack-1.pack"
    pack.write_bytes(b"PACK")
    os.chmod(pack, stat.S_IREAD)  # git writes packs read-only


def clone_standin(calls: list, *, source: Path | None = None, files=None, fail: str | None = None):
    async def executor(call: ToolCall, args: dict, inputs: list[str]) -> ToolResult:
        if call.tool != "git" or args.get("op") != "clone":
            return await fix_executor(call, args, inputs)
        calls.append((call.target_host, args))
        if fail:
            return ToolResult(ok=False, tool="git", exit_code=128, stderr_tail=fail)
        write_clone(Path(args["dest"]), files=files, source=source)
        return ToolResult(ok=True, tool="git", exit_code=0)

    return executor


def controller(executor, hosts=("github.com:443",)) -> SafetyController:
    return SafetyController(Allowlist(hosts), TestInputLibrary.load(), executor=executor)


# --------------------------------------------------------------------------------------------- #
# repo URLs
# --------------------------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url, target, name",
    [
        ("https://github.com/acme/demo-app", "github.com:443", "acme/demo-app"),
        ("https://github.com/acme/demo-app.git", "github.com:443", "acme/demo-app"),
        ("https://GitLab.com/group/sub/proj/", "gitlab.com:443", "group/sub/proj"),
        ("https://git.internal:8443/team/svc", "git.internal:8443", "team/svc"),
    ],
)
def test_accepted_repo_urls(url, target, name):
    parsed = parse_repo_url(url)
    assert (parsed.target, parsed.name) == (target, name)


@pytest.mark.parametrize(
    "url, why",
    [
        ("http://github.com/acme/app", "https://"),
        ("git@github.com:acme/app.git", "https://"),
        ("ssh://github.com/acme/app", "https://"),
        ("file:///C:/repos/app", "https://"),
        ("ext::sh -c touch% /tmp/pwned", "not allowed"),
        ("https://user:token@github.com/acme/app", "user name or token"),
        ("https://github.com/acme/app?ref=x", "query"),
        ("https://github.com/acme/app#main", "query"),
        ("https://github.com/acme", "name a repository"),
        ("https://github.com/acme/../other/app", "path part"),
        ("https://github.com/acme/-upload-pack=x", "path part"),
        ("https://github.com/acme/app name", "not allowed"),
        ("https://exa_mple.com/acme/app", "invalid host"),
        ("", "empty"),
    ],
)
def test_refused_repo_urls(url, why):
    with pytest.raises(ValueError, match=why):
        parse_repo_url(url)


# --------------------------------------------------------------------------------------------- #
# policy + controller
# --------------------------------------------------------------------------------------------- #
def test_the_clone_policy(tmp_path):
    dest = str(tmp_path / "aegis-S-0001")
    ok = validate_args("git", {"op": "clone", "repo": REPO, "dest": dest})
    assert ok["depth"] == 1 and required_target("git", ok) == "github.com:443"
    bad = [
        ({"op": "clone", "repo": REPO, "dest": dest, "depth": 50}, "shallow"),
        ({"op": "clone", "repo": REPO, "dest": "relative/dir"}, "absolute"),
        ({"op": "clone", "repo": REPO, "dest": str(tmp_path)}, "must not exist"),
        ({"op": "clone", "repo": REPO, "dest": str(tmp_path / "no" / "parent")}, "parent"),
        ({"op": "clone", "repo": "git@github.com:a/b", "dest": dest}, "https"),
        ({"op": "clone", "repo": REPO, "dest": dest, "patch": "p"}, "patch/workdir"),
        ({"op": "clone", "repo": REPO, "dest": dest, "branch": "x"}, "Extra inputs"),
    ]
    for args, why in bad:
        with pytest.raises(PolicyError, match=why):
            validate_args("git", args)
    assert required_target("git", {"op": "apply_check"}) is None


@pytest.mark.parametrize(
    "target, hosts, reason",
    [
        (None, ("github.com:443",), "target_host must be github.com:443"),
        ("demo-app:5000", ("demo-app:5000",), "target_host must be github.com:443"),
        ("github.com:443", ("gitlab.com:443",), "host not allowlisted"),
    ],
)
def test_the_controller_only_clones_from_an_allowed_git_host(tmp_path, target, hosts, reason):
    calls: list = []
    call = ToolCall(tool="git", scan_id="S-0001", target_host=target,
                    args={"op": "clone", "repo": REPO, "dest": str(tmp_path / "d")})
    result = asyncio.run(controller(clone_standin(calls), hosts).run(call))
    assert not result.ok and reason in result.blocked_reason
    assert calls == []  # nothing ran


def test_the_clone_command_line(tmp_path):
    dest = tmp_path / "aegis-S-0001"
    spec = BUILDERS["git"]({"op": "clone", "repo": REPO, "dest": str(dest), "depth": 1})
    argv = spec.argv
    clone = argv.index("clone")
    assert argv[0] == "git" and argv[clone:] == [
        "clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules",
        "--template=", "--quiet", "--", REPO, str(dest),
    ]
    config = [argv[i + 1] for i in range(clone) if argv[i] == "-c"]
    for setting in ("protocol.allow=never", "protocol.https.allow=always", "http.followRedirects=false", "credential.helper="):
        assert setting in config
    assert spec.env["GIT_TERMINAL_PROMPT"] == "0" and spec.env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert spec.env["GIT_CONFIG_GLOBAL"] == os.devnull and spec.env["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert spec.cwd == str(tmp_path) and spec.timeout >= 60


# --------------------------------------------------------------------------------------------- #
# the clone worker
# --------------------------------------------------------------------------------------------- #
def test_a_relative_tmp_root_is_resolved_before_the_clone(tmp_path, monkeypatch):
    # TNW-7: the launcher runs with AEGIS_DATA_DIR=data, so tmp_root arrives relative; the clone
    # policy requires an absolute dest, so prepare_source must resolve it first
    monkeypatch.chdir(tmp_path)
    calls: list = []
    clone_fn = make_clone_fn(("github.com:443",), executor=clone_standin(calls))
    prep = asyncio.run(prepare_source(repo=REPO, scan_id="S-0001", clone_fn=clone_fn, tmp_root="data/clones"))
    assert calls and Path(calls[0][1]["dest"]).is_absolute()
    assert Path(prep["source_path"]).is_dir() and prep["repo"]["commit"] == SHA


def test_a_clone_records_the_commit_and_drops_git(tmp_path):
    calls: list = []
    dest = tmp_path / "aegis-S-0001"
    info = asyncio.run(clone_repo(controller(clone_standin(calls, files={"app.py": "x = 1\n", "lib/u.py": "y\n"})), "S-0001", REPO, dest))
    assert calls[0][0] == "github.com:443"
    assert info == {**info, "commit": SHA, "branch": "main", "name": "acme/demo-app", "files": 2}
    assert not (dest / ".git").exists() and (dest / "lib" / "u.py").is_file()


def test_read_commit_from_packed_refs_and_detached_head(tmp_path):
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/dev\n", encoding="utf-8")
    (git / "packed-refs").write_text(f"# pack-refs with: peeled\n{SHA} refs/heads/dev\n", encoding="utf-8")
    assert read_commit(git) == SHA
    (git / "HEAD").write_text(SHA + "\n", encoding="utf-8")
    assert read_commit(git) == SHA
    assert read_commit(tmp_path / "missing") is None


def test_a_too_large_repo_is_refused_and_removed(tmp_path):
    calls: list = []
    clone_fn = make_clone_fn(("github.com:443",), executor=clone_standin(calls, files={"big.bin": "x" * 5000}), max_bytes=1000)
    with pytest.raises(CloneError, match="too large"):
        asyncio.run(prepare_source(repo=REPO, scan_id="S-0001", clone_fn=clone_fn, tmp_root=str(tmp_path)))
    assert not (tmp_path / "aegis-S-0001").exists()


def test_clone_failures_say_why(tmp_path):
    calls: list = []
    not_allowed = make_clone_fn(("gitlab.com:443",), executor=clone_standin(calls))
    with pytest.raises(CloneError, match="add github.com:443 to AEGIS_SAFETY__GIT_HOSTS"):
        asyncio.run(not_allowed(REPO, str(tmp_path / "a"), "S-0001"))
    missing = make_clone_fn(("github.com:443",), executor=clone_standin(calls, fail="remote: Repository not found."))
    with pytest.raises(CloneError, match="Repository not found"):
        asyncio.run(missing(REPO, str(tmp_path / "b"), "S-0002"))
    assert len(calls) == 1  # the refused host never reached git


def test_old_and_failed_clones_are_pruned(store, tmp_path):
    root = tmp_path / "clones"
    now = datetime.now(timezone.utc)

    def scan(status, finished=None):
        s = store.add_scan(mode="code", status=status, repo_url=REPO, config_json="{}")
        if finished is not None:
            store.update_scan(s.id, finished_at=finished)
        (root / f"aegis-{s.id}").mkdir(parents=True)
        write_clone(root / f"aegis-{s.id}" / "repo")  # read-only files inside, too
        return s.id

    running = scan(ScanStatus.running)
    recent = scan(ScanStatus.completed, now - timedelta(hours=1))
    old = scan(ScanStatus.completed, now - timedelta(hours=30))
    failed = scan(ScanStatus.failed, now)
    (root / "aegis-S-9999").mkdir()  # no such scan
    (root / "aegis-gitleaks-abc").mkdir()  # not a clone folder: never touched
    removed = prune_clones(root, store, keep_hours=24, now=now)
    assert sorted(removed) == sorted([old, failed, "S-9999"])
    assert sorted(p.name for p in root.iterdir()) == sorted([f"aegis-{running}", f"aegis-{recent}", "aegis-gitleaks-abc"])


# --------------------------------------------------------------------------------------------- #
# request validation
# --------------------------------------------------------------------------------------------- #
def test_repo_requests_are_checked_up_front():
    validate_request(ScanRequest(repo=REPO), git_hosts=("github.com:443",))
    validate_request(ScanRequest(repo=REPO))  # no git hosts given → only the URL is checked here
    with pytest.raises(RequestInvalid, match="AEGIS_SAFETY__GIT_HOSTS"):
        validate_request(ScanRequest(repo=REPO), git_hosts=())
    with pytest.raises(RequestInvalid, match="https://"):
        validate_request(ScanRequest(repo="git@github.com:acme/app.git"), git_hosts=("github.com:443",))


# --------------------------------------------------------------------------------------------- #
# a whole repo scan over HTTP
# --------------------------------------------------------------------------------------------- #
def _app(tmp_path, calls, git_hosts=("github.com:443",)) -> TestClient:
    settings = AppSettings(
        data_dir=str(tmp_path / "data"),
        offline_db_dir=str(tmp_path / "offline-db"),
        allowlist=("demo-app:5000",),
        git_hosts=git_hosts,
        model=ModelSettings(ollama_url="http://127.0.0.1:9"),
        api=ApiSettings(allowed_source_roots=(str(tmp_path / "src"),)),
    )
    overrides = dict(tool_executor=clone_standin(calls, source=ROOT / "demo-app"), rate_limit_rps=1000.0, rate_limit_burst=1000)
    return TestClient(create_app(settings, agent_overrides=overrides), base_url="http://127.0.0.1:8000", raise_server_exceptions=False)


def _wait(c: TestClient, scan_id: str, timeout: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = c.get(f"/api/scans/{scan_id}").json()
        if body["status"] not in ("queued", "running"):
            return body
        time.sleep(0.1)
    raise AssertionError(f"scan {scan_id} did not finish")


def test_a_repo_scan_over_http(tmp_path):
    calls: list = []
    with _app(tmp_path, calls) as c:
        health = c.get("/api/health").json()
        assert health["repo_scans"] == {"enabled": True, "git_hosts": ["github.com:443"]}

        assert c.post("/api/scans", json={"repo": "https://gitlab.com/acme/app"}).status_code == 422
        started = c.post("/api/scans", json={"repo": REPO})
        assert started.status_code == 202, started.text
        scan_id = started.json()["scan_id"]
        scan = _wait(c, scan_id)
        assert scan["status"] == "completed" and scan["mode"] == "code"

        assert calls and calls[0][0] == "github.com:443"
        clone = tmp_path / "data" / "clones" / f"aegis-{scan_id}"
        assert clone.is_dir() and not (clone / ".git").exists()  # kept for the fixes, without .git

        findings = c.get("/api/findings", params={"scan_id": scan_id}).json()
        types = {f["type"] for f in findings["items"]} if isinstance(findings, dict) else {f["type"] for f in findings}
        assert {"sqli", "secret"} <= types

        report = c.get("/api/reports", params={"scan_id": scan_id, "format": "json"}).json()
        assert report["scan"]["repo_url"] == REPO and report["scan"]["repo_commit"] == SHA
        html = c.get("/api/reports", params={"scan_id": scan_id, "format": "html"}).text
        assert REPO in html and SHA[:12] in html

        audit = c.get(f"/api/scans/{scan_id}/audit").json()
        git_calls = [t for t in audit["tool_calls"] if t["tool"] == "git"]
        assert git_calls and git_calls[0]["target_host"] == "github.com:443"


def test_repo_scans_are_off_without_git_hosts(tmp_path):
    with _app(tmp_path, [], git_hosts=()) as c:
        assert c.get("/api/health").json()["repo_scans"]["enabled"] is False
        resp = c.post("/api/scans", json={"repo": REPO})
        assert resp.status_code == 422 and "AEGIS_SAFETY__GIT_HOSTS" in resp.text


# --------------------------------------------------------------------------------------------- #
# a real clone (network; opt-in)
# --------------------------------------------------------------------------------------------- #
@pytest.mark.tools
@pytest.mark.skipif(os.environ.get("AEGIS_TEST_NETWORK") != "1", reason="set AEGIS_TEST_NETWORK=1 to clone from github.com")
def test_real_clone_of_a_public_repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    clone_fn = make_clone_fn(("github.com:443",), executor=execute_tool)
    info = asyncio.run(clone_fn("https://github.com/octocat/Hello-World", str(tmp_path / "aegis-S-0001"), "S-0001"))
    assert info["commit"] and len(info["commit"]) == 40 and info["files"] >= 1
    assert (tmp_path / "aegis-S-0001" / "README").is_file()
    assert not (tmp_path / "aegis-S-0001" / ".git").exists()
