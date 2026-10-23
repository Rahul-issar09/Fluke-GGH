"""AG05.2 — real route_mode / prepare / plan nodes."""

from __future__ import annotations

import asyncio
import json
import pathlib

import pytest

from _graph_helpers import make_run
from aegis.agent.deps import AgentDeps, MissingDeps
from aegis.agent.graph import build_aegis_graph
from aegis.agent.nodes.plan import plan
from aegis.agent.nodes.prepare import prepare, snapshot_db_dates
from aegis.agent.nodes.route_mode import route_mode
from aegis.agent.state import ScanInputs
from aegis.evidence.models import Mode
from aegis.router import RepoScanUnavailable

pytestmark = pytest.mark.phase("AG05")


# --- route_mode ------------------------------------------------------------ #
@pytest.mark.parametrize(
    "inputs,expected",
    [
        (ScanInputs(url="http://demo-app:5000", identities="/id"), Mode.runtime),
        (ScanInputs(folder="/scan"), Mode.code),
        (ScanInputs(repo="https://x/y"), Mode.code),
        (ScanInputs(url="http://demo-app:5000", folder="/scan", identities="/id"), Mode.correlated),
    ],
)
def test_route_mode_derives_mode_from_inputs(inputs, expected):
    out = route_mode({"scan_id": "S-0001", "inputs": inputs})
    assert out["mode"] is expected
    assert out["completed_stages"] == ["route_mode"]


def test_route_mode_keeps_state_mode_without_inputs():
    out = route_mode({"scan_id": "S-0001", "inputs": ScanInputs(), "mode": Mode.code})
    assert out["mode"] is Mode.code


def test_route_mode_without_inputs_or_mode_raises():
    with pytest.raises(ValueError):
        route_mode({"scan_id": "S-0001", "inputs": ScanInputs()})


# --- plan ------------------------------------------------------------------ #
@pytest.mark.parametrize(
    "mode,expected",
    [
        (Mode.runtime, ["runtime"]),
        (Mode.code, ["code", "crypto"]),
        (Mode.correlated, ["runtime", "code", "crypto"]),
    ],
)
def test_plan_per_mode(mode, expected):
    out = plan({"scan_id": "S-0001", "mode": mode})
    assert out["plan"] == expected


# --- prepare: folder ------------------------------------------------------- #
def test_prepare_folder_persists_scan_fields(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.code)
    asyncio.run(prepare(state, config))

    scan = store.get_scan(scan_id)
    assert scan.source_path == str(tmp_path / "scan")
    cfg = json.loads(scan.config_json)
    assert cfg["source_cleanup"] is False
    assert "demo-app:5000" in cfg["allowlist"] and "callback:8080" in cfg["allowlist"]
    assert set(json.loads(scan.db_snapshot_dates)) == {"osv", "trivy", "nuclei"}


def test_prepare_registers_target_host_in_allowlist(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    state["inputs"] = ScanInputs(url="https://api.internal:8443", identities="/id")
    asyncio.run(prepare(state, config))
    cfg = json.loads(store.get_scan(scan_id).config_json)
    assert "api.internal:8443" in cfg["allowlist"]


def test_prepare_does_not_write_into_user_folder(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.code)
    before = sorted(p.name for p in (tmp_path / "scan").iterdir())
    asyncio.run(prepare(state, config))
    assert sorted(p.name for p in (tmp_path / "scan").iterdir()) == before


# --- prepare: repo clone --------------------------------------------------- #
def test_prepare_repo_clone_marks_cleanup(store, tmp_path):
    def fake_clone(repo: str, dest: str, scan_id: str) -> None:
        pathlib.Path(dest).mkdir(parents=True)

    scan_id, state, config = make_run(store, tmp_path, Mode.code, clone_fn=fake_clone)
    state["inputs"] = ScanInputs(repo="https://example.com/x/y")
    asyncio.run(prepare(state, config))

    scan = store.get_scan(scan_id)
    assert pathlib.Path(scan.source_path).is_dir()
    assert json.loads(scan.config_json)["source_cleanup"] is True


def test_prepare_clone_failure_cleans_partial_dir(store, tmp_path):
    seen: dict = {}

    def failing_clone(repo: str, dest: str, scan_id: str) -> None:
        pathlib.Path(dest).mkdir(parents=True)  # partial clone left on disk
        (pathlib.Path(dest) / "half").write_text("x", encoding="utf-8")
        seen["dest"] = dest
        raise RuntimeError("network down")

    scan_id, state, config = make_run(store, tmp_path, Mode.code, clone_fn=failing_clone)
    state["inputs"] = ScanInputs(repo="https://example.com/x/y")
    with pytest.raises(RuntimeError):
        asyncio.run(prepare(state, config))
    assert not pathlib.Path(seen["dest"]).exists()


def test_prepare_repo_without_clone_fn_fails_clearly(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.code)
    state["inputs"] = ScanInputs(repo="https://example.com/x/y")
    with pytest.raises(RepoScanUnavailable):
        asyncio.run(prepare(state, config))


def test_prepare_requires_deps(store, tmp_path):
    _, state, _ = make_run(store, tmp_path, Mode.code)
    with pytest.raises(MissingDeps):
        asyncio.run(prepare(state, {}))


# --- DB snapshot dates ----------------------------------------------------- #
def test_snapshot_db_dates(tmp_path):
    (tmp_path / "osv").mkdir()
    (tmp_path / "trivy").mkdir()
    dates = snapshot_db_dates(str(tmp_path))
    assert dates["osv"] and dates["trivy"]
    assert dates["nuclei"] is None  # not staged


# --- ordering through the real graph --------------------------------------- #
async def test_mode3_visits_runtime_code_crypto_in_order(store, tmp_path):
    _, state, config = make_run(store, tmp_path, Mode.correlated)
    final = await build_aegis_graph().ainvoke(state, config)
    done = final["completed_stages"]
    assert final["mode"] is Mode.correlated
    assert final["plan"] == ["runtime", "code", "crypto"]
    assert [s for s in done if s in ("runtime", "code", "crypto")] == ["runtime", "code", "crypto"]
