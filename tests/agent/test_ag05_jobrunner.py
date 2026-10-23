"""AG05.4 — job runner, checkpointer, event bus (SSE source)."""

from __future__ import annotations

import asyncio
import json

import pytest

from _graph_helpers import make_run
from aegis.agent.graph import build_aegis_graph
from aegis.agent.nodes.worker_stage import STEP_REGISTRY
from aegis.agent.state import ScanInputs
from aegis.evidence.models import Mode, ScanStatus
from aegis.services.event_bus import EventBus, make_event
from aegis.services.job_runner import JobRunner, open_checkpointer

pytestmark = pytest.mark.phase("AG05")


@pytest.fixture
async def checkpointer(tmp_path):
    async with open_checkpointer(tmp_path / "data" / "checkpoints.db") as saver:
        yield saver


async def _collect(bus: EventBus, scan_id: str, timeout: float = 15.0) -> list:
    async def go():
        return [e async for e in bus.stream(scan_id)]

    return await asyncio.wait_for(go(), timeout)


def _runner(store, config) -> JobRunner:
    return JobRunner(store, bus=EventBus(), deps=config["configurable"]["deps"])


# --- events ---------------------------------------------------------------- #
async def test_one_event_per_node_then_completed(store, tmp_path, checkpointer):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    runner = _runner(store, config)
    graph = build_aegis_graph(checkpointer)

    runner.submit(scan_id, graph, state)
    events = await _collect(runner.bus, scan_id)
    await runner.wait(scan_id)

    assert (events[0].stage, events[0].status) == ("scan", "running")
    assert (events[-1].stage, events[-1].status) == ("scan", "completed")

    done = [e.node for e in events if e.status == "done"]
    parent_nodes = [n for n in done if n in (
        "route_mode", "prepare", "plan", "runtime", "normalize", "score", "investigate",
        "explain", "validate", "remediate", "finalize")]
    assert parent_nodes == [
        "route_mode", "prepare", "plan", "runtime", "normalize", "score", "investigate",
        "explain", "validate", "remediate", "finalize",
    ]
    # steps inside the runtime stage surface with stage="runtime" (C24)
    steps = [e.node for e in events if e.stage == "runtime" and e.node != "runtime"]
    assert steps[:3] == ["tls_scan", "validate_target", "discover_routes"]  # tls_scan first (TNW-2)
    assert all(e.ms is not None for e in events if e.status == "done")


async def test_status_transitions_and_timestamps(store, tmp_path, checkpointer):
    scan_id, state, config = make_run(store, tmp_path, Mode.code)
    runner = _runner(store, config)
    assert store.get_scan(scan_id).status == ScanStatus.queued

    runner.submit(scan_id, build_aegis_graph(checkpointer), state)
    await runner.wait(scan_id)

    scan = store.get_scan(scan_id)
    assert scan.status == ScanStatus.completed
    assert scan.started_at is not None and scan.finished_at is not None


async def test_late_subscriber_replays_history(store, tmp_path, checkpointer):
    scan_id, state, config = make_run(store, tmp_path, Mode.code)
    runner = _runner(store, config)
    runner.submit(scan_id, build_aegis_graph(checkpointer), state)
    await runner.wait(scan_id)  # scan fully finished before anyone subscribes

    events = await _collect(runner.bus, scan_id)
    assert events[0].status == "running" and events[-1].status == "completed"
    assert any(e.node == "finalize" for e in events)


# --- failure / cancel / concurrency ---------------------------------------- #
async def test_failure_marks_failed_records_reason_and_frees_slot(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.code)
    state["inputs"] = ScanInputs(repo="https://example.com/x/y")  # no clone_fn -> prepare fails
    runner = _runner(store, config)

    runner.submit(scan_id, build_aegis_graph(), state)
    events = await _collect(runner.bus, scan_id)
    await runner.wait(scan_id)

    assert events[-1].status == "failed"
    scan = store.get_scan(scan_id)
    assert scan.status == ScanStatus.failed
    assert "RepoScanUnavailable" in json.loads(scan.config_json)["failure_reason"]

    # the single slot is free again: a healthy scan still runs
    scan2, state2, _ = make_run(store, tmp_path, Mode.code)
    runner.submit(scan2, build_aegis_graph(), state2)
    await runner.wait(scan2)
    assert store.get_scan(scan2).status == ScanStatus.completed


async def test_cancel_running_scan(store, tmp_path, monkeypatch):
    started = asyncio.Event()

    async def hang(state, config):
        started.set()
        await asyncio.sleep(60)

    monkeypatch.setitem(STEP_REGISTRY, "runtime.validate_target", hang)
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    runner = _runner(store, config)

    runner.submit(scan_id, build_aegis_graph(), state)
    await asyncio.wait_for(started.wait(), 10)
    assert await runner.cancel(scan_id) is True

    events = await _collect(runner.bus, scan_id)
    assert events[-1].status == "cancelled"
    assert store.get_scan(scan_id).status == ScanStatus.cancelled
    assert await runner.cancel(scan_id) is False  # nothing active any more


async def test_one_scan_at_a_time(store, tmp_path, monkeypatch):
    gate = asyncio.Event()
    entered: list[str] = []

    async def hold(state, config):
        entered.append(state["scan_id"])
        await gate.wait()

    monkeypatch.setitem(STEP_REGISTRY, "runtime.validate_target", hold)
    a, state_a, config = make_run(store, tmp_path, Mode.runtime)
    b, state_b, _ = make_run(store, tmp_path, Mode.runtime)
    runner = _runner(store, config)

    runner.submit(a, build_aegis_graph(), state_a)
    runner.submit(b, build_aegis_graph(), state_b)
    await asyncio.sleep(0.5)

    assert entered == [a]  # b has not started
    assert store.get_scan(a).status == ScanStatus.running
    assert store.get_scan(b).status == ScanStatus.queued

    gate.set()
    await runner.wait(a)
    await runner.wait(b)
    assert entered == [a, b]
    assert store.get_scan(b).status == ScanStatus.completed


# --- checkpoint resume ------------------------------------------------------ #
async def test_resume_after_simulated_restart(store, tmp_path, monkeypatch):
    runs: list[str] = []

    def check_bola(state, config):
        runs.append(state["scan_id"])

    monkeypatch.setitem(STEP_REGISTRY, "runtime.check_bola", check_bola)
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    cp_path = tmp_path / "data" / "checkpoints.db"

    # process 1: run until just before `normalize`, then "crash"
    async with open_checkpointer(cp_path) as saver1:
        g1 = build_aegis_graph(saver1, interrupt_before=["normalize"])
        cfg = {"configurable": {**config["configurable"], "thread_id": scan_id}}
        partial = await g1.ainvoke(state, cfg)
        assert "runtime" in partial["completed_stages"]
        assert "normalize" not in partial["completed_stages"]

    # process 2: brand-new saver + graph on the same file picks up where it left off
    async with open_checkpointer(cp_path) as saver2:
        g2 = build_aegis_graph(saver2)
        final = await g2.ainvoke(None, cfg)

    assert final["completed_stages"][-1] == "finalize"
    assert final["completed_stages"].count("runtime") == 1
    assert runs == [scan_id]  # the runtime worker step was NOT re-run


async def test_runner_reports_pause_then_resumes(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.code)
    cp_path = tmp_path / "data" / "checkpoints.db"
    runner = _runner(store, config)

    async with open_checkpointer(cp_path) as saver:
        paused_graph = build_aegis_graph(saver, interrupt_before=["normalize"])
        runner.submit(scan_id, paused_graph, state)
        await runner.wait(scan_id)
        assert store.get_scan(scan_id).status == ScanStatus.awaiting_approval
        assert runner.bus.history(scan_id)[-1].status == "paused"

        runner.resume(scan_id, build_aegis_graph(saver))
        await runner.wait(scan_id)

    assert store.get_scan(scan_id).status == ScanStatus.completed
    assert runner.bus.history(scan_id)[-1].status == "completed"


# --- event bus unit --------------------------------------------------------- #
async def test_subscriber_cleanup_on_disconnect():
    bus = EventBus()
    bus.publish(make_event("S-1", "scan", "scan", "running"))
    agen = bus.stream("S-1")
    first = await agen.__anext__()
    assert first.status == "running" and bus.subscriber_count("S-1") == 1
    await agen.aclose()  # client disconnected
    assert bus.subscriber_count("S-1") == 0


async def test_history_is_a_bounded_ring_buffer():
    bus = EventBus(history_size=3)
    for i in range(10):
        bus.publish(make_event("S-1", "runtime", f"n{i}", "done"))
    assert [e.node for e in bus.history("S-1")] == ["n7", "n8", "n9"]


async def test_two_subscribers_both_receive_everything():
    bus = EventBus()
    results: list[list[str]] = [[], []]

    async def sub(idx: int):
        async for e in bus.stream("S-1"):
            results[idx].append(e.status)

    tasks = [asyncio.create_task(sub(0)), asyncio.create_task(sub(1))]
    await asyncio.sleep(0)  # let both register
    bus.publish(make_event("S-1", "scan", "scan", "running"))
    bus.publish(make_event("S-1", "scan", "scan", "completed"))
    await asyncio.wait_for(asyncio.gather(*tasks), 5)
    assert results == [["running", "completed"], ["running", "completed"]]
