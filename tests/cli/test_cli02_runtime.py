"""CLI02 — one runtime builder for the API and the CLI (CLI_PHASES.md).

``open_runtime`` builds every long-lived piece of AEGIS exactly once and in the right shape; the API
lifespan now uses it (the API tests cover that path), and the CLI will use it directly.
"""

from __future__ import annotations

import pytest

from aegis.api.main import StartupError as ApiStartupError
from aegis.api.main import check_model as api_check_model
from aegis.api.main import ensure_dirs as api_ensure_dirs
from aegis.config import AppSettings, ModelSettings
from aegis.services import runtime
from aegis.services.runtime import Runtime, StartupError, open_runtime
from fakes.fake_llm import PickFirstLLM

pytestmark = pytest.mark.phase("CLI02")

DOWN = "http://127.0.0.1:9"   # nothing listens here: the model check fails fast and is only logged


def _settings(tmp_path, **kw) -> AppSettings:
    return AppSettings(data_dir=str(tmp_path / "data"), model=ModelSettings(ollama_url=DOWN), **kw)


async def test_the_runtime_wires_every_piece_once(tmp_path):
    llm = PickFirstLLM()
    async with open_runtime(_settings(tmp_path), agent_overrides={"llm": llm}) as rt:
        assert isinstance(rt, Runtime)
        assert rt.graph.checkpointer is rt.checkpointer is rt.fix_graph.checkpointer      # one checkpointer
        assert rt.runner.store is rt.store and rt.runner.deps is rt.agent_deps
        assert rt.runner._sem._value == 1                                                   # one scan at a time
        assert rt.fix_service.graph is rt.fix_graph
        assert rt.scan_service.store is rt.store and rt.scan_service.graph is rt.graph
        assert rt.agent_deps.llm is llm and rt.agent_deps.data_dir == str(tmp_path / "data")
        assert rt.chat_settings.chroma_path == str(tmp_path / "data" / "chroma")             # index lives under data
        assert rt.query_service.latest_scan_id() is None
    for sub in runtime.DATA_SUBDIRS:
        assert (tmp_path / "data" / sub).is_dir()
    assert (tmp_path / "data" / "aegis.db").is_file() and (tmp_path / "data" / "checkpoints.db").is_file()


async def test_it_opens_and_closes_twice_on_the_same_data(tmp_path):
    settings = _settings(tmp_path)
    async with open_runtime(settings) as first:
        scan_id = first.store.add_scan(mode="code").id
    async with open_runtime(settings) as second:                 # the database was closed and reopened cleanly
        assert second.store.get_scan(scan_id) is not None
        assert second.query_service.latest_scan_id() == scan_id


async def test_an_absolute_chat_index_path_is_kept(tmp_path):
    from dataclasses import replace

    base = _settings(tmp_path)
    settings = replace(base, chat=replace(base.chat, chroma_path=str(tmp_path / "elsewhere")))
    async with open_runtime(settings) as rt:
        assert rt.chat_settings.chroma_path == str(tmp_path / "elsewhere")


async def test_an_unwritable_data_folder_is_refused_with_a_reason(tmp_path):
    blocker = tmp_path / "file-not-folder"
    blocker.write_text("x", encoding="utf-8")                     # a file where the data folder should be
    with pytest.raises(StartupError, match="not writable"):
        async with open_runtime(AppSettings(data_dir=str(blocker), model=ModelSettings(ollama_url=DOWN))):
            pass


def test_the_api_keeps_exporting_the_moved_names():
    assert ApiStartupError is StartupError
    assert api_ensure_dirs is runtime.ensure_dirs and api_check_model is runtime.check_model
