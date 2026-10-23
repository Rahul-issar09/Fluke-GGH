"""Shared test setup.

Puts the ``tests/`` directory on ``sys.path`` so shared helpers like
``fakes.fake_llm`` import cleanly from any test module, and guards the network.

**The network guard (LLM_PROVIDER_PHASES LP12, limitation L-3).** Every test may connect to this
machine only. A connection anywhere else is refused (so nothing hangs) *and* fails the test at
teardown — AEGIS often degrades gracefully on a connection error, which would otherwise hide the
attempt. It covers plain sockets and asyncio connections (on Windows, async connects bypass
``socket.connect``), and name lookups of non-local names. Tests that must reach the real world opt
out with their markers: ``gemini`` (Google), ``tools`` (real scanners), ``docker``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import sys

import pytest

_TESTS_DIR = os.path.dirname(__file__)
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)

_NETWORK_MARKERS = ("gemini", "tools", "docker")
_LOCAL_NAMES = {"localhost", "localhost.localdomain", ""}


def _is_local(host) -> bool:
    if host is None:
        return True                         # a Unix socket / an already-resolved local endpoint
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    host = str(host).strip("[]").split("%", 1)[0].lower()
    if host in _LOCAL_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def _is_ip(host) -> bool:
    try:
        ipaddress.ip_address(str(host.decode() if isinstance(host, bytes) else host).strip("[]").split("%", 1)[0])
        return True
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def network_guard(request, monkeypatch):
    if any(request.node.get_closest_marker(m) for m in _NETWORK_MARKERS):
        yield
        return
    attempts: list[str] = []
    request.node.network_attempts = attempts       # the guard's own tests read and clear it

    def refuse(where: str):
        attempts.append(where)
        return ConnectionRefusedError(f"network guard: this test may not reach {where}")

    real_connect, real_connect_ex = socket.socket.connect, socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo
    real_create_connection = asyncio.base_events.BaseEventLoop.create_connection

    def connect(self, address):
        if isinstance(address, tuple) and not _is_local(address[0]):
            raise refuse(f"{address[0]}:{address[1]}")
        return real_connect(self, address)

    def connect_ex(self, address):
        if isinstance(address, tuple) and not _is_local(address[0]):
            refuse(f"{address[0]}:{address[1]}")
            return 111                       # ECONNREFUSED
        return real_connect_ex(self, address)

    def getaddrinfo(host, *args, **kwargs):
        if not _is_local(host) and not _is_ip(host):   # a numeric address needs no DNS: the connect is checked
            attempts.append(f"DNS {host}")
            raise socket.gaierror(socket.EAI_NONAME, f"network guard: this test may not resolve {host}")
        return real_getaddrinfo(host, *args, **kwargs)

    async def create_connection(self, protocol_factory, host=None, port=None, *args, **kwargs):
        if host is not None and not _is_local(host):
            raise refuse(f"{host}:{port}")
        return await real_create_connection(self, protocol_factory, host, port, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "create_connection", create_connection)
    yield
    if attempts:
        pytest.fail(f"the test tried to reach the network: {sorted(set(attempts))[:5]} "
                    "(mark it gemini/tools/docker if it really must)", pytrace=False)


@pytest.fixture
def store(tmp_path):
    """Fresh EvidenceStore backed by a temp SQLite file."""
    from aegis.evidence.db import init_db, make_engine
    from aegis.evidence.store import EvidenceStore

    engine = make_engine(f"sqlite:///{(tmp_path / 'aegis.db').as_posix()}")
    init_db(engine)
    return EvidenceStore(engine)
