"""LP12 — the network guard itself: this machine is fine; anything else is refused and recorded,
which fails the test at teardown (these tests clear the record because they cause it on purpose)."""

from __future__ import annotations

import socket

import httpx
import pytest

pytestmark = pytest.mark.phase("LP12")


def test_local_connections_are_allowed(request):
    with socket.socket() as s:
        s.settimeout(1)
        s.connect_ex(("127.0.0.1", 9))           # refused by the OS (nothing listens), not by the guard
    assert socket.getaddrinfo("localhost", 80)
    assert request.node.network_attempts == []


def test_sockets_and_names_are_refused_and_recorded(request):
    with pytest.raises(ConnectionRefusedError, match="network guard"):
        socket.create_connection(("93.184.216.34", 80), timeout=1)
    with pytest.raises(socket.gaierror, match="network guard"):
        socket.getaddrinfo("example.com", 443)
    assert request.node.network_attempts == ["93.184.216.34:80", "DNS example.com"]
    request.node.network_attempts.clear()


async def test_async_clients_are_refused_and_recorded(request):
    async with httpx.AsyncClient(timeout=2) as client:
        with pytest.raises(httpx.ConnectError):
            await client.get("http://93.184.216.34/")
    assert request.node.network_attempts == ["93.184.216.34:80"]
    request.node.network_attempts.clear()


@pytest.mark.gemini
def test_marked_tests_opt_out(request):
    assert not hasattr(request.node, "network_attempts")
