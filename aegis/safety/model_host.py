"""Local-only model host check (MCP_PHASES MCP10.2, invariant M-7).

AEGIS uses offline models only: the Ollama URL must point at this machine or the local network.
``check_model_url`` resolves the host and refuses any public address — so a mistyped or copied
config can never send findings to a cloud endpoint. Loopback (127.0.0.0/8, ::1) and private,
link-local and unique-local ranges are allowed, so an Ollama on another machine in your LAN works.
There is no override flag. A host that does not resolve is refused (fail-closed).
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

__all__ = ["ModelHostRefused", "check_model_url", "is_local_address"]

Resolver = Callable[[str], list[str]]


class ModelHostRefused(ValueError):
    """The model URL is not on this machine or a private network."""


def _resolve(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def is_local_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])  # drop an IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_private or ip.is_link_local


def check_model_url(url: str, *, resolver: Resolver | None = None) -> list[str]:
    """Return the resolved addresses of *url*'s host, or raise :class:`ModelHostRefused`."""
    parts = urlsplit(url or "")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ModelHostRefused(f"model URL {url!r} is not an http(s) URL with a host")
    host = parts.hostname
    try:
        addresses = [host] if _is_ip(host) else (resolver or _resolve)(host)
    except OSError as exc:
        raise ModelHostRefused(
            f"model host {host!r} does not resolve ({type(exc).__name__}); set AEGIS_OLLAMA_URL, "
            "e.g. http://127.0.0.1:11434"
        ) from exc
    if not addresses:
        raise ModelHostRefused(f"model host {host!r} does not resolve")
    public = [a for a in addresses if not is_local_address(a)]
    if public:
        raise ModelHostRefused(
            f"model URL {url!r} resolves to a public address ({', '.join(public)}); AEGIS uses local models "
            "only; point AEGIS_OLLAMA_URL at this machine or your local network"
        )
    return addresses


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        return True
    except ValueError:
        return False
