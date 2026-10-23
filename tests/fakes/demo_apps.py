"""Load the demo target apps and callback listener in-process for tests (no network).

``demo-app`` / ``demo-app-patched`` / ``callback-listener`` contain a hyphen so
they are not importable packages. The apps are loaded under unique package
names (they use relative imports), and ``create_app()`` gives every caller a
fresh in-memory state.

``demo_stack`` wires the whole scan network in-process: ``demo-app:5000`` and
``callback:8080`` resolve to their ASGI apps, and the demo app's own outbound
HTTP client is pointed at the same listener — so a server-side fetch of the
callback URL really lands in the listener, exactly as it would on the Docker
network.
"""

from __future__ import annotations

import importlib
import importlib.util
import pathlib
import sys

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[2]
_APPS = {
    "vulnerable": ("demo_app", ROOT / "demo-app"),
    "patched": ("demo_app_patched", ROOT / "demo-app-patched"),
}


def identities_path(kind: str = "vulnerable") -> str:
    return str(_APPS[kind][1] / "identities.yml")


def create_demo_app(kind: str = "vulnerable", http_client: httpx.AsyncClient | None = None):
    name, path = _APPS[kind]
    if name not in sys.modules:
        pkg = path / "app"
        spec = importlib.util.spec_from_file_location(
            name, pkg / "__init__.py", submodule_search_locations=[str(pkg)]
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return importlib.import_module(f"{name}.main").create_app(http_client=http_client)


def create_listener():
    """A fresh callback-listener app (loaded from callback-listener/app.py)."""
    name = "callback_listener_app"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ROOT / "callback-listener" / "app.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name].create_app()


def create_app_from_dir(directory: pathlib.Path, name: str):
    """Load a copy of a demo app (``<directory>/app``) under a unique package name, for patched copies."""
    pkg = directory / "app"
    spec = importlib.util.spec_from_file_location(name, pkg / "__init__.py", submodule_search_locations=[str(pkg)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    try:
        return importlib.import_module(f"{name}.main").create_app()
    finally:
        for key in [k for k in sys.modules if k == name or k.startswith(name + ".")]:
            del sys.modules[key]


def demo_transport(kind: str = "vulnerable") -> httpx.ASGITransport:
    return httpx.ASGITransport(app=create_demo_app(kind))


class HostRouter(httpx.AsyncBaseTransport):
    """Dispatch requests to a transport by URL host (a stand-in for the scan network)."""

    def __init__(self, routes: dict[str, httpx.AsyncBaseTransport]):
        self._routes = routes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        transport = self._routes.get(request.url.host)
        if transport is None:
            raise httpx.ConnectError(f"no route to host {request.url.host}", request=request)
        return await transport.handle_async_request(request)


def demo_stack(kind: str = "vulnerable"):
    """Return ``(transport, listener_app)`` for ``demo-app:5000`` + ``callback:8080``."""
    listener = create_listener()
    listener_transport = httpx.ASGITransport(app=listener)
    # the demo app's own outbound client reaches the listener, wherever the URL points
    fetch_client = httpx.AsyncClient(transport=listener_transport)
    app = create_demo_app(kind, http_client=fetch_client)
    router = HostRouter(
        {"demo-app": httpx.ASGITransport(app=app), "callback": listener_transport}
    )
    return router, listener
