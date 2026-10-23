"""Backend entry point: ``uvicorn aegis.main:app`` (AG13.1).

Settings come from the environment (``AEGIS_*``); the MCP SSE server is mounted at ``/mcp``
when ``AEGIS_MCP__ENABLED`` is set (see ``aegis.api.main.create_app``).
"""

from __future__ import annotations

from aegis.api.main import create_app

app = create_app()
