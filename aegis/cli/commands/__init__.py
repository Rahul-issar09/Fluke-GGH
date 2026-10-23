"""CLI commands — one module per command group (CLI_PHASES.md section 4A).

A command parses its arguments, calls the backend (``aegis.cli.backend``) and hands the result to
the ``ui`` layer. It never imports AEGIS's services, agent or store directly (a test enforces this).
"""
