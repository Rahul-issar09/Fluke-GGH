"""The `aegis` command-line tool (CLI_PHASES.md).

Layout (CLI_PHASES.md section 4A): ``main.py`` is the entry point; ``commands/`` parse arguments and
call the backend; ``ui/`` renders everything shown on screen. The CLI holds no feature logic of its
own — every command calls the same services the REST API uses.
"""
