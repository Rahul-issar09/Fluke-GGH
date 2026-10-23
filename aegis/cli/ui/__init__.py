"""The CLI user interface — everything the user sees (CLI_PHASES.md section 4A).

``theme`` picks symbols the console can actually show; ``output`` renders tables, key/value
blocks, ``--json`` documents and errors. Commands hand data to this layer and never print directly.
"""
