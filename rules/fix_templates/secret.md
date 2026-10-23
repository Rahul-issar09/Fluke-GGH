description: Read the secret from the environment instead of source code. The key was already committed - rotate it.

Fix pattern for a hard-coded credential:
- Replace the string literal with a lookup of an environment variable named after the setting (for example the setting's own name).
- Use the standard library's os.environ; add "import os" at the top of the file only if it is not already imported.
- Prefer a safe default for local use (an empty string) over crashing at import time, unless the file already fails fast elsewhere.
- Never write a real or example secret value in your answer.
- The literal on the flagged line is hidden from you and shown as "<redacted>"; treat that line as the one to replace.
- Do not change any other behaviour, names or formatting.
