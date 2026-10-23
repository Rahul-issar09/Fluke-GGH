"""Demo configuration — patched: the secret comes from the environment."""
import os

API_KEY = os.environ.get("DEMO_API_KEY", "")
