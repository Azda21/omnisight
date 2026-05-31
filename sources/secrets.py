"""Tiny secret store for external-provider API keys.

Keeps keys out of the codebase and out of the scan database. Loaded from
data/secrets.json (or environment variables, which win), settable at runtime
via the settings endpoint so the user can paste a key in the UI without editing
files.
"""
import json
import os
from pathlib import Path


class SecretStore:
    ENV_MAP = {
        "shodan_api_key": "SHODAN_API_KEY",
        "censys_api_id": "CENSYS_API_ID",
        "censys_api_secret": "CENSYS_API_SECRET",
        "zoomeye_api_key": "ZOOMEYE_API_KEY",
    }

    def __init__(self, path: str = "data/secrets.json"):
        self.path = Path(path)
        self._data: dict = {}
        self.load()

    def load(self):
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def get(self, key: str) -> str:
        # Environment variable overrides the file.
        env = self.ENV_MAP.get(key)
        if env and os.environ.get(env):
            return os.environ[env]
        return self._data.get(key, "")

    def set(self, key: str, value: str):
        self._data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2))

    def status(self) -> dict:
        """Which providers are configured (without leaking the keys)."""
        return {
            "shodan": bool(self.get("shodan_api_key")),
            "censys": bool(self.get("censys_api_id") and self.get("censys_api_secret")),
            "zoomeye": bool(self.get("zoomeye_api_key")),
        }
