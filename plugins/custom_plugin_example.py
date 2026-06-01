# Example plugin interface and a simple plugin

from typing import Any

class PluginBase:
    def scan(self, target: str) -> Any:
        raise NotImplementedError

class CustomPlugin(PluginBase):
    def scan(self, target: str) -> str:
        # In production, plugin may call external libs, run heuristics etc.
        return f"custom-scan-result-for:{target}"

