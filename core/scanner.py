# Omnisight V2 - Core Scanner
# Async, modular, checkpointing and evolutionary-aware unified scanner

import asyncio
import json
import os
import time
from typing import List, Dict, Any

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'scan_results')
os.makedirs(DATA_DIR, exist_ok=True)


class UnifiedScannerV2:
    """
    Async unified scanner with:
    - quick_scan: one-click aggressive/normal scanning
    - selective_scan: keyword or module based
    - validate_results: lightweight validation
    - checkpointing to disk for evolutionary learning
    """

    def __init__(self):
        self.checkpoints: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def quick_scan(self, target: str, aggressive: bool = True, timeout: int = 60) -> List[Dict[str, Any]]:
        """One-click scan that parallelizes lightweight probes and aggregates results."""
        tasks = [self._probe_port(target, 80), self._probe_port(target, 443)]
        if aggressive:
            tasks += [self._probe_port(target, 8080), self._probe_banner(target, 22)]

        results = []
        for coro in asyncio.as_completed(tasks, timeout=timeout):
            try:
                res = await coro
                if res:
                    results.append(res)
            except asyncio.TimeoutError:
                results.append({"error": "probe timeout"})

        await self._save_checkpoint(target, results)
        return results

    async def selective_scan(self, target: str, keywords: List[str] = None) -> List[Dict[str, Any]]:
        keywords = keywords or []
        results = []
        # simple simulation: record keyword matches in target name (placeholder for real checks)
        for kw in keywords:
            if kw.lower() in target.lower():
                results.append({"type": "keyword_match", "keyword": kw})

        await self._save_checkpoint(target, results)
        return results

    async def validate_results(self) -> bool:
        # Lightweight heuristic validation of last checkpoint
        if not self.checkpoints:
            return False
        last = self.checkpoints[-1]
        # Placeholder rules: any result without error considered valid
        for r in last.get("results", []):
            if r.get("error"):
                return False
        return True

    async def _probe_port(self, target: str, port: int) -> Dict[str, Any]:
        # Non-blocking placeholder for port probe; would use async sockets in production
        await asyncio.sleep(0.02)
        # Simulate open/closed randomly but deterministic for now
        open_ports = {80, 443}
        return {"type": "port", "port": port, "open": port in open_ports}

    async def _probe_banner(self, target: str, port: int) -> Dict[str, Any]:
        await asyncio.sleep(0.03)
        return {"type": "banner", "port": port, "banner": "SSH-2.0-OpenSSH_8.4"}

    async def _save_checkpoint(self, target: str, results: List[Dict[str, Any]]):
        entry = {"target": target, "results": results, "timestamp": time.time()}
        async with self._lock:
            self.checkpoints.append(entry)
            filename = os.path.join(DATA_DIR, f"checkpoint_{int(time.time()*1000)}.json")
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(entry, f, indent=2)

