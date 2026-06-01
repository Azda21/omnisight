# Simple monitoring utility using asyncio

import asyncio
import time
from typing import Callable, Dict

class SimpleMonitor:
    """A lightweight monitor that watches targets and calls a callback on change.

    Usage:
        monitor = SimpleMonitor()
        monitor.watch("example.com", check_fn, interval=60)
    """

    def __init__(self):
        self._tasks: Dict[str, asyncio.Task] = {}

    def watch(self, name: str, check_fn: Callable[[], bool], interval: int = 60):
        if name in self._tasks:
            return

        async def runner():
            while True:
                try:
                    changed = await asyncio.get_event_loop().run_in_executor(None, check_fn)
                    if changed:
                        print(f"[MONITOR] Change detected for {name} at {time.ctime()}")
                except Exception as e:
                    print(f"[MONITOR] Error checking {name}: {e}")
                await asyncio.sleep(interval)

        task = asyncio.create_task(runner())
        self._tasks[name] = task

    def stop(self, name: str):
        t = self._tasks.pop(name, None)
        if t:
            t.cancel()

