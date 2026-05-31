"""In-process event bus for the live feed.

Continuous scanning is only compelling if you can *watch* it work. This is a
tiny async pub/sub: the scan/verify pipeline publishes events (port found,
access verified, risk raised) and any connected WebSocket client drains them in
real time, so the dashboard streams discoveries as they happen instead of
needing a refresh.
"""
import asyncio
import time
from collections import deque


class EventBus:
    def __init__(self, history: int = 100):
        self._subscribers: set[asyncio.Queue] = set()
        self._recent = deque(maxlen=history)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def publish(self, event_type: str, data: dict) -> None:
        event = {"type": event_type, "ts": time.time(), **data}
        self._recent.append(event)
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    def recent(self) -> list:
        return list(self._recent)


# Single shared bus for the app.
bus = EventBus()
