import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path

logger = logging.getLogger("omnisight.scheduler")


@dataclass
class ScheduledScan:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    targets: str = ""
    ports: str = "21-23,25,53,80,110,443,993,3306,3389,5432,8080,8443"
    protocol: str = "tcp"
    scan_mode: str = "auto"
    interval_seconds: int = 3600
    enabled: bool = True
    auto_verify: bool = False
    last_run: float = 0.0
    next_run: float = 0.0
    run_count: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["last_run_human"] = (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_run))
            if self.last_run else "never"
        )
        d["next_run_human"] = (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.next_run))
            if self.next_run else "-"
        )
        return d


class ScanScheduler:
    """Runs scans on a recurring interval and persists the schedule.

    Combined with the diff engine this is what makes OmniSight a monitoring
    platform rather than a one-shot tool: register a target once, and every
    interval it re-scans and the diff surfaces anything that changed. The
    schedule survives restarts because it lives in SQLite, not just memory.
    """

    def __init__(self, db, scan_runner):
        # scan_runner: async callable(ScheduledScan) -> session_id
        self.db = db
        self.scan_runner = scan_runner
        self._schedules: dict[str, ScheduledScan] = {}
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def start(self):
        await self._ensure_table()
        await self._load()
        self._stop.clear()
        self._task = asyncio.create_task(self._loop())
        logger.info(f"Scheduler started with {len(self._schedules)} schedule(s)")

    async def stop(self):
        self._stop.set()
        if self._task:
            await self._task

    async def _ensure_table(self):
        await self.db._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id TEXT PRIMARY KEY,
                name TEXT,
                targets TEXT,
                ports TEXT,
                protocol TEXT DEFAULT 'tcp',
                scan_mode TEXT DEFAULT 'auto',
                interval_seconds INTEGER DEFAULT 3600,
                enabled INTEGER DEFAULT 1,
                auto_verify INTEGER DEFAULT 0,
                last_run REAL DEFAULT 0,
                next_run REAL DEFAULT 0,
                run_count INTEGER DEFAULT 0
            );
        """)
        # Add column for databases created before auto_verify existed.
        try:
            await self.db._conn.execute("ALTER TABLE scheduled_scans ADD COLUMN auto_verify INTEGER DEFAULT 0")
        except Exception:
            pass
        await self.db._conn.commit()

    async def _load(self):
        cursor = await self.db._conn.execute("SELECT * FROM scheduled_scans")
        rows = await cursor.fetchall()
        columns = [d[0] for d in cursor.description]
        for row in rows:
            rec = dict(zip(columns, row))
            rec["enabled"] = bool(rec["enabled"])
            rec["auto_verify"] = bool(rec.get("auto_verify", 0))
            sched = ScheduledScan(**rec)
            self._schedules[sched.id] = sched

    async def _persist(self, sched: ScheduledScan):
        await self.db._conn.execute(
            """INSERT OR REPLACE INTO scheduled_scans
               (id, name, targets, ports, protocol, scan_mode, interval_seconds,
                enabled, auto_verify, last_run, next_run, run_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (sched.id, sched.name, sched.targets, sched.ports, sched.protocol,
             sched.scan_mode, sched.interval_seconds, int(sched.enabled),
             int(sched.auto_verify), sched.last_run, sched.next_run, sched.run_count),
        )
        await self.db._conn.commit()

    async def add(self, sched: ScheduledScan) -> ScheduledScan:
        sched.next_run = time.time() + sched.interval_seconds
        self._schedules[sched.id] = sched
        await self._persist(sched)
        logger.info(f"Scheduled scan added: {sched.name} every {sched.interval_seconds}s")
        return sched

    async def remove(self, sched_id: str) -> bool:
        if sched_id in self._schedules:
            del self._schedules[sched_id]
            await self.db._conn.execute("DELETE FROM scheduled_scans WHERE id = ?", (sched_id,))
            await self.db._conn.commit()
            return True
        return False

    async def set_enabled(self, sched_id: str, enabled: bool) -> bool:
        sched = self._schedules.get(sched_id)
        if not sched:
            return False
        sched.enabled = enabled
        if enabled and not sched.next_run:
            sched.next_run = time.time() + sched.interval_seconds
        await self._persist(sched)
        return True

    def list(self) -> list[dict]:
        return [s.to_dict() for s in self._schedules.values()]

    async def _loop(self):
        # Tick once a second; fire any schedule whose next_run has elapsed.
        while not self._stop.is_set():
            now = time.time()
            for sched in list(self._schedules.values()):
                if sched.enabled and sched.next_run and now >= sched.next_run:
                    sched.next_run = now + sched.interval_seconds
                    sched.last_run = now
                    sched.run_count += 1
                    await self._persist(sched)
                    asyncio.create_task(self._fire(sched))
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass

    async def _fire(self, sched: ScheduledScan):
        try:
            logger.info(f"Firing scheduled scan: {sched.name}")
            await self.scan_runner(sched)
        except Exception as e:
            logger.error(f"Scheduled scan '{sched.name}' failed: {e}")
