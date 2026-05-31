import json
import time
import logging
from pathlib import Path

from .query_parser import QueryParser

logger = logging.getLogger("omnisight.storage.database")


class Database:
    """SQLite-backed storage for scan sessions and local results cache."""

    def __init__(self, db_path: str = "data/omnisight.db"):
        self.db_path = db_path
        self._engine = None
        self._conn = None
        self._query_parser = QueryParser()

    async def connect(self):
        try:
            import aiosqlite
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = await aiosqlite.connect(self.db_path)
            await self._create_tables()
            logger.info(f"Database connected: {self.db_path}")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")

    async def _create_tables(self):
        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id TEXT PRIMARY KEY,
                name TEXT,
                targets TEXT,
                ports TEXT,
                protocol TEXT DEFAULT 'tcp',
                status TEXT DEFAULT 'pending',
                total_hosts INTEGER DEFAULT 0,
                open_ports_found INTEGER DEFAULT 0,
                start_time REAL,
                end_time REAL,
                error TEXT,
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                ip TEXT,
                port INTEGER,
                protocol TEXT,
                state TEXT,
                service TEXT,
                product TEXT,
                version TEXT,
                banner TEXT,
                country TEXT,
                country_code TEXT,
                city TEXT,
                asn INTEGER,
                as_org TEXT,
                data_json TEXT,
                timestamp REAL,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
            );

            CREATE INDEX IF NOT EXISTS idx_results_ip ON scan_results(ip);
            CREATE INDEX IF NOT EXISTS idx_results_port ON scan_results(port);
            CREATE INDEX IF NOT EXISTS idx_results_service ON scan_results(service);
            CREATE INDEX IF NOT EXISTS idx_results_country ON scan_results(country_code);
            CREATE INDEX IF NOT EXISTS idx_results_session ON scan_results(session_id);
        """)
        await self._conn.commit()

    async def save_session(self, session: dict):
        await self._conn.execute(
            """INSERT OR REPLACE INTO scan_sessions
               (id, name, targets, ports, protocol, status, total_hosts, open_ports_found, start_time, end_time, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session["id"], session.get("name", ""), session["targets"], session.get("ports", ""),
             session.get("protocol", "tcp"), session.get("status", "pending"),
             session.get("total_hosts", 0), session.get("open_ports_found", 0),
             session.get("start_time", time.time()), session.get("end_time", 0),
             session.get("error", "")),
        )
        await self._conn.commit()

    async def save_result(self, record: dict):
        data_json = json.dumps({k: v for k, v in record.items()
                                if k not in ("id", "session_id", "ip", "port", "protocol",
                                             "state", "service", "product", "version", "banner",
                                             "country", "country_code", "city", "asn", "as_org", "timestamp")})
        await self._conn.execute(
            """INSERT OR REPLACE INTO scan_results
               (id, session_id, ip, port, protocol, state, service, product, version, banner,
                country, country_code, city, asn, as_org, data_json, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (record["id"], record.get("scan_session_id", ""), record["ip"], record["port"],
             record["protocol"], record["state"], record.get("service", ""),
             record.get("product", ""), record.get("version", ""), record.get("banner", "")[:2000],
             record.get("country", ""), record.get("country_code", ""), record.get("city", ""),
             record.get("asn", 0), record.get("as_org", ""), data_json, record.get("timestamp", time.time())),
        )
        await self._conn.commit()

    async def search(self, query: str = "", filters: dict = None, page: int = 1, size: int = 20) -> dict:
        # Parse the Shodan-style DSL out of the free-text query first, then layer
        # any explicit filters passed via dedicated API params on top.
        parsed = self._query_parser.parse(query)
        where, params = self._query_parser.to_sql(parsed)

        conditions = [where] if where != "1=1" else []
        if where != "1=1":
            params = list(params)
        else:
            params = []

        if filters:
            for key, value in filters.items():
                if key in ("ip", "port", "service", "product", "country_code", "city", "asn"):
                    conditions.append(f"{key} = ?")
                    params.append(value)
                elif key == "session_id":
                    conditions.append("session_id = ?")
                    params.append(value)

        where = " AND ".join(conditions) if conditions else "1=1"
        offset = (page - 1) * size

        count_sql = f"SELECT COUNT(*) FROM scan_results WHERE {where}"
        cursor = await self._conn.execute(count_sql, params)
        total = (await cursor.fetchone())[0]

        sql = f"SELECT * FROM scan_results WHERE {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([size, offset])
        cursor = await self._conn.execute(sql, params)
        rows = await cursor.fetchall()

        columns = [d[0] for d in cursor.description]
        results = []
        for row in rows:
            record = dict(zip(columns, row))
            if record.get("data_json"):
                try:
                    extra = json.loads(record.pop("data_json"))
                    record.update(extra)
                except json.JSONDecodeError:
                    record.pop("data_json", None)
            results.append(record)

        return {"total": total, "results": results, "page": page, "pages": (total + size - 1) // size if total else 0}

    async def get_sessions(self, limit: int = 50) -> list[dict]:
        cursor = await self._conn.execute(
            "SELECT * FROM scan_sessions ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        columns = [d[0] for d in cursor.description]
        return [dict(zip(columns, row)) for row in rows]

    async def get_session_results(self, session_id: str) -> list[dict]:
        """All result rows for one scan session, fully rehydrated from JSON."""
        cursor = await self._conn.execute(
            "SELECT * FROM scan_results WHERE session_id = ? ORDER BY ip, port",
            (session_id,),
        )
        rows = await cursor.fetchall()
        columns = [d[0] for d in cursor.description]
        results = []
        for row in rows:
            record = dict(zip(columns, row))
            if record.get("data_json"):
                try:
                    record.update(json.loads(record.pop("data_json")))
                except json.JSONDecodeError:
                    record.pop("data_json", None)
            results.append(record)
        return results

    async def get_sessions_for_targets(self, targets: str, limit: int = 10) -> list[dict]:
        """Past completed sessions that scanned the same target spec — the
        timeline a diff walks along."""
        cursor = await self._conn.execute(
            "SELECT * FROM scan_sessions WHERE targets = ? AND status = 'completed' "
            "ORDER BY start_time DESC LIMIT ?",
            (targets, limit),
        )
        rows = await cursor.fetchall()
        columns = [d[0] for d in cursor.description]
        return [dict(zip(columns, row)) for row in rows]

    async def get_stats(self) -> dict:
        stats = {}
        cursor = await self._conn.execute("SELECT COUNT(*) FROM scan_results")
        stats["total_records"] = (await cursor.fetchone())[0]

        cursor = await self._conn.execute("SELECT COUNT(DISTINCT ip) FROM scan_results")
        stats["unique_hosts"] = (await cursor.fetchone())[0]

        cursor = await self._conn.execute(
            "SELECT service, COUNT(*) as cnt FROM scan_results WHERE service != '' GROUP BY service ORDER BY cnt DESC LIMIT 10"
        )
        stats["top_services"] = {row[0]: row[1] for row in await cursor.fetchall()}

        cursor = await self._conn.execute(
            "SELECT country_code, COUNT(*) as cnt FROM scan_results WHERE country_code != '' GROUP BY country_code ORDER BY cnt DESC LIMIT 10"
        )
        stats["top_countries"] = {row[0]: row[1] for row in await cursor.fetchall()}

        cursor = await self._conn.execute(
            "SELECT port, COUNT(*) as cnt FROM scan_results GROUP BY port ORDER BY cnt DESC LIMIT 10"
        )
        stats["top_ports"] = {row[0]: row[1] for row in await cursor.fetchall()}

        return stats

    async def close(self):
        if self._conn:
            await self._conn.close()
