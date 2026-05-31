import asyncio
import logging
import time
from pathlib import Path

from fastapi import FastAPI, Request, Query
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from ..config import Config
from ..scanner.engine import ScanEngine
from ..scanner.port_scanner import PortScanner
from ..fingerprint.service_detector import ServiceDetector
from ..fingerprint.ssl_analyzer import SSLAnalyzer
from ..fingerprint.web_analyzer import WebAnalyzer
from ..fingerprint.honeypot_detector import HoneypotDetector
from ..enrichment.geoip import GeoIPEnricher
from ..enrichment.dns_resolver import DNSEnricher
from ..enrichment.whois_lookup import WhoisEnricher
from ..enrichment.cve_correlator import CVECorrelator
from ..storage.elasticsearch_store import ElasticStore
from ..storage.database import Database
from ..storage.models import ScanRecord, ScanSession
from ..storage.diff import DiffEngine
from ..scheduler import ScanScheduler, ScheduledScan
from ..intelligence.categories import list_categories, CATEGORIES
from ..access import access_methods
from ..verify import AccessVerifier
from ..risk import score_record, score_host
from ..events import bus
from ..sources import ShodanSource, CensysSource, SecretStore
from ..scanner.crawler import OmniCrawler
from .. import i18n
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("omnisight.api")

config = Config.load()

app = FastAPI(title="OmniSight", version="1.0.0", description="Advanced Network Intelligence Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "web" / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "web" / "static")), name="static")

# Expose the translator and current language to every template.
templates.env.globals["t"] = i18n.t
templates.env.globals["lang"] = i18n.get_lang


@app.middleware("http")
async def language_middleware(request: Request, call_next):
    lang = request.cookies.get("lang", "tr")
    i18n.set_lang(lang)
    return await call_next(request)

scan_engine = ScanEngine(config)
service_detector = ServiceDetector()
ssl_analyzer = SSLAnalyzer()
web_analyzer = WebAnalyzer()
honeypot_detector = HoneypotDetector()
geoip = GeoIPEnricher()
dns_enricher = DNSEnricher()
whois_enricher = WhoisEnricher()
cve_correlator = CVECorrelator()
elastic = ElasticStore(config.storage.elasticsearch_hosts, config.storage.index_prefix)
db = Database()
diff_engine = DiffEngine()
verifier = AccessVerifier()
secrets = SecretStore()
scheduler: ScanScheduler | None = None
crawler = OmniCrawler(db, elastic, scan_engine, service_detector, geoip, web_analyzer, cve_correlator)


def _shodan() -> ShodanSource:
    return ShodanSource(secrets.get("shodan_api_key"))


def _censys() -> CensysSource:
    return CensysSource(secrets.get("censys_api_id"), secrets.get("censys_api_secret"))


async def global_search(q: str, source: str = "shodan", page: int = 1) -> dict:
    """Query an external global provider (Shodan/Censys) using the same DSL,
    then enrich each hit with connection methods and a risk verdict so global
    results behave exactly like local ones."""
    parsed = db._query_parser.parse(q)
    if source == "censys":
        provider = _censys()
    else:
        provider = _shodan()
    if not provider.available:
        return {"total": 0, "results": [], "error": "no_key", "source": source,
                "page": 1, "pages": 0}
    res = await provider.search(parsed, page=page)
    for r in res.get("results", []):
        r["_access"] = access_methods(r)
        r["_risk"] = score_record(r)
    # Normalise pagination fields the template expects.
    total = res.get("total", len(res.get("results", [])))
    res.setdefault("page", page)
    res.setdefault("pages", max(1, (total + 24) // 25))
    return res

active_scans: dict[str, ScanSession] = {}


@app.on_event("startup")
async def startup():
    global scheduler
    await db.connect()
    try:
        await elastic.connect()
    except Exception:
        logger.warning("Elasticsearch not available, using SQLite only")

    scheduler = ScanScheduler(db, _run_scheduled_scan)
    await scheduler.start()


@app.on_event("shutdown")
async def shutdown():
    if scheduler:
        await scheduler.stop()
    await crawler.stop()
    await elastic.close()
    await db.close()

# ─── Crawler API ───

@app.post("/api/crawler/start")
async def api_crawler_start():
    await crawler.start()
    return {"status": "started"}

@app.post("/api/crawler/stop")
async def api_crawler_stop():
    await crawler.stop()
    return {"status": "stopped"}

@app.get("/api/crawler/status")
async def api_crawler_status():
    return crawler.get_status()

@app.get("/crawler", response_class=HTMLResponse)
async def crawler_page(request: Request):
    return templates.TemplateResponse(request, "crawler.html", {"crawler_status": crawler.get_status()})

async def _run_scheduled_scan(sched: ScheduledScan):
    """Bridge a scheduler tick into a normal scan session, then optionally
    auto-verify access on everything it found."""
    session = ScanSession(
        name=f"{sched.name} (scheduled)",
        targets=sched.targets,
        ports=sched.ports,
        protocol=sched.protocol,
        status="running",
    )
    session.total_hosts = len(PortScanner.parse_targets(sched.targets))
    active_scans[session.id] = session
    await db.save_session(session.to_dict())
    await _run_scan(session, sched.scan_mode)

    if getattr(sched, "auto_verify", False):
        try:
            results = await db.get_session_results(session.id)
            sem = asyncio.Semaphore(20)

            async def _v(r):
                async with sem:
                    rep = await verifier.verify(r, aggressive=False)
                    r["access_level"] = rep.level
                    r["access_summary"] = rep.summary
                    await db.save_result(r)
                    if rep.level in ("open", "anonymous", "default_creds"):
                        logger.info(f"[ACCESS] {r['ip']}:{r['port']} → {rep.level}: {rep.summary}")

            await asyncio.gather(*[_v(r) for r in results])
        except Exception as e:
            logger.debug(f"auto-verify skipped: {e}")


async def unified_search(query: str = "", filters: dict = None, page: int = 1, size: int = 20) -> dict:
    """Single entry point for all searches.

    Prefers Elasticsearch when it is connected (scale, aggregations, geo) and
    falls back to the embedded SQLite store otherwise. Both honour the same DSL
    because they share one parser, so callers never branch on the backend."""
    if elastic.available:
        res = await elastic.search(query=query, filters=filters or {}, page=page, size=size)
        # If ES is up but empty (e.g. brand-new cluster), still try SQLite so a
        # freshly-seeded local DB isn't hidden behind an empty cluster.
        if res.get("total", 0) > 0:
            res["backend"] = "elasticsearch"
            return res
    res = await db.search(query=query, filters=filters or {}, page=page, size=size)
    res["backend"] = "sqlite"
    return res


# ─── Web UI Routes ───

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    stats = await db.get_stats()
    return templates.TemplateResponse(request, "index.html", {
        "stats": stats, "categories": list_categories(),
    })


@app.get("/set-lang")
async def set_language(lang: str = "tr", next: str = "/"):
    """Flip the UI language by setting a cookie, then bounce back."""
    from fastapi.responses import RedirectResponse
    resp = RedirectResponse(url=next or "/")
    resp.set_cookie("lang", lang if lang in i18n.SUPPORTED else "tr", max_age=31536000)
    return resp


@app.get("/api/categories")
async def api_categories():
    """The intent catalogue powering Easy mode and scan presets."""
    return list_categories()


@app.get("/api/settings")
async def api_get_settings():
    """Which global providers are configured (keys never returned)."""
    return secrets.status()


@app.post("/api/settings")
async def api_set_settings(
    shodan_api_key: str = Query(default=None),
    censys_api_id: str = Query(default=None),
    censys_api_secret: str = Query(default=None),
):
    if shodan_api_key is not None:
        secrets.set("shodan_api_key", shodan_api_key.strip())
    if censys_api_id is not None:
        secrets.set("censys_api_id", censys_api_id.strip())
    if censys_api_secret is not None:
        secrets.set("censys_api_secret", censys_api_secret.strip())
    return secrets.status()


@app.get("/api/global-search")
async def api_global_search(q: str = Query(default=""), source: str = Query(default="shodan"),
                            page: int = Query(default=1, ge=1)):
    """Search the whole internet via Shodan/Censys global data."""
    return await global_search(q, source=source, page=page)


@app.websocket("/ws/feed")
async def ws_feed(websocket: WebSocket):
    """Live discovery feed — streams scan/verify/risk events as they happen."""
    await websocket.accept()
    q = bus.subscribe()
    try:
        # Replay recent events so a fresh connection isn't empty.
        for ev in bus.recent()[-20:]:
            await websocket.send_json(ev)
        while True:
            event = await q.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        bus.unsubscribe(q)


@app.post("/api/fingerprint")
async def api_fingerprint(ip: str = Query(...), port: int = Query(...), service: str = Query(default="")):
    """Advanced fingerprints (favicon hash + JARM-style TLS) that identify a
    device even when its text banners are stripped. Use as a pivot key to find
    every other identical deployment."""
    from ..fingerprint.deep_fingerprint import deep_fingerprint
    fp = await deep_fingerprint(ip, port, service)
    return {"ip": ip, "port": port, **fp,
            "note": "favicon_hash/jarm aynı çıkan cihazlar aynı yazılımı çalıştırıyor demektir."}


@app.get("/api/risk/top")
async def api_risk_top(limit: int = Query(default=20, le=100)):
    """The riskiest hosts in the index — a prioritised worklist."""
    res = await db.search(query="", filters={}, page=1, size=500)
    by_host: dict[str, list] = {}
    for r in res["results"]:
        by_host.setdefault(r["ip"], []).append(r)
    ranked = []
    for ip, recs in by_host.items():
        hr = score_host(recs)
        ranked.append({"ip": ip, **hr})
    ranked.sort(key=lambda x: x["score"], reverse=True)
    return ranked[:limit]


@app.post("/api/demo/seed")
async def api_demo_seed():
    """Load a labelled demo dataset so search works on a fresh install."""
    from ..demo import build_demo_records
    records = build_demo_records()
    for rec in records:
        await db.save_result(rec)
        await elastic.store(rec)
    return {"seeded": len(records), "note": "Demo data tagged session_id='demo'. Wipe via /api/demo/clear."}


@app.post("/api/demo/clear")
async def api_demo_clear():
    """Remove all demo records."""
    await db._conn.execute("DELETE FROM scan_results WHERE session_id = 'demo'")
    await db._conn.commit()
    return {"cleared": True}


@app.post("/api/verify")
async def api_verify(ip: str = Query(...), port: int = Query(...),
                     service: str = Query(default=""), aggressive: bool = Query(default=False)):
    """Actively connect and report the real access level, with evidence.

    This is the 'I got in, so can you' check — it goes past the banner to
    confirm whether a service is wide open, anonymous, default-credentialed or
    locked. Read-only and non-destructive. Authorized targets only."""
    report = await verifier.verify({"ip": ip, "port": port, "service": service}, aggressive=aggressive)

    # Persist the verdict so it shows on the record and is searchable.
    try:
        rec = await db.search(query="", filters={"ip": ip, "port": port}, size=1)
        if rec["results"]:
            r = rec["results"][0]
            r["access_level"] = report.level
            r["access_summary"] = report.summary
            r["_access"] = access_methods(r)
            await db.save_result(r)
    except Exception as e:
        logger.debug(f"verify persist skipped: {e}")

    # Push exposed verdicts to the live feed.
    if report.level in ("open", "anonymous", "default_creds"):
        bus.publish("access", {"ip": ip, "port": port, "level": report.level,
                               "summary": report.summary})

    return report.to_dict()


@app.post("/api/verify-session/{session_id}")
async def api_verify_session(session_id: str, aggressive: bool = Query(default=False)):
    """Verify access for every open service found in a scan session."""
    results = await db.get_session_results(session_id)
    reports = []
    sem = asyncio.Semaphore(20)

    async def _one(r):
        async with sem:
            rep = await verifier.verify(r, aggressive=aggressive)
            r["access_level"] = rep.level
            r["access_summary"] = rep.summary
            await db.save_result(r)
            return rep.to_dict()

    reports = await asyncio.gather(*[_one(r) for r in results])
    summary = {}
    for rep in reports:
        summary[rep["level"]] = summary.get(rep["level"], 0) + 1
    return {"verified": len(reports), "by_level": summary, "reports": reports}


# A comprehensive sweep set — web, remote, db, mail, file, IoT, ICS, cameras,
# proxies and common alt ports. Used for "scan everything" continuous mode.
COMPREHENSIVE_PORTS = (
    "21,22,23,25,53,80,81,88,110,111,135,139,143,161,389,443,445,465,514,515,"
    "554,587,631,636,873,902,993,995,1080,1433,1521,1723,1883,1900,2000,2049,"
    "2082,2083,2222,2375,2376,3128,3306,3389,3690,4444,4500,4567,4899,5000,5001,"
    "5060,5432,5560,5601,5672,5683,5900,5901,5984,6379,6443,6660,7001,7070,7474,"
    "7547,7777,8000,8008,8009,8080,8081,8086,8088,8123,8161,8181,8291,8443,8500,"
    "8554,8728,8765,8800,8883,8888,9000,9042,9090,9100,9200,9300,9418,9600,9999,"
    "10000,10250,11211,15672,20000,27017,28017,32400,34567,37777,44818,47808,49152,50000"
)


@app.post("/api/continuous/start")
async def api_continuous_start(
    targets: str = Query(...),
    interval_seconds: int = Query(default=300, ge=60),
    ports: str = Query(default=COMPREHENSIVE_PORTS),
    auto_verify: bool = Query(default=True),
):
    """One-click continuous monitoring: re-scan a target on a loop, auto-verify
    access on what it finds, and surface everything via the normal feed."""
    if scheduler is None:
        return JSONResponse({"error": "Scheduler not ready"}, status_code=503)
    sched = ScheduledScan(
        name=f"Sürekli: {targets}",
        targets=targets, ports=ports, protocol="tcp",
        scan_mode="auto", interval_seconds=interval_seconds,
        auto_verify=auto_verify,
    )
    await scheduler.add(sched)
    # Kick off the first pass immediately so the user sees results now.
    asyncio.create_task(_run_scheduled_scan(sched))
    return {"started": True, "id": sched.id, "interval_seconds": interval_seconds}


@app.get("/search", response_class=HTMLResponse)
async def search_page(request: Request, q: str = "", page: int = 1, source: str = "local"):
    filters = {}
    for key in ("port", "service", "country", "product", "city", "asn"):
        val = request.query_params.get(key)
        if val:
            filters[key] = val

    results = {}
    matched = []

    if source == "live" and q:
        import re
        import socket
        
        # Simple heuristic: Does it look like an IP, CIDR, IP range, or a valid domain?
        is_valid_target = False
        clean_q = q.strip()
        
        # 1. CIDR or Range
        if "/" in clean_q or "-" in clean_q:
            # Assume it's an IP range if it contains / or -, PortScanner will handle specifics
            is_valid_target = True
        else:
            # 2. Check if it's a valid IP
            try:
                import ipaddress
                ipaddress.ip_address(clean_q)
                is_valid_target = True
            except ValueError:
                # 3. Check if it's a resolvable domain (and not a generic single word like "camera")
                if "." in clean_q and " " not in clean_q:
                    try:
                        socket.gethostbyname(clean_q)
                        is_valid_target = True
                    except socket.gaierror:
                        pass

        if not is_valid_target:
            results = {
                "error": "Lütfen canlı tarama için geçerli bir IP adresi, IP aralığı (CIDR) veya alan adı (domain) girin. "
                         "Cihaz türü veya anahtar kelime (ör. 'camera', 'port:80') aramak için 'Yerel Taramalar' sekmesini kullanın."
            }
        else:
            # Start a live scan via OmniSight's own engine instead of hitting Shodan
            session = ScanSession(
                name=f"Canlı Tarama: {q}",
                targets=q,
                ports="21-23,25,53,80,110,443,993,3306,3389,5432,8080,8443",
                protocol="tcp",
                status="running",
            )
            try:
                target_list = PortScanner.parse_targets(q)
                session.total_hosts = len(target_list)
                active_scans[session.id] = session
                await db.save_session(session.to_dict())
                asyncio.create_task(_run_scan(session, "auto"))
                results = {"session_id": session.id, "status": "started", "total_hosts": session.total_hosts}
            except ValueError as e:
                results = {"error": f"Hedef ayrıştırma hatası: {e}"}

    elif source != "live":
        results = await unified_search(query=q, filters=filters, page=page)
        # Attach connection methods + risk verdict so each result is actionable.
        for r in results.get("results", []):
            r["_access"] = access_methods(r)
            r["_risk"] = score_record(r)

        # Surface which intent categories the query resolved to, so the user sees
        # "Showing IP Cameras / DVR / NVR" rather than a bare keyword.
        parsed = db._query_parser.parse(q)
        for ck in parsed.categories:
            cat = CATEGORIES.get(ck)
            if cat:
                matched.append({"key": cat.key, "label": cat.label, "icon": cat.icon,
                                "description": cat.description})

    return templates.TemplateResponse(request, "search.html", {
        "query": q, "results": results, "filters": filters, "source": source,
        "provider_status": secrets.status(),
        "matched_categories": matched,
    })


@app.get("/host/{ip}", response_class=HTMLResponse)
async def host_detail(request: Request, ip: str):
    results = await db.search(query="", filters={"ip": ip}, size=100)
    for r in results["results"]:
        r["_access"] = access_methods(r)
        r["_risk"] = score_record(r)
    host_risk = score_host(results["results"])
    geo = geoip.lookup(ip)
    dns_info = await dns_enricher.reverse_lookup(ip)
    whois_info = await whois_enricher.lookup(ip)

    # Free Shodan InternetDB cross-reference (no API key) — what the rest of the
    # internet already knows about this host, next to your own scan.
    shodan_view = None
    try:
        if not ip.startswith(("192.168.", "10.", "172.16.", "127.")):
            sv = await _shodan().host_lookup(ip)
            if sv.get("results") or sv.get("tags"):
                shodan_view = {
                    "ports": sorted({r["port"] for r in sv.get("results", [])}),
                    "cves": sv["results"][0].get("cves", []) if sv.get("results") else [],
                    "tags": sv.get("tags", []),
                }
    except Exception:
        pass

    return templates.TemplateResponse(request, "detail.html", {
        "ip": ip, "records": results["results"], "host_risk": host_risk,
        "geo": geo, "dns": dns_info, "whois": whois_info, "shodan_view": shodan_view,
    })


@app.get("/stats", response_class=HTMLResponse)
async def stats_page(request: Request):
    stats = await db.get_stats()
    return templates.TemplateResponse(request, "stats.html", {"stats": stats})


# ─── API Routes ───

@app.post("/api/scan")
async def api_start_scan(
    targets: str = Query(..., description="Target IPs/CIDRs"),
    ports: str = Query(default="21-23,25,53,80,110,443,993,3306,3389,5432,8080,8443"),
    protocol: str = Query(default="tcp"),
    name: str = Query(default=""),
    scan_mode: str = Query(default="auto", description="auto | syn | connect"),
):
    session = ScanSession(
        name=name or f"Scan {targets}",
        targets=targets,
        ports=ports,
        protocol=protocol,
        status="running",
    )

    target_list = PortScanner.parse_targets(targets)
    session.total_hosts = len(target_list)
    active_scans[session.id] = session

    await db.save_session(session.to_dict())
    asyncio.create_task(_run_scan(session, scan_mode))

    return {"session_id": session.id, "status": "started", "total_hosts": session.total_hosts, "scan_mode": scan_mode}


async def _run_scan(session: ScanSession, scan_mode: str = "auto"):
    try:
        results = await scan_engine.scan(
            targets=session.targets,
            ports=session.ports,
            protocol=session.protocol,
            scan_mode=scan_mode,
        )

        session.open_ports_found = len(results)

        for sr in results:
            record = ScanRecord(
                ip=sr.ip,
                port=sr.port,
                protocol=sr.protocol,
                state=sr.state,
                banner=sr.banner,
                headers=sr.headers,
                ssl_info=sr.ssl_info,
                latency_ms=sr.latency_ms,
                deep_data=sr.deep_data,
                findings=list(sr.findings),
                os_guess=sr.os_guess,
                scan_session_id=session.id,
            )

            svc = service_detector.detect(sr.banner, sr.port)
            # Prefer the deep probe's protocol verdict; fall back to signature.
            record.service = sr.service or svc.name
            record.product = svc.product
            record.version = sr.version or svc.version

            geo = geoip.lookup(sr.ip)
            record.country = geo.country
            record.country_code = geo.country_code
            record.city = geo.city
            record.latitude = geo.latitude
            record.longitude = geo.longitude
            record.asn = geo.asn
            record.as_org = geo.as_org

            if sr.headers:
                wfp = web_analyzer.analyze(sr.headers, sr.banner)
                record.technologies = wfp.technologies
                record.cms = wfp.cms
                record.web_title = wfp.technologies[0] if wfp.technologies else ""
                record.web_server = wfp.server
                record.waf = wfp.waf

            probe_product = record.product or record.service
            if probe_product:
                cves = cve_correlator.correlate(probe_product, record.version, sr.banner)
                record.cves = cves

            record_dict = record.to_dict()
            await db.save_result(record_dict)
            await elastic.store(record_dict)

            # Stream every discovery to the live feed with its risk verdict.
            risk = score_record(record_dict)
            bus.publish("found", {
                "ip": record.ip, "port": record.port,
                "service": record.service or record.protocol,
                "product": record.product, "risk": risk.score,
                "severity": risk.severity,
            })

        session.status = "completed"
        session.end_time = time.time()
    except Exception as e:
        session.status = "failed"
        session.error = str(e)
        session.end_time = time.time()
        logger.error(f"Scan failed: {e}")
    finally:
        await db.save_session(session.to_dict())
        active_scans.pop(session.id, None)
        # Auto-diff against the previous completed scan of the same target.
        try:
            await _auto_diff(session)
        except Exception as e:
            logger.debug(f"Auto-diff skipped: {e}")


async def _auto_diff(session: ScanSession):
    if session.status != "completed":
        return
    history = await db.get_sessions_for_targets(session.targets, limit=2)
    if len(history) < 2:
        return
    # history[0] is this session, history[1] the prior one.
    prev = history[1]
    old = await db.get_session_results(prev["id"])
    new = await db.get_session_results(session.id)
    deltas = diff_engine.diff(old, new)
    summary = diff_engine.summarize(deltas)
    if summary["hosts_changed"]:
        logger.info(
            f"Change detected vs previous scan of {session.targets}: "
            f"{summary['ports_opened']} opened, {summary['ports_closed']} closed, "
            f"{summary['findings_new']} new findings"
        )


@app.get("/api/scan/{session_id}")
async def api_scan_status(session_id: str):
    if session_id in active_scans:
        return active_scans[session_id].to_dict()
    sessions = await db.get_sessions()
    for s in sessions:
        if s["id"] == session_id:
            return s
    return JSONResponse({"error": "Session not found"}, status_code=404)


@app.get("/api/search")
async def api_search(
    q: str = Query(default=""),
    port: int = Query(default=None),
    service: str = Query(default=None),
    country: str = Query(default=None),
    product: str = Query(default=None),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
):
    filters = {}
    if port:
        filters["port"] = port
    if service:
        filters["service"] = service
    if country:
        filters["country_code"] = country
    if product:
        filters["product"] = product

    return await unified_search(query=q, filters=filters, page=page, size=size)


@app.get("/api/host/{ip}")
async def api_host_info(ip: str):
    results = await db.search(query="", filters={"ip": ip}, size=100)
    geo = geoip.lookup(ip)
    dns_info = await dns_enricher.reverse_lookup(ip)

    return {
        "ip": ip,
        "ports": results["results"],
        "geo": {
            "country": geo.country, "country_code": geo.country_code,
            "city": geo.city, "latitude": geo.latitude, "longitude": geo.longitude,
            "asn": geo.asn, "as_org": geo.as_org,
        },
        "dns": {"reverse_dns": dns_info.reverse_dns, "hostnames": dns_info.hostnames},
        "total_open_ports": results["total"],
    }


@app.get("/api/stats")
async def api_stats():
    return await db.get_stats()


@app.get("/api/sessions")
async def api_sessions():
    return await db.get_sessions()


@app.get("/api/export/{session_id}")
async def api_export(session_id: str, format: str = Query(default="json")):
    results = await db.search(query="", filters={"session_id": session_id}, size=10000)

    if format == "csv":
        import csv
        import io
        output = io.StringIO()
        if results["results"]:
            writer = csv.DictWriter(output, fieldnames=results["results"][0].keys())
            writer.writeheader()
            writer.writerows(results["results"])
        return JSONResponse(content={"csv": output.getvalue()})

    return results


# ─── Diff API ───

@app.get("/api/diff")
async def api_diff(session_a: str = Query(...), session_b: str = Query(...)):
    """Diff two scan sessions by id (a = older baseline, b = newer)."""
    old = await db.get_session_results(session_a)
    new = await db.get_session_results(session_b)
    deltas = diff_engine.diff(old, new)
    return {
        "session_a": session_a,
        "session_b": session_b,
        "summary": diff_engine.summarize(deltas),
        "deltas": [d.to_dict() for d in deltas],
    }


@app.get("/api/diff/latest")
async def api_diff_latest(targets: str = Query(...)):
    """Diff the two most recent completed scans of a target spec."""
    history = await db.get_sessions_for_targets(targets, limit=2)
    if len(history) < 2:
        return {"error": "Need at least two completed scans of this target", "available": len(history)}
    new, old = history[0], history[1]
    old_r = await db.get_session_results(old["id"])
    new_r = await db.get_session_results(new["id"])
    deltas = diff_engine.diff(old_r, new_r)
    return {
        "targets": targets,
        "from_session": old["id"],
        "to_session": new["id"],
        "summary": diff_engine.summarize(deltas),
        "deltas": [d.to_dict() for d in deltas],
    }


@app.get("/diff", response_class=HTMLResponse)
async def diff_page(request: Request, targets: str = ""):
    diff_data = None
    if targets:
        history = await db.get_sessions_for_targets(targets, limit=2)
        if len(history) >= 2:
            old_r = await db.get_session_results(history[1]["id"])
            new_r = await db.get_session_results(history[0]["id"])
            deltas = diff_engine.diff(old_r, new_r)
            diff_data = {
                "summary": diff_engine.summarize(deltas),
                "deltas": [d.to_dict() for d in deltas],
                "from": history[1], "to": history[0],
            }
    sessions = await db.get_sessions()
    return templates.TemplateResponse(request, "diff.html", {
        "targets": targets, "diff": diff_data, "sessions": sessions,
    })


# ─── Scheduler API ───

@app.post("/api/schedule")
async def api_add_schedule(
    targets: str = Query(...),
    ports: str = Query(default="21-23,25,53,80,110,443,993,3306,3389,5432,8080,8443"),
    protocol: str = Query(default="tcp"),
    scan_mode: str = Query(default="auto"),
    interval_seconds: int = Query(default=3600, ge=60),
    name: str = Query(default=""),
):
    if scheduler is None:
        return JSONResponse({"error": "Scheduler not ready"}, status_code=503)
    sched = ScheduledScan(
        name=name or f"Monitor {targets}",
        targets=targets, ports=ports, protocol=protocol,
        scan_mode=scan_mode, interval_seconds=interval_seconds,
    )
    await scheduler.add(sched)
    return sched.to_dict()


@app.get("/api/schedules")
async def api_list_schedules():
    if scheduler is None:
        return []
    return scheduler.list()


@app.delete("/api/schedule/{sched_id}")
async def api_delete_schedule(sched_id: str):
    if scheduler is None:
        return JSONResponse({"error": "Scheduler not ready"}, status_code=503)
    ok = await scheduler.remove(sched_id)
    return {"removed": ok}


@app.post("/api/schedule/{sched_id}/toggle")
async def api_toggle_schedule(sched_id: str, enabled: bool = Query(...)):
    if scheduler is None:
        return JSONResponse({"error": "Scheduler not ready"}, status_code=503)
    ok = await scheduler.set_enabled(sched_id, enabled)
    return {"updated": ok}


@app.get("/monitor", response_class=HTMLResponse)
async def monitor_page(request: Request):
    schedules = scheduler.list() if scheduler else []
    return templates.TemplateResponse(request, "monitor.html", {"schedules": schedules})
