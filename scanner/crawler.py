import asyncio
import logging
import random
import ipaddress
import time
from typing import Optional

from ..storage.database import Database
from ..storage.elasticsearch_store import ElasticStore
from ..storage.models import ScanSession
from .engine import ScanEngine

logger = logging.getLogger("omnisight.scanner.crawler")

class OmniCrawler:
    def __init__(self, db, elastic, scan_engine, service_detector, geoip, web_analyzer, cve_correlator):
        self.db = db
        self.elastic = elastic
        self.scan_engine = scan_engine
        self.service_detector = service_detector
        self.geoip = geoip
        self.web_analyzer = web_analyzer
        self.cve_correlator = cve_correlator
        self.running = False
        self.task: Optional[asyncio.Task] = None
        
        # Stats
        self.ips_scanned = 0
        self.devices_found = 0
        self.start_time = 0.0
        self.current_target = ""

    def _generate_public_cidr(self) -> str:
        """Generates a random public /24 CIDR."""
        while True:
            # Generate a random IPv4 address
            ip_int = random.randint(0x01000000, 0xDFFFFFFF) # 1.0.0.0 to 223.255.255.255
            try:
                ip_obj = ipaddress.IPv4Address(ip_int)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
                    continue
                # Return the /24 network for this IP
                net = ipaddress.IPv4Network(f"{ip_obj}/24", strict=False)
                return str(net)
            except ValueError:
                continue

    async def start(self):
        if self.running:
            return
        self.running = True
        self.start_time = time.time()
        self.task = asyncio.create_task(self._crawl_loop())
        logger.info("OmniCrawler started.")

    async def stop(self):
        if not self.running:
            return
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("OmniCrawler stopped.")

    async def _crawl_loop(self):
        # We target a curated list of interesting ports for discovery
        # 80(HTTP), 443(HTTPS), 8080(HTTP Alt), 8443(HTTPS Alt), 554(RTSP Camera), 
        # 21(FTP), 22(SSH), 23(Telnet), 3306(MySQL), 5432(PostgreSQL), 27017(Mongo)
        ports = "21,22,23,80,443,554,3306,5432,8080,8443,27017"

        while self.running:
            try:
                target_cidr = self._generate_public_cidr()
                self.current_target = target_cidr
                logger.info(f"Crawler targeting: {target_cidr}")
                
                # We create a pseudo-session so findings get tagged and correlated
                session = ScanSession(
                    name=f"Crawler: {target_cidr}",
                    targets=target_cidr,
                    ports=ports,
                    protocol="tcp",
                    status="running"
                )
                session.total_hosts = 256
                await self.db.save_session(session.to_dict())
                
                # Use scan_engine directly
                results = await self.scan_engine.scan(
                    targets=target_cidr,
                    ports=ports,
                    protocol="tcp",
                    scan_mode="auto"
                )
                
                self.ips_scanned += 256
                
                # Process and save results
                from ..storage.models import ScanRecord
                for sr in results:
                    self.devices_found += 1
                    
                    # Same enrichment logic as app.py
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

                    svc = self.service_detector.detect(sr.banner, sr.port)
                    record.service = sr.service or svc.name
                    record.product = svc.product
                    record.version = sr.version or svc.version

                    geo = self.geoip.lookup(sr.ip)
                    record.country = geo.country
                    record.country_code = geo.country_code
                    record.city = geo.city
                    record.latitude = geo.latitude
                    record.longitude = geo.longitude
                    record.asn = geo.asn
                    record.as_org = geo.as_org

                    if sr.headers:
                        wfp = self.web_analyzer.analyze(sr.headers, sr.banner)
                        record.technologies = wfp.technologies
                        record.cms = wfp.cms
                        record.web_title = wfp.technologies[0] if wfp.technologies else ""
                        record.web_server = wfp.server
                        record.waf = wfp.waf

                    probe_product = record.product or record.service
                    if probe_product:
                        cves = self.cve_correlator.correlate(probe_product, record.version, sr.banner)
                        record.cves = cves

                    record_dict = record.to_dict()
                    await self.db.save_result(record_dict)
                    if self.elastic.available:
                        await self.elastic.store(record_dict)

                session.status = "completed"
                session.open_ports_found = len(results)
                session.end_time = time.time()
                await self.db.save_session(session.to_dict())
                
                # Small sleep to prevent burning CPU/Network completely
                await asyncio.sleep(2)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Crawler error on {self.current_target}: {e}")
                await asyncio.sleep(5)

    def get_status(self) -> dict:
        uptime = time.time() - self.start_time if self.running else 0
        speed = self.ips_scanned / uptime if uptime > 0 else 0
        return {
            "running": self.running,
            "current_target": self.current_target,
            "ips_scanned": self.ips_scanned,
            "devices_found": self.devices_found,
            "uptime_seconds": uptime,
            "ips_per_second": round(speed, 2)
        }
