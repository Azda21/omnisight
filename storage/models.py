import time
import uuid
from dataclasses import dataclass, field


@dataclass
class ScanRecord:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ip: str = ""
    port: int = 0
    protocol: str = ""
    state: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    os_guess: str = ""
    headers: dict = field(default_factory=dict)
    ssl_info: dict = field(default_factory=dict)

    # Enrichment
    country: str = ""
    country_code: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    asn: int = 0
    as_org: str = ""
    reverse_dns: str = ""
    whois_org: str = ""

    # Web fingerprint
    technologies: list = field(default_factory=list)
    cms: str = ""
    web_title: str = ""
    web_server: str = ""
    waf: str = ""

    # Vulnerabilities
    cves: list = field(default_factory=list)
    honeypot_score: float = 0.0

    # Deep-probe structured output and security findings
    deep_data: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    # Meta
    scan_session_id: str = ""
    timestamp: float = field(default_factory=time.time)
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "banner": self.banner[:2000],
            "os_guess": self.os_guess,
            "headers": self.headers,
            "ssl_info": {k: str(v) for k, v in self.ssl_info.items()},
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "location": {"lat": self.latitude, "lon": self.longitude} if self.latitude else None,
            "asn": self.asn,
            "as_org": self.as_org,
            "reverse_dns": self.reverse_dns,
            "whois_org": self.whois_org,
            "technologies": self.technologies,
            "cms": self.cms,
            "web_title": self.web_title,
            "web_server": self.web_server,
            "waf": self.waf,
            "cves": [{"id": c.cve_id, "severity": c.severity, "score": c.cvss_score, "description": c.description}
                     for c in self.cves] if self.cves else [],
            "honeypot_score": self.honeypot_score,
            "deep_data": self.deep_data,
            "findings": self.findings,
            "scan_session_id": self.scan_session_id,
            "timestamp": self.timestamp,
            "latency_ms": self.latency_ms,
        }


@dataclass
class ScanSession:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    targets: str = ""
    ports: str = ""
    protocol: str = "tcp"
    status: str = "pending"  # pending, running, completed, failed
    total_hosts: int = 0
    total_ports_scanned: int = 0
    open_ports_found: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "targets": self.targets,
            "ports": self.ports,
            "protocol": self.protocol,
            "status": self.status,
            "total_hosts": self.total_hosts,
            "total_ports_scanned": self.total_ports_scanned,
            "open_ports_found": self.open_ports_found,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.end_time - self.start_time if self.end_time else 0,
            "error": self.error,
        }
