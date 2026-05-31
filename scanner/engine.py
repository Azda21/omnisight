import asyncio
import logging
import time
from dataclasses import dataclass, field

from .port_scanner import PortScanner, PortResult
from .banner_grabber import BannerGrabber, BannerResult
from .deep_probe import DeepProbe
from .syn_scanner import SynScanner, syn_scan_supported

logger = logging.getLogger("omnisight.scanner.engine")


@dataclass
class ScanResult:
    ip: str
    port: int
    protocol: str
    state: str
    banner: str = ""
    raw_banner: bytes = b""
    service: str = ""
    version: str = ""
    os_guess: str = ""
    headers: dict = field(default_factory=dict)
    ssl_info: dict = field(default_factory=dict)
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    enrichment: dict = field(default_factory=dict)
    # Structured output from the protocol-specific deep probe, keyed by field.
    deep_data: dict = field(default_factory=dict)
    # Human-readable security observations surfaced from the deep probe
    # (anonymous FTP, unauthenticated MQTT, RDP without NLA, ...).
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "banner": self.banner,
            "service": self.service,
            "version": self.version,
            "os_guess": self.os_guess,
            "headers": self.headers,
            "ssl_info": {k: str(v) for k, v in self.ssl_info.items()},
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp,
            "enrichment": self.enrichment,
            "deep_data": self.deep_data,
            "findings": self.findings,
        }


class ScanEngine:
    def __init__(self, config=None):
        timeout = 5.0
        max_concurrent = 500
        rate_limit = 1000

        if config:
            timeout = config.scanner.timeout
            max_concurrent = config.scanner.max_concurrent
            rate_limit = config.scanner.rate_limit

        self.port_scanner = PortScanner(
            timeout=timeout,
            max_concurrent=max_concurrent,
            rate_limit=rate_limit,
        )
        self.banner_grabber = BannerGrabber(
            timeout=timeout,
            max_concurrent=max_concurrent // 2,
        )
        self.deep_probe = DeepProbe(
            timeout=timeout,
            max_concurrent=max(max_concurrent // 4, 20),
        )
        self._results: list[ScanResult] = []
        self._callbacks = []

    def on_result(self, callback):
        self._callbacks.append(callback)

    async def _notify(self, result: ScanResult):
        for cb in self._callbacks:
            if asyncio.iscoroutinefunction(cb):
                await cb(result)
            else:
                cb(result)

    async def scan(
        self,
        targets: str,
        ports: str = None,
        protocol: str = "tcp",
        grab_banners: bool = True,
        scan_mode: str = "auto",
    ) -> list[ScanResult]:
        target_list = PortScanner.parse_targets(targets)
        if ports:
            port_list = PortScanner.parse_ports(ports)
        else:
            port_list = PortScanner.parse_ports("21-23,25,53,80,110,443,993,3306,3389,5432,8080,8443")

        results = []
        start = time.monotonic()

        # ─ Phase 1 — discovery. SYN where we can (stateless, fast), connect otherwise ─
        use_syn = self._should_use_syn(scan_mode, protocol)
        logger.info(
            f"Scan started: {len(target_list)} targets, {len(port_list)} ports, "
            f"protocol={protocol}, mode={'syn' if use_syn else 'connect'}"
        )

        open_ports: list[tuple[str, int]] = []

        if use_syn:
            try:
                open_ports = await self._syn_discovery(target_list, port_list, results)
            except (PermissionError, OSError) as e:
                logger.warning(f"SYN scan unavailable ({e}); falling back to connect scan")
                use_syn = False
                results.clear()

        if not use_syn:
            async for port_result in self.port_scanner.scan_range(target_list, port_list, protocol):
                if port_result.state == "open":
                    open_ports.append((port_result.ip, port_result.port))

                    scan_result = ScanResult(
                        ip=port_result.ip,
                        port=port_result.port,
                        protocol=port_result.protocol,
                        state=port_result.state,
                        latency_ms=port_result.latency_ms,
                        timestamp=port_result.timestamp,
                    )
                    results.append(scan_result)

        if grab_banners and open_ports:
            # Phase 2 — banner grab: cheap, one round-trip, seeds the protocol guess.
            logger.info(f"Grabbing banners for {len(open_ports)} open ports...")
            banner_tasks = [
                self.banner_grabber.grab_banner(ip, port) for ip, port in open_ports
            ]
            banner_results = await asyncio.gather(*banner_tasks, return_exceptions=True)

            banner_map = {}
            for br in banner_results:
                if isinstance(br, BannerResult) and not br.error:
                    banner_map[(br.ip, br.port)] = br

            for sr in results:
                br = banner_map.get((sr.ip, sr.port))
                if br:
                    sr.banner = br.banner
                    sr.raw_banner = br.raw_banner
                    sr.headers = br.headers
                    sr.ssl_info = br.ssl_info
                    sr.service = br.protocol

            # Phase 3 — deep probe: speak the actual protocol for structured intel.
            deep_targets = [
                (sr.ip, sr.port, sr.service) for sr in results
            ]
            logger.info(f"Deep-probing {len(deep_targets)} services...")
            deep_map = await self.deep_probe.probe_many(deep_targets)

            for sr in results:
                deep = deep_map.get((sr.ip, sr.port))
                if deep:
                    sr.deep_data = deep.get("data", {})
                    self._apply_deep_data(sr, deep.get("probe", ""), sr.deep_data)
                await self._notify(sr)

        elapsed = time.monotonic() - start
        logger.info(f"Scan complete: {len(results)} open ports found in {elapsed:.1f}s")

        self._results = results
        return results

    def _should_use_syn(self, scan_mode: str, protocol: str) -> bool:
        if protocol != "tcp":
            return False
        if scan_mode == "connect":
            return False
        if scan_mode == "syn":
            return True
        # auto: use SYN only if the platform/privileges allow raw sockets.
        ok, _ = syn_scan_supported()
        return ok

    async def _syn_discovery(self, targets, ports, results) -> list[tuple[str, int]]:
        rate = getattr(self.port_scanner, "rate_limit", 5000)
        syn = SynScanner(rate_limit=max(rate, 1000))
        syn_results = await syn.scan(targets, ports)
        open_ports = []
        for sr in syn_results:
            open_ports.append((sr.ip, sr.port))
            results.append(ScanResult(
                ip=sr.ip, port=sr.port, protocol="tcp", state="open",
                latency_ms=sr.latency_ms, timestamp=sr.timestamp,
            ))
        return open_ports

    @staticmethod
    def _apply_deep_data(sr: ScanResult, probe: str, data: dict) -> None:
        """Promote structured deep-probe output into top-level fields and raise
        security findings. This is where speaking the protocol pays off."""
        if not data:
            return

        if probe == "ssh":
            sr.service = "ssh"
            sr.os_guess = data.get("os_hint", "") or sr.os_guess
            if data.get("software"):
                sr.version = data["software"]

        elif probe == "ftp":
            sr.service = "ftp"
            if data.get("software"):
                sr.version = f"{data['software']} {data.get('version', '')}".strip()
            if data.get("anonymous_login"):
                sr.findings.append("Anonymous FTP login permitted")

        elif probe == "smtp":
            sr.service = "smtp"
            if data.get("software"):
                sr.version = f"{data['software']} {data.get('version', '')}".strip()
            if data.get("auth_methods") and not data.get("supports_starttls"):
                sr.findings.append("SMTP AUTH offered without STARTTLS (credentials in cleartext)")

        elif probe in ("http", "https"):
            sr.service = probe
            if data.get("server"):
                sr.version = data["server"]
            if data.get("title"):
                sr.deep_data["title"] = data["title"]

        elif probe == "mysql":
            sr.service = "mysql"
            if data.get("version"):
                sr.version = data["version"]

        elif probe == "rdp":
            sr.service = "rdp"
            if data.get("is_rdp") and not data.get("nla_supported"):
                sr.findings.append("RDP exposed without NLA (pre-auth attack surface)")

        elif probe == "mqtt":
            sr.service = "mqtt"
            if data.get("allows_anonymous"):
                sr.findings.append("MQTT broker accepts unauthenticated connections")

        elif probe == "modbus":
            sr.service = "modbus"
            vendor = data.get("vendor", "")
            product = data.get("product_name", "")
            if vendor or product:
                sr.version = f"{vendor} {product}".strip()
            sr.findings.append("Exposed Modbus/ICS device (no native authentication)")

        elif probe == "rtsp":
            sr.service = "rtsp"
            if data.get("server"):
                sr.version = data["server"]
            if data.get("is_rtsp") and not data.get("requires_auth"):
                sr.findings.append("RTSP stream reachable without authentication")

    async def quick_scan(self, target: str) -> list[ScanResult]:
        return await self.scan(target, ports="21-23,25,53,80,110,443,993,3306,3389,5432,8080,8443")

    async def full_scan(self, target: str) -> list[ScanResult]:
        return await self.scan(target, ports="1-65535")

    @property
    def results(self) -> list[ScanResult]:
        return self._results
