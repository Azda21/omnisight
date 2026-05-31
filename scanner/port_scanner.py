import asyncio
import socket
import struct
import logging
import time
from dataclasses import dataclass, field
from typing import AsyncGenerator

from .rate_limiter import AdaptiveRateLimiter

logger = logging.getLogger("omnisight.scanner.port")


@dataclass
class PortResult:
    ip: str
    port: int
    protocol: str  # tcp / udp
    state: str  # open / closed / filtered
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


class PortScanner:
    def __init__(self, timeout: float = 3.0, max_concurrent: int = 500, rate_limit: int = 1000):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._limiter = AdaptiveRateLimiter(rate=float(rate_limit))
        self._scan_count = 0
        self._start_time = 0.0

    @staticmethod
    def parse_ports(port_spec: str) -> list[int]:
        ports = []
        for part in port_spec.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    @staticmethod
    def parse_targets(target_spec: str) -> list[str]:
        targets = []
        target_spec = target_spec.strip()
        if "/" in target_spec:
            targets.extend(PortScanner._cidr_to_ips(target_spec))
        elif "-" in target_spec.split(".")[-1]:
            base = ".".join(target_spec.split(".")[:-1])
            range_part = target_spec.split(".")[-1]
            start, end = range_part.split("-")
            for i in range(int(start), int(end) + 1):
                targets.append(f"{base}.{i}")
        else:
            targets.append(target_spec)
        return targets

    @staticmethod
    def _cidr_to_ips(cidr: str) -> list[str]:
        parts = cidr.split("/")
        ip = parts[0]
        prefix = int(parts[1])
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        network = ip_int & mask
        broadcast = network | (~mask & 0xFFFFFFFF)
        ips = []
        for addr in range(network + 1, broadcast):
            ips.append(socket.inet_ntoa(struct.pack("!I", addr)))
        return ips

    async def scan_tcp_port(self, ip: str, port: int) -> PortResult:
        await self._limiter.acquire()
        async with self._semaphore:
            start = time.monotonic()
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
                latency = (time.monotonic() - start) * 1000
                writer.close()
                await writer.wait_closed()
                self._limiter.record(success=True)
                return PortResult(ip=ip, port=port, protocol="tcp", state="open", latency_ms=latency)
            except asyncio.TimeoutError:
                self._limiter.record(success=False)
                return PortResult(ip=ip, port=port, protocol="tcp", state="filtered")
            except ConnectionRefusedError:
                # A refusal is a definitive answer from a live host, not pressure.
                self._limiter.record(success=True)
                return PortResult(ip=ip, port=port, protocol="tcp", state="closed")
            except OSError:
                self._limiter.record(success=False)
                return PortResult(ip=ip, port=port, protocol="tcp", state="filtered")

    async def scan_udp_port(self, ip: str, port: int) -> PortResult:
        await self._limiter.acquire()
        async with self._semaphore:
            start = time.monotonic()
            try:
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                probe = self._get_udp_probe(port)
                await loop.run_in_executor(None, sock.sendto, probe, (ip, port))
                try:
                    data, _ = await asyncio.wait_for(
                        loop.run_in_executor(None, sock.recvfrom, 4096),
                        timeout=self.timeout,
                    )
                    latency = (time.monotonic() - start) * 1000
                    sock.close()
                    return PortResult(ip=ip, port=port, protocol="udp", state="open", latency_ms=latency)
                except (asyncio.TimeoutError, socket.timeout):
                    sock.close()
                    return PortResult(ip=ip, port=port, protocol="udp", state="open|filtered")
            except OSError:
                return PortResult(ip=ip, port=port, protocol="udp", state="filtered")

    @staticmethod
    def _get_udp_probe(port: int) -> bytes:
        probes = {
            53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
            123: b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                 b"\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3",
            161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02"
                 b"\x04\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06"
                 b"\x05\x2b\x06\x01\x02\x01\x05\x00",
            1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n",
        }
        return probes.get(port, b"\x00")

    async def scan_host(self, ip: str, ports: list[int], protocol: str = "tcp") -> AsyncGenerator[PortResult, None]:
        scan_func = self.scan_tcp_port if protocol == "tcp" else self.scan_udp_port
        tasks = [scan_func(ip, port) for port in ports]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result.state == "open":
                logger.info(f"[OPEN] {ip}:{result.port}/{result.protocol} ({result.latency_ms:.1f}ms)")
            yield result

    async def scan_range(self, targets: list[str], ports: list[int], protocol: str = "tcp") -> AsyncGenerator[PortResult, None]:
        self._start_time = time.monotonic()
        self._scan_count = 0
        total = len(targets) * len(ports)
        logger.info(f"Starting scan: {len(targets)} hosts x {len(ports)} ports = {total} probes")

        scan_func = self.scan_tcp_port if protocol == "tcp" else self.scan_udp_port

        # Launch every (host, port) probe at once. Concurrency is bounded by the
        # connection semaphore and the rate limiter inside scan_*_port — NOT by
        # processing hosts one at a time. Scanning a /24 host-by-host means each
        # dead address blocks for the full timeout in series (≈ hosts × timeout,
        # i.e. minutes); fanning out collapses that to ≈ total/concurrency ×
        # timeout (seconds). This is the difference between a usable LAN sweep
        # and one that looks hung.
        tasks = [
            asyncio.ensure_future(scan_func(ip, port))
            for ip in targets
            for port in ports
        ]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            self._scan_count += 1
            if result.state == "open":
                logger.info(f"[OPEN] {result.ip}:{result.port}/{result.protocol} ({result.latency_ms:.1f}ms)")
            yield result
