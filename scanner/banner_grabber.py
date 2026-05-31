import asyncio
import ssl
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger("omnisight.scanner.banner")


@dataclass
class BannerResult:
    ip: str
    port: int
    protocol: str
    banner: str = ""
    raw_banner: bytes = b""
    ssl_info: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    error: str = ""


class BannerGrabber:
    PROTOCOL_PROBES = {
        21: ("ftp", b""),
        22: ("ssh", b""),
        23: ("telnet", b""),
        25: ("smtp", b""),
        80: ("http", b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: OmniSight/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"),
        110: ("pop3", b""),
        143: ("imap", b""),
        443: ("https", b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: OmniSight/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"),
        445: ("smb", b"\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x01\x28"),
        1433: ("mssql", b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00"),
        1883: ("mqtt", b"\x10\x0d\x00\x04MQTT\x04\x02\x00\x3c\x00\x01X"),
        3306: ("mysql", b""),
        3389: ("rdp", b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"),
        5432: ("postgresql", b"\x00\x00\x00\x08\x04\xd2\x16\x2f"),
        5672: ("amqp", b"AMQP\x00\x00\x09\x01"),
        5900: ("vnc", b""),
        6379: ("redis", b"PING\r\n"),
        8080: ("http", b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: OmniSight/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"),
        8443: ("https", b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: OmniSight/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"),
        9200: ("elasticsearch", b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: OmniSight/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"),
        27017: ("mongodb", b"\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\x01\x00\x00\x00\x15\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00"),
        502: ("modbus", b"\x00\x01\x00\x00\x00\x06\x01\x2b\x0e\x01\x00"),
        554: ("rtsp", b"OPTIONS rtsp://{host}:554 RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: OmniSight/1.0\r\n\r\n"),
        5060: ("sip", b"OPTIONS sip:{host} SIP/2.0\r\nVia: SIP/2.0/UDP {host}:5060\r\nMax-Forwards: 70\r\nFrom: <sip:scanner@omnisight.local>\r\nTo: <sip:{host}>\r\nCall-ID: scan@omnisight\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"),
    }

    SSL_PORTS = {443, 465, 636, 993, 995, 8443, 9443}

    def __init__(self, timeout: float = 5.0, max_concurrent: int = 200):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

    def _get_probe(self, port: int, host: str) -> tuple[str, bytes]:
        if port in self.PROTOCOL_PROBES:
            proto, probe = self.PROTOCOL_PROBES[port]
            if isinstance(probe, bytes) and b"{host}" in probe:
                probe = probe.replace(b"{host}", host.encode())
            return proto, probe
        return "unknown", b""

    async def grab_banner(self, ip: str, port: int, force_protocol: str = None) -> BannerResult:
        async with self._semaphore:
            proto, probe = self._get_probe(port, ip)
            if force_protocol:
                proto = force_protocol

            use_ssl = port in self.SSL_PORTS
            result = BannerResult(ip=ip, port=port, protocol=proto)

            try:
                if use_ssl:
                    result = await self._grab_ssl(ip, port, probe, proto)
                else:
                    result = await self._grab_tcp(ip, port, probe, proto)
            except Exception as e:
                result.error = str(e)
                logger.debug(f"Banner grab failed {ip}:{port}: {e}")

            return result

    async def _grab_tcp(self, ip: str, port: int, probe: bytes, proto: str) -> BannerResult:
        result = BannerResult(ip=ip, port=port, protocol=proto)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self.timeout
        )
        try:
            if not probe:
                data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
            else:
                writer.write(probe)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(8192), timeout=self.timeout)

            result.raw_banner = data
            result.banner = self._decode_banner(data)

            if proto in ("http", "https", "elasticsearch"):
                result.headers = self._parse_http_headers(result.banner)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        return result

    async def _grab_ssl(self, ip: str, port: int, probe: bytes, proto: str) -> BannerResult:
        result = BannerResult(ip=ip, port=port, protocol=proto)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx), timeout=self.timeout
        )
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                result.ssl_info = {
                    "version": ssl_obj.version(),
                    "cipher": ssl_obj.cipher(),
                    "peer_cert": ssl_obj.getpeercert(binary_form=False),
                }

            if not probe:
                data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
            else:
                writer.write(probe)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(8192), timeout=self.timeout)

            result.raw_banner = data
            result.banner = self._decode_banner(data)

            if proto in ("http", "https"):
                result.headers = self._parse_http_headers(result.banner)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        return result

    @staticmethod
    def _decode_banner(data: bytes) -> str:
        for encoding in ("utf-8", "latin-1", "ascii"):
            try:
                return data.decode(encoding)
            except (UnicodeDecodeError, ValueError):
                continue
        return data.hex()

    @staticmethod
    def _parse_http_headers(banner: str) -> dict:
        headers = {}
        lines = banner.split("\r\n")
        if lines:
            headers["_status_line"] = lines[0]
        for line in lines[1:]:
            if ": " in line:
                key, val = line.split(": ", 1)
                headers[key.lower()] = val
            elif line == "":
                break
        return headers

    async def grab_multiple(self, ip: str, ports: list[int]) -> list[BannerResult]:
        tasks = [self.grab_banner(ip, port) for port in ports]
        return await asyncio.gather(*tasks, return_exceptions=False)
