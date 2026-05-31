import asyncio
import logging
import os
import random
import socket
import struct
import time
from dataclasses import dataclass, field

from .rate_limiter import TokenBucket

logger = logging.getLogger("omnisight.scanner.syn")


@dataclass
class SynResult:
    ip: str
    port: int
    state: str  # open / closed
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


class SynCookie:
    """Stateless validation à la masscan.

    A connect()-based scanner must hold one socket (and FD) per outstanding
    probe — that caps you at a few thousand in flight. A stateless SYN scanner
    fires a SYN and forgets it; the only way to later tell a real SYN-ACK from
    spoofed noise is to encode a keyed hash of (ip, port) into the TCP sequence
    number and check that the ACK we get back equals seq+1. That is the SYN
    cookie. It lets send and receive run as two fully decoupled loops with zero
    per-probe state.
    """

    def __init__(self, secret: int | None = None):
        self.secret = secret if secret is not None else random.getrandbits(32)

    def make(self, ip: str, port: int) -> int:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mixed = (ip_int ^ self.secret) + (port * 0x9E3779B1)
        return mixed & 0xFFFFFFFF

    def verify(self, ip: str, port: int, ack: int) -> bool:
        # The peer ACKs our_seq + 1.
        return ((self.make(ip, port) + 1) & 0xFFFFFFFF) == ack


def syn_scan_supported() -> tuple[bool, str]:
    """Probe whether this process can open the raw sockets a SYN scan needs.

    Raw TCP sending is privileged (root / Administrator) and Windows further
    restricts crafted TCP on raw sockets. We detect that here so the engine can
    transparently fall back to the connect scanner instead of dying."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.close()
        return True, "raw socket available"
    except PermissionError:
        return False, "raw socket requires root/Administrator privileges"
    except OSError as e:
        return False, f"raw socket unavailable: {e}"


class SynScanner:
    def __init__(self, rate_limit: int = 5000, response_wait: float = 3.0):
        self.rate_limit = rate_limit
        self.response_wait = response_wait
        self._limiter = TokenBucket(rate=float(rate_limit), burst=min(rate_limit, 1000))
        self._cookie = SynCookie()
        self._src_ip = self._detect_src_ip()
        self._src_port = random.randint(40000, 60000)
        self._open: dict[tuple[str, int], float] = {}
        self._send_times: dict[tuple[str, int], float] = {}

    @staticmethod
    def _detect_src_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"

    def _build_syn(self, dst_ip: str, dst_port: int) -> bytes:
        seq = self._cookie.make(dst_ip, dst_port)

        # ─ TCP header ─
        offset_flags = (5 << 12) | 0x002  # data offset 5 words, SYN flag
        tcp_header = struct.pack(
            "!HHIIHHHH",
            self._src_port, dst_port, seq, 0,
            offset_flags, 1024, 0, 0,
        )
        # Pseudo-header for the TCP checksum.
        pseudo = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(self._src_ip),
            socket.inet_aton(dst_ip),
            0, socket.IPPROTO_TCP, len(tcp_header),
        )
        chk = _checksum(pseudo + tcp_header)
        tcp_header = tcp_header[:16] + struct.pack("!H", chk) + tcp_header[18:]

        # ─ IP header ─
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 20 + len(tcp_header),
            random.randint(0, 0xFFFF), 0, 64,
            socket.IPPROTO_TCP, 0,
            socket.inet_aton(self._src_ip),
            socket.inet_aton(dst_ip),
        )
        ip_chk = _checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack("!H", ip_chk) + ip_header[12:]

        return ip_header + tcp_header

    async def scan(self, targets: list[str], ports: list[int]) -> list[SynResult]:
        ok, reason = syn_scan_supported()
        if not ok:
            raise PermissionError(reason)

        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        send_sock.setblocking(False)

        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.setblocking(False)
        if os.name == "nt":
            # Windows needs promiscuous mode to receive inbound TCP on a raw socket.
            try:
                recv_sock.bind((self._src_ip, 0))
                recv_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except OSError as e:
                logger.warning(f"Could not enable promiscuous receive: {e}")

        self._open.clear()
        self._send_times.clear()
        stop = asyncio.Event()

        receiver = asyncio.create_task(self._receive_loop(recv_sock, stop))
        sender = asyncio.create_task(self._send_loop(send_sock, targets, ports))

        await sender
        # Give late SYN-ACKs time to arrive after the last probe goes out.
        await asyncio.sleep(self.response_wait)
        stop.set()
        await receiver

        send_sock.close()
        if os.name == "nt":
            try:
                recv_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        recv_sock.close()

        results = []
        for (ip, port), recv_t in self._open.items():
            sent_t = self._send_times.get((ip, port), recv_t)
            results.append(SynResult(
                ip=ip, port=port, state="open",
                latency_ms=max(0.0, (recv_t - sent_t) * 1000),
            ))
        return results

    async def _send_loop(self, sock, targets: list[str], ports: list[int]):
        loop = asyncio.get_event_loop()
        for ip in targets:
            for port in ports:
                await self._limiter.acquire()
                packet = self._build_syn(ip, port)
                self._send_times[(ip, port)] = time.monotonic()
                try:
                    await loop.sock_sendto(sock, packet, (ip, 0))
                except (OSError, AttributeError):
                    # Older event loops lack sock_sendto; fall back to blocking send.
                    try:
                        sock.sendto(packet, (ip, 0))
                    except OSError:
                        pass

    async def _receive_loop(self, sock, stop: asyncio.Event):
        loop = asyncio.get_event_loop()
        while not stop.is_set():
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            except OSError:
                continue
            self._parse_response(data)

    def _parse_response(self, data: bytes):
        if len(data) < 40:
            return
        ihl = (data[0] & 0x0F) * 4
        src_ip = socket.inet_ntoa(data[12:16])
        tcp = data[ihl:]
        if len(tcp) < 20:
            return

        src_port = struct.unpack("!H", tcp[0:2])[0]
        ack = struct.unpack("!I", tcp[8:12])[0]
        flags = tcp[13]
        syn = bool(flags & 0x02)
        ack_flag = bool(flags & 0x10)

        # A SYN-ACK to one of our probes means the port is open. Validate with
        # the cookie so spoofed/stray packets can't create phantom results.
        if syn and ack_flag and self._cookie.verify(src_ip, src_port, ack):
            self._open[(src_ip, src_port)] = time.monotonic()
