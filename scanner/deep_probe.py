import asyncio
import logging
from dataclasses import asdict, is_dataclass

from .protocols import PROTOCOL_MAP

logger = logging.getLogger("omnisight.scanner.deep_probe")


# Which protocol handler to run for a given open port. A single port can map to
# one deep probe; the banner grabber's coarse guess seeds this, the dispatcher
# refines it with a structured, protocol-aware exchange.
PORT_PROBE_MAP = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    80: "http",
    110: "smtp",     # POP3/IMAP reuse the line-banner SMTP-style reader well enough
    143: "smtp",
    443: "https",
    502: "modbus",
    554: "rtsp",
    587: "smtp",
    1883: "mqtt",
    3000: "http",
    3306: "mysql",
    3389: "rdp",
    5000: "http",
    8000: "http",
    8008: "http",
    8080: "http",
    8443: "https",
    8888: "http",
    9000: "http",
    9200: "http",
}


class DeepProbe:
    """Dispatches a port to its protocol-specific handler and returns structured
    intelligence.

    The banner grabber gives us raw bytes; that is enough to fingerprint a
    service by signature, but it cannot tell us *whether anonymous FTP login
    succeeds*, *which TLS negotiation an RDP server offers*, *whether an MQTT
    broker accepts unauthenticated CONNECTs*, or *the vendor strings behind a
    Modbus device-ID read*. Those answers require speaking the protocol. This
    class is the bridge between the open-port discovery phase and the rich
    per-protocol probes — without it those handlers are dead code.
    """

    def __init__(self, timeout: float = 5.0, max_concurrent: int = 100):
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._handlers: dict[str, object] = {}

    def _get_handler(self, name: str):
        if name not in self._handlers:
            cls = PROTOCOL_MAP.get(name)
            if cls is None:
                return None
            try:
                self._handlers[name] = cls(timeout=self.timeout)
            except TypeError:
                self._handlers[name] = cls()
        return self._handlers[name]

    @staticmethod
    def probe_for_port(port: int, banner_hint: str = "") -> str | None:
        if port in PORT_PROBE_MAP:
            return PORT_PROBE_MAP[port]
        # Fall back to whatever the banner grabber labelled the stream.
        hint = banner_hint.lower()
        if hint in PROTOCOL_MAP:
            return hint
        return None

    async def probe(self, ip: str, port: int, banner_hint: str = "") -> dict | None:
        probe_name = self.probe_for_port(port, banner_hint)
        if not probe_name:
            return None

        handler = self._get_handler(probe_name)
        if handler is None:
            return None

        async with self._semaphore:
            try:
                use_ssl = probe_name == "https" or port in (443, 8443, 9443)
                # HTTPProbe takes a use_ssl flag; the rest take (ip, port).
                if probe_name in ("http", "https"):
                    result = await asyncio.wait_for(
                        handler.probe(ip, port, use_ssl=use_ssl), timeout=self.timeout + 2
                    )
                else:
                    result = await asyncio.wait_for(
                        handler.probe(ip, port), timeout=self.timeout + 2
                    )
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"Deep probe {probe_name} failed for {ip}:{port}: {e}")
                return None

        return {
            "probe": probe_name,
            "data": asdict(result) if is_dataclass(result) else result,
        }

    async def probe_many(self, targets: list[tuple[str, int, str]]) -> dict[tuple[str, int], dict]:
        """Run deep probes for many (ip, port, banner_hint) tuples concurrently."""
        tasks = {
            (ip, port): asyncio.create_task(self.probe(ip, port, hint))
            for ip, port, hint in targets
        }
        out: dict[tuple[str, int], dict] = {}
        for key, task in tasks.items():
            try:
                res = await task
                if res:
                    out[key] = res
            except Exception:
                continue
        return out
