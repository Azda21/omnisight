import asyncio
import re
from dataclasses import dataclass, field


@dataclass
class RTSPResult:
    is_rtsp: bool = False
    server: str = ""
    methods: list = field(default_factory=list)
    requires_auth: bool = False
    status_code: int = 0
    headers: dict = field(default_factory=dict)


class RTSPProbe:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def probe(self, ip: str, port: int = 554) -> RTSPResult:
        result = RTSPResult()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )

            request = (
                f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: OmniSight/1.0\r\n"
                f"\r\n"
            ).encode()

            writer.write(request)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
            response = data.decode("utf-8", errors="replace")

            result = self._parse_response(response)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        return result

    @staticmethod
    def _parse_response(response: str) -> RTSPResult:
        result = RTSPResult()
        lines = response.split("\r\n")

        if lines:
            status_match = re.match(r"RTSP/[\d.]+\s+(\d+)", lines[0])
            if status_match:
                result.is_rtsp = True
                result.status_code = int(status_match.group(1))

        for line in lines[1:]:
            if ": " in line:
                key, val = line.split(": ", 1)
                result.headers[key.lower()] = val
                if key.lower() == "server":
                    result.server = val
                elif key.lower() == "public":
                    result.methods = [m.strip() for m in val.split(",")]
                elif key.lower() == "www-authenticate":
                    result.requires_auth = True

        return result
