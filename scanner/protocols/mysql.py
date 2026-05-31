import asyncio
import struct
from dataclasses import dataclass


@dataclass
class MySQLResult:
    version: str = ""
    protocol_version: int = 0
    server_id: int = 0
    charset: int = 0
    status: int = 0
    auth_plugin: str = ""
    capabilities: int = 0


class MySQLProbe:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def probe(self, ip: str, port: int = 3306) -> MySQLResult:
        result = MySQLResult()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )

            data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
            if len(data) > 4:
                result = self._parse_handshake(data)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        return result

    @staticmethod
    def _parse_handshake(data: bytes) -> MySQLResult:
        result = MySQLResult()
        try:
            pos = 4
            result.protocol_version = data[pos]
            pos += 1

            end = data.index(b"\x00", pos)
            result.version = data[pos:end].decode("utf-8", errors="replace")
            pos = end + 1

            if pos + 4 <= len(data):
                result.server_id = struct.unpack("<I", data[pos:pos + 4])[0]
                pos += 4

            pos += 8 + 1

            if pos + 2 <= len(data):
                result.charset = data[pos]
                pos += 1
                result.status = struct.unpack("<H", data[pos:pos + 2])[0]
                pos += 2
                result.capabilities = struct.unpack("<H", data[pos:pos + 2])[0]
        except (IndexError, struct.error):
            pass
        return result
