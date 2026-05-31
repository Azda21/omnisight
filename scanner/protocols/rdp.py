import asyncio
from dataclasses import dataclass


@dataclass
class RDPResult:
    is_rdp: bool = False
    ssl_supported: bool = False
    nla_supported: bool = False
    os_hint: str = ""
    product_version: str = ""


class RDPProbe:
    X224_CONNECTION_REQUEST = (
        b"\x03\x00\x00\x13"
        b"\x0e\xe0\x00\x00\x00\x00\x00"
        b"\x01\x00\x08\x00\x03\x00\x00\x00"
    )

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def probe(self, ip: str, port: int = 3389) -> RDPResult:
        result = RDPResult()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )

            writer.write(self.X224_CONNECTION_REQUEST)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)

            if len(data) >= 11:
                if data[0] == 0x03:
                    result.is_rdp = True
                    if len(data) >= 19:
                        neg_type = data[11]
                        if neg_type == 0x02:
                            flags = data[15] if len(data) > 15 else 0
                            selected = int.from_bytes(data[16:20], "little") if len(data) >= 20 else 0
                            if selected & 0x01:
                                result.ssl_supported = True
                            if selected & 0x02:
                                result.nla_supported = True

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        return result
