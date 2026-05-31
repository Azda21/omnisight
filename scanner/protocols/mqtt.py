import asyncio
import struct
from dataclasses import dataclass, field


@dataclass
class MQTTResult:
    is_mqtt: bool = False
    version: str = ""
    allows_anonymous: bool = False
    return_code: int = -1
    topics: list = field(default_factory=list)


class MQTTProbe:
    CONNECT_PACKET = (
        b"\x10\x12"
        b"\x00\x04MQTT"
        b"\x04"
        b"\x02"
        b"\x00\x3c"
        b"\x00\x06OmniSt"
    )

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def probe(self, ip: str, port: int = 1883) -> MQTTResult:
        result = MQTTResult()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )

            writer.write(self.CONNECT_PACKET)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)

            if len(data) >= 4:
                packet_type = (data[0] >> 4) & 0x0F
                if packet_type == 2:  # CONNACK
                    result.is_mqtt = True
                    result.return_code = data[3]
                    result.allows_anonymous = result.return_code == 0
                    result.version = "3.1.1"

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        return result
