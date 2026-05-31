import asyncio
import struct
from dataclasses import dataclass, field


@dataclass
class ModbusResult:
    is_modbus: bool = False
    device_id: str = ""
    vendor: str = ""
    product_code: str = ""
    revision: str = ""
    vendor_url: str = ""
    product_name: str = ""
    model_name: str = ""
    objects: dict = field(default_factory=dict)


class ModbusProbe:
    READ_DEVICE_ID = (
        b"\x00\x01"
        b"\x00\x00"
        b"\x00\x06"
        b"\x01"
        b"\x2b\x0e\x01\x00"
    )

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def probe(self, ip: str, port: int = 502) -> ModbusResult:
        result = ModbusResult()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )

            writer.write(self.READ_DEVICE_ID)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)

            if len(data) >= 9:
                func_code = data[7]
                if func_code == 0x2B:
                    result.is_modbus = True
                    result = self._parse_device_id(data, result)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        return result

    @staticmethod
    def _parse_device_id(data: bytes, result: ModbusResult) -> ModbusResult:
        try:
            if len(data) < 15:
                return result
            num_objects = data[13]
            pos = 14

            obj_names = {
                0: "vendor",
                1: "product_code",
                2: "revision",
                3: "vendor_url",
                4: "product_name",
                5: "model_name",
            }

            for _ in range(num_objects):
                if pos + 2 > len(data):
                    break
                obj_id = data[pos]
                obj_len = data[pos + 1]
                pos += 2
                if pos + obj_len > len(data):
                    break
                obj_val = data[pos:pos + obj_len].decode("utf-8", errors="replace")
                pos += obj_len

                result.objects[obj_id] = obj_val
                attr = obj_names.get(obj_id)
                if attr:
                    setattr(result, attr, obj_val)
        except (IndexError, struct.error):
            pass
        return result
