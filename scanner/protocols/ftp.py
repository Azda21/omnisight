import asyncio
import re
from dataclasses import dataclass


@dataclass
class FTPResult:
    banner: str = ""
    software: str = ""
    version: str = ""
    anonymous_login: bool = False
    os_hint: str = ""


class FTPProbe:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def probe(self, ip: str, port: int = 21) -> FTPResult:
        result = FTPResult()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )

            banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            result.banner = banner.decode("utf-8", errors="replace").strip()

            self._parse_banner(result)
            result.anonymous_login = await self._check_anonymous(reader, writer)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        return result

    async def _check_anonymous(self, reader, writer) -> bool:
        try:
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(512), timeout=3.0)
            resp_str = resp.decode("utf-8", errors="replace")
            if resp_str.startswith("331"):
                writer.write(b"PASS anonymous@omnisight.local\r\n")
                await writer.drain()
                resp2 = await asyncio.wait_for(reader.read(512), timeout=3.0)
                return resp2.decode("utf-8", errors="replace").startswith("230")
        except Exception:
            pass
        return False

    @staticmethod
    def _parse_banner(result: FTPResult):
        b = result.banner.lower()
        patterns = [
            (r"vsftpd\s+([\d.]+)", "vsftpd"),
            (r"proftpd\s+([\d.]+)", "ProFTPD"),
            (r"pure-ftpd", "Pure-FTPd"),
            (r"filezilla\s+server\s+([\d.]+)", "FileZilla Server"),
            (r"microsoft ftp service", "Microsoft FTP"),
            (r"serv-u\s+([\d.]+)", "Serv-U"),
        ]
        for pattern, name in patterns:
            match = re.search(pattern, b, re.IGNORECASE)
            if match:
                result.software = name
                if match.lastindex and match.lastindex >= 1:
                    result.version = match.group(1)
                break
