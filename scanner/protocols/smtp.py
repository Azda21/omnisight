import asyncio
import re
from dataclasses import dataclass, field


@dataclass
class SMTPResult:
    banner: str = ""
    software: str = ""
    version: str = ""
    hostname: str = ""
    supports_starttls: bool = False
    auth_methods: list = field(default_factory=list)
    commands: list = field(default_factory=list)


class SMTPProbe:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def probe(self, ip: str, port: int = 25) -> SMTPResult:
        result = SMTPResult()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )

            banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            result.banner = banner.decode("utf-8", errors="replace").strip()
            self._parse_banner(result)

            writer.write(b"EHLO omnisight.local\r\n")
            await writer.drain()
            ehlo_resp = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
            ehlo_str = ehlo_resp.decode("utf-8", errors="replace")

            for line in ehlo_str.split("\r\n"):
                line_clean = re.sub(r"^\d+-?\s*", "", line).strip()
                if line_clean:
                    result.commands.append(line_clean)
                    if "STARTTLS" in line_clean.upper():
                        result.supports_starttls = True
                    if "AUTH" in line_clean.upper():
                        parts = line_clean.split()
                        result.auth_methods = parts[1:] if len(parts) > 1 else []

            writer.write(b"QUIT\r\n")
            await writer.drain()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        return result

    @staticmethod
    def _parse_banner(result: SMTPResult):
        b = result.banner
        patterns = [
            (r"postfix", "Postfix"),
            (r"exim\s*([\d.]+)?", "Exim"),
            (r"sendmail", "Sendmail"),
            (r"microsoft esmtp", "Microsoft Exchange"),
            (r"dovecot", "Dovecot"),
            (r"haraka", "Haraka"),
        ]
        for pattern, name in patterns:
            match = re.search(pattern, b, re.IGNORECASE)
            if match:
                result.software = name
                if match.lastindex and match.lastindex >= 1:
                    result.version = match.group(1) or ""
                break

        host_match = re.search(r"220\s+([\w.-]+)", b)
        if host_match:
            result.hostname = host_match.group(1)
