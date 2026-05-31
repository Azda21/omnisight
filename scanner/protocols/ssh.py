import asyncio
import re
from dataclasses import dataclass


@dataclass
class SSHResult:
    version: str = ""
    software: str = ""
    protocol: str = ""
    key_exchange: list = None
    host_key_algorithms: list = None
    os_hint: str = ""

    def __post_init__(self):
        if self.key_exchange is None:
            self.key_exchange = []
        if self.host_key_algorithms is None:
            self.host_key_algorithms = []


class SSHProbe:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def probe(self, ip: str, port: int = 22) -> SSHResult:
        result = SSHResult()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )

            banner = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            banner_str = banner.decode("utf-8", errors="replace").strip()
            result.version = banner_str

            match = re.match(r"SSH-(\d+\.\d+)-(.+)", banner_str)
            if match:
                result.protocol = match.group(1)
                result.software = match.group(2)

            result.os_hint = self._guess_os(result.software)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        return result

    @staticmethod
    def _guess_os(software: str) -> str:
        s = software.lower()
        if "ubuntu" in s:
            return "Ubuntu Linux"
        if "debian" in s:
            return "Debian Linux"
        if "centos" in s or "redhat" in s or "rhel" in s:
            return "CentOS/RHEL Linux"
        if "freebsd" in s:
            return "FreeBSD"
        if "openbsd" in s:
            return "OpenBSD"
        if "windows" in s:
            return "Windows"
        if "dropbear" in s:
            return "Embedded Linux (Dropbear)"
        if "openssh" in s:
            return "Linux/Unix (OpenSSH)"
        if "cisco" in s:
            return "Cisco IOS"
        if "mikrotik" in s:
            return "MikroTik RouterOS"
        return ""
