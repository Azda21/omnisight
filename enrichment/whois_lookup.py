import asyncio
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger("omnisight.enrichment.whois")


@dataclass
class WhoisInfo:
    ip: str = ""
    domain: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: list = field(default_factory=list)
    status: list = field(default_factory=list)
    org: str = ""
    country: str = ""
    emails: list = field(default_factory=list)
    raw: str = ""


class WhoisEnricher:
    def __init__(self, cache_ttl: int = 86400):
        self.cache_ttl = cache_ttl
        self._cache: dict[str, tuple[float, WhoisInfo]] = {}

    async def lookup(self, target: str) -> WhoisInfo:
        if target in self._cache:
            ts, info = self._cache[target]
            if time.time() - ts < self.cache_ttl:
                return info

        info = WhoisInfo(ip=target)
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._do_whois, target)
            info = result
            self._cache[target] = (time.time(), info)
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {target}: {e}")

        return info

    @staticmethod
    def _do_whois(target: str) -> WhoisInfo:
        info = WhoisInfo(ip=target)
        try:
            import whois
            w = whois.whois(target)
            info.domain = w.domain_name if isinstance(w.domain_name, str) else (w.domain_name[0] if w.domain_name else "")
            info.registrar = w.registrar or ""
            info.creation_date = str(w.creation_date) if w.creation_date else ""
            info.expiration_date = str(w.expiration_date) if w.expiration_date else ""
            info.updated_date = str(w.updated_date) if w.updated_date else ""
            info.name_servers = w.name_servers or []
            info.status = w.status if isinstance(w.status, list) else ([w.status] if w.status else [])
            info.org = w.org or ""
            info.country = w.country or ""
            info.emails = w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else [])
        except Exception:
            pass
        return info
