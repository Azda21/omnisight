import asyncio
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("omnisight.enrichment.dns")


@dataclass
class DNSInfo:
    ip: str = ""
    hostnames: list = field(default_factory=list)
    reverse_dns: str = ""
    a_records: list = field(default_factory=list)
    aaaa_records: list = field(default_factory=list)
    mx_records: list = field(default_factory=list)
    ns_records: list = field(default_factory=list)
    txt_records: list = field(default_factory=list)
    cname_records: list = field(default_factory=list)


class DNSEnricher:
    def __init__(self, resolvers: list[str] = None):
        self.resolvers = resolvers or ["8.8.8.8", "1.1.1.1"]
        self._resolver = None
        try:
            import dns.asyncresolver
            self._resolver = dns.asyncresolver.Resolver()
            self._resolver.nameservers = self.resolvers
            self._resolver.timeout = 5
            self._resolver.lifetime = 10
        except ImportError:
            logger.warning("dnspython not installed")

    async def reverse_lookup(self, ip: str) -> DNSInfo:
        info = DNSInfo(ip=ip)
        if not self._resolver:
            return info

        import dns.reversename
        import dns.asyncresolver
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = await self._resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                hostname = str(rdata.target).rstrip(".")
                info.hostnames.append(hostname)
            if info.hostnames:
                info.reverse_dns = info.hostnames[0]
        except Exception:
            pass

        return info

    async def forward_lookup(self, hostname: str) -> DNSInfo:
        info = DNSInfo()
        if not self._resolver:
            return info

        record_types = {
            "A": "a_records",
            "AAAA": "aaaa_records",
            "MX": "mx_records",
            "NS": "ns_records",
            "TXT": "txt_records",
            "CNAME": "cname_records",
        }

        tasks = []
        for rtype in record_types:
            tasks.append(self._safe_resolve(hostname, rtype))

        results = await asyncio.gather(*tasks)

        for (rtype, records) in zip(record_types.keys(), results):
            attr = record_types[rtype]
            setattr(info, attr, records)

        if info.a_records:
            info.ip = info.a_records[0]

        return info

    async def _safe_resolve(self, hostname: str, rtype: str) -> list[str]:
        try:
            answers = await self._resolver.resolve(hostname, rtype)
            results = []
            for rdata in answers:
                if rtype == "MX":
                    results.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
                elif rtype == "TXT":
                    results.append(" ".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings))
                else:
                    results.append(str(rdata).rstrip("."))
            return results
        except Exception:
            return []
