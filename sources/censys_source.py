"""Censys Search API v2 integration — a second global internet source.

Censys uses HTTP Basic auth (API ID + secret) and its own query language. We
translate the OmniSight DSL into Censys field syntax and normalize the hosts/
services response into OmniSight records, so Censys hits render like everything
else and can be compared against Shodan and local data.
"""
import base64
import logging

logger = logging.getLogger("omnisight.sources.censys")

CENSYS_SEARCH = "https://search.censys.io/api/v2/hosts/search"


async def _get_json(url, params, headers, timeout=20.0):
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, headers=headers, timeout=timeout) as resp:
                if resp.status != 200:
                    return None, f"HTTP {resp.status}: {(await resp.text())[:200]}"
                return await resp.json(), None
    except Exception as e:
        return None, str(e)


def _query_to_censys(parsed) -> str:
    parts = list(parsed.text_terms)
    mapping = {
        "port": "services.port", "service": "services.service_name",
        "product": "services.software.product", "country_code": "location.country_code",
        "city": "location.city", "as_org": "autonomous_system.name",
    }
    for col, val in parsed.filters.items():
        ck = mapping.get(col)
        if ck:
            parts.append(f'{ck}: "{val}"' if isinstance(val, str) else f"{ck}: {val}")
    cat_terms = {
        "camera": "services.service_name: RTSP", "database": "services.service_name: MYSQL",
        "ics": "services.port: 502", "router": "router", "web": "services.service_name: HTTP",
    }
    for c in parsed.categories:
        parts.append(cat_terms.get(c, c))
    return " and ".join(parts) if parts else "services.port: 80"


class CensysSource:
    name = "censys"

    def __init__(self, api_id: str = "", api_secret: str = ""):
        self.api_id = api_id
        self.api_secret = api_secret

    @property
    def available(self) -> bool:
        return bool(self.api_id and self.api_secret)

    async def search(self, parsed, page: int = 1) -> dict:
        if not self.available:
            return {"total": 0, "results": [], "error": "Censys API kimliği yok."}
        query = _query_to_censys(parsed)
        token = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode()).decode()
        data, err = await _get_json(
            CENSYS_SEARCH, {"q": query, "per_page": 25},
            {"Authorization": f"Basic {token}", "Accept": "application/json"},
        )
        if err:
            return {"total": 0, "results": [], "error": err, "query": query}
        result = data.get("result", {})
        hits = result.get("hits", [])
        records = []
        for host in hits:
            records.extend(self._normalize_host(host))
        return {"total": result.get("total", len(records)), "results": records,
                "source": "censys", "query": query}

    @staticmethod
    def _normalize_host(host: dict) -> list:
        ip = host.get("ip", "")
        loc = host.get("location", {}) or {}
        asys = host.get("autonomous_system", {}) or {}
        out = []
        for svc in host.get("services", []):
            out.append({
                "ip": ip,
                "port": svc.get("port", 0),
                "protocol": svc.get("transport_protocol", "TCP").lower(),
                "state": "open",
                "service": (svc.get("service_name", "") or "").lower(),
                "product": (svc.get("software", [{}])[0].get("product", "")
                            if svc.get("software") else ""),
                "version": "",
                "banner": (svc.get("banner", "") or "")[:2000],
                "country": loc.get("country", ""),
                "country_code": loc.get("country_code", ""),
                "city": loc.get("city", "") or "",
                "asn": asys.get("asn", 0),
                "as_org": asys.get("name", "") or "",
                "reverse_dns": (host.get("dns", {}) or {}).get("reverse_dns", {}).get("names", [""])[0] if host.get("dns") else "",
                "cves": [],
                "timestamp": 0, "latency_ms": 0,
                "source": "censys",
            })
        return out
