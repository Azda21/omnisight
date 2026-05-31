"""Shodan integration — global internet search.

Three tiers of access, used in priority order:

1. **Search API** (`/shodan/host/search`) — paid Membership plan required.
   Answers broad queries like "all cameras in Turkey".
2. **Host API** (`/shodan/host/{ip}`) — works with ANY API key (including free
   Developer plan). Returns full banner data for a single IP.
3. **InternetDB** (`https://internetdb.shodan.io/{ip}`) — completely free, no
   key needed. Returns open ports / CVEs / hostnames for one IP.

When the user has a free-tier API key the search endpoint returns HTTP 403.
We detect that and transparently fall back to Host API or InternetDB so
OmniSight keeps working regardless of plan.
"""
import ipaddress
import logging
import re

logger = logging.getLogger("omnisight.sources.shodan")

SHODAN_SEARCH = "https://api.shodan.io/shodan/host/search"
SHODAN_HOST = "https://api.shodan.io/shodan/host/{ip}"
SHODAN_API_INFO = "https://api.shodan.io/api-info"
SHODAN_INTERNETDB = "https://internetdb.shodan.io/{ip}"

# Simple IP regex for extracting IPs from queries
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


async def _get_json(url: str, params: dict | None = None, timeout: float = 20.0):
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    return None, f"HTTP {resp.status}: {text[:200]}"
                return await resp.json(), None
    except Exception as e:
        return None, str(e)


def _is_ip(text: str) -> bool:
    """Check whether *text* is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(text.strip())
        return True
    except ValueError:
        return False


def _extract_ips(text: str) -> list[str]:
    """Pull all IPv4 addresses out of *text*."""
    return [ip for ip in _IP_RE.findall(text) if _is_ip(ip)]


def _query_to_shodan(parsed) -> str:
    """Translate an OmniSight ParsedQuery into Shodan query syntax (they overlap
    heavily, which is the point — the same DSL works on both)."""
    parts: list[str] = []
    parts.extend(parsed.text_terms)
    mapping = {
        "port": "port", "service": "product", "product": "product",
        "country_code": "country", "city": "city", "as_org": "org",
        "reverse_dns": "hostname", "os_guess": "os",
    }
    for col, val in parsed.filters.items():
        sk = mapping.get(col)
        if sk:
            parts.append(f'{sk}:"{val}"' if isinstance(val, str) and " " in val else f"{sk}:{val}")
    for col, val in parsed.negations.items():
        sk = mapping.get(col)
        if sk:
            parts.append(f"-{sk}:{val}")
    # Category → a representative Shodan term so "camera" hits real cameras.
    cat_terms = {
        "camera": "webcam", "router": "router", "printer": "printer",
        "database": "product:MySQL", "ics": "port:502", "voip": "port:5060",
        "nas": "Synology", "iot": "port:1883", "mail": "port:25", "web": "http",
    }
    for c in parsed.categories:
        parts.append(cat_terms.get(c, c))
    if parsed.flags.get("vuln") in ("true", "1", "yes"):
        parts.append("vuln:*")
    return " ".join(parts).strip() or "port:80"


class ShodanSource:
    name = "shodan"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._plan: str | None = None  # "membership", "dev", or None

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    # ------------------------------------------------------------------
    # Plan detection (cached per instance)
    # ------------------------------------------------------------------
    async def _detect_plan(self) -> str:
        """Check Shodan API plan: 'membership' if search is allowed, else 'dev'."""
        if self._plan is not None:
            return self._plan
        data, err = await _get_json(SHODAN_API_INFO, {"key": self.api_key})
        if err or data is None:
            self._plan = "dev"
            return self._plan
        # Paid plans have query_credits > 0
        if data.get("query_credits", 0) > 0:
            self._plan = "membership"
        else:
            self._plan = "dev"
        logger.info("Shodan plan detected: %s (query_credits=%s)",
                     self._plan, data.get("query_credits"))
        return self._plan

    # ------------------------------------------------------------------
    # Primary search
    # ------------------------------------------------------------------
    async def search(self, parsed, page: int = 1) -> dict:
        if not self.api_key:
            return {"total": 0, "results": [], "error": "Shodan API anahtarı yok."}

        query = _query_to_shodan(parsed)
        plan = await self._detect_plan()

        # --- Paid plan: use the full search endpoint -----------------------
        if plan == "membership":
            data, err = await _get_json(SHODAN_SEARCH, {
                "key": self.api_key, "query": query, "page": page,
            })
            if err:
                # If 403 anyway (credits ran out mid-session), fall through
                if "403" not in str(err):
                    return {"total": 0, "results": [], "error": err, "query": query}
                logger.warning("Search 403 despite membership plan — falling back")
            else:
                results = [self._normalize_match(m) for m in data.get("matches", [])]
                return {"total": data.get("total", 0), "results": results,
                        "source": "shodan", "query": query}

        # --- Free plan: use per-IP Host API (/shodan/host/{ip}) ------------
        # Try to extract IPs from the query itself
        ips = _extract_ips(query)
        # Also check text_terms for raw IPs the user typed
        if hasattr(parsed, "text_terms"):
            for term in parsed.text_terms:
                if _is_ip(term) and term not in ips:
                    ips.append(term)

        if ips:
            return await self._host_api_multi(ips, query)

        # No IPs in query and free plan — explain the limitation clearly
        return {
            "total": 0,
            "results": [],
            "source": "shodan",
            "query": query,
            "error": (
                "Shodan ücretsiz (Developer) API anahtarı genel arama desteklemiyor. "
                "IP adresi girerek tek tek sorgulama yapabilirsiniz veya "
                "Shodan Membership planına yükseltmeniz gerekiyor. "
                "Örnek: doğrudan bir IP adresi yazın (ör. 8.8.8.8)."
            ),
        }

    # ------------------------------------------------------------------
    # Host API — per-IP, works with free key
    # ------------------------------------------------------------------
    async def _host_api_single(self, ip: str) -> dict | None:
        """Query /shodan/host/{ip} — free-tier compatible."""
        data, err = await _get_json(
            SHODAN_HOST.format(ip=ip), {"key": self.api_key}
        )
        if err:
            logger.warning("Shodan host API error for %s: %s", ip, err)
            return None
        return data

    async def _host_api_multi(self, ips: list[str], query: str) -> dict:
        """Query Host API for several IPs and merge results."""
        import asyncio
        tasks = [self._host_api_single(ip) for ip in ips[:10]]  # cap at 10
        raw_results = await asyncio.gather(*tasks)
        all_results = []
        for data in raw_results:
            if data is None:
                continue
            for service in data.get("data", []):
                service["ip_str"] = data.get("ip_str", "")
                service.setdefault("location", {
                    "country_name": data.get("country_name", ""),
                    "country_code": data.get("country_code", ""),
                    "city": data.get("city", ""),
                })
                service.setdefault("org", data.get("org", ""))
                service.setdefault("asn", data.get("asn", ""))
                service.setdefault("hostnames", data.get("hostnames", []))
                all_results.append(self._normalize_match(service))
        return {
            "total": len(all_results),
            "results": all_results,
            "source": "shodan-host",
            "query": query,
        }

    # ------------------------------------------------------------------
    # InternetDB — completely free, no key needed
    # ------------------------------------------------------------------
    async def host_lookup(self, ip: str) -> dict:
        """Free InternetDB lookup — works with no API key."""
        # If we have an API key, prefer the richer Host API
        if self.api_key:
            data = await self._host_api_single(ip)
            if data:
                results = []
                for service in data.get("data", []):
                    service["ip_str"] = data.get("ip_str", "")
                    service.setdefault("location", {
                        "country_name": data.get("country_name", ""),
                        "country_code": data.get("country_code", ""),
                        "city": data.get("city", ""),
                    })
                    service.setdefault("org", data.get("org", ""))
                    service.setdefault("asn", data.get("asn", ""))
                    service.setdefault("hostnames", data.get("hostnames", []))
                    results.append(self._normalize_match(service))
                return {"ip": ip, "results": results,
                        "tags": data.get("tags", []), "source": "shodan-host"}

        # Fallback: InternetDB (no key needed)
        data, err = await _get_json(SHODAN_INTERNETDB.format(ip=ip))
        if err:
            return {"ip": ip, "error": err, "results": []}
        results = []
        for port in data.get("ports", []):
            results.append({
                "ip": ip, "port": port, "protocol": "tcp", "state": "open",
                "service": "", "product": "", "version": "",
                "banner": "", "hostnames": data.get("hostnames", []),
                "cves": [{"id": c, "severity": "", "score": 0, "description": ""}
                         for c in data.get("vulns", [])],
                "technologies": data.get("cpes", []),
                "reverse_dns": (data.get("hostnames") or [""])[0],
                "source": "shodan-internetdb",
            })
        return {"ip": ip, "results": results, "tags": data.get("tags", []),
                "source": "shodan-internetdb"}

    @staticmethod
    def _normalize_match(m: dict) -> dict:
        loc = m.get("location", {}) or {}
        vulns = m.get("vulns", {}) or {}
        cves = []
        if isinstance(vulns, dict):
            for cid, info in vulns.items():
                cves.append({"id": cid, "severity": "",
                             "score": (info or {}).get("cvss", 0) if isinstance(info, dict) else 0,
                             "description": (info or {}).get("summary", "") if isinstance(info, dict) else ""})
        elif isinstance(vulns, list):
            cves = [{"id": c, "severity": "", "score": 0, "description": ""} for c in vulns]

        http = m.get("http", {}) or {}
        return {
            "ip": m.get("ip_str", ""),
            "port": m.get("port", 0),
            "protocol": m.get("transport", "tcp"),
            "state": "open",
            "service": (m.get("_shodan", {}) or {}).get("module", "") or m.get("product", "").lower(),
            "product": m.get("product", ""),
            "version": m.get("version", "") or "",
            "banner": (m.get("data", "") or "")[:2000],
            "country": loc.get("country_name", ""),
            "country_code": loc.get("country_code", ""),
            "city": loc.get("city", "") or "",
            "asn": int((m.get("asn", "AS0") or "AS0").lstrip("AS") or 0) if str(m.get("asn", "")).lstrip("AS").isdigit() else 0,
            "as_org": m.get("org", "") or "",
            "reverse_dns": (m.get("hostnames") or [""])[0] if m.get("hostnames") else "",
            "web_title": http.get("title", "") or "",
            "technologies": [c.get("name", "") for c in (http.get("components", {}) or {}).values()] if isinstance(http.get("components"), dict) else [],
            "cves": cves,
            "timestamp": 0,
            "latency_ms": 0,
            "source": m.get("source", "shodan"),
        }
