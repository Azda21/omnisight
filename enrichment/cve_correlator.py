import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("omnisight.enrichment.cve")


@dataclass
class CVEEntry:
    cve_id: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    description: str = ""
    affected_product: str = ""
    affected_versions: str = ""
    references: list = field(default_factory=list)


class CVECorrelator:
    KNOWN_VULNS = {
        "openssh": {
            "7.": [CVEEntry("CVE-2020-15778", "HIGH", 7.8, "Command injection via scp", "OpenSSH", "<8.0")],
            "6.": [CVEEntry("CVE-2016-10009", "HIGH", 7.3, "Agent forwarding arbitrary library loading", "OpenSSH", "<7.0")],
            "5.": [CVEEntry("CVE-2016-0777", "MEDIUM", 6.5, "Information leak via roaming", "OpenSSH", "5.x-7.1")],
        },
        "apache": {
            "2.4.49": [CVEEntry("CVE-2021-41773", "CRITICAL", 9.8, "Path traversal and RCE", "Apache httpd", "2.4.49")],
            "2.4.50": [CVEEntry("CVE-2021-42013", "CRITICAL", 9.8, "Path traversal bypass", "Apache httpd", "2.4.50")],
            "2.4.": [CVEEntry("CVE-2021-44790", "CRITICAL", 9.8, "Buffer overflow in mod_lua", "Apache httpd", "<2.4.52")],
        },
        "nginx": {
            "1.": [CVEEntry("CVE-2021-23017", "HIGH", 7.7, "DNS resolver vulnerability", "nginx", "0.6.18-1.20.0")],
        },
        "vsftpd": {
            "2.3.4": [CVEEntry("CVE-2011-2523", "CRITICAL", 10.0, "Backdoor in vsftpd 2.3.4", "vsftpd", "2.3.4")],
        },
        "proftpd": {
            "1.3.5": [CVEEntry("CVE-2015-3306", "CRITICAL", 10.0, "Unauthenticated command execution via mod_copy", "ProFTPD", "1.3.5")],
        },
        "mysql": {
            "5.": [CVEEntry("CVE-2012-2122", "HIGH", 7.5, "Authentication bypass", "MySQL", "5.1-5.6")],
        },
        "redis": {
            "": [CVEEntry("CVE-2022-0543", "CRITICAL", 10.0, "Lua sandbox escape (Debian-specific)", "Redis", "<6.2.7")],
        },
        "elasticsearch": {
            "1.": [CVEEntry("CVE-2015-1427", "CRITICAL", 9.8, "RCE via Groovy scripting", "Elasticsearch", "1.x")],
            "": [CVEEntry("CVE-2021-22145", "MEDIUM", 6.5, "Information disclosure", "Elasticsearch", "<7.13.4")],
        },
        "iis": {
            "10.": [CVEEntry("CVE-2021-31166", "CRITICAL", 9.8, "HTTP Protocol Stack RCE", "IIS", "10.0")],
        },
        "exim": {
            "4.": [CVEEntry("CVE-2019-10149", "CRITICAL", 9.8, "RCE via crafted recipient address", "Exim", "4.87-4.91")],
        },
    }

    def __init__(self, nvd_api_key: str = ""):
        self.nvd_api_key = nvd_api_key

    def correlate(self, service: str, version: str, banner: str = "") -> list[CVEEntry]:
        matches = []
        service_lower = service.lower()
        banner_lower = banner.lower()

        for product_key, version_map in self.KNOWN_VULNS.items():
            if product_key in service_lower or product_key in banner_lower:
                for ver_prefix, cves in version_map.items():
                    if not ver_prefix or (version and version.startswith(ver_prefix)):
                        matches.extend(cves)

        seen = set()
        unique = []
        for cve in matches:
            if cve.cve_id not in seen:
                seen.add(cve.cve_id)
                unique.append(cve)

        unique.sort(key=lambda c: c.cvss_score, reverse=True)
        return unique

    async def search_nvd(self, keyword: str) -> list[CVEEntry]:
        if not self.nvd_api_key:
            return []

        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": keyword, "resultsPerPage": 10},
                    headers={"apiKey": self.nvd_api_key} if self.nvd_api_key else {},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return self._parse_nvd_response(data)
        except Exception as e:
            logger.error(f"NVD API search failed: {e}")
        return []

    @staticmethod
    def _parse_nvd_response(data: dict) -> list[CVEEntry]:
        entries = []
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")

            descriptions = cve_data.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity = ""
            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "")
                    break

            refs = [r.get("url", "") for r in cve_data.get("references", [])]

            entries.append(CVEEntry(
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                description=desc[:300],
                references=refs[:5],
            ))

        return entries
