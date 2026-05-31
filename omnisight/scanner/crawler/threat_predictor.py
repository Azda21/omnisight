"""Threat Predictor - ML-based vulnerability and threat intelligence.

Predicts:
- Likelihood of vulnerabilities
- Critical CVEs
- Exploit availability
- Attack patterns
- Device categorization
"""

import logging
import random
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger("omnisight.scanner.crawler.threat_predictor")


class CVEIntelligence:
    """CVE threat intelligence database."""

    def __init__(self):
        self.cve_database: Dict[str, Dict[str, Any]] = {
            "apache": {
                "cve_count": 45,
                "critical_count": 3,
                "avg_cvss": 7.2,
                "exploits_available": 15,
            },
            "nginx": {
                "cve_count": 12,
                "critical_count": 0,
                "avg_cvss": 5.8,
                "exploits_available": 2,
            },
            "openssh": {
                "cve_count": 28,
                "critical_count": 2,
                "avg_cvss": 6.9,
                "exploits_available": 8,
            },
            "mysql": {
                "cve_count": 38,
                "critical_count": 4,
                "avg_cvss": 7.5,
                "exploits_available": 12,
            },
            "postgresql": {
                "cve_count": 22,
                "critical_count": 1,
                "avg_cvss": 6.1,
                "exploits_available": 4,
            },
        }
        self.trending_services = ["Log4Shell", "Spring4Shell", "PrintNightmare"]

    async def get_service_threat_level(self, service: str) -> Dict[str, Any]:
        """Get threat level for a service."""
        service_lower = service.lower()

        # Check direct match
        if service_lower in self.cve_database:
            intel = self.cve_database[service_lower]
            return {
                "service": service,
                "threat_level": self._calculate_threat_level(intel),
                "cve_info": intel,
            }

        # Check partial match
        for known_service, intel in self.cve_database.items():
            if known_service in service_lower or service_lower in known_service:
                return {
                    "service": service,
                    "threat_level": self._calculate_threat_level(intel),
                    "cve_info": intel,
                }

        return {
            "service": service,
            "threat_level": "unknown",
            "cve_info": None,
        }

    @staticmethod
    def _calculate_threat_level(intel: Dict[str, Any]) -> str:
        """Calculate threat level from CVE data."""
        critical = intel.get("critical_count", 0)
        avg_cvss = intel.get("avg_cvss", 0)

        if critical > 2 or avg_cvss > 8.0:
            return "critical"
        elif critical > 0 or avg_cvss > 7.0:
            return "high"
        elif avg_cvss > 5.0:
            return "medium"
        else:
            return "low"


class DeviceProfiler:
    """Profile and categorize devices."""

    DEVICE_TYPES = {
        "webcam": {"ports": [80, 443, 8080], "services": ["rtsp", "http", "mjpeg"]},
        "firewall": {"ports": [443, 8443], "services": ["https", "admin"]},
        "router": {"ports": [80, 443, 8080], "services": ["http", "https"]},
        "printer": {"ports": [9100, 515, 631], "services": ["lpd", "ipp"]},
        "database": {"ports": [3306, 5432, 27017], "services": ["mysql", "postgresql", "mongodb"]},
        "ssh_server": {"ports": [22], "services": ["ssh"]},
        "web_server": {"ports": [80, 443, 8080, 8443], "services": ["http", "https"]},
        "smtp": {"ports": [25, 587, 465], "services": ["smtp", "submission"]},
    }

    async def profile_device(
        self, open_ports: List[int], services: List[str]
    ) -> Dict[str, Any]:
        """Profile device based on ports and services."""
        scores: Dict[str, float] = defaultdict(float)

        for device_type, profile in self.DEVICE_TYPES.items():
            port_match = sum(1 for p in open_ports if p in profile["ports"])
            service_match = sum(1 for s in services if s.lower() in profile["services"])

            score = (port_match / len(profile["ports"])) * 0.6 + (
                service_match / len(profile["services"])
            ) * 0.4

            if score > 0:
                scores[device_type] = score

        if scores:
            likely_type = max(scores, key=scores.get)
            confidence = scores[likely_type]
        else:
            likely_type = "unknown"
            confidence = 0.0

        return {
            "likely_type": likely_type,
            "confidence": confidence,
            "scores": dict(scores),
            "open_ports": open_ports,
            "services": services,
        }


class ThreatPredictor:
    """Main threat prediction engine."""

    def __init__(self):
        self.cve_intel = CVEIntelligence()
        self.profiler = DeviceProfiler()
        self.prediction_cache: Dict[str, Dict[str, Any]] = {}

    async def predict_vulnerability_risk(
        self,
        ip: str,
        open_ports: List[int],
        services: List[str],
        os_info: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Predict vulnerability risk for a device.

        Returns risk score (0.0 - 1.0) and factors.
        """
        base_risk = 0.0

        # Risk from number of open ports
        port_risk = min(len(open_ports) / 10.0, 1.0) * 0.2
        base_risk += port_risk

        # Risk from services
        service_risks = []
        for service in services:
            threat_info = await self.cve_intel.get_service_threat_level(service)
            threat_level = threat_info.get("threat_level", "unknown")
            risk_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "unknown": 0.1}
            service_risks.append(risk_map.get(threat_level, 0.1))

        if service_risks:
            avg_service_risk = sum(service_risks) / len(service_risks) * 0.5
            base_risk += avg_service_risk

        # Risk from device type
        profile = await self.profiler.profile_device(open_ports, services)
        device_type_risk = {
            "webcam": 0.7,
            "printer": 0.4,
            "router": 0.8,
            "database": 0.9,
            "web_server": 0.6,
            "firewall": 0.7,
            "ssh_server": 0.5,
            "smtp": 0.4,
            "unknown": 0.3,
        }
        risk = device_type_risk.get(profile["likely_type"], 0.3) * 0.3
        base_risk += risk

        return {
            "ip": ip,
            "risk_score": min(base_risk, 1.0),
            "risk_level": self._score_to_level(base_risk),
            "factors": {
                "port_risk": port_risk,
                "service_risk": sum(service_risks) / len(service_risks) if service_risks else 0,
                "device_type": profile["likely_type"],
                "device_confidence": profile["confidence"],
            },
            "services_threat": [
                {
                    "service": s,
                    "threat": await self.cve_intel.get_service_threat_level(s),
                }
                for s in services
            ],
        }

    async def predict_exploit_likelihood(
        self, services: List[str]
    ) -> List[Dict[str, Any]]:
        """Predict likelihood of public exploits for services."""
        exploits = []

        for service in services:
            threat_info = await self.cve_intel.get_service_threat_level(service)
            cve_info = threat_info.get("cve_info")

            if cve_info:
                exploit_likelihood = (
                    cve_info.get("exploits_available", 0) / 
                    max(cve_info.get("cve_count", 1), 1)
                )
                exploits.append({
                    "service": service,
                    "exploit_likelihood": exploit_likelihood,
                    "public_exploits": cve_info.get("exploits_available", 0),
                    "total_cves": cve_info.get("cve_count", 0),
                })

        return sorted(exploits, key=lambda x: x["exploit_likelihood"], reverse=True)

    async def predict_trending_threats(self) -> List[str]:
        """Get currently trending threats/exploits."""
        return self.cve_intel.trending_services.copy()

    @staticmethod
    def _score_to_level(score: float) -> str:
        """Convert risk score to level."""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.2:
            return "low"
        else:
            return "minimal"

    async def batch_predict(
        self, devices: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Batch predict for multiple devices."""
        results = []
        for device in devices:
            risk = await self.predict_vulnerability_risk(
                device.get("ip"),
                device.get("open_ports", []),
                device.get("services", []),
            )
            results.append(risk)
        return results
