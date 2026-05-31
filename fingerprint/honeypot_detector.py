import re
from dataclasses import dataclass


@dataclass
class HoneypotScore:
    score: float = 0.0
    is_honeypot: bool = False
    indicators: list = None
    confidence: str = "unknown"

    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []


class HoneypotDetector:
    def analyze(self, scan_results: list) -> HoneypotScore:
        score = HoneypotScore()
        indicators = []

        if len(scan_results) > 1:
            open_ports = [r for r in scan_results if r.get("state") == "open"]
            port_count = len(open_ports)

            if port_count > 50:
                indicators.append(("too_many_ports", 0.8, f"{port_count} open ports is suspicious"))
            elif port_count > 20:
                indicators.append(("many_ports", 0.4, f"{port_count} open ports is somewhat suspicious"))

            unusual_combos = self._check_unusual_combos(open_ports)
            if unusual_combos:
                indicators.append(("unusual_combo", 0.5, unusual_combos))

        for result in scan_results:
            banner = result.get("banner", "")
            if banner:
                hp_sigs = self._check_honeypot_signatures(banner)
                indicators.extend(hp_sigs)

                version_issue = self._check_version_anomaly(banner)
                if version_issue:
                    indicators.append(version_issue)

                latency = result.get("latency_ms", 0)
                if latency > 0 and latency < 1:
                    indicators.append(("instant_response", 0.3, f"Suspiciously fast response: {latency}ms"))

        if indicators:
            total_weight = sum(w for _, w, _ in indicators)
            score.score = min(total_weight / len(indicators) * len(indicators), 1.0)
            score.indicators = [f"{name}: {desc}" for name, _, desc in indicators]
            score.is_honeypot = score.score > 0.6

            if score.score > 0.8:
                score.confidence = "high"
            elif score.score > 0.5:
                score.confidence = "medium"
            else:
                score.confidence = "low"

        return score

    @staticmethod
    def _check_unusual_combos(open_ports: list) -> str:
        ports = {r.get("port") for r in open_ports}
        suspicious = []
        if 22 in ports and 23 in ports and 3389 in ports:
            suspicious.append("SSH + Telnet + RDP on same host")
        if 80 in ports and 8080 in ports and 8443 in ports and 443 in ports:
            suspicious.append("Multiple HTTP ports all open")
        if 3306 in ports and 5432 in ports and 27017 in ports:
            suspicious.append("MySQL + PostgreSQL + MongoDB all exposed")
        if 502 in ports and (80 in ports) and (22 in ports):
            suspicious.append("Modbus + HTTP + SSH combination")
        return "; ".join(suspicious)

    @staticmethod
    def _check_honeypot_signatures(banner: str) -> list[tuple]:
        indicators = []
        honeypot_names = [
            "cowrie", "kippo", "dionaea", "honeyd", "glastopf",
            "conpot", "elastichoney", "honeytrap", "mailoney",
            "heralding", "tanner", "snare",
        ]
        bl = banner.lower()
        for name in honeypot_names:
            if name in bl:
                indicators.append(("known_honeypot", 0.95, f"Known honeypot signature: {name}"))

        if "SSH-2.0-OpenSSH_" in banner:
            version_match = re.search(r"OpenSSH_([\d.]+)", banner)
            if version_match:
                ver = version_match.group(1)
                ancient = ["4.3", "5.1", "5.3", "5.5"]
                if any(ver.startswith(a) for a in ancient):
                    indicators.append(("ancient_version", 0.4, f"Very old OpenSSH version: {ver}"))

        return indicators

    @staticmethod
    def _check_version_anomaly(banner: str) -> tuple | None:
        windows_ssh = re.search(r"SSH.*Windows", banner, re.IGNORECASE)
        linux_rdp = re.search(r"RDP.*Linux", banner, re.IGNORECASE)
        if windows_ssh and "OpenSSH_for_Windows" not in banner:
            return ("os_mismatch", 0.5, "SSH banner mentions Windows unusually")
        if linux_rdp:
            return ("os_mismatch", 0.3, "RDP banner mentions Linux")
        return None
