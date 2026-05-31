"""Risk scoring & remediation.

ZoomEye/Shodan hand you data and leave the judgement to you. This turns each
finding into a verdict: a 0–100 exposure score, *why* it scored that way, and
*what to do about it* — in plain Turkish. The point is to move from "here is an
open port" to "this is dangerous, here is how bad, here is the fix", which is
the part a human actually needs.
"""
from dataclasses import dataclass, field

# Services that should rarely face the open network — exposure alone is a risk.
DANGEROUS_PORTS = {
    23: ("Telnet", 25, "Telnet şifreyi açık metin gönderir. SSH'a geç ve telnet'i kapat."),
    3389: ("RDP", 30, "RDP doğrudan internete açık olmamalı. VPN arkasına al, NLA aç."),
    445: ("SMB", 25, "SMB dışarı açık olmamalı. Güvenlik duvarıyla kısıtla (WannaCry vektörü)."),
    139: ("NetBIOS", 15, "Eski dosya paylaşımı. Dışarıya kapat."),
    5900: ("VNC", 30, "VNC genelde zayıf korunur. VPN arkasına al, güçlü şifre koy."),
    3306: ("MySQL", 30, "Veritabanı internete açık olmamalı. Sadece uygulama sunucusuna izin ver."),
    5432: ("PostgreSQL", 30, "Veritabanını dışarı kapat, güvenlik duvarı kuralı ekle."),
    6379: ("Redis", 35, "Redis varsayılan olarak şifresiz. Bind 127.0.0.1 + requirepass ayarla."),
    27017: ("MongoDB", 35, "MongoDB'yi dışarı kapat, kimlik doğrulama aç."),
    9200: ("Elasticsearch", 30, "ES'i dışarı kapat, güvenlik (xpack) aç."),
    11211: ("Memcached", 30, "Memcached UDP amplifikasyon riski. Dışarı kapat."),
    502: ("Modbus", 40, "ICS cihazı! İnternete asla açık olmamalı. Hemen segmente al."),
    102: ("S7/SIMATIC", 40, "Endüstriyel PLC. Ağ segmentasyonu şart."),
    47808: ("BACnet", 35, "Bina otomasyonu. Dışarı kapat."),
    1883: ("MQTT", 20, "MQTT broker'ı kimlik doğrulamasız olabilir. TLS + auth ekle."),
    21: ("FTP", 15, "FTP şifreyi açık gönderir. SFTP/FTPS'e geç."),
}

ACCESS_WEIGHT = {
    "default_creds": 50,
    "open": 45,
    "anonymous": 40,
    "auth_required": 5,
    "unreachable": 0,
}

SEVERITY_BANDS = [
    (75, "critical", "🔴 Kritik"),
    (50, "high", "🟠 Yüksek"),
    (25, "medium", "🟡 Orta"),
    (0, "low", "🟢 Düşük"),
]


@dataclass
class RiskReport:
    score: int = 0
    severity: str = "low"
    severity_label: str = "🟢 Düşük"
    reasons: list = field(default_factory=list)        # why it scored
    remediations: list = field(default_factory=list)   # how to fix

    def to_dict(self) -> dict:
        return {
            "score": self.score, "severity": self.severity,
            "severity_label": self.severity_label,
            "reasons": self.reasons, "remediations": self.remediations,
        }


def _band(score: int):
    for threshold, key, label in SEVERITY_BANDS:
        if score >= threshold:
            return key, label
    return "low", "🟢 Düşük"


def score_record(record: dict) -> RiskReport:
    report = RiskReport()
    score = 0
    port = int(record.get("port", 0))
    service = (record.get("service") or "").lower()

    # 1) Exposed dangerous service.
    if port in DANGEROUS_PORTS:
        name, weight, fix = DANGEROUS_PORTS[port]
        score += weight
        report.reasons.append(f"{name} servisi ağa açık (port {port}).")
        report.remediations.append(fix)

    # 2) Verified access level (the strongest signal — we actually got in).
    level = record.get("access_level")
    if level and level in ACCESS_WEIGHT:
        w = ACCESS_WEIGHT[level]
        if w >= 40:
            score += w
            if level == "default_creds":
                report.reasons.append("Varsayılan şifre çalışıyor — herkes girebilir.")
                report.remediations.append("Şifreyi HEMEN değiştir; varsayılanı asla kullanma.")
            elif level == "open":
                report.reasons.append("Kimlik doğrulama YOK — veri korumasız.")
                report.remediations.append("Kimlik doğrulama/şifre zorunlu yap.")
            elif level == "anonymous":
                report.reasons.append("Anonim erişim açık.")
                report.remediations.append("Anonim girişi kapat.")

    # 3) Known CVEs.
    cves = record.get("cves") or []
    for c in cves:
        sev = (c.get("severity") or "").upper()
        cid = c.get("id", "")
        if sev == "CRITICAL":
            score += 30
            report.reasons.append(f"Kritik zafiyet: {cid} (skor {c.get('score','')}).")
            report.remediations.append(f"{cid} için yazılımı güncelle/yama uygula.")
        elif sev == "HIGH":
            score += 20
            report.reasons.append(f"Yüksek zafiyet: {cid}.")
            report.remediations.append(f"{cid} için güncelleme yap.")
        elif sev == "MEDIUM":
            score += 10
            report.reasons.append(f"Orta zafiyet: {cid}.")

    # 4) Security findings raised during the scan.
    for f in (record.get("findings") or []):
        score += 15
        report.reasons.append(f)
    # 5) Weak TLS hints in stored ssl_info.
    ssl_info = str(record.get("ssl_info") or "")
    if "weak_cipher" in ssl_info or "SSLv" in ssl_info or "TLSv1.0" in ssl_info:
        score += 10
        report.reasons.append("Zayıf/eski TLS yapılandırması.")
        report.remediations.append("TLS 1.2+ zorunlu kıl, zayıf şifreleri kapat.")

    score = max(0, min(100, score))
    report.score = score
    report.severity, report.severity_label = _band(score)

    if not report.reasons:
        report.reasons.append("Belirgin risk sinyali yok.")
    # De-duplicate remediations while preserving order.
    seen = set()
    report.remediations = [r for r in report.remediations if not (r in seen or seen.add(r))]
    return report


def score_host(records: list[dict]) -> dict:
    """Aggregate a host's services into one risk posture."""
    reports = [score_record(r) for r in records]
    if not reports:
        return {"score": 0, "severity": "low", "severity_label": "🟢 Düşük", "services": 0}
    top = max(reports, key=lambda r: r.score)
    # Host score = worst service, nudged up by breadth of exposure.
    host_score = min(100, top.score + min(len(records) - 1, 5) * 2)
    sev, label = _band(host_score)
    return {
        "score": host_score, "severity": sev, "severity_label": label,
        "services": len(records),
        "worst": top.to_dict(),
    }
