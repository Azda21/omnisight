import asyncio
import ssl
import hashlib
import datetime
from dataclasses import dataclass, field


@dataclass
class SSLInfo:
    version: str = ""
    cipher_suite: str = ""
    cipher_bits: int = 0
    subject: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    expired: bool = False
    days_until_expiry: int = 0
    self_signed: bool = False
    san: list = field(default_factory=list)
    fingerprint_sha256: str = ""
    key_type: str = ""
    key_size: int = 0
    weak_cipher: bool = False
    vulnerabilities: list = field(default_factory=list)


WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
    "RC2", "IDEA", "SEED",
}


class SSLAnalyzer:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def analyze(self, ip: str, port: int = 443) -> SSLInfo:
        info = SSLInfo()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx),
                timeout=self.timeout,
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                info.version = ssl_obj.version() or ""
                cipher = ssl_obj.cipher()
                if cipher:
                    info.cipher_suite = cipher[0]
                    info.cipher_bits = cipher[2] if len(cipher) > 2 else 0

                cert_der = ssl_obj.getpeercert(binary_form=True)
                if cert_der:
                    info.fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()

                cert = ssl_obj.getpeercert(binary_form=False)
                if cert:
                    info = self._parse_cert(cert, info)

            info.weak_cipher = self._check_weak_cipher(info.cipher_suite)
            info.vulnerabilities = self._check_vulnerabilities(info)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        return info

    @staticmethod
    def _parse_cert(cert: dict, info: SSLInfo) -> SSLInfo:
        subject = cert.get("subject", ())
        for rdn in subject:
            for attr_type, attr_value in rdn:
                info.subject[attr_type] = attr_value

        issuer = cert.get("issuer", ())
        for rdn in issuer:
            for attr_type, attr_value in rdn:
                info.issuer[attr_type] = attr_value

        info.serial_number = str(cert.get("serialNumber", ""))
        info.not_before = cert.get("notBefore", "")
        info.not_after = cert.get("notAfter", "")

        if info.not_after:
            try:
                expiry = datetime.datetime.strptime(info.not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                info.days_until_expiry = (expiry - now).days
                info.expired = info.days_until_expiry < 0
            except ValueError:
                pass

        info.self_signed = info.subject == info.issuer

        san = cert.get("subjectAltName", ())
        info.san = [val for _, val in san]

        return info

    @staticmethod
    def _check_weak_cipher(cipher_name: str) -> bool:
        upper = cipher_name.upper()
        return any(weak in upper for weak in WEAK_CIPHERS)

    @staticmethod
    def _check_vulnerabilities(info: SSLInfo) -> list[str]:
        vulns = []
        if info.version in ("SSLv2", "SSLv3"):
            vulns.append(f"Deprecated protocol: {info.version}")
        if info.version == "TLSv1.0":
            vulns.append("TLS 1.0 is deprecated (CVE-2011-3389 BEAST)")
        if info.version == "TLSv1.1":
            vulns.append("TLS 1.1 is deprecated")
        if info.weak_cipher:
            vulns.append(f"Weak cipher: {info.cipher_suite}")
        if info.self_signed:
            vulns.append("Self-signed certificate")
        if info.expired:
            vulns.append(f"Certificate expired {abs(info.days_until_expiry)} days ago")
        if info.cipher_bits and info.cipher_bits < 128:
            vulns.append(f"Low cipher strength: {info.cipher_bits} bits")
        return vulns
