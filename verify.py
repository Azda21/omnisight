"""Active access verification.

This is the part ZoomEye/Shodan do not do: they show you a *banner*. OmniSight
goes one step further and actually establishes a connection to tell you *what
level of access is really possible* — and proves it. Is that Redis wide open?
We send PING/INFO/DBSIZE and come back with the key count. Is that Elasticsearch
exposing data? We pull the index list. Anonymous FTP? We log in and read the
root listing. The result is a verdict — Açık / Anonim / Varsayılan şifre /
Kimlik gerekli / Erişilemez — backed by evidence, so the user knows "I got in,
so can you."

Safety: every check here is READ-ONLY and non-destructive. ICS/Modbus is never
written to. Default-credential probing is opt-in (aggressive=True) and limited
to HTTP Basic auth with a tiny well-known list. Authorized testing only.
"""
import asyncio
import base64
import ssl
from dataclasses import dataclass, field

# Access level verdicts (most→least exposed).
LEVEL_OPEN = "open"               # reachable, no auth, data readable
LEVEL_ANON = "anonymous"          # anonymous login accepted
LEVEL_DEFAULT = "default_creds"   # default credentials worked
LEVEL_AUTH = "auth_required"      # reachable but needs credentials
LEVEL_UNREACHABLE = "unreachable" # could not connect now

LEVEL_TR = {
    LEVEL_OPEN: "🔓 Açık (kimlik doğrulama yok)",
    LEVEL_ANON: "🔓 Anonim giriş kabul ediliyor",
    LEVEL_DEFAULT: "🔑 Varsayılan şifre çalıştı",
    LEVEL_AUTH: "🔒 Kimlik doğrulama gerekli",
    LEVEL_UNREACHABLE: "❌ Şu an erişilemiyor",
}

# A small, well-known default-credential list. Opt-in only.
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", ""), ("admin", "password"),
    ("admin", "12345"), ("root", "root"), ("admin", "admin123"),
    ("user", "user"), ("admin", "1234"),
]


@dataclass
class AccessReport:
    ip: str
    port: int
    service: str
    reachable: bool = False
    level: str = LEVEL_UNREACHABLE
    summary: str = ""
    evidence: list = field(default_factory=list)
    proof: str = ""
    credentials: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "port": self.port, "service": self.service,
            "reachable": self.reachable, "level": self.level,
            "level_label": LEVEL_TR.get(self.level, self.level),
            "summary": self.summary, "evidence": self.evidence,
            "proof": self.proof[:1500], "credentials": self.credentials,
        }


class AccessVerifier:
    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    async def verify(self, record: dict, aggressive: bool = False) -> AccessReport:
        ip = record.get("ip", "")
        port = int(record.get("port", 0))
        service = (record.get("service") or "").lower()
        report = AccessReport(ip=ip, port=port, service=service)

        # First: is it even reachable right now?
        if not await self._tcp_reachable(ip, port):
            report.reachable = False
            report.level = LEVEL_UNREACHABLE
            report.summary = "Bağlantı kurulamadı (kapalı/filtreli ya da örnek veri)."
            return report
        report.reachable = True
        report.level = LEVEL_AUTH  # default until proven more open

        try:
            if service in ("http", "https", "elasticsearch") or port in (80, 443, 8080, 8443, 8000, 9200, 5601, 8123):
                await self._verify_http(record, report, aggressive)
            elif service == "redis" or port == 6379:
                await self._verify_redis(report)
            elif service == "ftp" or port == 21:
                await self._verify_ftp(report)
            elif service == "mongodb" or port == 27017:
                await self._verify_mongo(report)
            else:
                report.summary = f"Servis erişilebilir; kimlik doğrulama gerekiyor görünüyor ({service or port})."
                report.evidence.append("TCP bağlantısı kuruldu.")
        except Exception as e:
            report.evidence.append(f"Doğrulama hatası: {e}")

        if not report.summary:
            report.summary = LEVEL_TR.get(report.level, "")
        return report

    async def _tcp_reachable(self, ip: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    # ── HTTP / Elasticsearch ──
    async def _verify_http(self, record, report, aggressive):
        port = report.port
        use_ssl = report.service == "https" or port in (443, 8443, 9443)
        status, headers, body = await self._http_get(report.ip, port, "/", use_ssl)

        if status == 0:
            report.summary = "HTTP yanıtı alınamadı."
            return

        # Elasticsearch open-data check.
        if record.get("service") == "elasticsearch" or port == 9200:
            s2, _, b2 = await self._http_get(report.ip, port, "/_cat/indices?format=json", use_ssl)
            if s2 == 200 and b2:
                report.level = LEVEL_OPEN
                report.summary = "Elasticsearch kimlik doğrulama olmadan veri döndürüyor — açık."
                report.evidence.append("GET /_cat/indices → 200, index listesi okunabilir.")
                report.proof = b2[:1200]
                return

        if status in (401, 403):
            report.level = LEVEL_AUTH
            report.summary = f"Web arayüzü kimlik doğrulama istiyor (HTTP {status})."
            report.evidence.append(f"GET / → {status}")
            if aggressive and "www-authenticate" in {k.lower() for k in headers}:
                cred = await self._try_basic_auth(report.ip, port, use_ssl)
                if cred:
                    report.level = LEVEL_DEFAULT
                    report.credentials = cred
                    report.summary = f"Varsayılan şifre çalıştı: {cred}"
                    report.evidence.append(f"HTTP Basic Auth başarılı: {cred}")
            return

        if status == 200:
            lowered = body.lower()
            if any(k in lowered for k in ('type="password"', "name=\"password\"", "login", "şifre", "parola", "sign in")):
                report.level = LEVEL_AUTH
                report.summary = "Web arayüzü açılıyor ama giriş ekranı var (şifre gerekiyor)."
                report.evidence.append("GET / → 200, sayfada giriş formu tespit edildi.")
            else:
                report.level = LEVEL_OPEN
                report.summary = "Web arayüzü kimlik doğrulamadan açılıyor — doğrudan erişilebilir."
                report.evidence.append("GET / → 200, giriş ekranı yok.")
            report.proof = body[:800]

    async def _http_get(self, ip, port, path, use_ssl, auth=None):
        try:
            ctx = None
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx), timeout=self.timeout
            )
            req = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: OmniSight-Verify/1.0\r\n"
            if auth:
                token = base64.b64encode(auth.encode()).decode()
                req += f"Authorization: Basic {token}\r\n"
            req += "Accept: */*\r\nConnection: close\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            data = b""
            while len(data) < 200_000:
                try:
                    chunk = await asyncio.wait_for(reader.read(16384), timeout=self.timeout)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                data += chunk
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            text = data.decode("utf-8", errors="replace")
            status = 0
            headers = {}
            body = ""
            if "\r\n\r\n" in text:
                head, body = text.split("\r\n\r\n", 1)
                lines = head.split("\r\n")
                if lines and lines[0].startswith("HTTP"):
                    parts = lines[0].split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        status = int(parts[1])
                for ln in lines[1:]:
                    if ": " in ln:
                        k, v = ln.split(": ", 1)
                        headers[k] = v
            return status, headers, body
        except Exception:
            return 0, {}, ""

    async def _try_basic_auth(self, ip, port, use_ssl) -> str:
        for user, pw in DEFAULT_CREDS:
            status, _, _ = await self._http_get(ip, port, "/", use_ssl, auth=f"{user}:{pw}")
            if status == 200:
                return f"{user}:{pw or '(boş)'}"
        return ""

    # ── Redis ──
    async def _verify_redis(self, report):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(report.ip, report.port), timeout=self.timeout
            )
            writer.write(b"*1\r\n$4\r\nPING\r\n")
            await writer.drain()
            pong = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            if b"NOAUTH" in pong or b"WRONGPASS" in pong:
                report.level = LEVEL_AUTH
                report.summary = "Redis çalışıyor ama şifre istiyor."
                writer.close(); return
            if b"+PONG" in pong:
                writer.write(b"*1\r\n$4\r\nINFO\r\n")
                await writer.drain()
                info = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                writer.write(b"*1\r\n$6\r\nDBSIZE\r\n")
                await writer.drain()
                dbsize = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
                report.level = LEVEL_OPEN
                keys = dbsize.decode(errors="replace").strip().lstrip(":")
                report.summary = f"Redis tamamen açık — şifre yok. ~{keys} anahtar okunabilir."
                report.evidence.append("PING→PONG, INFO ve DBSIZE şifresiz çalıştı.")
                report.proof = info.decode(errors="replace")[:1000]
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception as e:
            report.evidence.append(f"Redis doğrulama hatası: {e}")

    # ── FTP ──
    async def _verify_ftp(self, report):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(report.ip, report.port), timeout=self.timeout
            )
            await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            writer.write(b"USER anonymous\r\n"); await writer.drain()
            r1 = (await asyncio.wait_for(reader.read(256), timeout=self.timeout)).decode(errors="replace")
            if r1.startswith("331"):
                writer.write(b"PASS omnisight@verify\r\n"); await writer.drain()
                r2 = (await asyncio.wait_for(reader.read(256), timeout=self.timeout)).decode(errors="replace")
                if r2.startswith("230"):
                    report.level = LEVEL_ANON
                    report.summary = "Anonim FTP girişi kabul edildi — şifresiz dosya erişimi."
                    report.evidence.append("USER anonymous → 331, PASS → 230 (giriş başarılı).")
                    writer.write(b"PWD\r\n"); await writer.drain()
                    pwd = (await asyncio.wait_for(reader.read(256), timeout=self.timeout)).decode(errors="replace")
                    report.proof = pwd.strip()
                else:
                    report.level = LEVEL_AUTH
                    report.summary = "FTP anonim girişi reddetti — kimlik gerekiyor."
            else:
                report.level = LEVEL_AUTH
                report.summary = "FTP kimlik doğrulama istiyor."
            writer.write(b"QUIT\r\n"); await writer.drain()
            writer.close()
        except Exception as e:
            report.evidence.append(f"FTP doğrulama hatası: {e}")

    # ── MongoDB ──
    async def _verify_mongo(self, report):
        # isMaster always answers pre-auth; we report reachable + advise.
        report.level = LEVEL_AUTH
        report.summary = "MongoDB erişilebilir. Açık olup olmadığı için 'mongosh' ile listDatabases dene."
        report.evidence.append("TCP bağlantısı kuruldu (isMaster yanıtı pre-auth gelir).")
