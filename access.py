"""Access advisor.

Finding an exposed service is only half the job — the next question an operator
asks is always "how do I actually reach it?". This module turns a scan record
into the concrete, copy-pasteable way to connect: a browser URL for a web UI, an
``rtsp://`` string for VLC, an ``mstsc`` command for RDP, the right CLI for each
database, and so on. It is convenience for *authorized* access, not exploitation
— it only constructs the address/command you would type yourself.
"""
from dataclasses import dataclass, field


@dataclass
class AccessMethod:
    kind: str          # "web" | "command" | "url" | "note"
    label: str         # what this lets you do (Turkish)
    value: str         # URL or command to open/copy
    hint: str = ""     # extra guidance
    openable: bool = False  # can be opened directly in a new tab
    tool: str = ""     # which app to use it in (shown as a badge)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "label": self.label, "value": self.value,
                "hint": self.hint, "openable": self.openable, "tool": self.tool}


def _is_web(service: str, port: int) -> bool:
    if service in ("http", "https", "http-proxy", "https-alt", "elasticsearch"):
        return True
    return port in (80, 443, 8080, 8443, 8000, 8888, 5000, 9200, 5601, 8123, 9090)


def _is_tls(service: str, port: int) -> bool:
    return service == "https" or port in (443, 8443, 9443)


def access_methods(record: dict) -> list[dict]:
    """Return the ways to reach a given (ip, port, service) record."""
    ip = record.get("ip", "")
    port = record.get("port", 0)
    service = (record.get("service") or "").lower()
    methods: list[AccessMethod] = []

    # ── Web UIs ──
    if _is_web(service, port):
        scheme = "https" if _is_tls(service, port) else "http"
        url = f"{scheme}://{ip}:{port}/"
        methods.append(AccessMethod(
            kind="web", label="Web arayüzünü tarayıcıda aç",
            value=url, openable=True, tool="Tarayıcı",
            hint="Bu butona tıkla — cihazın yönetim paneli yeni sekmede açılır.",
        ))

    # ── Cameras (RTSP) ──
    if service == "rtsp" or port in (554, 8554, 10554):
        methods.append(AccessMethod(
            kind="url", label="Kamera akışını izle",
            value=f"rtsp://{ip}:{port}/", tool="VLC Player",
            hint="VLC'yi aç > Ortam menüsü > 'Ağ Akışı Aç' > bu adresi yapıştır > Oynat. (VLC kurulu değilse videolan.org'dan indir.) Kameraya göre yol gerekebilir: /Streaming/Channels/1",
        ))

    # ── Remote desktop ──
    if service == "rdp" or port == 3389:
        methods.append(AccessMethod(
            kind="command", label="Uzak Masaüstü ile bağlan",
            value=f"mstsc /v:{ip}:{port}", tool="Çalıştır (Win+R)",
            hint="Win+R tuşuna bas > açılan kutuya bu komutu yapıştır > Enter. Windows'un kendi Uzak Masaüstü uygulaması açılır.",
        ))

    if service == "vnc" or port in (5900, 5901, 5800):
        methods.append(AccessMethod(
            kind="url", label="VNC görüntüleyici ile bağlan",
            value=f"{ip}:{port}", tool="VNC Viewer",
            hint="RealVNC Viewer (realvnc.com'dan ücretsiz) kur > adres kutusuna bunu yaz > bağlan.",
        ))

    # ── Shell ──
    if service == "ssh" or port == 22:
        methods.append(AccessMethod(
            kind="command", label="SSH ile bağlan",
            value=f"ssh -p {port} kullanici@{ip}", tool="CMD / PowerShell",
            hint="Komut İstemi (CMD) veya PowerShell aç > komutu yapıştır. 'kullanici' yerine geçerli kullanıcı adını yaz (ör. admin, root).",
        ))
    if service == "telnet" or port == 23:
        methods.append(AccessMethod(
            kind="command", label="Telnet ile bağlan",
            value=f"telnet {ip} {port}", tool="CMD",
            hint="Komut İstemi'ne yapıştır. (Telnet kapalıysa: Denetim Masası > Windows özelliklerini aç/kapat > Telnet İstemcisi'ni işaretle.)",
        ))

    # ── File / NAS ──
    if service == "ftp" or port == 21:
        methods.append(AccessMethod(
            kind="url", label="FTP'ye bağlan",
            value=f"ftp://{ip}:{port}/", openable=True, tool="Tarayıcı",
            hint="Butona tıkla (tarayıcıda açılır) veya FileZilla kullan. Anonim giriş açıksa şifre gerekmez.",
        ))
    if service == "smb" or port == 445:
        methods.append(AccessMethod(
            kind="command", label="Paylaşılan dosyalara eriş",
            value=f"\\\\{ip}", openable=False, tool="Dosya Gezgini",
            hint="Dosya Gezgini'ni aç > en üstteki adres çubuğuna bunu yaz > Enter. Paylaşılan klasörler listelenir.",
        ))

    # ── Databases ──
    db_cli = {
        "mysql": (f"mysql -h {ip} -P {port} -u root -p", "MySQL Workbench veya HeidiSQL gibi bir araç da kullanabilirsin."),
        "postgresql": (f"psql -h {ip} -p {port} -U postgres", "pgAdmin veya DBeaver de kullanabilirsin."),
        "redis": (f"redis-cli -h {ip} -p {port}", "Şifresizse doğrudan çalışır — bağlanınca INFO yaz."),
        "mongodb": (f"mongosh mongodb://{ip}:{port}/", "MongoDB Compass (grafik arayüz) de kullanabilirsin."),
        "mssql": (f"sqlcmd -S {ip},{port} -U sa", "SSMS (SQL Server Management Studio) de kullanabilirsin."),
    }
    if service in db_cli:
        cmd, hint = db_cli[service]
        methods.append(AccessMethod(
            kind="command", label=f"{service.upper()} veritabanına bağlan",
            value=cmd, hint=hint, tool="CMD / PowerShell",
        ))

    # ── Mail ──
    if service in ("smtp",) or port in (25, 587):
        methods.append(AccessMethod(
            kind="command", label="SMTP sunucusunu test et",
            value=f"telnet {ip} {port}", tool="CMD",
            hint="Komut İstemi'ne yapıştır. Bağlanınca EHLO yaz, desteklenen özellikleri görürsün.",
        ))

    # ── IoT / MQTT ──
    if service == "mqtt" or port in (1883, 8883):
        methods.append(AccessMethod(
            kind="command", label="MQTT konularını dinle",
            value=f"mosquitto_sub -h {ip} -p {port} -t # -v", tool="CMD (Mosquitto)",
            hint="Mosquitto araçlarını kur (mosquitto.org). MQTT Explorer (grafik arayüz) daha kolaydır.",
        ))

    # ── ICS / SCADA ──
    if service == "modbus" or port == 502:
        methods.append(AccessMethod(
            kind="note", label="Modbus/ICS cihazı — DİKKAT",
            value=f"modpoll -m tcp -p {port} {ip}", tool="modpoll",
            hint="Endüstriyel cihaz. SADECE OKUMA yap; yazma komutu fiziksel sürece (motor, vana...) zarar verebilir.",
        ))

    # ── VoIP ──
    if service == "sip" or port in (5060, 5061):
        methods.append(AccessMethod(
            kind="note", label="SIP/VoIP servisi",
            value=f"sip:{ip}:{port}", tool="Linphone / Zoiper",
            hint="Bir SIP istemcisi (Linphone, Zoiper) ile test edilebilir.",
        ))

    # Fallback for anything else: raw TCP banner check.
    if not methods:
        methods.append(AccessMethod(
            kind="command", label="Bağlantıyı test et (banner gör)",
            value=f"ncat {ip} {port}", tool="CMD (Nmap/ncat)",
            hint="ncat, Nmap ile gelir (nmap.org). Yoksa PowerShell'de: Test-NetConnection " + ip + " -Port " + str(port),
        ))

    return [m.to_dict() for m in methods]
