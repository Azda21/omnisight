"""Intent-aware search intelligence.

ZoomEye/Shodan make you already know that an IP camera answers on RTSP/554, or
that a Hikvision device fingerprints as ``App-webs`` / ``DNVRS-Webs``. A normal
user just knows the word *camera*. This module closes that gap: it maps a plain
intent word to the full set of signals (ports, vendor product strings, banner
patterns, page titles, services) that actually identify that class of device,
and expands a single keyword into a precise multi-signal OR query.

That is what makes ``camera`` here outperform a literal ``camera`` substring
search on ZoomEye — we match the *device*, not the word.
"""
import re
from dataclasses import dataclass, field


@dataclass
class Category:
    key: str
    label: str
    icon: str
    description: str
    # User words that trigger this category (multilingual where useful).
    aliases: list = field(default_factory=list)
    # DISTINCTIVE ports only — ones that on their own strongly imply this device
    # class (RTSP 554, Dahua 37777). Generic web ports (80/443/8080) are left
    # out on purpose: matching them standalone would flag every web server. The
    # web-UI devices on those ports are still caught by banner/product/title
    # signatures below. This split is what keeps recall high without wrecking
    # precision — the gap most naive keyword searches fall into.
    ports: list = field(default_factory=list)
    products: list = field(default_factory=list)      # vendor / product strings
    banner_patterns: list = field(default_factory=list)  # substrings seen in banners
    title_patterns: list = field(default_factory=list)   # web page <title> hints
    services: list = field(default_factory=list)
    # Broad port set to use when *scanning* for this category (includes the
    # generic web ports, because you do want to probe them during a sweep).
    scan_ports: str = ""


CATEGORIES: dict[str, Category] = {
    "camera": Category(
        key="camera",
        label="IP Cameras / DVR / NVR",
        icon="\U0001F4F9",
        description="Network cameras, video recorders and surveillance web UIs.",
        aliases=["camera", "cameras", "webcam", "kamera", "cctv", "dvr", "nvr",
                 "surveillance", "ipcam", "ip-cam"],
        ports=[554, 88, 8899, 34567, 37777, 10554],  # distinctive, no generic web
        products=["Hikvision", "Dahua", "Axis", "Foscam", "Vivotek", "Reolink",
                  "Mobotix", "GeoVision", "Uniview", "Hanwha", "Bosch Security",
                  "Amcrest", "Wansview", "Sunell", "Avtech"],
        banner_patterns=["RTSP/1.0", "RTSP/1.1", "DNVRS-Webs", "App-webs",
                         "Hipcam", "Network Camera", "IP Camera", "NetSurveillance",
                         "GoAhead", "Boa/", "ipcamera", "webcamXP", "webcam 7",
                         "Server: Hikvision", "Server: Dahua", "uc-httpd",
                         "Cross Web Server", "JAWS/"],
        title_patterns=["webcam", "ip camera", "network camera", "live view",
                        "surveillance", "NVR", "DVR", "WEB SERVICE", "video web server"],
        services=["rtsp"],
        scan_ports="80,81,88,554,8000,8080,8081,8899,9000,34567,37777,10554",
    ),
    "router": Category(
        key="router",
        label="Routers / Network Gear",
        icon="\U0001F4E1",
        description="Home and enterprise routers, switches, firewalls and admin panels.",
        aliases=["router", "routers", "modem", "gateway", "firewall", "switch",
                 "mikrotik", "cisco", "ubiquiti", "pfsense", "openwrt"],
        ports=[8291, 8728, 2000],  # MikroTik/Cisco distinctive; SSH/HTTP via product
        products=["MikroTik", "RouterOS", "Cisco", "Ubiquiti", "EdgeOS", "DD-WRT",
                  "OpenWrt", "pfSense", "TP-LINK", "D-Link", "Netgear", "ASUS",
                  "Huawei", "ZTE", "Juniper", "Fortinet", "FortiGate", "SonicWALL"],
        # Router-distinctive only — generic embedded servers (GoAhead, Boa,
        # lighttpd, uhttpd) are shared with cameras/IoT, so they are deliberately
        # left out to avoid cross-category false positives.
        banner_patterns=["RouterOS", "MikroTik", "Cisco IOS", "EdgeOS", "DD-WRT",
                         "OpenWrt", "FortiGate", "Huawei Home Gateway", "RT-AC",
                         "TP-LINK Router", "ZTE", "DrayTek"],
        title_patterns=["RouterOS", "TP-LINK", "D-LINK", "NETGEAR", "FortiGate",
                        "DrayTek", "broadband"],
        # No generic ssh/telnet/http service match — that would catch every web
        # and shell host. Routers are identified by product, distinctive port or
        # vendor banner instead.
        services=[],
        scan_ports="22,23,80,161,443,2000,8080,8291,8443,8728",
    ),
    "printer": Category(
        key="printer",
        label="Network Printers",
        icon="\U0001F5A8",
        description="Exposed network printers and print servers.",
        aliases=["printer", "printers", "yazici", "yazıcı", "print", "mfp"],
        ports=[515, 631, 9100],  # LPD/IPP/JetDirect — distinctive
        products=["HP", "Canon", "Epson", "Brother", "Lexmark", "Xerox", "Kyocera",
                  "Ricoh", "Samsung", "Zebra", "JetDirect"],
        banner_patterns=["HP-ChaiSOE", "JetDirect", "IPP", "CUPS", "Brother",
                         "EPSON", "KONICA MINOLTA", "Lexmark", "Server: HP",
                         "Virata-EmWeb", "Printer"],
        title_patterns=["printer", "JetDirect", "EWS", "Web Image Monitor",
                        "RICOH", "Brother", "EPSON", "Canon", "Embedded Web Server"],
        services=["ipp"],   # http is too generic to imply a printer
        scan_ports="80,161,443,515,631,9100",
    ),
    "database": Category(
        key="database",
        label="Exposed Databases",
        icon="\U0001F5C4",
        description="Internet-facing database servers — often unauthenticated.",
        aliases=["database", "databases", "db", "veritabani", "veritabanı",
                 "mysql", "postgres", "postgresql", "mongodb", "mongo", "redis",
                 "elastic", "elasticsearch", "mssql", "oracle", "cassandra"],
        ports=[1433, 1521, 3306, 5432, 6379, 9042, 9200, 11211, 27017, 5984, 7000, 7474],
        products=["MySQL", "MariaDB", "PostgreSQL", "MongoDB", "Redis",
                  "Elasticsearch", "Microsoft SQL Server", "Oracle", "Cassandra",
                  "CouchDB", "Memcached", "Neo4j"],
        banner_patterns=["mysql_native_password", "MariaDB", "PostgreSQL",
                         "MongoDB", "+PONG", "redis_version", "cluster_name",
                         "It looks like you are trying to access MongoDB",
                         "couchdb", "Welcome to", " has gone away"],
        title_patterns=["phpMyAdmin", "Adminer", "Mongo Express", "Kibana",
                        "CouchDB", "RedisInsight"],
        services=["mysql", "postgresql", "mongodb", "redis", "elasticsearch"],
        scan_ports="1433,1521,3306,5432,5984,6379,7474,9042,9200,11211,27017",
    ),
    "ics": Category(
        key="ics",
        label="ICS / SCADA / OT",
        icon="\U0001F3ED",
        description="Industrial control systems and PLCs — critical infrastructure.",
        aliases=["ics", "scada", "plc", "modbus", "industrial", "ot", "endustriyel",
                 "endüstriyel", "bacnet", "s7", "siemens", "dnp3"],
        ports=[102, 502, 1911, 2404, 4000, 9600, 20000, 44818, 47808, 1962, 789],
        products=["Siemens", "Schneider", "Allen-Bradley", "Rockwell", "Modicon",
                  "Wago", "Beckhoff", "Moxa", "Niagara", "Tridium", "ABB", "Omron"],
        banner_patterns=["Modbus", "Siemens", "S7-", "SIMATIC", "BACnet",
                         "Tridium", "Niagara", "EtherNet/IP", "CODESYS", "Schneider",
                         "Allen-Bradley", "Wago", "Moxa", "FINS"],
        title_patterns=["SCADA", "HMI", "PLC", "Niagara", "Schneider Electric",
                        "Siemens", "control system", "automation"],
        services=["modbus"],
        scan_ports="102,502,789,1911,1962,2404,4000,9600,20000,44818,47808",
    ),
    "voip": Category(
        key="voip",
        label="VoIP / SIP / PBX",
        icon="\U0001F4DE",
        description="Voice-over-IP phones, SIP servers and PBX systems.",
        aliases=["voip", "sip", "pbx", "asterisk", "freepbx", "telefon", "phone"],
        ports=[5060, 5061, 5038],  # SIP/AMI — distinctive
        products=["Asterisk", "FreePBX", "FreeSWITCH", "3CX", "Grandstream",
                  "Yealink", "Polycom", "Cisco CallManager", "Avaya", "Kamailio"],
        banner_patterns=["SIP/2.0", "Asterisk", "FreeSWITCH", "kamailio", "OpenSIPS",
                         "Grandstream", "Yealink", "Polycom", "3CX"],
        title_patterns=["FreePBX", "3CX", "Grandstream", "VoIP", "PBX", "SIP"],
        services=["sip"],
        scan_ports="80,443,2000,5038,5060,5061",
    ),
    "nas": Category(
        key="nas",
        label="NAS / Storage",
        icon="\U0001F4BE",
        description="Network-attached storage and file servers.",
        aliases=["nas", "storage", "depolama", "synology", "qnap", "freenas",
                 "truenas", "samba", "smb", "ftp"],
        ports=[139, 445, 2049, 5000, 5001],  # SMB/NFS/Synology — distinctive
        products=["Synology", "QNAP", "TrueNAS", "FreeNAS", "Western Digital",
                  "Buffalo", "Netgear ReadyNAS", "Samba", "DiskStation"],
        banner_patterns=["Synology", "QNAP", "DiskStation", "nginx", "Samba",
                         "ProFTPD", "vsftpd", "WD My Cloud", "ReadyNAS"],
        title_patterns=["Synology", "DiskStation", "QNAP", "QTS", "TrueNAS",
                        "ReadyNAS", "My Cloud", "File Station"],
        services=["smb"],   # ftp alone is too generic; NAS caught via product/SMB
        scan_ports="21,139,445,2049,5000,5001,8080,9000",
    ),
    "remote": Category(
        key="remote",
        label="Remote Access",
        icon="\U0001F5A5",
        description="Remote desktop and shell access — RDP, VNC, SSH, Telnet.",
        aliases=["remote", "rdp", "vnc", "ssh", "telnet", "uzak", "desktop",
                 "teamviewer", "anydesk"],
        ports=[22, 23, 3389, 5900, 5901, 5800, 5938, 4899],
        products=["OpenSSH", "Dropbear", "RealVNC", "TightVNC", "UltraVNC",
                  "TeamViewer", "AnyDesk", "xrdp", "Microsoft Terminal Services"],
        banner_patterns=["SSH-2.0", "RFB 003", "RDP", "Microsoft Terminal",
                         "xrdp", "VNC", "Dropbear", "radmin"],
        title_patterns=["Remote Desktop", "VNC", "Guacamole", "noVNC"],
        services=["ssh", "telnet", "rdp", "vnc"],
        scan_ports="22,23,3389,4899,5800,5900,5901,5938",
    ),
    "iot": Category(
        key="iot",
        label="IoT / Smart Home",
        icon="\U0001F3E0",
        description="Smart-home hubs, sensors and consumer IoT devices.",
        aliases=["iot", "smarthome", "smart-home", "mqtt", "homeassistant",
                 "akilli", "akıllı", "sensor", "tasmota", "shelly"],
        ports=[1883, 8883, 8123, 5683],  # MQTT/HA/CoAP — distinctive
        products=["Home Assistant", "Tasmota", "Shelly", "Sonoff", "ESPHome",
                  "Mosquitto", "OpenHAB", "Domoticz", "Philips Hue"],
        banner_patterns=["MQTT", "Mosquitto", "Home Assistant", "Tasmota",
                         "Shelly", "ESP8266", "ESP32", "lwIP", "CoAP"],
        title_patterns=["Home Assistant", "Tasmota", "Shelly", "openHAB",
                        "Domoticz", "Smart Home"],
        services=["mqtt"],
        scan_ports="80,443,1883,5683,8123,8883,8888,9999",
    ),
    "mail": Category(
        key="mail",
        label="Mail Servers",
        icon="\U00002709",
        description="SMTP/IMAP/POP3 mail servers and webmail panels.",
        aliases=["mail", "email", "smtp", "imap", "pop3", "exchange", "posta",
                 "webmail", "zimbra"],
        ports=[25, 110, 143, 465, 587, 993, 995],  # mail protocols — distinctive
        products=["Postfix", "Exim", "Sendmail", "Microsoft Exchange", "Dovecot",
                  "Zimbra", "Courier", "Exchange", "Roundcube"],
        banner_patterns=["ESMTP", "Postfix", "Exim", "Sendmail", "Microsoft ESMTP",
                         "Dovecot", "Zimbra", "IMAP4", "POP3"],
        title_patterns=["Roundcube", "Zimbra", "Outlook Web", "Horde", "webmail"],
        services=["smtp", "imap", "pop3"],
        scan_ports="25,80,110,143,443,465,587,993,995",
    ),
    "web": Category(
        key="web",
        label="Web Servers / Panels",
        icon="\U0001F310",
        description="Web servers, admin panels and exposed dashboards.",
        aliases=["web", "website", "http", "panel", "dashboard", "admin", "cms"],
        ports=[80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090],
        products=["nginx", "Apache", "Microsoft IIS", "LiteSpeed", "Tomcat",
                  "WordPress", "Jenkins", "Grafana", "Kibana", "phpMyAdmin"],
        banner_patterns=["Server: nginx", "Server: Apache", "Microsoft-IIS",
                         "X-Powered-By", "Set-Cookie", "Jenkins", "Grafana"],
        title_patterns=["Dashboard", "Login", "Admin", "Jenkins", "Grafana",
                        "Kibana", "phpMyAdmin", "Welcome"],
        services=["http", "https"],
        scan_ports="80,443,3000,5000,8000,8080,8443,8888,9090",
    ),
}


def list_categories() -> list[dict]:
    """Compact category list for the UI chips."""
    return [
        {
            "key": c.key,
            "label": c.label,
            "icon": c.icon,
            "description": c.description,
            "scan_ports": c.scan_ports,
        }
        for c in CATEGORIES.values()
    ]


# Alias → category-key lookup, built once.
_ALIAS_INDEX: dict[str, str] = {}
for _cat in CATEGORIES.values():
    for _alias in _cat.aliases:
        _ALIAS_INDEX[_alias.lower()] = _cat.key


def detect_categories(text: str) -> list[str]:
    """Return category keys whose alias appears as a whole word in *text*."""
    if not text:
        return []
    found = []
    words = re.findall(r"[\w-]+", text.lower())
    wordset = set(words)
    for alias, key in _ALIAS_INDEX.items():
        if alias in wordset and key not in found:
            found.append(key)
    return found


class SearchIntelligence:
    """Expands a detected category into backend-specific query fragments."""

    @staticmethod
    def get(category_key: str) -> Category | None:
        return CATEGORIES.get(category_key)

    def expand_to_sql(self, category_key: str) -> tuple[str, list]:
        """An OR group matching any signal for the category.

        Matches if the row is on a known port for that device class OR its
        product/banner/title/service matches a known signature. That breadth is
        the point: a Hikvision NVR with a stripped banner still matches on
        port 37777; one on an odd port still matches on the ``App-webs`` string.
        """
        cat = CATEGORIES.get(category_key)
        if not cat:
            return "", []

        ors: list[str] = []
        params: list = []

        if cat.ports:
            placeholders = ",".join("?" for _ in cat.ports)
            ors.append(f"port IN ({placeholders})")
            params.extend(cat.ports)

        for product in cat.products:
            ors.append("product LIKE ?")
            params.append(f"%{product}%")

        for pat in cat.banner_patterns:
            ors.append("banner LIKE ?")
            params.append(f"%{pat}%")

        for pat in cat.title_patterns:
            ors.append("data_json LIKE ?")
            params.append(f'%{pat}%')

        for svc in cat.services:
            ors.append("service = ?")
            params.append(svc)

        if not ors:
            return "", []
        return "(" + " OR ".join(ors) + ")", params

    def expand_to_es(self, category_key: str) -> dict | None:
        cat = CATEGORIES.get(category_key)
        if not cat:
            return None

        should: list = []
        if cat.ports:
            should.append({"terms": {"port": cat.ports}})
        for product in cat.products:
            should.append({"match": {"product": product}})
        for pat in cat.banner_patterns:
            should.append({"match_phrase": {"banner": pat}})
        for pat in cat.title_patterns:
            should.append({"match": {"web_title": pat}})
        for svc in cat.services:
            should.append({"term": {"service": svc}})

        if not should:
            return None
        return {"bool": {"should": should, "minimum_should_match": 1}}
