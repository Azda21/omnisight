"""Demo dataset.

OmniSight indexes only what it scans — unlike ZoomEye's pre-built global cloud,
a fresh install has an empty database, so a search returns nothing until you run
a scan. That is correct behaviour, but it makes the tool look broken on first
open. This module loads a small, clearly-labelled set of realistic devices so a
new user can immediately try `camera`, `router`, `database`, `ics`, `country:TR`
and see the intent engine work. Every record is tagged session_id='demo' so it
can be wiped in one call.
"""
import random
import time
import uuid

# Realistic device fixtures whose banners/products match the intent signatures
# in intelligence/categories.py, spread across countries, with some findings/CVEs.
_DEMO_DEVICES = [
    # ── Cameras / DVR / NVR ──
    {"ip": "185.42.17.10", "port": 554, "service": "rtsp", "product": "Hikvision",
     "version": "", "banner": "RTSP/1.0 200 OK\r\nServer: Hikvision\r\nPublic: OPTIONS, DESCRIBE, PLAY",
     "country": "Turkey", "country_code": "TR", "city": "Istanbul",
     "findings": ["RTSP stream reachable without authentication"]},
    {"ip": "185.42.17.11", "port": 37777, "service": "unknown", "product": "Dahua",
     "version": "Dahua DVR", "banner": "\x20\x00\x00\x00DHIP DVR-Webs",
     "country": "Turkey", "country_code": "TR", "city": "Ankara", "findings": []},
    {"ip": "91.203.45.20", "port": 8000, "service": "http", "product": "",
     "version": "App-webs", "banner": "HTTP/1.1 200 OK\r\nServer: App-webs/\r\nContent-Type: text/html",
     "web_title": "IP Camera", "country": "Germany", "country_code": "DE", "city": "Berlin",
     "findings": []},
    {"ip": "203.0.113.45", "port": 554, "service": "rtsp", "product": "Axis",
     "version": "", "banner": "RTSP/1.0 401 Unauthorized\r\nServer: GoAhead-Webs\r\nWWW-Authenticate: Digest",
     "country": "United States", "country_code": "US", "city": "Dallas", "findings": []},
    {"ip": "78.135.22.8", "port": 88, "service": "unknown", "product": "Foscam",
     "version": "", "banner": "Server: Boa/0.94 Network Camera",
     "country": "Turkey", "country_code": "TR", "city": "Izmir",
     "findings": ["Anonymous access permitted"]},

    # ── Routers / Network gear ──
    {"ip": "212.156.88.4", "port": 8291, "service": "unknown", "product": "MikroTik",
     "version": "RouterOS 6.45", "banner": "MikroTik RouterOS",
     "country": "Turkey", "country_code": "TR", "city": "Istanbul",
     "cves": [{"id": "CVE-2018-14847", "severity": "CRITICAL", "score": 9.1,
               "description": "MikroTik RouterOS directory traversal / auth bypass"}],
     "findings": []},
    {"ip": "94.103.12.6", "port": 22, "service": "ssh", "product": "Cisco",
     "version": "Cisco SSH 1.25", "banner": "SSH-2.0-Cisco-1.25",
     "country": "Russia", "country_code": "RU", "city": "Moscow", "findings": []},
    {"ip": "188.40.77.9", "port": 80, "service": "http", "product": "TP-LINK",
     "version": "", "banner": "HTTP/1.1 200 OK\r\nServer: TP-LINK Router",
     "web_title": "TL-WR841N", "country": "Germany", "country_code": "DE", "city": "Munich",
     "findings": []},

    # ── Databases ──
    {"ip": "159.89.34.12", "port": 3306, "service": "mysql", "product": "MySQL",
     "version": "5.7.34", "banner": "5.7.34-log mysql_native_password",
     "country": "United States", "country_code": "US", "city": "New York",
     "cves": [{"id": "CVE-2012-2122", "severity": "HIGH", "score": 7.5,
               "description": "MySQL authentication bypass"}], "findings": []},
    {"ip": "46.101.55.7", "port": 27017, "service": "mongodb", "product": "MongoDB",
     "version": "3.4.2", "banner": "MongoDB ismaster",
     "country": "Netherlands", "country_code": "NL", "city": "Amsterdam",
     "findings": ["MongoDB reachable without authentication"]},
    {"ip": "212.156.90.15", "port": 6379, "service": "redis", "product": "Redis",
     "version": "5.0.7", "banner": "+PONG\r\nredis_version:5.0.7",
     "country": "Turkey", "country_code": "TR", "city": "Istanbul",
     "findings": ["Redis reachable without authentication"],
     "cves": [{"id": "CVE-2022-0543", "severity": "CRITICAL", "score": 10.0,
               "description": "Redis Lua sandbox escape"}]},
    {"ip": "104.18.22.33", "port": 9200, "service": "elasticsearch", "product": "Elasticsearch",
     "version": "1.4.2", "banner": 'HTTP/1.1 200 OK\r\n{"cluster_name":"elasticsearch"}',
     "country": "United States", "country_code": "US", "city": "San Jose",
     "cves": [{"id": "CVE-2015-1427", "severity": "CRITICAL", "score": 9.8,
               "description": "Elasticsearch Groovy RCE"}], "findings": []},

    # ── ICS / SCADA ──
    {"ip": "31.145.66.2", "port": 502, "service": "modbus", "product": "Schneider",
     "version": "Schneider Modicon", "banner": "Modbus/TCP Schneider Electric",
     "country": "Turkey", "country_code": "TR", "city": "Kocaeli",
     "findings": ["Exposed Modbus/ICS device (no native authentication)"]},
    {"ip": "77.88.21.4", "port": 102, "service": "unknown", "product": "Siemens",
     "version": "SIMATIC S7", "banner": "ISO-TSAP S7-300 SIMATIC",
     "country": "Germany", "country_code": "DE", "city": "Hamburg",
     "findings": ["Exposed ICS device"]},
    {"ip": "200.55.12.9", "port": 47808, "service": "unknown", "product": "Tridium",
     "version": "Niagara", "banner": "BACnet Tridium Niagara",
     "country": "Brazil", "country_code": "BR", "city": "Sao Paulo", "findings": []},

    # ── VoIP ──
    {"ip": "185.42.17.55", "port": 5060, "service": "sip", "product": "Asterisk",
     "version": "", "banner": "SIP/2.0 200 OK\r\nServer: Asterisk PBX 13.1",
     "country": "Turkey", "country_code": "TR", "city": "Bursa", "findings": []},
    {"ip": "62.210.11.3", "port": 5060, "service": "sip", "product": "FreeSWITCH",
     "version": "", "banner": "SIP/2.0 200 OK\r\nUser-Agent: FreeSWITCH",
     "country": "France", "country_code": "FR", "city": "Paris", "findings": []},

    # ── NAS ──
    {"ip": "94.103.12.40", "port": 5000, "service": "http", "product": "Synology",
     "version": "DSM 6.2", "banner": "HTTP/1.1 200 OK\r\nServer: nginx\r\nSynology DiskStation",
     "web_title": "Synology DiskStation", "country": "Germany", "country_code": "DE",
     "city": "Frankfurt", "findings": []},
    {"ip": "159.89.34.88", "port": 445, "service": "smb", "product": "Samba",
     "version": "", "banner": "Samba SMB QNAP",
     "country": "United States", "country_code": "US", "city": "Chicago", "findings": []},

    # ── Remote access ──
    {"ip": "212.156.88.30", "port": 3389, "service": "rdp", "product": "Microsoft Terminal Services",
     "version": "", "banner": "RDP", "country": "Turkey", "country_code": "TR", "city": "Istanbul",
     "findings": ["RDP exposed without NLA (pre-auth attack surface)"]},
    {"ip": "46.101.55.99", "port": 5900, "service": "vnc", "product": "RealVNC",
     "version": "RFB 003.008", "banner": "RFB 003.008",
     "country": "Netherlands", "country_code": "NL", "city": "Amsterdam",
     "findings": ["VNC reachable"]},

    # ── IoT / Smart home ──
    {"ip": "185.42.17.77", "port": 1883, "service": "mqtt", "product": "Mosquitto",
     "version": "1.6.9", "banner": "MQTT Mosquitto broker",
     "country": "Turkey", "country_code": "TR", "city": "Antalya",
     "findings": ["MQTT broker accepts unauthenticated connections"]},
    {"ip": "104.18.22.66", "port": 8123, "service": "http", "product": "Home Assistant",
     "version": "", "banner": "HTTP/1.1 200 OK\r\nServer: Home Assistant",
     "web_title": "Home Assistant", "country": "United States", "country_code": "US",
     "city": "Seattle", "findings": []},

    # ── Mail ──
    {"ip": "188.40.77.50", "port": 25, "service": "smtp", "product": "Postfix",
     "version": "", "banner": "220 mail.example.de ESMTP Postfix",
     "country": "Germany", "country_code": "DE", "city": "Berlin", "findings": []},
    {"ip": "212.156.90.40", "port": 25, "service": "smtp", "product": "Exim",
     "version": "4.94", "banner": "220 mail.example.tr ESMTP Exim 4.94",
     "country": "Turkey", "country_code": "TR", "city": "Istanbul",
     "cves": [{"id": "CVE-2019-10149", "severity": "CRITICAL", "score": 9.8,
               "description": "Exim RCE via crafted recipient"}], "findings": []},

    # ── Web servers ──
    {"ip": "104.18.22.10", "port": 443, "service": "https", "product": "nginx",
     "version": "1.18.0", "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
     "web_title": "Welcome", "country": "United States", "country_code": "US",
     "city": "Los Angeles", "findings": []},
    {"ip": "78.135.22.50", "port": 80, "service": "http", "product": "Apache httpd",
     "version": "2.4.49", "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49",
     "web_title": "Dashboard", "country": "Turkey", "country_code": "TR", "city": "Izmir",
     "cves": [{"id": "CVE-2021-41773", "severity": "CRITICAL", "score": 9.8,
               "description": "Apache 2.4.49 path traversal and RCE"}], "findings": []},
]


def build_demo_records() -> list[dict]:
    """Materialise the fixtures into full scan_result rows."""
    now = time.time()
    records = []
    for dev in _DEMO_DEVICES:
        rec = {
            "id": str(uuid.uuid4()),
            "scan_session_id": "demo",
            "ip": dev["ip"],
            "port": dev["port"],
            "protocol": "tcp",
            "state": "open",
            "service": dev.get("service", ""),
            "product": dev.get("product", ""),
            "version": dev.get("version", ""),
            "banner": dev.get("banner", ""),
            "os_guess": "",
            "headers": {},
            "ssl_info": {},
            "country": dev.get("country", ""),
            "country_code": dev.get("country_code", ""),
            "city": dev.get("city", ""),
            "asn": random.randint(1000, 60000),
            "as_org": dev.get("country", "") + " Telecom",
            "reverse_dns": "",
            "whois_org": "",
            "technologies": [dev["product"]] if dev.get("product") else [],
            "cms": "",
            "web_title": dev.get("web_title", ""),
            "web_server": dev.get("product", "") if dev.get("service", "").startswith("http") else "",
            "waf": "",
            "cves": dev.get("cves", []),
            "honeypot_score": 0.0,
            "findings": dev.get("findings", []),
            "deep_data": {},
            "timestamp": now - random.randint(0, 3600),
            "latency_ms": round(random.uniform(5, 120), 1),
        }
        records.append(rec)
    return records
