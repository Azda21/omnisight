import re
from dataclasses import dataclass, field


@dataclass
class ServiceInfo:
    name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    os_type: str = ""
    device_type: str = ""
    cpe: str = ""
    confidence: float = 0.0


class ServiceDetector:
    SIGNATURES = [
        # SSH
        (r"SSH-[\d.]+-OpenSSH[_\s]*([\d.p]+)", "ssh", "OpenSSH", 1),
        (r"SSH-[\d.]+-dropbear[_\s]*([\d.]+)?", "ssh", "Dropbear", 1),
        (r"SSH-[\d.]+-libssh[_\s]*([\d.]+)?", "ssh", "libssh", 1),
        (r"SSH-[\d.]+-Cisco[_\s]*([\d.]+)?", "ssh", "Cisco SSH", 1),

        # HTTP
        (r"HTTP/[\d.]+\s+\d+", "http", "", 3),
        (r"nginx/([\d.]+)", "http", "nginx", 2),
        (r"Apache/([\d.]+)", "http", "Apache httpd", 2),
        (r"Microsoft-IIS/([\d.]+)", "http", "Microsoft IIS", 2),
        (r"LiteSpeed", "http", "LiteSpeed", 2),
        (r"lighttpd/([\d.]+)", "http", "lighttpd", 2),
        (r"cloudflare", "http", "Cloudflare", 2),

        # FTP
        (r"220.*vsftpd\s+([\d.]+)", "ftp", "vsftpd", 1),
        (r"220.*ProFTPD\s+([\d.]+)", "ftp", "ProFTPD", 1),
        (r"220.*Pure-FTPd", "ftp", "Pure-FTPd", 1),
        (r"220.*FileZilla Server\s+([\d.]+)", "ftp", "FileZilla Server", 1),
        (r"220.*Microsoft FTP", "ftp", "Microsoft FTP", 1),

        # SMTP
        (r"220.*Postfix", "smtp", "Postfix", 1),
        (r"220.*Exim\s*([\d.]+)?", "smtp", "Exim", 1),
        (r"220.*Sendmail", "smtp", "Sendmail", 1),
        (r"220.*Microsoft ESMTP", "smtp", "Microsoft Exchange", 1),

        # MySQL / MariaDB
        (r"([\d.]+)-MariaDB", "mysql", "MariaDB", 1),
        (r"mysql", "mysql", "MySQL", 3),

        # PostgreSQL
        (r"PostgreSQL", "postgresql", "PostgreSQL", 2),

        # Redis
        (r"\+PONG", "redis", "Redis", 1),
        (r"redis_version:([\d.]+)", "redis", "Redis", 1),

        # MongoDB
        (r"MongoDB", "mongodb", "MongoDB", 2),
        (r"ismaster", "mongodb", "MongoDB", 3),

        # Elasticsearch
        (r"elasticsearch", "elasticsearch", "Elasticsearch", 2),
        (r'"cluster_name"', "elasticsearch", "Elasticsearch", 2),

        # RDP
        (r"\x03\x00", "rdp", "RDP", 3),

        # VNC
        (r"RFB\s+([\d.]+)", "vnc", "VNC", 1),

        # MQTT
        (r"MQTT", "mqtt", "MQTT Broker", 2),

        # Telnet
        (r"\xff[\xfb\xfc\xfd\xfe]", "telnet", "Telnet", 2),

        # DNS
        (r"BIND\s+([\d.]+)", "dns", "BIND", 1),
    ]

    def detect(self, banner: str, port: int = 0) -> ServiceInfo:
        best = ServiceInfo()
        best_confidence = 0

        for pattern, service, product, priority in self.SIGNATURES:
            try:
                match = re.search(pattern, banner, re.IGNORECASE | re.DOTALL)
            except re.error:
                continue

            if match:
                confidence = (4 - priority) / 3.0
                if confidence > best_confidence:
                    best_confidence = confidence
                    best.name = service
                    best.product = product
                    best.confidence = confidence
                    if match.lastindex and match.lastindex >= 1:
                        best.version = match.group(1)

        if not best.name and port:
            best = self._guess_by_port(port)

        return best

    @staticmethod
    def _guess_by_port(port: int) -> ServiceInfo:
        port_services = {
            21: ("ftp", "FTP"),
            22: ("ssh", "SSH"),
            23: ("telnet", "Telnet"),
            25: ("smtp", "SMTP"),
            53: ("dns", "DNS"),
            80: ("http", "HTTP"),
            110: ("pop3", "POP3"),
            143: ("imap", "IMAP"),
            443: ("https", "HTTPS"),
            445: ("smb", "SMB"),
            993: ("imaps", "IMAPS"),
            995: ("pop3s", "POP3S"),
            1433: ("mssql", "MSSQL"),
            1883: ("mqtt", "MQTT"),
            3306: ("mysql", "MySQL"),
            3389: ("rdp", "RDP"),
            5432: ("postgresql", "PostgreSQL"),
            5672: ("amqp", "AMQP"),
            5900: ("vnc", "VNC"),
            6379: ("redis", "Redis"),
            8080: ("http-proxy", "HTTP Proxy"),
            8443: ("https-alt", "HTTPS Alt"),
            9200: ("elasticsearch", "Elasticsearch"),
            27017: ("mongodb", "MongoDB"),
            502: ("modbus", "Modbus"),
            554: ("rtsp", "RTSP"),
            5060: ("sip", "SIP"),
        }
        info = ServiceInfo()
        if port in port_services:
            info.name, info.product = port_services[port]
            info.confidence = 0.3
        return info
