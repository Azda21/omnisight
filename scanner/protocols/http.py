import asyncio
import ssl
import re
from dataclasses import dataclass, field


@dataclass
class HTTPResult:
    status_code: int = 0
    status_text: str = ""
    headers: dict = field(default_factory=dict)
    title: str = ""
    server: str = ""
    powered_by: str = ""
    content_type: str = ""
    body_preview: str = ""
    redirect_url: str = ""
    technologies: list = field(default_factory=list)
    favicon_hash: str = ""


class HTTPProbe:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def probe(self, ip: str, port: int, use_ssl: bool = False) -> HTTPResult:
        result = HTTPResult()
        try:
            ssl_ctx = None
            if use_ssl or port in (443, 8443, 9443):
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx),
                timeout=self.timeout,
            )

            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: OmniSight/1.0 (Security Scanner)\r\n"
                f"Accept: text/html,application/xhtml+xml,*/*\r\n"
                f"Accept-Encoding: identity\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

            writer.write(request)
            await writer.drain()

            response = b""
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(16384), timeout=self.timeout)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 1_000_000:
                        break
                except asyncio.TimeoutError:
                    break

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            decoded = response.decode("utf-8", errors="replace")
            result = self._parse_response(decoded)

        except Exception:
            pass

        return result

    def _parse_response(self, raw: str) -> HTTPResult:
        result = HTTPResult()

        if "\r\n\r\n" in raw:
            header_section, body = raw.split("\r\n\r\n", 1)
        else:
            header_section = raw
            body = ""

        lines = header_section.split("\r\n")
        if lines:
            status_match = re.match(r"HTTP/[\d.]+\s+(\d+)\s*(.*)", lines[0])
            if status_match:
                result.status_code = int(status_match.group(1))
                result.status_text = status_match.group(2)

        for line in lines[1:]:
            if ": " in line:
                key, val = line.split(": ", 1)
                result.headers[key.lower()] = val

        result.server = result.headers.get("server", "")
        result.powered_by = result.headers.get("x-powered-by", "")
        result.content_type = result.headers.get("content-type", "")
        result.redirect_url = result.headers.get("location", "")

        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if title_match:
            result.title = title_match.group(1).strip()[:200]

        result.body_preview = body[:500]
        result.technologies = self._detect_technologies(result.headers, body)

        return result

    @staticmethod
    def _detect_technologies(headers: dict, body: str) -> list[str]:
        techs = []
        server = headers.get("server", "").lower()
        powered = headers.get("x-powered-by", "").lower()
        body_lower = body.lower()

        tech_signatures = {
            "nginx": "nginx" in server,
            "Apache": "apache" in server,
            "IIS": "microsoft-iis" in server,
            "LiteSpeed": "litespeed" in server,
            "Cloudflare": "cloudflare" in server,
            "PHP": "php" in powered,
            "ASP.NET": "asp.net" in powered or "x-aspnet-version" in headers,
            "Express": "express" in powered,
            "Django": "csrfmiddlewaretoken" in body_lower,
            "WordPress": "wp-content" in body_lower or "wp-includes" in body_lower,
            "Joomla": "joomla" in body_lower or "/media/system/js" in body_lower,
            "Drupal": "drupal" in body_lower or "sites/default/files" in body_lower,
            "React": "react" in body_lower or "_reactRoot" in body,
            "Vue.js": "vue" in body_lower or "__vue__" in body,
            "Angular": "ng-version" in body_lower,
            "jQuery": "jquery" in body_lower,
            "Bootstrap": "bootstrap" in body_lower,
            "Laravel": "laravel" in body_lower or "laravel_session" in str(headers),
            "Spring": "x-application-context" in headers,
            "Tomcat": "tomcat" in server.lower() or "tomcat" in body_lower,
        }

        for name, detected in tech_signatures.items():
            if detected:
                techs.append(name)

        return techs
