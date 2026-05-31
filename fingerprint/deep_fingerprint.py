"""Advanced fingerprinting that survives banner stripping.

A device can hide its `Server:` header, but it cannot easily hide *how* it
negotiates TLS or *what favicon it serves*. Two techniques exploit that:

- **favicon hash** (mmh3 of the base64 favicon) — the same trick that lets you
  pivot from one Cisco/GitLab/router to every other identical deployment on the
  internet, even when every text banner is blank.
- **JARM-style TLS fingerprint** — send a handful of deliberately varied TLS
  Client Hellos and hash the pattern of the server's responses. Two servers
  running the same stack answer identically; a stripped banner doesn't change
  that. This is how you fingerprint malware C2, load balancers and appliances
  that reveal nothing in their headers.

These are the kind of fingerprints ZoomEye/Shodan expose as premium pivots;
here they run locally against what you scanned.
"""
import asyncio
import hashlib
import socket
import ssl
import struct


def favicon_hash(favicon_bytes: bytes) -> str:
    """Shodan-compatible favicon hash (mmh3 of base64), with a sha256 fallback
    when mmh3 isn't installed so the feature still produces a stable pivot key."""
    import base64
    b64 = base64.encodebytes(favicon_bytes)
    try:
        import mmh3
        return str(mmh3.hash(b64))
    except ImportError:
        return "sha256:" + hashlib.sha256(b64).hexdigest()[:16]


async def fetch_favicon_hash(ip: str, port: int, use_ssl: bool = False, timeout: float = 6.0) -> str:
    try:
        ctx = None
        if use_ssl or port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout)
        writer.write(f"GET /favicon.ico HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        data = b""
        while len(data) < 200_000:
            try:
                chunk = await asyncio.wait_for(reader.read(16384), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            data += chunk
        writer.close()
        if b"\r\n\r\n" in data:
            head, body = data.split(b"\r\n\r\n", 1)
            if b"200" in head.split(b"\r\n")[0] and body:
                return favicon_hash(body)
    except Exception:
        pass
    return ""


# A few deliberately different TLS configurations. The *pattern* of which ones
# succeed and which cipher/version the server picks is the fingerprint.
_JARM_PROBES = [
    (ssl.TLSVersion.TLSv1_2, "ALL:@SECLEVEL=0"),
    (ssl.TLSVersion.TLSv1_3, "ALL:@SECLEVEL=0"),
    (ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES128-GCM-SHA256"),
    (ssl.TLSVersion.TLSv1_2, "DEFAULT"),
]


async def jarm_fingerprint(ip: str, port: int, timeout: float = 6.0) -> str:
    """A lightweight JARM-style fingerprint: probe with several TLS configs and
    hash the (version, cipher) the server selects for each."""
    responses = []
    for min_ver, ciphers in _JARM_PROBES:
        token = await _tls_probe(ip, port, min_ver, ciphers, timeout)
        responses.append(token)
    raw = "|".join(responses)
    if raw == "|||" or all(r == "" for r in responses):
        return ""
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


async def _tls_probe(ip, port, min_ver, ciphers, timeout) -> str:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = min_ver
            ctx.maximum_version = min_ver
        except (ValueError, OSError):
            pass
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError:
            pass
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout)
        ssl_obj = writer.get_extra_info("ssl_object")
        token = ""
        if ssl_obj:
            cipher = ssl_obj.cipher()
            token = f"{ssl_obj.version()}:{cipher[0] if cipher else ''}"
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return token
    except Exception:
        return ""


async def deep_fingerprint(ip: str, port: int, service: str = "") -> dict:
    """Run the advanced fingerprints appropriate for the service."""
    result = {}
    is_tls = service == "https" or port in (443, 8443, 9443)
    is_web = service in ("http", "https") or port in (80, 443, 8080, 8443, 8000)

    if is_web:
        fav = await fetch_favicon_hash(ip, port, use_ssl=is_tls)
        if fav:
            result["favicon_hash"] = fav
    if is_tls:
        jarm = await jarm_fingerprint(ip, port)
        if jarm:
            result["jarm"] = jarm
    return result
