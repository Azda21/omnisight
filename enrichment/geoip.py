import logging
from dataclasses import dataclass

logger = logging.getLogger("omnisight.enrichment.geoip")


@dataclass
class GeoIPInfo:
    ip: str = ""
    country: str = ""
    country_code: str = ""
    city: str = ""
    region: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""
    asn: int = 0
    as_org: str = ""
    isp: str = ""


class GeoIPEnricher:
    def __init__(self, city_db_path: str = None, asn_db_path: str = None):
        self._city_reader = None
        self._asn_reader = None
        try:
            import geoip2.database
            if city_db_path:
                self._city_reader = geoip2.database.Reader(city_db_path)
            if asn_db_path:
                self._asn_reader = geoip2.database.Reader(asn_db_path)
        except Exception as e:
            logger.warning(f"GeoIP databases not loaded: {e}")

    def lookup(self, ip: str) -> GeoIPInfo:
        info = GeoIPInfo(ip=ip)

        if self._city_reader:
            try:
                resp = self._city_reader.city(ip)
                info.country = resp.country.name or ""
                info.country_code = resp.country.iso_code or ""
                info.city = resp.city.name or ""
                info.region = resp.subdivisions.most_specific.name if resp.subdivisions else ""
                info.latitude = resp.location.latitude or 0.0
                info.longitude = resp.location.longitude or 0.0
                info.timezone = resp.location.time_zone or ""
            except Exception:
                pass

        if self._asn_reader:
            try:
                resp = self._asn_reader.asn(ip)
                info.asn = resp.autonomous_system_number or 0
                info.as_org = resp.autonomous_system_organization or ""
            except Exception:
                pass

        return info

    def close(self):
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()
