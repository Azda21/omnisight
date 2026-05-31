"""Minimal i18n layer.

A request-scoped current language (cookie-driven) plus a `t(key)` lookup that
the Jinja templates call. Turkish is the default; an EN/TR toggle in the nav
flips the cookie. Keys fall back to Turkish, then to the key itself, so a
missing translation degrades gracefully instead of crashing a page.
"""
from contextvars import ContextVar

_current_lang: ContextVar[str] = ContextVar("lang", default="tr")

SUPPORTED = ("tr", "en")


def set_lang(lang: str) -> None:
    _current_lang.set(lang if lang in SUPPORTED else "tr")


def get_lang() -> str:
    return _current_lang.get()


TRANSLATIONS: dict[str, dict[str, str]] = {
    # ── Navigation ──
    "nav.dashboard": {"tr": "Panel", "en": "Dashboard"},
    "nav.search": {"tr": "Arama", "en": "Search"},
    "nav.diff": {"tr": "Karşılaştır", "en": "Diff"},
    "nav.monitor": {"tr": "İzleme", "en": "Monitor"},
    "nav.stats": {"tr": "İstatistik", "en": "Statistics"},
    "nav.api": {"tr": "API", "en": "API"},
    "nav.new_scan": {"tr": "Yeni Tarama", "en": "New Scan"},

    # ── Home ──
    "home.subtitle": {"tr": "Gelişmiş Ağ İstihbarat Platformu", "en": "Advanced Network Intelligence Platform"},
    "home.search_ph": {"tr": "Bir cihaz yaz: kamera, router, veritabanı, yazıcı...",
                       "en": "Type a device: camera, router, database, printer..."},
    "mode.easy": {"tr": "Kolay", "en": "Easy"},
    "mode.advanced": {"tr": "Gelişmiş", "en": "Advanced"},
    "btn.search": {"tr": "Ara", "en": "Search"},
    "home.recent_scans": {"tr": "Son Taramalar", "en": "Recent Scans"},
    "home.no_data_title": {"tr": "Henüz veri yok", "en": "No data yet"},
    "home.seed_demo": {"tr": "Örnek Veri Yükle", "en": "Load Demo Data"},
    "home.real_scan": {"tr": "Gerçek Tarama Başlat", "en": "Start Real Scan"},

    # ── Stats labels ──
    "stat.total_records": {"tr": "Toplam Kayıt", "en": "Total Records"},
    "stat.unique_hosts": {"tr": "Benzersiz Cihaz", "en": "Unique Hosts"},
    "stat.services": {"tr": "Tespit Edilen Servis", "en": "Services Detected"},
    "stat.countries": {"tr": "Ülke", "en": "Countries"},
    "stat.top_services": {"tr": "En Çok Servis", "en": "Top Services"},
    "stat.top_ports": {"tr": "En Çok Port", "en": "Top Ports"},

    # ── Search page ──
    "search.results_found": {"tr": "sonuç bulundu", "en": "results found"},
    "search.page": {"tr": "Sayfa", "en": "Page"},
    "search.of": {"tr": "/", "en": "of"},
    "search.no_results": {"tr": "Sonuç yok. Farklı bir sorgu dene veya yeni tarama başlat.",
                          "en": "No results found. Try a different query or start a new scan."},
    "search.showing": {"tr": "Gösterilen:", "en": "Showing"},
    "search.prev": {"tr": "Önceki", "en": "Previous"},
    "search.next": {"tr": "Sonraki", "en": "Next"},

    # ── Detail page ──
    "detail.location": {"tr": "Konum", "en": "Location"},
    "detail.network": {"tr": "Ağ", "en": "Network"},
    "detail.open_ports": {"tr": "Açık Portlar", "en": "Open Ports"},
    "detail.how_connect": {"tr": "Nasıl Bağlanılır", "en": "How to Connect"},
    "detail.technologies": {"tr": "Teknolojiler", "en": "Technologies"},
    "detail.vulns": {"tr": "Olası Zafiyetler", "en": "Potential Vulnerabilities"},

    # ── Scan modal ──
    "scan.title": {"tr": "Yeni Tarama", "en": "New Scan"},
    "scan.target": {"tr": "Hedef (IP, CIDR, aralık)", "en": "Target (IP, CIDR, range)"},
    "scan.ports": {"tr": "Portlar", "en": "Ports"},
    "scan.protocol": {"tr": "Protokol", "en": "Protocol"},
    "scan.mode": {"tr": "Tarama Modu", "en": "Scan Mode"},
    "scan.name": {"tr": "Tarama Adı", "en": "Scan Name"},
    "scan.presets": {"tr": "Cihaz Hazır Ayarları", "en": "Device Presets"},
    "scan.presets_hint": {"tr": "(doğru portları senin için doldurur)", "en": "(fills the right ports for you)"},
    "scan.start": {"tr": "Taramayı Başlat", "en": "Start Scan"},
    "scan.optional": {"tr": "İsteğe bağlı", "en": "Optional"},

    # ── Diff ──
    "diff.title": {"tr": "Tarama Karşılaştırma", "en": "Scan Diff"},
    "diff.opened": {"tr": "Açılan Port", "en": "Ports Opened"},
    "diff.closed": {"tr": "Kapanan Port", "en": "Ports Closed"},
    "diff.changed": {"tr": "Değişen Servis", "en": "Services Changed"},
    "diff.new_findings": {"tr": "Yeni Bulgu", "en": "New Findings"},
    "diff.new_cves": {"tr": "Yeni CVE", "en": "New CVEs"},
    "diff.resolved": {"tr": "Çözülen", "en": "Resolved"},

    # ── Monitor ──
    "monitor.title": {"tr": "Sürekli İzleme", "en": "Continuous Monitoring"},
    "monitor.new": {"tr": "Yeni İzleyici", "en": "New Monitor"},
    "monitor.active": {"tr": "Aktif İzleyiciler", "en": "Active Monitors"},
}


def t(key: str) -> str:
    lang = get_lang()
    entry = TRANSLATIONS.get(key)
    if not entry:
        return key
    return entry.get(lang) or entry.get("tr") or key
