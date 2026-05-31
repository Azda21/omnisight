import re
import hashlib
from dataclasses import dataclass, field


@dataclass
class WebFingerprint:
    technologies: list = field(default_factory=list)
    cms: str = ""
    framework: str = ""
    language: str = ""
    server: str = ""
    js_libraries: list = field(default_factory=list)
    css_frameworks: list = field(default_factory=list)
    analytics: list = field(default_factory=list)
    cdn: str = ""
    waf: str = ""
    favicon_hash: str = ""
    meta_generator: str = ""
    headers_fingerprint: dict = field(default_factory=dict)


class WebAnalyzer:
    CMS_SIGNATURES = {
        "WordPress": [
            r"wp-content/", r"wp-includes/", r"wp-json",
            r'<meta name="generator" content="WordPress',
        ],
        "Joomla": [
            r"/media/system/js/", r"/templates/",
            r'<meta name="generator" content="Joomla',
        ],
        "Drupal": [
            r"sites/default/files", r"drupal\.js", r"Drupal\.settings",
            r'<meta name="generator" content="Drupal',
        ],
        "Magento": [
            r"mage/cookies\.js", r"/skin/frontend/", r"Mage\.Cookies",
        ],
        "Shopify": [
            r"cdn\.shopify\.com", r"myshopify\.com",
        ],
        "Ghost": [
            r"ghost-url", r'<meta name="generator" content="Ghost',
        ],
        "Wix": [
            r"wix\.com", r"_wix_browser_sess",
        ],
        "Squarespace": [
            r"squarespace\.com", r"static\.squarespace",
        ],
    }

    FRAMEWORK_SIGNATURES = {
        "React": [r"_reactRoot", r"__REACT", r"react\.production", r"react-dom"],
        "Vue.js": [r"__vue__", r"Vue\.js", r"vue\.runtime", r"vue\.min\.js"],
        "Angular": [r"ng-version", r"ng-app", r"angular\.js", r"angular\.min"],
        "Next.js": [r"_next/", r"__NEXT_DATA__"],
        "Nuxt.js": [r"__nuxt", r"_nuxt/"],
        "Svelte": [r"svelte", r"__svelte"],
        "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
        "Django": [r"csrfmiddlewaretoken", r"django"],
        "Rails": [r"csrf-token", r"action_dispatch"],
        "Spring": [r"x-application-context", r"jsessionid"],
        "Express": [r"X-Powered-By.*Express"],
        "Flask": [r"Werkzeug"],
        "ASP.NET": [r"__VIEWSTATE", r"X-AspNet-Version", r"asp\.net"],
    }

    JS_LIB_SIGNATURES = {
        "jQuery": [r"jquery", r"jQuery"],
        "Bootstrap": [r"bootstrap\.min", r"bootstrap\.css"],
        "Tailwind CSS": [r"tailwindcss", r"tailwind\.css"],
        "Lodash": [r"lodash"],
        "Moment.js": [r"moment\.min\.js"],
        "D3.js": [r"d3\.min\.js", r"d3\.js"],
        "Chart.js": [r"chart\.min\.js"],
        "Three.js": [r"three\.min\.js"],
        "Socket.io": [r"socket\.io"],
        "Axios": [r"axios\.min\.js"],
    }

    ANALYTICS_SIGNATURES = {
        "Google Analytics": [r"google-analytics\.com", r"gtag", r"UA-\d+"],
        "Google Tag Manager": [r"googletagmanager\.com", r"GTM-"],
        "Facebook Pixel": [r"connect\.facebook\.net", r"fbq\("],
        "Hotjar": [r"hotjar\.com"],
        "Mixpanel": [r"mixpanel\.com"],
        "Segment": [r"segment\.com", r"analytics\.js"],
    }

    WAF_SIGNATURES = {
        "Cloudflare": [r"cf-ray", r"cloudflare"],
        "AWS WAF": [r"awselb", r"x-amz-"],
        "Akamai": [r"akamai", r"x-akamai"],
        "Sucuri": [r"sucuri", r"x-sucuri"],
        "Imperva": [r"incap_ses", r"visid_incap"],
        "ModSecurity": [r"mod_security", r"modsecurity"],
        "F5 BIG-IP": [r"bigip", r"f5"],
    }

    def analyze(self, headers: dict, body: str) -> WebFingerprint:
        fp = WebFingerprint()
        combined = str(headers) + body

        fp.server = headers.get("server", "")
        fp.headers_fingerprint = self._extract_security_headers(headers)

        fp.cms = self._match_category(combined, self.CMS_SIGNATURES)
        fp.framework = self._match_category(combined, self.FRAMEWORK_SIGNATURES)
        fp.waf = self._match_category(str(headers), self.WAF_SIGNATURES)

        fp.js_libraries = self._match_all(combined, self.JS_LIB_SIGNATURES)
        fp.analytics = self._match_all(combined, self.ANALYTICS_SIGNATURES)

        fp.language = self._detect_language(headers, body)
        fp.cdn = self._detect_cdn(headers)

        gen_match = re.search(r'<meta\s+name="generator"\s+content="([^"]+)"', body, re.IGNORECASE)
        if gen_match:
            fp.meta_generator = gen_match.group(1)

        fp.technologies = self._compile_tech_list(fp)

        return fp

    @staticmethod
    def _match_category(text: str, signatures: dict) -> str:
        for name, patterns in signatures.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return name
        return ""

    @staticmethod
    def _match_all(text: str, signatures: dict) -> list[str]:
        found = []
        for name, patterns in signatures.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    found.append(name)
                    break
        return found

    @staticmethod
    def _detect_language(headers: dict, body: str) -> str:
        powered = headers.get("x-powered-by", "").lower()
        if "php" in powered:
            return "PHP"
        if "asp.net" in powered:
            return "C#/ASP.NET"
        if "express" in powered:
            return "JavaScript/Node.js"
        if "servlet" in str(headers).lower() or "java" in str(headers).lower():
            return "Java"
        if "werkzeug" in str(headers).lower() or "python" in str(headers).lower():
            return "Python"
        if "ruby" in str(headers).lower():
            return "Ruby"
        return ""

    @staticmethod
    def _detect_cdn(headers: dict) -> str:
        h = str(headers).lower()
        cdns = {
            "Cloudflare": "cf-ray",
            "AWS CloudFront": "x-amz-cf",
            "Fastly": "x-fastly",
            "Akamai": "x-akamai",
            "Azure CDN": "x-azure",
            "Google Cloud CDN": "x-goog",
            "KeyCDN": "x-keycdn",
            "StackPath": "x-sp-",
        }
        for name, sig in cdns.items():
            if sig in h:
                return name
        return ""

    @staticmethod
    def _extract_security_headers(headers: dict) -> dict:
        security_headers = [
            "x-frame-options", "x-content-type-options", "x-xss-protection",
            "strict-transport-security", "content-security-policy",
            "referrer-policy", "permissions-policy", "cross-origin-opener-policy",
            "cross-origin-resource-policy",
        ]
        found = {}
        for h in security_headers:
            val = headers.get(h)
            if val:
                found[h] = val
        return found

    @staticmethod
    def _compile_tech_list(fp: WebFingerprint) -> list[str]:
        techs = []
        if fp.cms:
            techs.append(fp.cms)
        if fp.framework:
            techs.append(fp.framework)
        if fp.language:
            techs.append(fp.language)
        if fp.server:
            techs.append(fp.server)
        if fp.waf:
            techs.append(f"WAF: {fp.waf}")
        if fp.cdn:
            techs.append(f"CDN: {fp.cdn}")
        techs.extend(fp.js_libraries)
        techs.extend(fp.analytics)
        return techs

    @staticmethod
    def compute_favicon_hash(favicon_bytes: bytes) -> str:
        import base64
        b64 = base64.encodebytes(favicon_bytes)
        import mmh3
        return str(mmh3.hash(b64))
