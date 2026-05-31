import re
import shlex
from dataclasses import dataclass, field

from ..intelligence.categories import (
    SearchIntelligence, detect_categories, CATEGORIES,
)


@dataclass
class ParsedQuery:
    """A search query decomposed into structured filters and free text.

    The dashboard advertises a Shodan/ZoomEye-style filter syntax
    (`port:443 country:TR product:nginx vuln:true "exact phrase"`). That promise
    is only real if the backend actually parses it instead of treating the whole
    string as a substring match — this is what does that.
    """
    text_terms: list = field(default_factory=list)   # free-text, AND-ed
    filters: dict = field(default_factory=dict)        # field -> value
    negations: dict = field(default_factory=dict)      # field -> value to exclude
    flags: dict = field(default_factory=dict)          # boolean toggles (vuln, ssl)
    categories: list = field(default_factory=list)     # intent categories (camera, db...)

    @property
    def free_text(self) -> str:
        return " ".join(self.text_terms)


# Maps a user-facing filter key to the canonical storage column it queries.
FIELD_ALIASES = {
    "port": "port",
    "service": "service",
    "svc": "service",
    "product": "product",
    "app": "product",
    "version": "version",
    "country": "country_code",
    "cc": "country_code",
    "city": "city",
    "asn": "asn",
    "as": "asn",
    "org": "as_org",
    "ip": "ip",
    "host": "reverse_dns",
    "hostname": "reverse_dns",
    "os": "os_guess",
    "title": "web_title",
    "server": "web_server",
    "tech": "technologies",
    "cms": "cms",
    "waf": "waf",
}

# Boolean / special filters handled outside a simple column equality.
FLAG_FIELDS = {"vuln", "ssl", "honeypot", "anon"}


class QueryParser:
    _TOKEN_RE = re.compile(r'(-?)(\w+):(.+)')

    def __init__(self):
        self._intel = SearchIntelligence()

    def parse(self, raw: str) -> ParsedQuery:
        result = ParsedQuery()
        if not raw or not raw.strip():
            return result

        try:
            tokens = shlex.split(raw)
        except ValueError:
            # Unbalanced quotes — fall back to whitespace split.
            tokens = raw.split()

        for token in tokens:
            match = self._TOKEN_RE.match(token)
            if not match:
                result.text_terms.append(token)
                continue

            neg, key, value = match.group(1), match.group(2).lower(), match.group(3)
            value = value.strip('"\'')

            # Explicit category filter: cat:camera / category:database
            if key in ("cat", "category"):
                if value.lower() in CATEGORIES:
                    result.categories.append(value.lower())
                continue

            if key in FLAG_FIELDS:
                result.flags[key] = value.lower()
                continue

            column = FIELD_ALIASES.get(key)
            if column is None:
                result.text_terms.append(token)
                continue

            if key in ("country", "cc"):
                value = value.upper()
            if column in ("port", "asn"):
                try:
                    value = int(value)
                except ValueError:
                    result.text_terms.append(token)
                    continue

            if neg == "-":
                result.negations[column] = value
            else:
                result.filters[column] = value

        # Intent detection: a bare word like "camera" becomes a category
        # expansion instead of a literal substring match. Pull the trigger word
        # out of the free text so the broad OR-expansion isn't narrowed by an
        # AND on the literal word.
        if result.text_terms:
            detected = detect_categories(" ".join(result.text_terms))
            if detected:
                trigger_words = set()
                for key in detected:
                    if key not in result.categories:
                        result.categories.append(key)
                    trigger_words.update(a.lower() for a in CATEGORIES[key].aliases)
                result.text_terms = [
                    t for t in result.text_terms if t.lower() not in trigger_words
                ]

        return result

    def to_sql(self, parsed: ParsedQuery) -> tuple[str, list]:
        """Render a parsed query into a parameterised SQL WHERE clause."""
        clauses: list[str] = []
        params: list = []

        # Intent expansion — each category becomes a broad OR group, AND-ed in.
        for cat_key in parsed.categories:
            frag, frag_params = self._intel.expand_to_sql(cat_key)
            if frag:
                clauses.append(frag)
                params.extend(frag_params)

        for term in parsed.text_terms:
            clauses.append(
                "(ip LIKE ? OR banner LIKE ? OR service LIKE ? OR product LIKE ? "
                "OR as_org LIKE ? OR city LIKE ? OR data_json LIKE ?)"
            )
            like = f"%{term}%"
            params.extend([like] * 7)

        for column, value in parsed.filters.items():
            if column == "technologies":
                clauses.append("data_json LIKE ?")
                params.append(f"%{value}%")
            else:
                clauses.append(f"{column} = ?")
                params.append(value)

        for column, value in parsed.negations.items():
            clauses.append(f"({column} IS NULL OR {column} != ?)")
            params.append(value)

        # Flag filters lean on the JSON blob where structured findings live.
        if parsed.flags.get("vuln") in ("true", "1", "yes"):
            clauses.append("data_json LIKE ?")
            params.append('%"cves": [{%')
        if parsed.flags.get("ssl") == "weak":
            clauses.append("data_json LIKE ?")
            params.append('%weak_cipher%')
        if parsed.flags.get("honeypot") in ("true", "1", "yes"):
            clauses.append("CAST(json_extract(data_json, '$.honeypot_score') AS REAL) > 0.6")
        if parsed.flags.get("anon") in ("true", "1", "yes"):
            clauses.append("data_json LIKE ?")
            params.append('%nonymous%')

        where = " AND ".join(clauses) if clauses else "1=1"
        return where, params

    def to_elasticsearch(self, parsed: ParsedQuery) -> dict:
        """Render a parsed query into an Elasticsearch bool query.

        Same DSL, two backends: SQLite for the embedded/offline path, ES for
        scale. Keeping both behind one parser means a query behaves identically
        whichever store is live."""
        must: list = []
        must_not: list = []
        filt: list = []

        # Intent expansion — each category is a should-group required via filter.
        for cat_key in parsed.categories:
            frag = self._intel.expand_to_es(cat_key)
            if frag:
                filt.append(frag)

        for term in parsed.text_terms:
            must.append({
                "multi_match": {
                    "query": term,
                    "fields": [
                        "ip", "banner", "service", "product", "version",
                        "web_title", "technologies", "country", "city",
                        "as_org", "reverse_dns", "os_guess", "findings",
                    ],
                    "type": "best_fields",
                }
            })

        # Map storage columns back to ES field names (they mostly match).
        es_field = {"country_code": "country_code", "as_org": "as_org",
                    "reverse_dns": "reverse_dns", "web_title": "web_title",
                    "web_server": "web_server"}

        for column, value in parsed.filters.items():
            field = es_field.get(column, column)
            if column in ("technologies",):
                filt.append({"term": {"technologies": value}})
            elif column in ("web_title",):
                must.append({"match": {"web_title": value}})
            else:
                filt.append({"term": {field: value}})

        for column, value in parsed.negations.items():
            must_not.append({"term": {es_field.get(column, column): value}})

        if parsed.flags.get("vuln") in ("true", "1", "yes"):
            filt.append({"nested": {"path": "cves",
                                    "query": {"exists": {"field": "cves.id"}}}})
        if parsed.flags.get("ssl") == "weak":
            must.append({"match": {"ssl_info": "weak"}})
        if parsed.flags.get("honeypot") in ("true", "1", "yes"):
            filt.append({"range": {"honeypot_score": {"gt": 0.6}}})
        if parsed.flags.get("anon") in ("true", "1", "yes"):
            must.append({"match": {"findings": "anonymous"}})

        if not (must or must_not or filt):
            return {"match_all": {}}

        return {"bool": {
            "must": must or [{"match_all": {}}],
            "must_not": must_not,
            "filter": filt,
        }}
