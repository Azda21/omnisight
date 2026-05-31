import logging
from datetime import datetime

from .query_parser import QueryParser

logger = logging.getLogger("omnisight.storage.elasticsearch")


INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "ip": {"type": "ip"},
            "port": {"type": "integer"},
            "protocol": {"type": "keyword"},
            "state": {"type": "keyword"},
            "service": {"type": "keyword"},
            "product": {"type": "keyword"},
            "version": {"type": "keyword"},
            "banner": {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 2000}}},
            "os_guess": {"type": "keyword"},
            "headers": {"type": "object", "enabled": False},
            "ssl_info": {"type": "object", "enabled": False},
            "country": {"type": "keyword"},
            "country_code": {"type": "keyword"},
            "city": {"type": "keyword"},
            "location": {"type": "geo_point"},
            "asn": {"type": "integer"},
            "as_org": {"type": "keyword"},
            "reverse_dns": {"type": "keyword"},
            "whois_org": {"type": "keyword"},
            "technologies": {"type": "keyword"},
            "cms": {"type": "keyword"},
            "web_title": {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 256}}},
            "web_server": {"type": "keyword"},
            "waf": {"type": "keyword"},
            "cves": {"type": "nested", "properties": {
                "id": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "score": {"type": "float"},
                "description": {"type": "text"},
            }},
            "honeypot_score": {"type": "float"},
            "findings": {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 256}}},
            "deep_data": {"type": "object", "enabled": False},
            "scan_session_id": {"type": "keyword"},
            "timestamp": {"type": "date", "format": "epoch_second"},
            "latency_ms": {"type": "float"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
    }
}


class ElasticStore:
    def __init__(self, hosts: list[str] = None, index_prefix: str = "omnisight"):
        self.hosts = hosts or ["http://localhost:9200"]
        self.index_prefix = index_prefix
        self._client = None
        self._query_parser = QueryParser()

    @property
    def available(self) -> bool:
        return self._client is not None

    async def connect(self):
        try:
            from elasticsearch import AsyncElasticsearch
            self._client = AsyncElasticsearch(self.hosts)
            info = await self._client.info()
            logger.info(f"Connected to Elasticsearch: {info['version']['number']}")
            await self._ensure_index()
        except Exception as e:
            logger.warning(f"Elasticsearch not available: {e}. Using fallback storage.")
            self._client = None

    async def _ensure_index(self):
        if not self._client:
            return
        index = self._get_index_name()
        exists = await self._client.indices.exists(index=index)
        if not exists:
            await self._client.indices.create(index=index, body=INDEX_MAPPING)
            logger.info(f"Created index: {index}")

    def _get_index_name(self) -> str:
        date = datetime.utcnow().strftime("%Y.%m")
        return f"{self.index_prefix}-{date}"

    async def store(self, record: dict) -> str | None:
        if not self._client:
            return None
        try:
            resp = await self._client.index(
                index=self._get_index_name(),
                id=record.get("id"),
                document=record,
            )
            return resp.get("_id")
        except Exception as e:
            logger.error(f"Failed to store record: {e}")
            return None

    async def bulk_store(self, records: list[dict]) -> int:
        if not self._client or not records:
            return 0
        actions = []
        index = self._get_index_name()
        for rec in records:
            actions.append({"index": {"_index": index, "_id": rec.get("id")}})
            actions.append(rec)
        try:
            from elasticsearch.helpers import async_bulk
            success, _ = await async_bulk(self._client, self._gen_actions(records, index))
            return success
        except Exception as e:
            logger.error(f"Bulk store failed: {e}")
            return 0

    @staticmethod
    def _gen_actions(records, index):
        for rec in records:
            yield {
                "_index": index,
                "_id": rec.get("id"),
                "_source": rec,
            }

    async def search(self, query: str, filters: dict = None, page: int = 1, size: int = 20) -> dict:
        if not self._client:
            return {"total": 0, "results": [], "page": page}

        # Reuse the shared DSL parser so ES honours the exact same query syntax
        # as the SQLite path (port:443 country:TR -service:http vuln:true ...).
        parsed = self._query_parser.parse(query or "")

        # Layer any explicit API filters onto the parsed query.
        if filters:
            for key, value in filters.items():
                if key == "country":
                    parsed.filters["country_code"] = str(value).upper()
                elif key in ("port", "service", "product", "city", "asn",
                             "country_code", "ip"):
                    parsed.filters[key] = value
                elif key == "session_id":
                    parsed.filters["scan_session_id"] = value
                elif key == "has_vuln":
                    parsed.flags["vuln"] = "true"

        es_query = self._query_parser.to_elasticsearch(parsed)

        body = {
            "query": es_query,
            "from": (page - 1) * size,
            "size": size,
            "sort": [{"timestamp": "desc"}],
        }

        try:
            resp = await self._client.search(
                index=f"{self.index_prefix}-*",
                body=body,
            )
            hits = resp.get("hits", {})
            total = hits.get("total", {}).get("value", 0)
            results = [hit["_source"] for hit in hits.get("hits", [])]
            return {"total": total, "results": results, "page": page, "pages": (total + size - 1) // size}
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return {"total": 0, "results": [], "page": page}

    async def get_stats(self) -> dict:
        if not self._client:
            return {}
        try:
            resp = await self._client.search(
                index=f"{self.index_prefix}-*",
                body={
                    "size": 0,
                    "aggs": {
                        "total_hosts": {"cardinality": {"field": "ip"}},
                        "services": {"terms": {"field": "service", "size": 20}},
                        "countries": {"terms": {"field": "country_code", "size": 20}},
                        "ports": {"terms": {"field": "port", "size": 20}},
                        "products": {"terms": {"field": "product", "size": 20}},
                        "vulnerabilities": {"nested": {"path": "cves"}, "aggs": {
                            "severity": {"terms": {"field": "cves.severity"}}
                        }},
                    }
                }
            )
            aggs = resp.get("aggregations", {})
            return {
                "total_records": resp["hits"]["total"]["value"],
                "unique_hosts": aggs.get("total_hosts", {}).get("value", 0),
                "top_services": {b["key"]: b["doc_count"] for b in aggs.get("services", {}).get("buckets", [])},
                "top_countries": {b["key"]: b["doc_count"] for b in aggs.get("countries", {}).get("buckets", [])},
                "top_ports": {b["key"]: b["doc_count"] for b in aggs.get("ports", {}).get("buckets", [])},
                "top_products": {b["key"]: b["doc_count"] for b in aggs.get("products", {}).get("buckets", [])},
            }
        except Exception as e:
            logger.error(f"Stats query failed: {e}")
            return {}

    async def close(self):
        if self._client:
            await self._client.close()
