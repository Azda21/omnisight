import yaml
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class ScannerConfig:
    max_concurrent: int = 500
    timeout: int = 5
    retries: int = 2
    rate_limit: int = 1000
    default_ports: dict = field(default_factory=lambda: {
        "tcp": "21-23,25,53,80,110,443,993,3306,3389,5432,8080,8443",
        "udp": "53,67,123,161,500,514"
    })
    protocols: list = field(default_factory=lambda: ["http", "ssh", "ftp", "smtp", "mysql"])


@dataclass
class StorageConfig:
    elasticsearch_hosts: list = field(default_factory=lambda: ["http://localhost:9200"])
    index_prefix: str = "omnisight"
    database_url: str = "sqlite+aiosqlite:///data/omnisight.db"


@dataclass
class APIConfig:
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    secret_key: str = "change-me-in-production"


class Config:
    def __init__(self, config_path: str = None):
        self.raw = {}
        if config_path:
            path = Path(config_path)
            if path.exists():
                with open(path) as f:
                    self.raw = yaml.safe_load(f) or {}

        scanner_data = self.raw.get("scanner", {})
        defaults = ScannerConfig()
        self.scanner = ScannerConfig(
            max_concurrent=scanner_data.get("max_concurrent", 500),
            timeout=scanner_data.get("timeout", 5),
            retries=scanner_data.get("retries", 2),
            rate_limit=scanner_data.get("rate_limit", 1000),
            default_ports=scanner_data.get("default_ports", defaults.default_ports),
            protocols=scanner_data.get("protocols", defaults.protocols),
        )

        storage_data = self.raw.get("storage", {})
        es_data = storage_data.get("elasticsearch", {})
        db_data = storage_data.get("database", {})
        self.storage = StorageConfig(
            elasticsearch_hosts=es_data.get("hosts", ["http://localhost:9200"]),
            index_prefix=es_data.get("index_prefix", "omnisight"),
            database_url=db_data.get("url", "sqlite+aiosqlite:///data/omnisight.db"),
        )

        api_data = self.raw.get("api", {})
        self.api = APIConfig(
            host=api_data.get("host", "0.0.0.0"),
            port=api_data.get("port", 8000),
            debug=api_data.get("debug", False),
            secret_key=api_data.get("secret_key", "change-me-in-production"),
        )

    @classmethod
    def load(cls, path: str = None) -> "Config":
        if path is None:
            candidates = [
                Path("config/default.yaml"),
                Path("config.yaml"),
                Path.home() / ".omnisight" / "config.yaml",
            ]
            for c in candidates:
                if c.exists():
                    return cls(str(c))
            return cls()
        return cls(path)
