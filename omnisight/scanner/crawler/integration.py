"""Configuration and Integration Guide for Advanced OmniCrawler

This file demonstrates how to integrate the advanced crawler into your main application.
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional

from omnisight.scanner.crawler.core_crawler import AdvancedOmniCrawler
from omnisight.scanner.crawler.distributed import DistributedCoordinator
from omnisight.scanner.crawler.threat_predictor import ThreatPredictor

logger = logging.getLogger(__name__)


class CrawlerService:
    """Service wrapper for advanced crawler operations."""

    def __init__(
        self,
        db,
        elastic,
        scan_engine,
        service_detector,
        geoip,
        web_analyzer,
        cve_correlator,
        osint_api_keys: Optional[dict] = None,
        node_id: str = "master",
    ):
        """Initialize crawler service."""
        self.crawler = AdvancedOmniCrawler(
            db=db,
            elastic=elastic,
            scan_engine=scan_engine,
            service_detector=service_detector,
            geoip=geoip,
            web_analyzer=web_analyzer,
            cve_correlator=cve_correlator,
            osint_api_keys=osint_api_keys or {},
        )

        self.coordinator = DistributedCoordinator(node_id=node_id)
        self.threat_predictor = ThreatPredictor()
        self._initialized = False

    async def initialize(self, plugins_config: Optional[Path] = None) -> None:
        """Initialize all subsystems."""
        logger.info("Initializing crawler service...")

        # Initialize crawler with plugins
        await self.crawler.initialize(plugins_config)

        self._initialized = True
        logger.info("Crawler service initialized successfully")

    async def start(self) -> None:
        """Start all services."""
        if not self._initialized:
            raise RuntimeError("Service not initialized. Call initialize() first.")

        await self.crawler.start()
        logger.info("Crawler service started")

    async def stop(self) -> None:
        """Stop all services."""
        await self.crawler.stop()
        logger.info("Crawler service stopped")

    def get_crawler(self) -> AdvancedOmniCrawler:
        """Get crawler instance."""
        return self.crawler

    def get_coordinator(self) -> DistributedCoordinator:
        """Get coordinator instance."""
        return self.coordinator

    def get_threat_predictor(self) -> ThreatPredictor:
        """Get threat predictor instance."""
        return self.threat_predictor


# Example integration in your main app.py
async def example_integration():
    """Example of how to integrate into main application."""
    
    # Assuming you have these from your existing setup
    from omnisight.storage.database import Database
    from omnisight.storage.elasticsearch_store import ElasticStore
    from omnisight.scanner.engine import ScanEngine

    # Initialize database and other components
    db = Database()
    elastic = ElasticStore()
    scanner = ScanEngine()
    # ... other components

    # Create crawler service
    crawler_service = CrawlerService(
        db=db,
        elastic=elastic,
        scan_engine=scanner,
        service_detector=None,  # Your detector
        geoip=None,  # Your geoip
        web_analyzer=None,  # Your analyzer
        cve_correlator=None,  # Your correlator
        osint_api_keys={
            "shodan": "YOUR_SHODAN_KEY",
            "censys_uid": "YOUR_CENSYS_UID",
            "censys_secret": "YOUR_CENSYS_SECRET",
        },
    )

    # Initialize
    config_path = Path("config/crawler_plugins.json")
    await crawler_service.initialize(config_path)

    # Start crawling
    await crawler_service.start()

    # Monitor for a while
    for _ in range(60):
        status = crawler_service.get_crawler().get_status()
        logger.info(f"Crawler status: {status}")
        await asyncio.sleep(1)

    # Stop
    await crawler_service.stop()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(example_integration())
