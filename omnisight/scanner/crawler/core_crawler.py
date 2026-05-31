"""Core Advanced OmniCrawler - Enhanced with plugins, ML, and compliance.

Extends the basic crawler with:
- Plugin management system
- Advanced target generation
- Behavior optimization
- Legal compliance
- Multi-threaded distributed scanning
"""

import asyncio
import logging
import time
from typing import Optional, List, Dict, Any
from pathlib import Path

from ..engine import ScanEngine
from .plugin_manager import PluginManager
from .target_generator import AdvancedTargetGenerator
from .behavior_optimizer import BehaviorOptimizer
from .compliance_engine import LegalComplianceEngine, LegalJurisdiction

logger = logging.getLogger("omnisight.scanner.crawler.core_crawler")


class AdvancedOmniCrawler:
    """Advanced crawler with full enterprise features."""

    def __init__(
        self,
        db,
        elastic,
        scan_engine: ScanEngine,
        service_detector,
        geoip,
        web_analyzer,
        cve_correlator,
        osint_api_keys: Dict[str, str] = None,
    ):
        # Core components
        self.db = db
        self.elastic = elastic
        self.scan_engine = scan_engine
        self.service_detector = service_detector
        self.geoip = geoip
        self.web_analyzer = web_analyzer
        self.cve_correlator = cve_correlator

        # Advanced components
        self.plugin_manager = PluginManager()
        self.target_generator = AdvancedTargetGenerator(osint_api_keys)
        self.behavior_optimizer = BehaviorOptimizer()
        self.compliance_engine = LegalComplianceEngine()

        # State
        self.running = False
        self.task: Optional[asyncio.Task] = None

        # Statistics
        self.stats = {
            "ips_scanned": 0,
            "devices_found": 0,
            "vulnerabilities_found": 0,
            "honeypots_detected": 0,
            "compliance_violations": 0,
            "start_time": 0.0,
            "current_target": "",
            "scan_sessions": 0,
        }

    async def initialize(self, plugins_config_path: Optional[Path] = None) -> None:
        """Initialize all subsystems."""
        logger.info("Initializing Advanced OmniCrawler...")

        # Load plugin configuration
        if plugins_config_path and plugins_config_path.exists():
            await self.plugin_manager.load_config(plugins_config_path)

        # Auto-discover plugins
        await self.plugin_manager.auto_discover_plugins()

        logger.info("Advanced OmniCrawler initialized successfully")

    async def start(self) -> None:
        """Start the crawler."""
        if self.running:
            logger.warning("Crawler already running")
            return

        self.running = True
        self.stats["start_time"] = time.time()
        self.task = asyncio.create_task(self._crawl_loop())
        logger.info("Advanced OmniCrawler started")

    async def stop(self) -> None:
        """Stop the crawler."""
        if not self.running:
            return

        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        await self.plugin_manager.shutdown()
        logger.info("Advanced OmniCrawler stopped")

    async def _crawl_loop(self) -> None:
        """Main crawling loop."""
        while self.running:
            try:
                # Get intelligently selected targets
                targets = await self.target_generator.get_smart_targets(count=1)

                for target_info in targets:
                    if not self.running:
                        break

                    target_cidr = target_info["cidr"]
                    self.stats["current_target"] = target_cidr

                    # Check compliance
                    compliance_check = await self.compliance_engine.check_target(
                        target_cidr, LegalJurisdiction.US
                    )

                    if not compliance_check["allowed"]:
                        logger.warning(
                            f"Target blocked by compliance: {target_cidr} - "
                            f"{compliance_check['violations']}"
                        )
                        self.stats["compliance_violations"] += 1
                        continue

                    # Get adaptive ports
                    ports = await self.behavior_optimizer.get_recommended_ports()
                    ports_str = ",".join(map(str, ports))

                    logger.info(f"Scanning target: {target_cidr} (score: {target_info['score']:.2f})")

                    try:
                        # Perform scan
                        results = await self.scan_engine.scan(
                            targets=target_cidr,
                            ports=ports_str,
                            protocol="tcp",
                            scan_mode="auto",
                        )

                        self.stats["ips_scanned"] += 256

                        # Process results
                        for result in results:
                            self.stats["devices_found"] += 1

                            # Prepare record
                            record = result.to_dict() if hasattr(result, "to_dict") else result

                            # Call plugins for enrichment
                            enriched = await self.plugin_manager.call_plugins_by_capability(
                                "enrichment", record
                            )

                            # Merge plugin results
                            for enrichment in enriched:
                                if enrichment.get("result"):
                                    record.update(enrichment["result"])

                            # Save to database
                            await self.db.save_result(record)

                            # Save to Elasticsearch
                            if self.elastic and self.elastic.available:
                                await self.elastic.store(record)

                            # Record for behavior optimization
                            await self.behavior_optimizer.record_scan_result(
                                target_cidr.split("/")[0],
                                result.port if hasattr(result, "port") else 0,
                                {
                                    "success": True,
                                    "response_time": 0,
                                    "service": result.service if hasattr(result, "service") else None,
                                },
                            )

                        # Get adaptive delay
                        delay = await self.behavior_optimizer.get_delay()
                        await asyncio.sleep(delay)

                    except Exception as e:
                        logger.error(f"Scan error on {target_cidr}: {e}")
                        await self.behavior_optimizer.record_scan_result(
                            target_cidr.split("/")[0],
                            0,
                            {"success": False, "response_time": 0, "error": str(e)},
                        )
                        await asyncio.sleep(5)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Crawler loop error: {e}")
                await asyncio.sleep(5)

    def get_status(self) -> Dict[str, Any]:
        """Get crawler status."""
        uptime = time.time() - self.stats["start_time"] if self.running else 0
        speed = self.stats["ips_scanned"] / uptime if uptime > 0 else 0

        return {
            "running": self.running,
            "stats": self.stats,
            "uptime_seconds": uptime,
            "ips_per_second": round(speed, 2),
            "target_score_info": {
                "top_targets": self.target_generator.target_history,
            },
            "behavior": self.behavior_optimizer.get_metrics(),
            "plugins_loaded": len(self.plugin_manager.get_plugins_info()),
        }

    async def get_compliance_report(self) -> Dict[str, Any]:
        """Get compliance audit report."""
        return await self.compliance_engine.generate_compliance_report()

    async def add_to_opt_out(self, target: str) -> None:
        """Add target to compliance opt-out list."""
        self.compliance_engine.add_to_opt_out(target)

    async def get_behavior_recommendations(self) -> Dict[str, Any]:
        """Get AI-driven behavior adaptation recommendations."""
        return await self.behavior_optimizer.adapt_strategy()
