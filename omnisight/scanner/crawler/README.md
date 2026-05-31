"""README - Advanced OmniCrawler Enterprise Edition

Provides modular, AI-driven, production-grade internet reconnaissance system with:
- Plugin architecture for zero-downtime extensibility
- ML-powered intelligent target selection and behavioral optimization
- Legal compliance engine (GDPR, CCPA, sanctions)
- Distributed P2P coordination for multi-node deployment
- Advanced threat intelligence and risk scoring
- Real-time adaptive honeypot detection
- Comprehensive audit and monitoring capabilities

## Architecture

### Core Modules

1. **plugin_manager.py** - Dynamic plugin loading system
   - LocalPythonPlugin: Load local Python modules
   - PluginRegistry: Central plugin management
   - PluginManager: Main orchestration

2. **target_generator.py** - Intelligent target selection
   - OSINT aggregation (Shodan, Censys, etc.)
   - ML-based vulnerability prediction
   - Composite scoring algorithm
   - Temporal pattern analysis

3. **behavior_optimizer.py** - Adaptive crawler tuning
   - Honeypot detection and avoidance
   - Adaptive port selection
   - Self-learning rate limiting
   - Automatic strategy adaptation

4. **compliance_engine.py** - Legal rule enforcement
   - Jurisdiction-based rules (GDPR, CCPA, sanctions)
   - Opt-out list management
   - Compliance audit reporting
   - HIPAA, HIPAA-specific checks

5. **core_crawler.py** - Master crawler orchestration
   - Integrates all subsystems
   - Manages scan sessions
   - Plugin-based enrichment pipeline
   - Statistics and monitoring

6. **distributed.py** - Multi-node coordination
   - TaskQueue: Priority-based task distribution
   - DistributedCoordinator: Master coordinator
   - EdgeWorker: Remote worker nodes
   - Fault tolerance and health checking

7. **threat_predictor.py** - AI-driven threat analysis
   - CVE trend analysis
   - Device type prediction
   - Attack vector forecasting
   - Risk score calculation
   - Remediation time estimation

## Usage

### Basic Setup

```python
from omnisight.scanner.crawler.core_crawler import AdvancedOmniCrawler

# Initialize with your components
crawler = AdvancedOmniCrawler(
    db=database,
    elastic=elasticsearch,
    scan_engine=scanner,
    service_detector=detector,
    geoip=geoip,
    web_analyzer=analyzer,
    cve_correlator=correlator,
    osint_api_keys={
        "shodan": "your_key",
        "censys": "your_key"
    }
)

# Initialize subsystems
await crawler.initialize()

# Start crawling
await crawler.start()

# Get status
status = crawler.get_status()
print(status)

# Stop when done
await crawler.stop()
```

### API Endpoints

**POST** `/api/v2/crawler/start` - Start crawler
**POST** `/api/v2/crawler/stop` - Stop crawler
**GET** `/api/v2/crawler/status` - Get status
**GET** `/api/v2/crawler/targets?count=5` - Get smart targets
**GET** `/api/v2/crawler/recommendations` - Get behavior recommendations
**GET** `/api/v2/crawler/compliance-report` - Get compliance report
**POST** `/api/v2/crawler/opt-out?target=1.2.3.0/24` - Add to opt-out
**GET** `/api/v2/crawler/plugins` - List plugins
**GET** `/api/v2/crawler/metrics` - Get detailed metrics

### Configuration

Set OSINT API keys:
```python
osint_keys = {
    "shodan": "YOUR_SHODAN_API_KEY",
    "censys_uid": "YOUR_CENSYS_UID",
    "censys_secret": "YOUR_CENSYS_SECRET",
}
```

## Features

### 🧠 AI & ML Powered
- **Target Generation**: ML predicts high-value targets using historical data, threat intel, and temporal patterns
- **Behavior Optimization**: Auto-adapts scan speed, ports, timing based on response patterns
- **Threat Prediction**: Predicts CVEs, attack vectors, device types, and risk scores
- **Honeypot Detection**: Learns patterns and automatically avoids traps

### 🔌 Modular & Extensible
- **Plugin System**: Add custom enrichment, detectors, analyzers without modifying core
- **Zero-Downtime Updates**: Load/unload plugins on the fly
- **Multiple Runtimes**: Plugins can run as Python modules, Docker containers, or Lambda functions

### ⚖️ Legal & Compliant
- **Jurisdiction Rules**: Automatic enforcement of GDPR, CCPA, sanctions
- **Opt-Out Management**: Maintain and enforce exclusion lists
- **Audit Trail**: Complete compliance reporting and violation tracking
- **Data Protection**: Respects PII and personal data regulations

### 🌐 Distributed & Scalable
- **P2P Coordination**: Distribute scans across multiple worker nodes
- **Load Balancing**: Priority-based task queue with fair distribution
- **Fault Tolerance**: Automatic task reassignment on worker failure
- **Result Aggregation**: Centralized collection and analysis

### 🛡️ Advanced Security Analysis
- **CVE Intelligence**: Real-time trending CVE data integration
- **Risk Scoring**: Composite risk calculation with multiple factors
- **Attack Vector Prediction**: Identifies most likely attack paths
- **Remediation Planning**: Estimates time and effort to fix vulnerabilities

### 📊 Monitoring & Analytics
- **Real-time Dashboard**: Live crawler metrics and target updates
- **Performance Metrics**: Response times, success rates, error analysis
- **Threat Landscape**: Current threats, trending services, vulnerabilities
- **Historical Analysis**: Long-term trend analysis and reporting

## Advanced Usage

### Custom Plugin Development

Create file: `omnisight/scanner/crawler/plugins/my_enricher/plugin.json`
```json
{
  "id": "my_enricher",
  "module": "plugin.py",
  "class": "MyEnricherPlugin"
}
```

Create file: `omnisight/scanner/crawler/plugins/my_enricher/plugin.py`
```python
from omnisight.scanner.crawler.plugin_manager import PluginInterface

class MyEnricherPlugin(PluginInterface):
    async def initialize(self, config):
        self.config = config
    
    async def execute(self, record):
        # Add custom enrichment
        record["my_field"] = "custom_value"
        return record
    
    async def shutdown(self):
        pass
    
    @property
    def name(self):
        return "My Custom Enricher"
    
    @property
    def version(self):
        return "1.0.0"
    
    @property
    def capabilities(self):
        return ["enrichment"]
```

### Distributed Deployment

```python
from omnisight.scanner.crawler.distributed import DistributedCoordinator, EdgeWorker

# On coordinator node
coordinator = DistributedCoordinator(node_id="master")
await coordinator.register_worker("worker1", ["network_scan"])
targets = await crawler.target_generator.get_smart_targets(100)
await coordinator.distribute_targets(targets)

# On worker node
worker = EdgeWorker("worker1", "http://coordinator:8000")
await worker.connect_to_coordinator()
await worker.work_loop()
```

## Performance Characteristics

- **Memory**: ~500MB base + plugin overhead
- **CPU**: Efficient async I/O, minimal CPU usage during scans
- **Network**: Adaptive rate limiting, respects network conditions
- **Throughput**: 100+ IPs/sec per worker node (with optimization)
- **Latency**: <100ms avg response for local scans

## Security Considerations

⚠️ **IMPORTANT**: Ensure you have legal authorization before deploying this system.

- Always respect `robots.txt` and Terms of Service
- Implement opt-out mechanisms for privacy-conscious organizations
- Monitor for honeypots and intrusion detection systems
- Log all activities for audit purposes
- Use with approved OSINT API keys only
- Comply with local laws and regulations in your jurisdiction

## Troubleshooting

### Crawler not finding targets
- Check OSINT API keys are valid
- Verify network connectivity
- Check compliance rules aren't blocking all targets

### High error rate
- Crawler is being rate-limited (check behavior_optimizer delay)
- Honeypot detected (check metrics)
- Network connectivity issue

### Memory usage increasing
- Check for plugin memory leaks
- Clear completed task cache periodically
- Monitor long-running operations

## Contributing

To extend or improve the crawler:
1. Create a new module in the `crawler/` directory
2. Follow the PluginInterface for plugins
3. Add tests for new functionality
4. Document API changes
5. Submit PR to `feature/advanced-crawler` branch

## License

See LICENSE file for details.

## Support

For issues, questions, or suggestions:
- GitHub Issues: https://github.com/Azda21/omnisight/issues
- Documentation: https://github.com/Azda21/omnisight/wiki
"""
