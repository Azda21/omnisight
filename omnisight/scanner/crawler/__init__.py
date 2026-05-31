"""Advanced OmniCrawler - Modular, AI-driven network reconnaissance system.

Features:
- Plug-and-play plugin architecture
- ML-based behavior optimization
- Distributed P2P coordination
- Legal/compliance rule engine
- Real-time threat prediction
- Multi-modal device enrichment
- Active defense feedback integration
"""

from .core_crawler import OmniCrawler
from .plugin_manager import PluginManager
from .target_generator import AdvancedTargetGenerator
from .behavior_optimizer import BehaviorOptimizer

__all__ = [
    "OmniCrawler",
    "PluginManager",
    "AdvancedTargetGenerator",
    "BehaviorOptimizer",
]

__version__ = "2.0.0"
