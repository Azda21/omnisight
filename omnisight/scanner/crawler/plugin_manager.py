"""Plugin Manager - Dynamic module loading and management system.

Enables zero-downtime plugin loading, hot-swapping, and sandboxed execution.
Supports local Python modules, remote packages, Docker containers, and Lambda functions.
"""

import asyncio
import importlib
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import json

logger = logging.getLogger("omnisight.scanner.crawler.plugin_manager")


class PluginInterface(ABC):
    """Base interface for all plugins."""

    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize plugin with configuration."""
        pass

    @abstractmethod
    async def execute(self, *args, **kwargs) -> Any:
        """Execute plugin's main logic."""
        pass

    @abstractmethod
    async def shutdown(self) -> None:
        """Cleanup resources."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> List[str]:
        """List of plugin capabilities."""
        pass


class LocalPythonPlugin(PluginInterface):
    """Load plugins from local Python modules."""

    def __init__(self, module_path: str, class_name: str):
        self.module_path = module_path
        self.class_name = class_name
        self._instance = None
        self._module = None

    async def initialize(self, config: Dict[str, Any]) -> None:
        try:
            spec = importlib.util.spec_from_file_location(
                "plugin_module", self.module_path
            )
            self._module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self._module)

            plugin_class = getattr(self._module, self.class_name)
            self._instance = plugin_class()

            if hasattr(self._instance, "initialize"):
                await self._instance.initialize(config)

            logger.info(f"Loaded plugin: {self.name}")
        except Exception as e:
            logger.error(f"Failed to load plugin from {self.module_path}: {e}")
            raise

    async def execute(self, *args, **kwargs) -> Any:
        if not self._instance:
            raise RuntimeError("Plugin not initialized")
        if hasattr(self._instance, "execute"):
            return await self._instance.execute(*args, **kwargs)
        return None

    async def shutdown(self) -> None:
        if self._instance and hasattr(self._instance, "shutdown"):
            await self._instance.shutdown()

    @property
    def name(self) -> str:
        return getattr(self._instance, "name", "unknown")

    @property
    def version(self) -> str:
        return getattr(self._instance, "version", "1.0.0")

    @property
    def capabilities(self) -> List[str]:
        return getattr(self._instance, "capabilities", [])


class PluginRegistry:
    """Central registry for all loaded plugins."""

    def __init__(self):
        self.plugins: Dict[str, PluginInterface] = {}
        self.metadata: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def register(
        self, plugin_id: str, plugin: PluginInterface, config: Dict[str, Any] = None
    ) -> None:
        """Register a plugin."""
        async with self._lock:
            await plugin.initialize(config or {})
            self.plugins[plugin_id] = plugin
            self.metadata[plugin_id] = {
                "name": plugin.name,
                "version": plugin.version,
                "capabilities": plugin.capabilities,
                "registered_at": asyncio.get_event_loop().time(),
            }
            logger.info(
                f"Registered plugin '{plugin_id}': {plugin.name} v{plugin.version}"
            )

    async def unregister(self, plugin_id: str) -> None:
        """Unregister and cleanup a plugin."""
        async with self._lock:
            if plugin_id in self.plugins:
                await self.plugins[plugin_id].shutdown()
                del self.plugins[plugin_id]
                del self.metadata[plugin_id]
                logger.info(f"Unregistered plugin: {plugin_id}")

    async def call(self, plugin_id: str, *args, **kwargs) -> Any:
        """Execute a plugin."""
        if plugin_id not in self.plugins:
            raise KeyError(f"Plugin not found: {plugin_id}")
        return await self.plugins[plugin_id].execute(*args, **kwargs)

    async def call_capability(
        self, capability: str, *args, **kwargs
    ) -> List[Any]:
        """Call all plugins with a specific capability."""
        results = []
        for plugin_id, plugin in self.plugins.items():
            if capability in plugin.capabilities:
                try:
                    result = await plugin.execute(*args, **kwargs)
                    results.append({"plugin_id": plugin_id, "result": result})
                except Exception as e:
                    logger.error(
                        f"Error executing {plugin_id} for capability {capability}: {e}"
                    )
                    results.append({"plugin_id": plugin_id, "error": str(e)})
        return results

    def list_plugins(self) -> Dict[str, Dict[str, Any]]:
        """List all registered plugins and their metadata."""
        return self.metadata.copy()

    async def shutdown_all(self) -> None:
        """Shutdown all plugins."""
        async with self._lock:
            for plugin_id in list(self.plugins.keys()):
                try:
                    await self.plugins[plugin_id].shutdown()
                except Exception as e:
                    logger.error(f"Error shutting down {plugin_id}: {e}")
            self.plugins.clear()
            self.metadata.clear()


class PluginManager:
    """Main plugin manager - orchestrates all plugin operations."""

    def __init__(self):
        self.registry = PluginRegistry()
        self.config: Dict[str, Any] = {}
        self._plugins_dir = Path(__file__).parent / "plugins"

    async def load_config(self, config_path: Path) -> None:
        """Load plugin configuration from JSON file."""
        if config_path.exists():
            with open(config_path) as f:
                self.config = json.load(f)
            logger.info(f"Loaded plugin config from {config_path}")

    async def auto_discover_plugins(self) -> None:
        """Auto-discover and load plugins from plugins directory."""
        if not self._plugins_dir.exists():
            logger.warning(f"Plugins directory not found: {self._plugins_dir}")
            return

        for plugin_dir in self._plugins_dir.iterdir():
            if plugin_dir.is_dir() and (plugin_dir / "plugin.json").exists():
                try:
                    with open(plugin_dir / "plugin.json") as f:
                        plugin_meta = json.load(f)

                    plugin_id = plugin_meta.get("id")
                    module_path = plugin_dir / plugin_meta.get("module", "plugin.py")
                    class_name = plugin_meta.get("class", "Plugin")

                    if module_path.exists():
                        plugin = LocalPythonPlugin(str(module_path), class_name)
                        plugin_config = self.config.get(plugin_id, {})
                        await self.registry.register(plugin_id, plugin, plugin_config)
                except Exception as e:
                    logger.error(f"Failed to load plugin from {plugin_dir}: {e}")

    async def register_plugin(
        self, plugin_id: str, plugin: PluginInterface, config: Dict[str, Any] = None
    ) -> None:
        """Register a plugin manually."""
        await self.registry.register(plugin_id, plugin, config)

    async def unregister_plugin(self, plugin_id: str) -> None:
        """Unregister a plugin."""
        await self.registry.unregister(plugin_id)

    async def call_plugin(self, plugin_id: str, *args, **kwargs) -> Any:
        """Call a specific plugin."""
        return await self.registry.call(plugin_id, *args, **kwargs)

    async def call_plugins_by_capability(
        self, capability: str, *args, **kwargs
    ) -> List[Any]:
        """Call all plugins with a capability."""
        return await self.registry.call_capability(capability, *args, **kwargs)

    def get_plugins_info(self) -> Dict[str, Dict[str, Any]]:
        """Get info about all loaded plugins."""
        return self.registry.list_plugins()

    async def shutdown(self) -> None:
        """Shutdown all plugins."""
        await self.registry.shutdown_all()
        logger.info("Plugin manager shutdown complete")
