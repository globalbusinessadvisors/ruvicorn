"""
Enhanced ASGI server implementation extending uvicorn functionality.
"""

import asyncio
import signal
import logging
import uvicorn
from typing import Optional, Dict, Any, Set
from contextlib import asynccontextmanager
from pathlib import Path

from .config import Config, AutoConfig
from .logging import StructuredLogger, MetricsCollector
from .hot_reload import HotReloader
from .middleware import (
    RateLimiter,
    CacheControl,
    JWTAuth,
    CORSConfig,
    SecurityHeaders,
)

class RuvicornServer:
    """
    Enhanced ASGI server with improved functionality.
    """
    
    def __init__(
        self,
        app: str,
        config: Optional[Config] = None,
        **kwargs
    ):
        self.config = config or AutoConfig(app=app, **kwargs)
        self.logger = self._setup_logger()
        self.metrics = self._setup_metrics() if self.config.metrics_enabled else None
        self.hot_reloader = self._setup_hot_reloader() if self.config.reload else None
        self.middleware_stack = self._setup_middleware()
        self._active_connections: Set[str] = set()
        self._server_state = "stopped"
        self._reload_count = 0
        self._reload_stats = {
            "total_reloads": 0,
            "partial_reloads": 0,
            "full_reloads": 0,
            "last_error": None
        }
    
    def _setup_logger(self) -> StructuredLogger:
        """Initialize the enhanced structured logger."""
        return StructuredLogger(
            level=self.config.log_level.upper(),
            format=self.config.log_format,
            structured=self.config.structured_logging
        )
    
    def _setup_metrics(self) -> MetricsCollector:
        """Initialize the metrics collector."""
        return MetricsCollector(
            prometheus_enabled=self.config.prometheus_enabled
        )
    
    def _setup_hot_reloader(self) -> HotReloader:
        """Initialize the enhanced hot reloader."""
        return HotReloader(
            reload_dirs=self.config.reload_dirs or [str(Path.cwd())],
            on_reload=self._handle_reload
        )
    
    def _setup_middleware(self) -> Dict[str, Any]:
        """Initialize configured middleware stack."""
        middleware = {}
        
        if self.config.middleware["rate_limit"]["enabled"]:
            middleware["rate_limit"] = RateLimiter(
                **self.config.middleware["rate_limit"]
            )
            
        if self.config.middleware["cache"]["enabled"]:
            middleware["cache"] = CacheControl(
                **self.config.middleware["cache"]
            )
            
        if self.config.middleware["cors"]["enabled"]:
            middleware["cors"] = CORSConfig(
                **self.config.middleware["cors"]
            )
            
        if self.config.middleware["security"]["enabled"]:
            middleware["security"] = SecurityHeaders(
                **self.config.middleware["security"]
            )
            
        return middleware
    
    async def _handle_reload(self, changes: Set[str]) -> None:
        """
        Handle code changes during development.
        
        This implements zero-downtime reloads by:
        1. Detecting if changes require full or partial reload
        2. Maintaining existing connections during reload
        3. Gracefully transitioning to new code
        """
        self._reload_count += 1
        self._reload_stats["total_reloads"] += 1
        
        try:
            # Determine reload type based on changed files
            requires_full_reload = any(
                change.endswith((".py", ".pyd", ".so"))
                for change in changes
            )
            
            if requires_full_reload:
                self._reload_stats["full_reloads"] += 1
                await self._full_reload()
            else:
                self._reload_stats["partial_reloads"] += 1
                await self._partial_reload(changes)
                
        except Exception as e:
            self.logger.error(f"Reload failed: {str(e)}")
            self._reload_stats["last_error"] = str(e)
    
    async def _full_reload(self) -> None:
        """
        Perform a full server reload while preserving connections.
        """
        self.logger.info("Performing full server reload")
        
        # Create new application instance
        new_app = await self._create_new_app_instance()
        
        # Gracefully shutdown old workers
        await self._graceful_worker_shutdown()
        
        # Start new workers with new application
        await self._start_new_workers(new_app)
        
        self.logger.info("Full reload completed")
    
    async def _partial_reload(self, changes: Set[str]) -> None:
        """
        Perform a partial reload of only changed components.
        """
        self.logger.info(f"Performing partial reload for changes: {changes}")
        
        # Reload only affected modules
        for change in changes:
            if change.endswith(".py"):
                module_name = Path(change).stem
                await self._reload_module(module_name)
        
        self.logger.info("Partial reload completed")
    
    async def _graceful_worker_shutdown(self) -> None:
        """
        Gracefully shutdown workers while maintaining existing connections.
        """
        # Wait for existing requests to complete
        if self._active_connections:
            self.logger.info(
                f"Waiting for {len(self._active_connections)} "
                "active connections to complete"
            )
            while self._active_connections:
                await asyncio.sleep(0.1)
    
    async def _create_new_app_instance(self) -> Any:
        """
        Create a new instance of the application with updated code.
        """
        # Import the application module fresh
        module_name, app_attr = self.config.app.split(":")
        module = __import__(module_name, fromlist=[app_attr])
        
        # Reload the module to get updated code
        import importlib
        importlib.reload(module)
        
        return getattr(module, app_attr)
    
    async def _reload_module(self, module_name: str) -> None:
        """
        Reload a specific Python module.
        """
        try:
            module = __import__(module_name)
            import importlib
            importlib.reload(module)
        except ImportError as e:
            self.logger.error(f"Failed to reload module {module_name}: {e}")
    
    async def start(self) -> None:
        """
        Start the enhanced server.
        """
        self._server_state = "starting"
        self.logger.info(
            f"Starting Ruvicorn server on {self.config.host}:{self.config.port}"
        )
        
        # Setup signal handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_event_loop().add_signal_handler(
                sig,
                lambda s=sig: asyncio.create_task(self.shutdown(s))
            )
        
        # Start metrics collector if enabled
        if self.metrics:
            await self.metrics.start()
        
        # Start hot reloader if enabled
        if self.hot_reloader:
            await self.hot_reloader.start()
        
        # Create the ASGI application with middleware
        app = await self._create_application()
        
        # Start uvicorn with our configuration
        config = uvicorn.Config(
            app,
            host=self.config.host,
            port=self.config.port,
            workers=self.config.workers,
            log_level=self.config.log_level,
            access_log=self.config.access_log,
        )
        
        self._server_state = "running"
        self.server = uvicorn.Server(config=config)
        await self.server.serve()
    
    async def shutdown(self, sig: Optional[signal.Signals] = None) -> None:
        """
        Gracefully shutdown the server.
        """
        if self._server_state == "stopped":
            return
            
        self._server_state = "shutting_down"
        self.logger.info("Initiating graceful shutdown")
        
        # Stop hot reloader if running
        if self.hot_reloader:
            await self.hot_reloader.stop()
        
        # Stop metrics collector if running
        if self.metrics:
            await self.metrics.stop()
        
        # Wait for active connections to complete
        await self._graceful_worker_shutdown()
        
        # Shutdown the server
        if hasattr(self, 'server'):
            self.server.should_exit = True
        
        self._server_state = "stopped"
        self.logger.info("Server shutdown complete")
    
    async def _create_application(self) -> Any:
        """
        Create the ASGI application with configured middleware.
        """
        app = await self._create_new_app_instance()
        
        # Apply middleware in reverse order
        if "security" in self.middleware_stack:
            app = self.middleware_stack["security"].wrap(app)
        if "cors" in self.middleware_stack:
            app = self.middleware_stack["cors"].wrap(app)
        if "cache" in self.middleware_stack:
            app = self.middleware_stack["cache"].wrap(app)
        if "rate_limit" in self.middleware_stack:
            app = self.middleware_stack["rate_limit"].wrap(app)
        
        return app
    
    @property
    def reload_stats(self) -> Dict[str, Any]:
        """Get statistics about server reloads."""
        return self._reload_stats.copy()
    
    @asynccontextmanager
    async def connection_tracking(self):
        """
        Context manager for tracking active connections.
        """
        conn_id = str(id(asyncio.current_task()))
        self._active_connections.add(conn_id)
        try:
            yield
        finally:
            self._active_connections.discard(conn_id)
