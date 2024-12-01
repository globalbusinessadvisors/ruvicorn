"""
Enhanced ASGI server implementation extending uvicorn functionality.
"""

import asyncio
import signal
import logging
import uvicorn
from typing import Optional, Dict, Any, Set, Callable, Awaitable
from contextlib import asynccontextmanager
from pathlib import Path

from .config import Config, AutoConfig
from .logging import StructuredLogger, MetricsCollector
from .hot_reload import HotReloader
from .drain import ConnectionDrainer, DrainState
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
        self.connection_drainer = ConnectionDrainer(
            drain_timeout=self.config.drain_timeout,
            grace_period=self.config.grace_period,
            logger=self.logger
        )
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
        """
        self._reload_count += 1
        self._reload_stats["total_reloads"] += 1
        
        try:
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
        
        # Start draining before reload
        await self.connection_drainer.start_draining()
        
        # Create new application instance
        new_app = await self._create_new_app_instance()
        
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
        Gracefully shutdown the server with connection draining.
        """
        if self._server_state == "stopped":
            return
            
        self._server_state = "shutting_down"
        self.logger.info("Initiating graceful shutdown with connection draining")
        
        # Start connection draining
        await self.connection_drainer.start_draining()
        
        # Stop hot reloader if running
        if self.hot_reloader:
            await self.hot_reloader.stop()
        
        # Stop metrics collector if running
        if self.metrics:
            await self.metrics.stop()
        
        # Shutdown the server
        if hasattr(self, 'server'):
            self.server.should_exit = True
        
        self._server_state = "stopped"
        
        # Log drain statistics
        if self.connection_drainer.drain_duration is not None:
            self.logger.info(
                f"Server shutdown complete. Drain duration: "
                f"{self.connection_drainer.drain_duration:.2f}s, "
                f"Connections drained: {self.connection_drainer.stats.drained_connections}, "
                f"Connections rejected: {self.connection_drainer.stats.rejected_connections}"
            )
    
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
        
        # Wrap the application with connection tracking
        original_app = app
        
        async def connection_tracking_middleware(scope, receive, send):
            if scope["type"] != "http":
                return await original_app(scope, receive, send)
                
            conn_id = str(id(asyncio.current_task()))
            
            # Try to start tracking the connection
            if not self.connection_drainer.start_connection(
                conn_id,
                scope.get("path", ""),
                scope.get("method", ""),
                f"{scope.get('client', ('unknown', 0))[0]}:{scope.get('client', ('', 0))[1]}"
            ):
                # Connection rejected during drain
                response = {
                    "type": "http.response.start",
                    "status": 503,
                    "headers": [
                        (b"content-type", b"text/plain"),
                        (b"retry-after", b"5"),
                    ],
                }
                await send(response)
                await send({"type": "http.response.body", "body": b"Server is shutting down"})
                return
                
            try:
                await original_app(scope, receive, send)
            finally:
                self.connection_drainer.end_connection(conn_id)
        
        return connection_tracking_middleware
    
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
    
    def add_cleanup_hook(self, hook: Callable[[], Awaitable[None]]) -> None:
        """
        Add a cleanup hook to be called during shutdown.
        """
        self.connection_drainer.add_cleanup_hook(hook)
    
    @property
    def drain_stats(self) -> Dict[str, Any]:
        """Get current connection drain statistics."""
        return {
            "state": self.connection_drainer.state.value,
            "active_connections": len(self.connection_drainer.active_connections),
            "total_connections": self.connection_drainer.stats.total_connections,
            "drained_connections": self.connection_drainer.stats.drained_connections,
            "rejected_connections": self.connection_drainer.stats.rejected_connections,
            "longest_connection": self.connection_drainer.stats.longest_connection,
            "drain_duration": self.connection_drainer.drain_duration
        }
