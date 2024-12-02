"""
Configuration management for the enhanced server.
"""

import os
import logging
from typing import Optional, Dict, Any, List, Union
from pathlib import Path

class Config:
    """
    Server configuration with enhanced options.
    """
    
    def __init__(
        self,
        app: str,
        host: str = "127.0.0.1",
        port: int = 8000,
        reload: bool = False,
        workers: int = 1,
        log_level: str = "info",
        log_format: str = "default",
        access_log: bool = True,
        structured_logging: bool = False,
        metrics_enabled: bool = False,
        prometheus_enabled: bool = False,
        reload_dirs: Optional[List[str]] = None,
        drain_timeout: float = 30.0,
        grace_period: float = 5.0,
        middleware: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.app = app
        self.host = host
        self.port = port
        self.reload = reload
        self.workers = workers
        self.log_level = log_level
        self.log_format = log_format
        self.access_log = access_log
        self.structured_logging = structured_logging
        self.metrics_enabled = metrics_enabled
        self.prometheus_enabled = prometheus_enabled
        self.reload_dirs = reload_dirs
        self.drain_timeout = drain_timeout
        self.grace_period = grace_period
        
        # Default middleware configuration
        self.middleware = {
            "rate_limit": {
                "enabled": False,
                "rate": "100/minute"
            },
            "cache": {
                "enabled": False,
                "ttl": 300
            },
            "cors": {
                "enabled": False,
                "allow_origins": ["*"],
                "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
            },
            "security": {
                "enabled": False,
                "hsts": True,
                "xss_protection": True,
                "content_security_policy": None
            }
        }
        
        # Update middleware with user-provided config
        if middleware:
            for key, value in middleware.items():
                if key in self.middleware:
                    self.middleware[key].update(value)

class AutoConfig(Config):
    """
    Configuration with automatic detection of common settings.
    """
    
    def __init__(self, app: str, **kwargs):
        # Detect reload directories
        if "reload_dirs" not in kwargs:
            kwargs["reload_dirs"] = self._detect_reload_dirs()
            
        # Auto-enable structured logging if prometheus is enabled
        if kwargs.get("prometheus_enabled"):
            kwargs["structured_logging"] = True
            
        super().__init__(app, **kwargs)
    
    def _detect_reload_dirs(self) -> List[str]:
        """
        Automatically detect directories to watch for reload.
        """
        dirs = []
        cwd = Path.cwd()
        
        # Common Python project directories
        common_dirs = ["app", "src", "backend", "api"]
        for dir_name in common_dirs:
            if (cwd / dir_name).is_dir():
                dirs.append(str(cwd / dir_name))
                
        # Add current directory if no common dirs found
        if not dirs:
            dirs.append(str(cwd))
            
        return dirs
