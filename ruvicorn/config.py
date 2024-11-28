"""
Configuration management for Ruvicorn server.
"""

import os
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass, field
import yaml
from dotenv import load_dotenv

class ConfigurationError(Exception):
    """Raised when there's an error in configuration."""
    pass

@dataclass
class Config:
    """Base configuration class for Ruvicorn."""
    app: str
    host: str = "127.0.0.1"
    port: int = 8000
    reload: bool = False
    reload_dirs: List[str] = field(default_factory=list)
    workers: int = 1
    log_level: str = "info"
    log_format: str = "json"
    access_log: bool = True
    
    # Enhanced features
    metrics_enabled: bool = False
    prometheus_enabled: bool = False
    structured_logging: bool = True
    
    # Middleware configurations
    middleware: Dict[str, Any] = field(default_factory=lambda: {
        "rate_limit": {
            "enabled": False,
            "requests_per_minute": 60,
            "burst_size": 5
        },
        "cache": {
            "enabled": False,
            "max_age": 300
        },
        "cors": {
            "enabled": False,
            "allow_origins": [],
            "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": []
        },
        "security": {
            "enabled": True,
            "hsts": True,
            "xss_protection": True,
            "content_security_policy": {}
        }
    })

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> 'Config':
        """Load configuration from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise ConfigurationError(f"Configuration file not found: {path}")
            
        with open(path) as f:
            try:
                config_dict = yaml.safe_load(f)
                return cls(**config_dict)
            except yaml.YAMLError as e:
                raise ConfigurationError(f"Error parsing configuration file: {e}")

class AutoConfig(Config):
    """
    Enhanced configuration with automatic project detection and optimization.
    """
    def __init__(self, app: Optional[str] = None, **kwargs):
        if app is None:
            app = self._detect_app()
        super().__init__(app=app, **kwargs)
        self._load_env_vars()
        self._optimize_for_project()
    
    def _detect_app(self) -> str:
        """
        Automatically detect the main application module.
        """
        # Look for common patterns
        common_files = ["main.py", "app.py", "api.py"]
        for file in common_files:
            if Path(file).exists():
                module_name = Path(file).stem
                # Try to import and find app instance
                try:
                    sys.path.insert(0, str(Path.cwd()))
                    module = __import__(module_name)
                    for attr in ["app", "application"]:
                        if hasattr(module, attr):
                            return f"{module_name}:{attr}"
                except ImportError:
                    continue
                finally:
                    sys.path.pop(0)
        
        raise ConfigurationError(
            "Could not automatically detect application. "
            "Please specify the application explicitly."
        )
    
    def _load_env_vars(self) -> None:
        """
        Load and process environment variables.
        """
        # Load .env file if it exists
        env_file = Path(".env")
        if env_file.exists():
            load_dotenv(env_file)
        
        # Override config with environment variables
        env_mappings = {
            "RUVICORN_HOST": "host",
            "RUVICORN_PORT": ("port", int),
            "RUVICORN_WORKERS": ("workers", int),
            "RUVICORN_LOG_LEVEL": "log_level",
            "RUVICORN_LOG_FORMAT": "log_format",
            "RUVICORN_RELOAD": ("reload", lambda x: x.lower() == "true"),
        }
        
        for env_var, config_attr in env_mappings.items():
            if isinstance(config_attr, tuple):
                attr, converter = config_attr
            else:
                attr, converter = config_attr, str
                
            if env_value := os.getenv(env_var):
                setattr(self, attr, converter(env_value))
    
    def _optimize_for_project(self) -> None:
        """
        Apply optimizations based on detected project type.
        """
        try:
            sys.path.insert(0, str(Path.cwd()))
            
            # Check for FastAPI
            try:
                import fastapi
                self._optimize_for_fastapi()
            except ImportError:
                pass
            
            # Check for Starlette
            try:
                import starlette
                self._optimize_for_starlette()
            except ImportError:
                pass
                
        finally:
            sys.path.pop(0)
    
    def _optimize_for_fastapi(self) -> None:
        """Apply FastAPI-specific optimizations."""
        # Enable features that work well with FastAPI
        self.structured_logging = True
        self.metrics_enabled = True
        
        # Configure middleware defaults
        self.middleware["cors"]["enabled"] = True
        self.middleware["rate_limit"]["enabled"] = True
        
        # Set optimal worker count if not specified
        if self.workers == 1:
            self.workers = (os.cpu_count() or 1) * 2 + 1
    
    def _optimize_for_starlette(self) -> None:
        """Apply Starlette-specific optimizations."""
        # Enable basic features
        self.structured_logging = True
        
        # Configure middleware defaults
        self.middleware["security"]["enabled"] = True
        
        # Set optimal worker count if not specified
        if self.workers == 1:
            self.workers = (os.cpu_count() or 1) * 2
