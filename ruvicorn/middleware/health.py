"""
Health check middleware for monitoring application status.
"""

from typing import Dict, Optional, List, Any, Callable
import json
import time
import psutil
import os

class HealthStatus:
    """Health status information container."""
    
    def __init__(self):
        self.start_time = time.time()
        self.checks: Dict[str, Callable] = {}
        self.last_check: Optional[Dict] = None
    
    def add_check(self, name: str, check_func: Callable) -> None:
        """Add a health check function."""
        self.checks[name] = check_func
    
    def get_system_metrics(self) -> Dict:
        """Get system resource metrics."""
        process = psutil.Process(os.getpid())
        
        return {
            "cpu_percent": process.cpu_percent(),
            "memory_percent": process.memory_percent(),
            "threads": process.num_threads(),
            "open_files": len(process.open_files()),
            "connections": len(process.connections())
        }
    
    async def run_checks(self) -> Dict:
        """Run all registered health checks."""
        results = {
            "status": "healthy",
            "timestamp": time.time(),
            "uptime": time.time() - self.start_time,
            "system": self.get_system_metrics(),
            "checks": {}
        }
        
        for name, check in self.checks.items():
            try:
                check_result = await check() if callable(check) else check
                results["checks"][name] = {
                    "status": "healthy",
                    "details": check_result
                }
            except Exception as e:
                results["checks"][name] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
                results["status"] = "unhealthy"
        
        self.last_check = results
        return results

class HealthCheckMiddleware:
    """
    ASGI middleware for health checks and monitoring.
    """
    
    def __init__(
        self,
        app: Any,
        path: str = "/health",
        detailed_path: str = "/health/detailed",
        status: Optional[HealthStatus] = None,
        cache_duration: int = 60,  # Cache health check results for 60 seconds
        required_checks: Optional[List[str]] = None
    ):
        self.app = app
        self.path = path
        self.detailed_path = detailed_path
        self.status = status or HealthStatus()
        self.cache_duration = cache_duration
        self.required_checks = required_checks or []
        
        # Add default checks
        self.status.add_check("system", self.status.get_system_metrics)
    
    def add_check(self, name: str, check_func: Callable) -> None:
        """Add a custom health check."""
        self.status.add_check(name, check_func)
    
    async def _get_cached_health_check(self, detailed: bool = False) -> Dict:
        """Get cached health check results or run new checks."""
        current_time = time.time()
        last_check = self.status.last_check
        
        if (
            not last_check or
            current_time - last_check["timestamp"] > self.cache_duration
        ):
            results = await self.status.run_checks()
        else:
            results = last_check
        
        if not detailed:
            # Simplified response for basic health check
            return {
                "status": results["status"],
                "timestamp": results["timestamp"]
            }
        
        return results
    
    def _check_required_services(self, results: Dict) -> bool:
        """Verify that required services are healthy."""
        if not self.required_checks:
            return True
        
        for check in self.required_checks:
            check_result = results.get("checks", {}).get(check, {})
            if check_result.get("status") != "healthy":
                return False
        
        return True
    
    async def __call__(
        self,
        scope: Dict,
        receive: Any,
        send: Any
    ) -> None:
        """ASGI middleware implementation."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        path = scope.get("path", "")
        
        if path not in [self.path, self.detailed_path]:
            await self.app(scope, receive, send)
            return
        
        # Handle health check request
        is_detailed = path == self.detailed_path
        results = await self._get_cached_health_check(is_detailed)
        
        # Determine response status code
        status_code = 200
        if not self._check_required_services(results):
            status_code = 503  # Service Unavailable
        elif results["status"] != "healthy":
            status_code = 500  # Internal Server Error
        
        # Send response
        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"cache-control", f"max-age={self.cache_duration}".encode())
            ]
        })
        
        await send({
            "type": "http.response.body",
            "body": json.dumps(results).encode()
        })
