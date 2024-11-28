"""
Metrics collection and monitoring functionality.
"""

import time
import asyncio
from typing import Dict, Any, List, Optional, Set
from collections import defaultdict, deque
from dataclasses import dataclass, field
import statistics
from datetime import datetime, timedelta
import threading
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    REGISTRY,
    generate_latest
)

@dataclass
class RequestMetrics:
    """Metrics for a single request."""
    method: str
    path: str
    status_code: int
    duration_ms: float
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class ErrorMetrics:
    """Metrics for an error occurrence."""
    error_type: str
    message: str
    endpoint: str
    stack_trace: Optional[str]
    timestamp: datetime = field(default_factory=datetime.now)

class MetricsWindow:
    """
    Sliding window for metrics collection.
    """
    
    def __init__(self, window_size: int = 3600):  # 1 hour default
        self.window_size = window_size
        self.values = deque(maxlen=window_size)
        self._lock = threading.Lock()
    
    def add(self, value: Any) -> None:
        """Add a value to the window."""
        with self._lock:
            self.values.append(value)
            self._cleanup()
    
    def get_values(self) -> List[Any]:
        """Get all values in the current window."""
        with self._lock:
            self._cleanup()
            return list(self.values)
    
    def _cleanup(self) -> None:
        """Remove values outside the window."""
        cutoff = datetime.now() - timedelta(seconds=self.window_size)
        while self.values and self.values[0].timestamp < cutoff:
            self.values.popleft()

class MetricsCollector:
    """
    Collects and manages application metrics.
    """
    
    def __init__(
        self,
        window_size: int = 3600,
        prometheus_enabled: bool = False
    ):
        self.window_size = window_size
        self.prometheus_enabled = prometheus_enabled
        
        # Metrics storage
        self.requests = MetricsWindow(window_size)
        self.errors = MetricsWindow(window_size)
        self.custom_metrics: Dict[str, Any] = {}
        
        # Prometheus metrics
        if prometheus_enabled:
            self._setup_prometheus_metrics()
        
        self._lock = threading.Lock()
        self._running = False
    
    def _setup_prometheus_metrics(self) -> None:
        """Set up Prometheus metrics."""
        self.prom_request_counter = Counter(
            "http_requests_total",
            "Total HTTP requests",
            ["method", "path", "status"]
        )
        
        self.prom_request_duration = Histogram(
            "http_request_duration_seconds",
            "HTTP request duration in seconds",
            ["method", "path"],
            buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        )
        
        self.prom_error_counter = Counter(
            "error_total",
            "Total errors",
            ["type", "endpoint"]
        )
        
        self.prom_active_connections = Gauge(
            "active_connections",
            "Number of active connections"
        )
    
    async def start(self) -> None:
        """Start metrics collection."""
        self._running = True
    
    async def stop(self) -> None:
        """Stop metrics collection."""
        self._running = False
    
    def record_request(
        self,
        method: str,
        path: str,
        status_code: int,
        duration_ms: float
    ) -> None:
        """Record metrics for a request."""
        metrics = RequestMetrics(
            method=method,
            path=path,
            status_code=status_code,
            duration_ms=duration_ms
        )
        
        self.requests.add(metrics)
        
        if self.prometheus_enabled:
            self.prom_request_counter.labels(
                method=method,
                path=path,
                status=str(status_code)
            ).inc()
            
            self.prom_request_duration.labels(
                method=method,
                path=path
            ).observe(duration_ms / 1000.0)
    
    def record_error(
        self,
        error_type: str,
        message: str,
        endpoint: str,
        stack_trace: Optional[str] = None
    ) -> None:
        """Record metrics for an error."""
        metrics = ErrorMetrics(
            error_type=error_type,
            message=message,
            endpoint=endpoint,
            stack_trace=stack_trace
        )
        
        self.errors.add(metrics)
        
        if self.prometheus_enabled:
            self.prom_error_counter.labels(
                type=error_type,
                endpoint=endpoint
            ).inc()
    
    def get_statistics(
        self,
        time_window: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get statistical summary of collected metrics."""
        window = time_window or self.window_size
        cutoff = datetime.now() - timedelta(seconds=window)
        
        # Filter metrics within time window
        recent_requests = [
            r for r in self.requests.get_values()
            if r.timestamp >= cutoff
        ]
        
        recent_errors = [
            e for e in self.errors.get_values()
            if e.timestamp >= cutoff
        ]
        
        if not recent_requests:
            return {
                "total_requests": 0,
                "avg_response_time": 0,
                "error_rate": 0,
                "status_codes": {},
                "endpoints": {}
            }
        
        # Calculate statistics
        durations = [r.duration_ms for r in recent_requests]
        status_codes = defaultdict(int)
        endpoints = defaultdict(list)
        
        for req in recent_requests:
            status_codes[req.status_code] += 1
            endpoints[req.path].append(req.duration_ms)
        
        # Endpoint statistics
        endpoint_stats = {}
        for path, times in endpoints.items():
            endpoint_stats[path] = {
                "count": len(times),
                "avg_duration": statistics.mean(times),
                "min_duration": min(times),
                "max_duration": max(times),
                "p95_duration": statistics.quantiles(times, n=20)[18]
                if len(times) >= 20 else max(times)
            }
        
        return {
            "total_requests": len(recent_requests),
            "requests_per_second": len(recent_requests) / window,
            "avg_response_time": statistics.mean(durations),
            "p95_response_time": statistics.quantiles(durations, n=20)[18]
            if len(durations) >= 20 else max(durations),
            "error_rate": len(recent_errors) / len(recent_requests),
            "status_codes": dict(status_codes),
            "endpoints": endpoint_stats
        }
    
    def get_error_summary(
        self,
        time_window_minutes: int = 60
    ) -> List[Dict[str, Any]]:
        """Get summary of errors within the time window."""
        cutoff = datetime.now() - timedelta(minutes=time_window_minutes)
        
        # Group errors by type and endpoint
        error_groups: Dict[tuple, List[ErrorMetrics]] = defaultdict(list)
        for error in self.errors.get_values():
            if error.timestamp >= cutoff:
                key = (error.error_type, error.endpoint, error.message)
                error_groups[key].append(error)
        
        # Create summary for each error group
        summary = []
        for (error_type, endpoint, message), errors in error_groups.items():
            summary.append({
                "error_type": error_type,
                "endpoint": endpoint,
                "message": message,
                "count": len(errors),
                "first_seen": min(e.timestamp for e in errors),
                "last_seen": max(e.timestamp for e in errors),
                "sample_stack_trace": errors[-1].stack_trace
            })
        
        return sorted(
            summary,
            key=lambda x: (x["count"], x["last_seen"]),
            reverse=True
        )

class PrometheusMetrics:
    """
    Prometheus metrics integration.
    """
    
    def __init__(self):
        self._custom_counters: Dict[str, Counter] = {}
        self._custom_gauges: Dict[str, Gauge] = {}
        self._custom_histograms: Dict[str, Histogram] = {}
    
    def register_counter(
        self,
        name: str,
        description: str,
        labels: Optional[List[str]] = None
    ) -> None:
        """Register a new Prometheus counter."""
        self._custom_counters[name] = Counter(
            name,
            description,
            labels or []
        )
    
    def register_gauge(
        self,
        name: str,
        description: str,
        labels: Optional[List[str]] = None
    ) -> None:
        """Register a new Prometheus gauge."""
        self._custom_gauges[name] = Gauge(
            name,
            description,
            labels or []
        )
    
    def register_histogram(
        self,
        name: str,
        description: str,
        labels: Optional[List[str]] = None,
        buckets: Optional[tuple] = None
    ) -> None:
        """Register a new Prometheus histogram."""
        self._custom_histograms[name] = Histogram(
            name,
            description,
            labels or [],
            buckets=buckets
        )
    
    def increment_counter(
        self,
        name: str,
        value: float = 1,
        labels: Optional[Dict[str, str]] = None
    ) -> None:
        """Increment a counter."""
        if name in self._custom_counters:
            if labels:
                self._custom_counters[name].labels(**labels).inc(value)
            else:
                self._custom_counters[name].inc(value)
    
    def set_gauge(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None
    ) -> None:
        """Set a gauge value."""
        if name in self._custom_gauges:
            if labels:
                self._custom_gauges[name].labels(**labels).set(value)
            else:
                self._custom_gauges[name].set(value)
    
    def observe_histogram(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None
    ) -> None:
        """Record a histogram observation."""
        if name in self._custom_histograms:
            if labels:
                self._custom_histograms[name].labels(**labels).observe(value)
            else:
                self._custom_histograms[name].observe(value)
    
    def export_metrics(self) -> bytes:
        """Export all metrics in Prometheus format."""
        return generate_latest(REGISTRY)
