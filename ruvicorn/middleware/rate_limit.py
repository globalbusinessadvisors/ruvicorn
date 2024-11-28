"""
Rate limiting middleware implementation.
"""

import time
import asyncio
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict
import hashlib
from datetime import datetime, timedelta
import json

@dataclass
class RateLimitState:
    """State for a rate-limited endpoint."""
    requests: int = 0
    window_start: float = 0.0
    last_request: float = 0.0
    tokens: float = 0.0
    previous_requests: int = 0

class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""
    pass

class RateLimiter:
    """
    Enhanced rate limiting middleware with support for multiple strategies
    and dynamic configuration.
    """
    
    def __init__(
        self,
        requests_per_minute: int = 60,
        burst_size: int = 5,
        strategy: str = "sliding_window",
        window_size: int = 60,
        path_limits: Optional[Dict[str, int]] = None,
        exclude_paths: Optional[set] = None,
        storage_backend: Optional[Any] = None
    ):
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.strategy = strategy
        self.window_size = window_size
        self.path_limits = path_limits or {}
        self.exclude_paths = exclude_paths or set()
        self.storage = storage_backend or self._create_default_storage()
        
        # Rate in tokens per second
        self.rate = requests_per_minute / 60.0
        
        # Clean up task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
    
    def _create_default_storage(self) -> Dict:
        """Create default in-memory storage."""
        return defaultdict(lambda: defaultdict(RateLimitState))
    
    async def start(self) -> None:
        """Start the rate limiter and cleanup task."""
        if self._running:
            return
        
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def stop(self) -> None:
        """Stop the rate limiter and cleanup task."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
    
    async def _cleanup_loop(self) -> None:
        """Periodically clean up expired rate limit states."""
        while self._running:
            try:
                now = time.time()
                expired_window = now - self.window_size * 2  # Keep one extra window for sliding window
                
                # Clean up expired entries
                for client_id in list(self.storage.keys()):
                    for path in list(self.storage[client_id].keys()):
                        state = self.storage[client_id][path]
                        if state.window_start < expired_window:
                            del self.storage[client_id][path]
                    
                    # Remove client if no paths remain
                    if not self.storage[client_id]:
                        del self.storage[client_id]
                
                await asyncio.sleep(60)  # Cleanup every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue running
                print(f"Error in rate limit cleanup: {e}")
                await asyncio.sleep(60)
    
    def get_limit_for_path(self, path: str) -> int:
        """Get the rate limit for a specific path."""
        # Check for exact path match
        if path in self.path_limits:
            return self.path_limits[path]
        
        # Check for pattern matches
        for pattern, limit in self.path_limits.items():
            if pattern.endswith("*") and path.startswith(pattern[:-1]):
                return limit
        
        return self.requests_per_minute
    
    def _get_client_identifier(self, scope: Dict) -> str:
        """Generate a unique identifier for the client."""
        client = scope.get("client", [None, None])[0] or "unknown"
        headers = dict(scope.get("headers", []))
        
        # Include relevant headers in the identifier
        forwarded_for = headers.get(b"x-forwarded-for", b"").decode()
        real_ip = headers.get(b"x-real-ip", b"").decode()
        
        # Create a unique identifier based on available information
        identifier_parts = [
            str(client),
            forwarded_for,
            real_ip,
            headers.get(b"user-agent", b"").decode()
        ]
        
        identifier = hashlib.sha256(
            json.dumps(identifier_parts).encode()
        ).hexdigest()
        
        return identifier
    
    async def check_rate_limit(
        self,
        scope: Dict,
        receive: Any,
        send: Any
    ) -> bool:
        """
        Check if the request should be rate limited.
        Returns True if request is allowed, False if rate limited.
        """
        path = scope["path"]
        
        # Skip rate limiting for excluded paths
        if path in self.exclude_paths:
            return True
        
        client_id = self._get_client_identifier(scope)
        now = time.time()
        
        state = self.storage[client_id][path]
        limit = min(self.get_limit_for_path(path), self.burst_size)
        
        if self.strategy == "token_bucket":
            return await self._check_token_bucket(state, now, limit)
        elif self.strategy == "sliding_window":
            return await self._check_sliding_window(state, now, limit)
        else:  # fixed_window
            return await self._check_fixed_window(state, now, limit)
    
    async def _check_token_bucket(
        self,
        state: RateLimitState,
        now: float,
        limit: int
    ) -> bool:
        """
        Token bucket rate limiting algorithm.
        """
        # Calculate tokens to add based on time passed
        time_passed = now - state.last_request
        new_tokens = time_passed * self.rate
        
        # Update token count
        state.tokens = min(
            self.burst_size,
            state.tokens + new_tokens
        )
        
        if state.tokens >= 1:
            state.tokens -= 1
            state.last_request = now
            return True
        
        return False
    
    async def _check_sliding_window(
        self,
        state: RateLimitState,
        now: float,
        limit: int
    ) -> bool:
        """
        Sliding window rate limiting algorithm.
        """
        # Initialize window if not set
        if state.window_start == 0:
            state.window_start = now
            state.requests = 0
            state.previous_requests = 0
        
        # Calculate time elapsed since window start
        elapsed = now - state.window_start
        
        # If window has expired, slide to new window
        if elapsed >= self.window_size:
            # Save current window's requests for weighting
            state.previous_requests = state.requests
            
            # Start new window
            state.window_start = now - (elapsed % self.window_size)
            state.requests = 0
        
        # Calculate the weight of the previous window
        weight = max(0, 1 - (elapsed / self.window_size))
        weighted_previous = int(state.previous_requests * weight)
        
        # Calculate total requests including current window and weighted previous
        total_requests = state.requests + weighted_previous
        
        # Check if adding this request would exceed the limit
        if total_requests >= limit:
            return False
        
        # Update request count
        state.requests += 1
        state.last_request = now
        return True
    
    async def _check_fixed_window(
        self,
        state: RateLimitState,
        now: float,
        limit: int
    ) -> bool:
        """
        Fixed window rate limiting algorithm.
        """
        # Calculate window boundaries
        window_start = int(now / self.window_size) * self.window_size
        
        # Reset if in new window
        if window_start > state.window_start:
            state.window_start = window_start
            state.requests = 0
        
        # Check if limit is exceeded
        if state.requests >= limit:
            return False
        
        state.requests += 1
        state.last_request = now
        return True
    
    async def __call__(
        self,
        scope: Dict,
        receive: Any,
        send: Any
    ) -> None:
        """
        ASGI middleware implementation.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        allowed = await self.check_rate_limit(scope, receive, send)
        
        if not allowed:
            # Return 429 Too Many Requests
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"retry-after", str(self.window_size).encode())
                ]
            })
            
            await send({
                "type": "http.response.body",
                "body": json.dumps({
                    "error": "Rate limit exceeded",
                    "retry_after": self.window_size
                }).encode()
            })
            return
        
        await self.app(scope, receive, send)
    
    def wrap(self, app: Any) -> "RateLimiter":
        """
        Wrap an ASGI application with rate limiting middleware.
        """
        self.app = app
        return self
