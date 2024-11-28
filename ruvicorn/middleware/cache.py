"""
Enhanced caching middleware implementation.
"""

import time
import json
import hashlib
from typing import Dict, Optional, Any, Tuple, Set, List
from dataclasses import dataclass
from datetime import datetime, timedelta
import asyncio
from urllib.parse import urlparse, parse_qs

@dataclass
class CacheEntry:
    """Represents a cached response."""
    content: bytes
    headers: list
    status: int
    created_at: float
    expires_at: float
    etag: str
    vary_headers: Dict[str, str]

class CacheControl:
    """
    Enhanced caching middleware with support for various caching strategies
    and cache control directives.
    """
    
    def __init__(
        self,
        max_age: int = 300,  # 5 minutes default
        strategies: Optional[Dict[str, Dict[str, Any]]] = None,
        include_query_params: bool = True,
        ignore_query_params: Optional[Set[str]] = None,
        vary_headers: Optional[Set[str]] = None,
        storage_backend: Optional[Any] = None,
        cache_control_header: Optional[str] = None
    ):
        self.max_age = max_age
        self.strategies = strategies or {}
        self.include_query_params = include_query_params
        self.ignore_query_params = ignore_query_params or set()
        self.vary_headers = vary_headers or {"accept", "accept-encoding"}
        self.storage = storage_backend or {}
        self.cache_control_header = cache_control_header
        
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self) -> None:
        """Start the cache middleware and cleanup task."""
        if self._running:
            return
            
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def stop(self) -> None:
        """Stop the cache middleware and cleanup task."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
    
    async def _cleanup_loop(self) -> None:
        """Periodically clean up expired cache entries."""
        while self._running:
            try:
                now = time.time()
                
                # Remove expired entries
                expired_keys = [
                    key for key, entry in self.storage.items()
                    if entry.expires_at <= now
                ]
                
                for key in expired_keys:
                    del self.storage[key]
                
                await asyncio.sleep(60)  # Cleanup every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in cache cleanup: {e}")
                await asyncio.sleep(60)
    
    def _get_cache_key(
        self,
        scope: Dict,
        vary_values: Dict[str, str]
    ) -> str:
        """Generate a unique cache key for the request."""
        path = scope["path"]
        method = scope["method"]
        
        # Handle query parameters
        if self.include_query_params:
            query_string = scope.get("query_string", b"").decode()
            if query_string:
                parsed_qs = parse_qs(query_string)
                # Remove ignored query parameters
                filtered_qs = {
                    k: v for k, v in parsed_qs.items()
                    if k not in self.ignore_query_params
                }
                if filtered_qs:
                    path = f"{path}?{json.dumps(filtered_qs, sort_keys=True)}"
        
        # Include vary headers in the cache key
        vary_part = json.dumps(vary_values, sort_keys=True)
        
        key_parts = [method, path, vary_part]
        return hashlib.sha256(
            json.dumps(key_parts).encode()
        ).hexdigest()
    
    def _get_vary_values(self, scope: Dict) -> Dict[str, str]:
        """Extract values for headers specified in Vary."""
        headers = dict(scope.get("headers", []))
        return {
            header: headers.get(header.encode(), b"").decode()
            for header in self.vary_headers
        }
    
    def _get_cache_strategy(self, path: str) -> Dict[str, Any]:
        """Get the caching strategy for a path."""
        # Check for exact path match
        if path in self.strategies:
            return self.strategies[path]
        
        # Check for pattern matches
        for pattern, strategy in self.strategies.items():
            if pattern.endswith("*") and path.startswith(pattern[:-1]):
                return strategy
        
        # Return default strategy
        return {
            "max_age": self.max_age,
            "stale_while_revalidate": 0,
            "private": False,
            "immutable": False
        }
    
    def _generate_etag(self, content: bytes, headers: List[Tuple[bytes, bytes]]) -> str:
        """Generate an ETag for the response."""
        content_hash = hashlib.sha256(content).hexdigest()
        
        # Convert headers to a serializable format
        serializable_headers = [
            (k.decode(), v.decode())
            for k, v in headers
        ]
        
        headers_hash = hashlib.sha256(
            json.dumps(serializable_headers, sort_keys=True).encode()
        ).hexdigest()
        
        return f'"{content_hash[:8]}-{headers_hash[:8]}"'
    
    async def get_cached_response(
        self,
        scope: Dict
    ) -> Optional[CacheEntry]:
        """Get a cached response if available."""
        vary_values = self._get_vary_values(scope)
        cache_key = self._get_cache_key(scope, vary_values)
        
        entry = self.storage.get(cache_key)
        if not entry:
            return None
        
        now = time.time()
        if entry.expires_at <= now:
            # Check for stale-while-revalidate
            strategy = self._get_cache_strategy(scope["path"])
            stale_while_revalidate = strategy.get("stale_while_revalidate", 0)
            
            if stale_while_revalidate > 0:
                if entry.expires_at + stale_while_revalidate > now:
                    # Mark for background revalidation
                    asyncio.create_task(
                        self._revalidate_cache_entry(scope, cache_key)
                    )
                    return entry
            
            del self.storage[cache_key]
            return None
        
        return entry
    
    async def cache_response(
        self,
        scope: Dict,
        status: int,
        headers: list,
        content: bytes
    ) -> None:
        """Cache a response."""
        if not self._should_cache_response(scope, status, headers):
            return
        
        strategy = self._get_cache_strategy(scope["path"])
        max_age = strategy.get("max_age", self.max_age)
        
        vary_values = self._get_vary_values(scope)
        cache_key = self._get_cache_key(scope, vary_values)
        
        now = time.time()
        entry = CacheEntry(
            content=content,
            headers=headers,
            status=status,
            created_at=now,
            expires_at=now + max_age,
            etag=self._generate_etag(content, headers),
            vary_headers=vary_values
        )
        
        self.storage[cache_key] = entry
    
    def _should_cache_response(
        self,
        scope: Dict,
        status: int,
        headers: list
    ) -> bool:
        """Determine if a response should be cached."""
        if scope["method"] != "GET":
            return False
        
        if status != 200:
            return False
        
        headers_dict = dict(headers)
        cache_control = headers_dict.get(b"cache-control", b"").decode()
        
        if "no-store" in cache_control or "no-cache" in cache_control:
            return False
        
        return True
    
    async def _revalidate_cache_entry(
        self,
        scope: Dict,
        cache_key: str
    ) -> None:
        """Revalidate a stale cache entry in the background."""
        try:
            # Create a new request to revalidate
            headers = dict(scope.get("headers", []))
            if cache_key in self.storage:
                entry = self.storage[cache_key]
                headers[b"if-none-match"] = entry.etag.encode()
            
            # TODO: Implement actual revalidation logic here
            # This would involve making a new request to the origin
            pass
        except Exception as e:
            print(f"Error revalidating cache entry: {e}")
    
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
        
        # Check cache for GET requests
        if scope["method"] == "GET":
            cached = await self.get_cached_response(scope)
            if cached:
                # Return cached response
                await send({
                    "type": "http.response.start",
                    "status": cached.status,
                    "headers": cached.headers + [
                        (b"x-cache", b"HIT"),
                        (b"etag", cached.etag.encode())
                    ]
                })
                await send({
                    "type": "http.response.body",
                    "body": cached.content
                })
                return
        
        # Capture the response to potentially cache it
        response_started = False
        response_body = []
        response_status = 200
        response_headers = []
        
        async def send_wrapper(message):
            nonlocal response_started, response_status, response_headers
            
            if message["type"] == "http.response.start":
                response_started = True
                response_status = message["status"]
                response_headers = message["headers"]
            elif message["type"] == "http.response.body":
                response_body.append(message.get("body", b""))
            
            await send(message)
        
        await self.app(scope, receive, send_wrapper)
        
        # Cache the response if appropriate
        if response_started and response_body:
            content = b"".join(response_body)
            await self.cache_response(
                scope,
                response_status,
                response_headers,
                content
            )
    
    def wrap(self, app: Any) -> "CacheControl":
        """Wrap an ASGI application with caching middleware."""
        self.app = app
        return self
