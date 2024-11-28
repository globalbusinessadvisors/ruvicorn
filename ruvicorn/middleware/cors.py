"""
Enhanced CORS (Cross-Origin Resource Sharing) middleware implementation.
"""

from typing import List, Set, Dict, Optional, Any, Union
import re
from urllib.parse import urlparse
import json

class CORSConfig:
    """
    Enhanced CORS middleware with comprehensive configuration options
    and dynamic origin validation.
    """
    
    def __init__(
        self,
        allow_origins: Union[List[str], str] = "*",
        allow_methods: List[str] = None,
        allow_headers: List[str] = None,
        allow_credentials: bool = False,
        expose_headers: List[str] = None,
        max_age: int = 600,
        allow_origin_regex: Optional[str] = None,
        allow_private_network: bool = False,
        origin_whitelist: Optional[Set[str]] = None,
        debug: bool = False
    ):
        self.allow_origins = (
            [allow_origins]
            if isinstance(allow_origins, str)
            else allow_origins
        )
        self.allow_methods = allow_methods or [
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
        ]
        self.allow_headers = allow_headers or [
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Content-Type",
            "Authorization"
        ]
        self.allow_credentials = allow_credentials
        self.expose_headers = expose_headers or []
        self.max_age = max_age
        self.allow_origin_regex = (
            re.compile(allow_origin_regex)
            if allow_origin_regex
            else None
        )
        self.allow_private_network = allow_private_network
        self.origin_whitelist = origin_whitelist or set()
        self.debug = debug
    
    def is_origin_allowed(self, origin: str) -> bool:
        """
        Check if the given origin is allowed based on configuration.
        """
        if "*" in self.allow_origins:
            return True
        
        if origin in self.allow_origins:
            return True
        
        if origin in self.origin_whitelist:
            return True
        
        if self.allow_origin_regex and self.allow_origin_regex.match(origin):
            return True
        
        # Parse the origin URL
        try:
            parsed_origin = urlparse(origin)
            origin_domain = parsed_origin.netloc.lower()
            
            # Remove port if present
            if ":" in origin_domain:
                origin_domain = origin_domain.split(":")[0]
            
            # Check wildcard domains
            for allowed in self.allow_origins:
                if allowed.startswith("*."):
                    # Extract the base domain from the wildcard pattern
                    base_domain = allowed[2:]
                    
                    # Check if the origin domain ends with the base domain
                    # and has a dot before it to ensure it's a proper subdomain
                    if (origin_domain.endswith(base_domain) and 
                        len(origin_domain) > len(base_domain) and
                        origin_domain[-(len(base_domain) + 1)] == '.'):
                        return True
                elif allowed.startswith("https://*.") or allowed.startswith("http://*."):
                    # Handle legacy format with scheme included
                    scheme, _, pattern = allowed.partition("://")
                    base_domain = pattern[2:]  # Remove *. prefix
                    
                    if (parsed_origin.scheme == scheme and
                        origin_domain.endswith(base_domain) and 
                        len(origin_domain) > len(base_domain) and
                        origin_domain[-(len(base_domain) + 1)] == '.'):
                        return True
        except Exception:
            return False
        
        return False
    
    def is_private_network_request(self, headers: Dict[bytes, bytes]) -> bool:
        """
        Check if the request is from a private network.
        """
        return (
            b"access-control-request-private-network" in headers or
            headers.get(b"origin", b"").startswith((b"http://192.168.", b"http://10."))
        )
    
    def get_preflight_headers(
        self,
        origin: str,
        request_method: Optional[str] = None,
        request_headers: Optional[List[str]] = None,
        is_private_network: bool = False
    ) -> List[tuple]:
        """
        Generate headers for CORS preflight response.
        """
        headers = []
        
        # Basic CORS headers
        headers.append((b"access-control-allow-origin", origin.encode()))
        
        if self.allow_credentials:
            headers.append((b"access-control-allow-credentials", b"true"))
        
        if request_method and request_method in self.allow_methods:
            headers.append((
                b"access-control-allow-methods",
                ", ".join(self.allow_methods).encode()
            ))
        
        if request_headers:
            allowed_headers = [
                h for h in request_headers
                if h.lower() in [h2.lower() for h2 in self.allow_headers]
            ]
            if allowed_headers:
                headers.append((
                    b"access-control-allow-headers",
                    ", ".join(allowed_headers).encode()
                ))
        
        if self.expose_headers:
            headers.append((
                b"access-control-expose-headers",
                ", ".join(self.expose_headers).encode()
            ))
        
        if self.max_age is not None:
            headers.append((
                b"access-control-max-age",
                str(self.max_age).encode()
            ))
        
        if is_private_network and self.allow_private_network:
            headers.append((
                b"access-control-allow-private-network",
                b"true"
            ))
        
        # Add Vary header
        vary_headers = ["Origin"]
        if request_headers:
            vary_headers.append("Access-Control-Request-Headers")
        headers.append((
            b"vary",
            ", ".join(vary_headers).encode()
        ))
        
        return headers
    
    def get_response_headers(
        self,
        origin: str,
        is_private_network: bool = False
    ) -> List[tuple]:
        """
        Generate headers for CORS response.
        """
        headers = []
        
        headers.append((b"access-control-allow-origin", origin.encode()))
        
        if self.allow_credentials:
            headers.append((b"access-control-allow-credentials", b"true"))
        
        if self.expose_headers:
            headers.append((
                b"access-control-expose-headers",
                ", ".join(self.expose_headers).encode()
            ))
        
        if is_private_network and self.allow_private_network:
            headers.append((
                b"access-control-allow-private-network",
                b"true"
            ))
        
        # Add Vary header
        headers.append((b"vary", b"Origin"))
        
        return headers
    
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
        
        headers = dict(scope.get("headers", []))
        origin = headers.get(b"origin", b"").decode()
        
        if not origin:
            await self.app(scope, receive, send)
            return
        
        if not self.is_origin_allowed(origin):
            if self.debug:
                print(f"Origin not allowed: {origin}")
            response = {
                "error": "Origin not allowed",
                "message": f"The origin '{origin}' is not allowed to access this resource"
            }
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [(b"content-type", b"application/json")]
            })
            await send({
                "type": "http.response.body",
                "body": json.dumps(response).encode()
            })
            return
        
        is_private_network = self.is_private_network_request(headers)
        
        if scope["method"] == "OPTIONS":
            # Handle CORS preflight request
            request_method = headers.get(
                b"access-control-request-method", b""
            ).decode()
            request_headers = headers.get(
                b"access-control-request-headers", b""
            ).decode()
            
            if request_headers:
                request_headers = [
                    h.strip() for h in request_headers.split(",")
                ]
            
            preflight_headers = self.get_preflight_headers(
                origin,
                request_method,
                request_headers,
                is_private_network
            )
            
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": preflight_headers
            })
            await send({
                "type": "http.response.body",
                "body": b""
            })
            return
        
        # Handle actual request
        response_started = False
        
        async def send_wrapper(message):
            nonlocal response_started
            
            if message["type"] == "http.response.start":
                response_started = True
                headers = message.get("headers", [])
                cors_headers = self.get_response_headers(
                    origin,
                    is_private_network
                )
                message["headers"] = headers + cors_headers
            
            await send(message)
        
        await self.app(scope, receive, send_wrapper)
    
    def wrap(self, app: Any) -> "CORSConfig":
        """Wrap an ASGI application with CORS middleware."""
        self.app = app
        return self
