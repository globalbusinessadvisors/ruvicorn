"""
JWT authentication middleware implementation.
"""

import jwt
import time
import hashlib
from typing import Dict, Optional, List, Set, Any, Callable
from datetime import datetime, timedelta
import json
import logging
from dataclasses import dataclass
import asyncio
from jwt.exceptions import (
    InvalidTokenError,
    ExpiredSignatureError,
    InvalidAlgorithmError
)

class AuthenticationError(Exception):
    """Base class for authentication errors."""
    pass

class InvalidToken(AuthenticationError):
    """Raised when token is invalid."""
    pass

class TokenExpired(AuthenticationError):
    """Raised when token has expired."""
    pass

class InsufficientScope(AuthenticationError):
    """Raised when token lacks required scope."""
    pass

@dataclass
class TokenBlacklist:
    """Manages blacklisted tokens."""
    tokens: Set[str] = None
    expiry_times: Dict[str, float] = None
    
    def __post_init__(self):
        self.tokens = set()
        self.expiry_times = {}
    
    def add(self, token: str, expires_at: float):
        """Add a token to the blacklist."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        self.tokens.add(token_hash)
        self.expiry_times[token_hash] = expires_at
    
    def is_blacklisted(self, token: str) -> bool:
        """Check if a token is blacklisted."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return token_hash in self.tokens
    
    def cleanup(self):
        """Remove expired tokens from blacklist."""
        now = time.time()
        expired = {
            token for token, expires_at in self.expiry_times.items()
            if expires_at <= now
        }
        self.tokens -= expired
        for token in expired:
            del self.expiry_times[token]

class JWTAuth:
    """
    Enhanced JWT authentication middleware with support for
    multiple token types and authorization scopes.
    """
    
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        token_prefix: str = "Bearer",
        access_token_expires: int = 3600,  # 1 hour
        refresh_token_expires: int = 86400,  # 24 hours
        scopes: Optional[Dict[str, List[str]]] = None,
        exempt_paths: Optional[Set[str]] = None,
        on_auth_error: Optional[Callable] = None,
        token_blacklist: Optional[TokenBlacklist] = None
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.token_prefix = token_prefix
        self.access_token_expires = access_token_expires
        self.refresh_token_expires = refresh_token_expires
        self.scopes = scopes or {}
        self.exempt_paths = exempt_paths or set()
        self.on_auth_error = on_auth_error
        self.blacklist = token_blacklist or TokenBlacklist()
        
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        self.logger = logging.getLogger("ruvicorn.auth")
    
    async def start(self) -> None:
        """Start the authentication middleware and cleanup task."""
        if self._running:
            return
            
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def stop(self) -> None:
        """Stop the authentication middleware and cleanup task."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
    
    async def _cleanup_loop(self) -> None:
        """Periodically clean up blacklisted tokens."""
        while self._running:
            try:
                self.blacklist.cleanup()
                await asyncio.sleep(300)  # Clean up every 5 minutes
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in token cleanup: {e}")
                await asyncio.sleep(300)
    
    def create_token(
        self,
        subject: str,
        token_type: str = "access",
        scopes: Optional[List[str]] = None,
        extra_claims: Optional[Dict] = None
    ) -> str:
        """Create a new JWT token."""
        now = datetime.utcnow()
        
        expires_in = (
            self.refresh_token_expires
            if token_type == "refresh"
            else self.access_token_expires
        )
        
        claims = {
            "sub": subject,
            "type": token_type,
            "iat": now,
            "exp": now + timedelta(seconds=expires_in),
            "jti": hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
        }
        
        if scopes:
            claims["scope"] = " ".join(scopes)
        
        if extra_claims:
            claims.update(extra_claims)
        
        return jwt.encode(
            claims,
            self.secret_key,
            algorithm=self.algorithm
        )
    
    def decode_token(self, token: str) -> Dict:
        """Decode and validate a JWT token."""
        try:
            # First verify the token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            
            # Then check if it's blacklisted
            if self.blacklist.is_blacklisted(token):
                raise InvalidToken("Token has been blacklisted")
            
            return payload
        except ExpiredSignatureError:
            raise TokenExpired("Token has expired")
        except InvalidAlgorithmError:
            raise InvalidToken("Invalid token algorithm")
        except InvalidTokenError as e:
            raise InvalidToken(str(e))
    
    def blacklist_token(self, token: str) -> None:
        """Add a token to the blacklist."""
        try:
            # First verify the token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            expires_at = datetime.fromtimestamp(payload["exp"]).timestamp()
            self.blacklist.add(token, expires_at)
        except Exception:
            pass  # Don't blacklist invalid tokens
    
    def check_scope(
        self,
        required_scope: str,
        token_scopes: List[str]
    ) -> bool:
        """
        Check if the token has the required scope.
        Handles scope inheritance (e.g., 'admin' includes all scopes).
        """
        if not required_scope:
            return True
        
        for scope in token_scopes:
            # Check direct match
            if scope == required_scope:
                return True
            
            # Check inherited scopes
            if scope in self.scopes:
                if required_scope in self.scopes[scope]:
                    return True
        
        return False
    
    def _get_token_from_header(self, headers: Dict) -> Optional[str]:
        """Extract token from Authorization header."""
        auth_header = headers.get(b"authorization", b"").decode()
        
        if not auth_header:
            return None
        
        parts = auth_header.split()
        
        if len(parts) != 2 or parts[0] != self.token_prefix:
            return None
        
        return parts[1]
    
    async def authenticate(self, scope: Dict) -> Dict:
        """Authenticate a request and return the token payload."""
        headers = dict(scope.get("headers", []))
        token = self._get_token_from_header(headers)
        
        if not token:
            raise InvalidToken("No token provided")
        
        return self.decode_token(token)
    
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
        
        path = scope["path"]
        
        # Skip authentication for exempt paths
        if path in self.exempt_paths:
            await self.app(scope, receive, send)
            return
        
        try:
            payload = await self.authenticate(scope)
            
            # Add user information to scope
            scope["user"] = payload
            
            # Check required scope if specified in path config
            required_scope = getattr(self.app, "required_scope", None)
            if required_scope:
                token_scopes = payload.get("scope", "").split()
                if not self.check_scope(required_scope, token_scopes):
                    raise InsufficientScope(
                        f"Token lacks required scope: {required_scope}"
                    )
            
            await self.app(scope, receive, send)
            
        except AuthenticationError as e:
            response = {
                "error": e.__class__.__name__,
                "message": str(e)
            }
            
            if self.on_auth_error:
                await self.on_auth_error(scope, e)
            
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", f"{self.token_prefix} realm='API'".encode())
                ]
            })
            
            await send({
                "type": "http.response.body",
                "body": json.dumps(response).encode()
            })
    
    def wrap(self, app: Any) -> "JWTAuth":
        """Wrap an ASGI application with JWT authentication middleware."""
        self.app = app
        return self
    
    def requires_scope(self, scope: str) -> Callable:
        """
        Decorator to specify required scope for a route.
        
        @app.route("/admin")
        @jwt_auth.requires_scope("admin")
        async def admin_route():
            ...
        """
        def decorator(f):
            setattr(f, "required_scope", scope)
            return f
        return decorator
