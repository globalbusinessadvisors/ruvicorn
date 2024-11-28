import pytest
from datetime import datetime, timedelta
import jwt
import time
import asyncio
from typing import Optional

from ruvicorn.middleware.rate_limit import RateLimiter, RateLimitExceeded
from ruvicorn.middleware.cache import CacheControl, CacheEntry
from ruvicorn.middleware.auth import (
    JWTAuth,
    InvalidToken,
    TokenExpired,
    InsufficientScope,
    TokenBlacklist
)
from ruvicorn.middleware.cors import CORSConfig
from ruvicorn.middleware.security import SecurityHeaders

# Fixtures

@pytest.fixture
def mock_request():
    """Fixture to create a mock request object for testing middleware."""
    class MockRequest:
        def __init__(self, headers=None, client=None, method="GET", path="/"):
            self.headers = headers or {}
            self.client = client or {"host": "127.0.0.1"}
            self.method = method
            self.path = path
            
    return MockRequest

@pytest.fixture
def mock_response():
    """Fixture to create a mock response object for testing middleware."""
    class MockResponse:
        def __init__(self, status_code=200, headers=None, body=None):
            self.status_code = status_code
            self.headers = headers or {}
            self.body = body
            
    return MockResponse

@pytest.fixture
def mock_scope():
    """Fixture to create a mock ASGI scope."""
    return {
        "type": "http",
        "method": "GET",
        "path": "/api/test",
        "client": ("127.0.0.1", 12345),
        "headers": [
            (b"user-agent", b"test-client"),
            (b"x-forwarded-for", b"127.0.0.1"),
            (b"accept", b"application/json"),
            (b"accept-encoding", b"gzip")
        ]
    }

@pytest.fixture
def jwt_auth():
    """Fixture to create a JWT auth instance."""
    return JWTAuth(
        secret_key="test_secret",
        algorithm="HS256",
        scopes={
            "admin": ["read", "write", "delete"],
            "user": ["read", "write"],
            "guest": ["read"]
        }
    )

@pytest.fixture
def cors_config():
    """Fixture to create a CORS config instance."""
    return CORSConfig(
        allow_origins=["https://example.com", "*.test.com"],
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        allow_credentials=True,
        expose_headers=["X-Custom-Header"],
        max_age=3600,
        allow_origin_regex=r"^https://api-\w+\.example\.com$",
        allow_private_network=True
    )

@pytest.fixture
def security_headers():
    """Fixture to create a SecurityHeaders instance."""
    return SecurityHeaders(
        hsts_enabled=True,
        hsts_max_age=31536000,
        content_security_policy={
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
            "connect-src": ["'self'", "https://api.example.com"]
        },
        permissions_policy={
            "geolocation": ["self"],
            "camera": [],
            "microphone": [],
            "payment": ["https://payment.example.com"]
        },
        trusted_types=True,
        trusted_types_policies=["default", "escape"],
        expect_ct=True,
        expect_ct_report_uri="https://report.example.com/ct"
    )

# Rate Limiter Tests

async def test_rate_limiter_sliding_window(mock_scope):
    """Test rate limiting with sliding window strategy."""
    rate_limiter = RateLimiter(
        requests_per_minute=60,
        burst_size=5,
        strategy="sliding_window"
    )
    
    # Test normal request flow within limits
    for _ in range(5):
        allowed = await rate_limiter.check_rate_limit(mock_scope, None, None)
        assert allowed is True
    
    # Test rate limit exceeded
    mock_scope["path"] = "/api/test"  # Reset path to ensure same rate limit applies
    allowed = await rate_limiter.check_rate_limit(mock_scope, None, None)
    assert allowed is False

async def test_rate_limiter_token_bucket(mock_scope):
    """Test rate limiting with token bucket strategy."""
    rate_limiter = RateLimiter(
        requests_per_minute=60,
        burst_size=3,
        strategy="token_bucket"
    )
    
    # Test burst handling
    for _ in range(3):  # Should allow burst up to burst_size
        allowed = await rate_limiter.check_rate_limit(mock_scope, None, None)
        assert allowed is True
    
    # Should be rate limited after burst
    allowed = await rate_limiter.check_rate_limit(mock_scope, None, None)
    assert allowed is False
    
    # Wait for token replenishment
    await asyncio.sleep(2)
    allowed = await rate_limiter.check_rate_limit(mock_scope, None, None)
    assert allowed is True

async def test_rate_limiter_path_specific(mock_scope):
    """Test path-specific rate limiting."""
    rate_limiter = RateLimiter(
        requests_per_minute=60,
        path_limits={
            "/api/limited": 2,
            "/api/public": 1000
        }
    )
    
    # Test limited path
    mock_scope["path"] = "/api/limited"
    for _ in range(2):
        allowed = await rate_limiter.check_rate_limit(mock_scope, None, None)
        assert allowed is True
    
    allowed = await rate_limiter.check_rate_limit(mock_scope, None, None)
    assert allowed is False
    
    # Test public path
    mock_scope["path"] = "/api/public"
    for _ in range(5):  # Should allow more requests
        allowed = await rate_limiter.check_rate_limit(mock_scope, None, None)
        assert allowed is True

async def test_rate_limiter_excluded_paths(mock_scope):
    """Test rate limiting with excluded paths."""
    rate_limiter = RateLimiter(
        requests_per_minute=1,  # Very restrictive
        exclude_paths={"/health", "/metrics"}
    )
    
    # Test excluded path
    mock_scope["path"] = "/health"
    for _ in range(10):  # Should allow all requests
        allowed = await rate_limiter.check_rate_limit(mock_scope, None, None)
        assert allowed is True
    
    # Test non-excluded path
    mock_scope["path"] = "/api/test"
    allowed = await rate_limiter.check_rate_limit(mock_scope, None, None)
    assert allowed is True
    allowed = await rate_limiter.check_rate_limit(mock_scope, None, None)
    assert allowed is False

# Cache Control Tests

async def test_cache_basic_operations(mock_scope):
    """Test basic cache operations."""
    cache = CacheControl(max_age=300)  # 5 minutes cache
    
    # Initially should have no cached response
    cached = await cache.get_cached_response(mock_scope)
    assert cached is None
    
    # Cache a response
    content = b'{"data": "test"}'
    headers = [(b"content-type", b"application/json")]
    await cache.cache_response(mock_scope, 200, headers, content)
    
    # Should now get cached response
    cached = await cache.get_cached_response(mock_scope)
    assert cached is not None
    assert cached.content == content
    assert cached.status == 200
    assert cached.headers == headers

async def test_cache_vary_headers(mock_scope):
    """Test caching with vary headers."""
    cache = CacheControl(
        max_age=300,
        vary_headers={"accept", "accept-encoding"}
    )
    
    content = b'{"data": "test"}'
    headers = [(b"content-type", b"application/json")]
    
    # Cache with original headers
    await cache.cache_response(mock_scope, 200, headers, content)
    
    # Should get cache hit with same headers
    cached = await cache.get_cached_response(mock_scope)
    assert cached is not None
    
    # Modify accept header
    mock_scope["headers"] = [
        (b"user-agent", b"test-client"),
        (b"accept", b"text/html"),  # Changed accept header
        (b"accept-encoding", b"gzip")
    ]
    
    # Should get cache miss with different headers
    cached = await cache.get_cached_response(mock_scope)
    assert cached is None

async def test_cache_strategies(mock_scope):
    """Test different caching strategies."""
    cache = CacheControl(
        max_age=300,
        strategies={
            "/api/static": {"max_age": 3600, "immutable": True},
            "/api/dynamic": {"max_age": 60, "stale_while_revalidate": 30}
        }
    )
    
    # Test static content path
    mock_scope["path"] = "/api/static"
    content = b'{"data": "static"}'
    headers = [(b"content-type", b"application/json")]
    await cache.cache_response(mock_scope, 200, headers, content)
    
    cached = await cache.get_cached_response(mock_scope)
    assert cached is not None
    assert cached.expires_at - cached.created_at == 3600  # 1 hour
    
    # Test dynamic content path
    mock_scope["path"] = "/api/dynamic"
    content = b'{"data": "dynamic"}'
    await cache.cache_response(mock_scope, 200, headers, content)
    
    cached = await cache.get_cached_response(mock_scope)
    assert cached is not None
    assert cached.expires_at - cached.created_at == 60  # 1 minute

async def test_cache_query_params(mock_scope):
    """Test caching with query parameters."""
    cache = CacheControl(
        max_age=300,
        include_query_params=True,
        ignore_query_params={"_t"}  # Ignore timestamp parameter
    )
    
    # Add query parameters to scope
    mock_scope["query_string"] = b"id=123&_t=1234567"
    
    content = b'{"data": "test"}'
    headers = [(b"content-type", b"application/json")]
    await cache.cache_response(mock_scope, 200, headers, content)
    
    # Should get cache hit with same relevant query params
    cached = await cache.get_cached_response(mock_scope)
    assert cached is not None
    
    # Change ignored query param
    mock_scope["query_string"] = b"id=123&_t=7654321"
    cached = await cache.get_cached_response(mock_scope)
    assert cached is not None  # Should still hit cache
    
    # Change relevant query param
    mock_scope["query_string"] = b"id=456&_t=1234567"
    cached = await cache.get_cached_response(mock_scope)
    assert cached is None  # Should miss cache

# JWT Auth Tests

async def test_jwt_token_creation(jwt_auth):
    """Test JWT token creation and validation."""
    # Create access token
    token = jwt_auth.create_token(
        subject="user123",
        token_type="access",
        scopes=["read", "write"]
    )
    
    # Decode and validate token
    payload = jwt_auth.decode_token(token)
    assert payload["sub"] == "user123"
    assert payload["type"] == "access"
    assert "read write" in payload["scope"]

async def test_jwt_token_expiration(jwt_auth):
    """Test JWT token expiration."""
    # Create token with very short expiration
    jwt_auth.access_token_expires = 1  # 1 second
    token = jwt_auth.create_token(subject="user123")
    
    # Token should be valid initially
    payload = jwt_auth.decode_token(token)
    assert payload["sub"] == "user123"
    
    # Wait for token to expire
    await asyncio.sleep(2)
    
    # Token should now be expired
    with pytest.raises(TokenExpired):
        jwt_auth.decode_token(token)

async def test_jwt_scope_checking(jwt_auth):
    """Test JWT scope-based authorization."""
    # Create token with admin scope
    admin_token = jwt_auth.create_token(
        subject="admin123",
        scopes=["admin"]
    )
    
    # Create token with user scope
    user_token = jwt_auth.create_token(
        subject="user123",
        scopes=["user"]
    )
    
    # Admin token should have access to all scopes
    admin_payload = jwt_auth.decode_token(admin_token)
    assert jwt_auth.check_scope("delete", admin_payload["scope"].split())
    
    # User token should not have access to admin scopes
    user_payload = jwt_auth.decode_token(user_token)
    assert not jwt_auth.check_scope("delete", user_payload["scope"].split())
    assert jwt_auth.check_scope("write", user_payload["scope"].split())

async def test_jwt_token_blacklist(jwt_auth):
    """Test JWT token blacklisting."""
    # Create and blacklist a token
    token = jwt_auth.create_token(subject="user123")
    jwt_auth.blacklist_token(token)
    
    # Blacklisted token should be rejected
    with pytest.raises(InvalidToken):
        jwt_auth.decode_token(token)
    
    # New token should still work
    new_token = jwt_auth.create_token(subject="user123")
    payload = jwt_auth.decode_token(new_token)
    assert payload["sub"] == "user123"

async def test_jwt_authentication_middleware(jwt_auth, mock_scope):
    """Test JWT authentication middleware."""
    # Create a token and add it to request headers
    token = jwt_auth.create_token(subject="user123", scopes=["read"])
    mock_scope["headers"].append(
        (b"authorization", f"Bearer {token}".encode())
    )
    
    # Authentication should succeed
    payload = await jwt_auth.authenticate(mock_scope)
    assert payload["sub"] == "user123"
    
    # Test invalid token
    mock_scope["headers"][-1] = (
        b"authorization",
        b"Bearer invalid.token.here"
    )
    with pytest.raises(InvalidToken):
        await jwt_auth.authenticate(mock_scope)
    
    # Test missing token
    mock_scope["headers"] = mock_scope["headers"][:-1]  # Remove auth header
    with pytest.raises(InvalidToken):
        await jwt_auth.authenticate(mock_scope)

# CORS Tests

def test_cors_origin_validation(cors_config):
    """Test CORS origin validation."""
    # Test exact match
    assert cors_config.is_origin_allowed("https://example.com") is True
    
    # Test wildcard subdomain
    assert cors_config.is_origin_allowed("https://api.test.com") is True
    assert cors_config.is_origin_allowed("https://dev.test.com") is True
    
    # Test regex pattern
    assert cors_config.is_origin_allowed("https://api-prod.example.com") is True
    assert cors_config.is_origin_allowed("https://api-dev.example.com") is True
    
    # Test disallowed origins
    assert cors_config.is_origin_allowed("https://malicious.com") is False
    assert cors_config.is_origin_allowed("http://example.com") is False  # Wrong protocol

def test_cors_preflight_headers(cors_config):
    """Test CORS preflight response headers."""
    headers = cors_config.get_preflight_headers(
        origin="https://example.com",
        request_method="POST",
        request_headers=["Authorization", "Content-Type"],
        is_private_network=True
    )
    
    headers_dict = dict(headers)
    
    # Check basic CORS headers
    assert headers_dict[b"access-control-allow-origin"] == b"https://example.com"
    assert headers_dict[b"access-control-allow-credentials"] == b"true"
    assert b"GET" in headers_dict[b"access-control-allow-methods"]
    assert b"POST" in headers_dict[b"access-control-allow-methods"]
    
    # Check allowed headers
    assert b"Authorization" in headers_dict[b"access-control-allow-headers"]
    assert b"Content-Type" in headers_dict[b"access-control-allow-headers"]
    
    # Check private network
    assert headers_dict[b"access-control-allow-private-network"] == b"true"
    
    # Check max age
    assert headers_dict[b"access-control-max-age"] == b"3600"

def test_cors_response_headers(cors_config):
    """Test CORS actual response headers."""
    headers = cors_config.get_response_headers(
        origin="https://example.com",
        is_private_network=True
    )
    
    headers_dict = dict(headers)
    
    # Check response headers
    assert headers_dict[b"access-control-allow-origin"] == b"https://example.com"
    assert headers_dict[b"access-control-allow-credentials"] == b"true"
    assert b"X-Custom-Header" in headers_dict[b"access-control-expose-headers"]
    assert headers_dict[b"access-control-allow-private-network"] == b"true"
    assert headers_dict[b"vary"] == b"Origin"

async def test_cors_middleware_preflight(cors_config, mock_scope):
    """Test CORS middleware handling of preflight requests."""
    mock_scope["method"] = "OPTIONS"
    mock_scope["headers"] = [
        (b"origin", b"https://example.com"),
        (b"access-control-request-method", b"POST"),
        (b"access-control-request-headers", b"authorization, content-type"),
        (b"access-control-request-private-network", b"true")
    ]
    
    # Track sent responses
    sent_messages = []
    async def send(message):
        sent_messages.append(message)
    
    # Mock app that shouldn't be called for preflight
    async def app(scope, receive, send):
        assert False, "App should not be called for preflight"
    
    cors_config.app = app
    await cors_config(mock_scope, None, send)
    
    # Check preflight response
    assert len(sent_messages) == 2
    start_message = sent_messages[0]
    assert start_message["status"] == 200
    
    # Convert headers to dict for easier checking
    headers_dict = dict(start_message["headers"])
    assert headers_dict[b"access-control-allow-origin"] == b"https://example.com"
    assert headers_dict[b"access-control-allow-methods"]
    assert headers_dict[b"access-control-allow-headers"]
    assert headers_dict[b"access-control-allow-private-network"] == b"true"

async def test_cors_middleware_actual_request(cors_config, mock_scope):
    """Test CORS middleware handling of actual requests."""
    mock_scope["headers"] = [
        (b"origin", b"https://example.com"),
    ]
    
    # Track sent responses
    sent_messages = []
    async def send(message):
        sent_messages.append(message)
    
    # Mock app that returns a simple response
    async def app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")]
        })
        await send({
            "type": "http.response.body",
            "body": b'{"hello": "world"}'
        })
    
    cors_config.app = app
    await cors_config(mock_scope, None, send)
    
    # Check response
    assert len(sent_messages) == 2
    start_message = sent_messages[0]
    assert start_message["status"] == 200
    
    # Check CORS headers were added
    headers_dict = dict(start_message["headers"])
    assert headers_dict[b"access-control-allow-origin"] == b"https://example.com"
    assert headers_dict[b"access-control-allow-credentials"] == b"true"
    assert b"X-Custom-Header" in headers_dict[b"access-control-expose-headers"]

async def test_cors_middleware_disallowed_origin(cors_config, mock_scope):
    """Test CORS middleware rejection of disallowed origins."""
    mock_scope["headers"] = [
        (b"origin", b"https://malicious.com"),
    ]
    
    # Track sent responses
    sent_messages = []
    async def send(message):
        sent_messages.append(message)
    
    # Mock app that shouldn't be called
    async def app(scope, receive, send):
        assert False, "App should not be called for disallowed origin"
    
    cors_config.app = app
    await cors_config(mock_scope, None, send)
    
    # Check error response
    assert len(sent_messages) == 2
    start_message = sent_messages[0]
    assert start_message["status"] == 403

# Security Headers Tests

def test_security_headers_hsts(security_headers):
    """Test HSTS header generation."""
    headers = dict(security_headers.get_security_headers(is_https=True))
    
    hsts_header = headers[b"strict-transport-security"].decode()
    assert "max-age=31536000" in hsts_header
    assert "includeSubDomains" in hsts_header
    
    # HSTS should not be present for non-HTTPS requests
    headers = dict(security_headers.get_security_headers(is_https=False))
    assert b"strict-transport-security" not in headers

def test_security_headers_csp(security_headers):
    """Test Content Security Policy header generation."""
    headers = dict(security_headers.get_security_headers())
    
    csp_header = headers[b"content-security-policy"].decode()
    assert "default-src 'self'" in csp_header
    assert "script-src 'self' 'unsafe-inline'" in csp_header
    assert "img-src 'self' data: https:" in csp_header
    assert "connect-src 'self' https://api.example.com" in csp_header

def test_security_headers_permissions_policy(security_headers):
    """Test Permissions Policy header generation."""
    headers = dict(security_headers.get_security_headers())
    
    pp_header = headers[b"permissions-policy"].decode()
    assert "geolocation=(self)" in pp_header
    assert "camera=()" in pp_header
    assert "payment=(https://payment.example.com)" in pp_header

def test_security_headers_trusted_types(security_headers):
    """Test Trusted Types header generation."""
    headers = dict(security_headers.get_security_headers())
    
    tt_header = headers[b"trusted-types"].decode()
    assert "default" in tt_header
    assert "escape" in tt_header

def test_security_headers_expect_ct(security_headers):
    """Test Expect-CT header generation."""
    headers = dict(security_headers.get_security_headers())
    
    expect_ct_header = headers[b"expect-ct"].decode()
    assert "max-age=" in expect_ct_header
    assert "report-uri=\"https://report.example.com/ct\"" in expect_ct_header

def test_security_headers_defaults():
    """Test default security headers configuration."""
    headers = SecurityHeaders()
    header_dict = dict(headers.get_security_headers())
    
    # Check presence of default headers
    assert b"x-frame-options" in header_dict
    assert b"x-content-type-options" in header_dict
    assert b"x-xss-protection" in header_dict
    assert b"referrer-policy" in header_dict
    assert b"content-security-policy" in header_dict
    
    # Check default values
    assert header_dict[b"x-frame-options"] == b"DENY"
    assert header_dict[b"x-content-type-options"] == b"nosniff"
    assert header_dict[b"x-xss-protection"] == b"1; mode=block"

async def test_security_headers_middleware(security_headers, mock_scope):
    """Test security headers middleware integration."""
    mock_scope["scheme"] = "https"
    
    # Track sent responses
    sent_messages = []
    async def send(message):
        sent_messages.append(message)
    
    # Mock app that returns a simple response
    async def app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")]
        })
        await send({
            "type": "http.response.body",
            "body": b'{"hello": "world"}'
        })
    
    security_headers.app = app
    await security_headers(mock_scope, None, send)
    
    # Check response
    assert len(sent_messages) == 2
    start_message = sent_messages[0]
    assert start_message["status"] == 200
    
    # Convert headers to dict for easier checking
    headers_dict = dict(start_message["headers"])
    
    # Check security headers were added
    assert b"strict-transport-security" in headers_dict
    assert b"content-security-policy" in headers_dict
    assert b"x-frame-options" in headers_dict
    assert b"x-content-type-options" in headers_dict
    assert b"permissions-policy" in headers_dict

def test_security_headers_csp_report_only():
    """Test CSP Report-Only mode."""
    headers = SecurityHeaders(
        content_security_policy_report_only=True,
        content_security_policy_report_uri="https://report.example.com/csp"
    )
    
    header_dict = dict(headers.get_security_headers())
    
    # Check that CSP is in report-only mode
    assert b"content-security-policy-report-only" in header_dict
    assert b"content-security-policy" not in header_dict
    
    csp_header = header_dict[b"content-security-policy-report-only"].decode()
    assert "report-uri https://report.example.com/csp" in csp_header

def test_security_headers_cross_origin_policies():
    """Test cross-origin security policies."""
    headers = SecurityHeaders(
        cross_origin_embedder_policy=True,
        cross_origin_opener_policy=True,
        cross_origin_resource_policy="same-site"
    )
    
    header_dict = dict(headers.get_security_headers())
    
    assert header_dict[b"cross-origin-embedder-policy"] == b"require-corp"
    assert header_dict[b"cross-origin-opener-policy"] == b"same-origin"
    assert header_dict[b"cross-origin-resource-policy"] == b"same-site"
