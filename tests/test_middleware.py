"""
Tests for Ruvicorn middleware components.
"""

import pytest
import json
import time
import asyncio
import gzip
import brotli
from typing import Optional
from datetime import datetime, timedelta

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
from ruvicorn.middleware.validation import (
    ValidationMiddleware,
    RequestValidator,
    ValidationRule,
    ValidationType,
    ValidationError
)
from ruvicorn.middleware.health import HealthCheckMiddleware, HealthStatus
from ruvicorn.middleware.compression import CompressionMiddleware

# Rate Limiting Tests

@pytest.mark.asyncio
async def test_rate_limiter_basic():
    """Test basic rate limiting functionality."""
    limiter = RateLimiter(
        requests_per_minute=30,
        burst_size=5,
        strategy="sliding_window"
    )
    
    # Mock ASGI scope
    scope = {
        "type": "http",
        "path": "/test",
        "client": ("127.0.0.1", 8000),
        "headers": []
    }
    
    # Test initial requests within limit
    for _ in range(5):
        allowed = await limiter.check_rate_limit(scope, None, None)
        assert allowed is True
    
    # Test exceeding burst size
    allowed = await limiter.check_rate_limit(scope, None, None)
    assert allowed is False

@pytest.mark.asyncio
async def test_rate_limiter_strategies():
    """Test different rate limiting strategies."""
    strategies = ["token_bucket", "sliding_window", "fixed_window"]
    
    for strategy in strategies:
        limiter = RateLimiter(
            requests_per_minute=60,
            burst_size=3,
            strategy=strategy
        )
        
        scope = {
            "type": "http",
            "path": "/test",
            "client": ("127.0.0.1", 8000),
            "headers": []
        }
        
        # Test burst handling
        for _ in range(3):
            assert await limiter.check_rate_limit(scope, None, None) is True
        
        # Should be limited after burst
        assert await limiter.check_rate_limit(scope, None, None) is False
        
        # Wait for rate limit window to pass
        await asyncio.sleep(1)
        assert await limiter.check_rate_limit(scope, None, None) is True

@pytest.mark.asyncio
async def test_rate_limiter_path_limits():
    """Test path-specific rate limits."""
    path_limits = {
        "/api/high": 100,
        "/api/low": 10,
        "/api/docs*": 50  # Pattern matching
    }
    
    limiter = RateLimiter(
        requests_per_minute=30,
        path_limits=path_limits
    )
    
    # Test different paths
    paths = [
        ("/api/high", 100),
        ("/api/low", 10),
        ("/api/docs/v1", 50),
        ("/other", 30)  # Default limit
    ]
    
    for path, expected_limit in paths:
        scope = {
            "type": "http",
            "path": path,
            "client": ("127.0.0.1", 8000),
            "headers": []
        }
        
        assert limiter.get_limit_for_path(path) == expected_limit

@pytest.mark.asyncio
async def test_rate_limiter_exclusions():
    """Test path exclusions from rate limiting."""
    exclude_paths = {"/health", "/metrics"}
    
    limiter = RateLimiter(
        requests_per_minute=1,
        exclude_paths=exclude_paths
    )
    
    # Test excluded path
    scope = {
        "type": "http",
        "path": "/health",
        "client": ("127.0.0.1", 8000),
        "headers": []
    }
    
    # Should always allow excluded paths
    for _ in range(5):
        assert await limiter.check_rate_limit(scope, None, None) is True
    
    # Test non-excluded path
    scope["path"] = "/api"
    assert await limiter.check_rate_limit(scope, None, None) is True
    assert await limiter.check_rate_limit(scope, None, None) is False

@pytest.mark.asyncio
async def test_rate_limiter_cleanup():
    """Test rate limiter state cleanup."""
    limiter = RateLimiter(
        requests_per_minute=30,
        window_size=1
    )
    
    scope = {
        "type": "http",
        "path": "/test",
        "client": ("127.0.0.1", 8000),
        "headers": []
    }
    
    # Fill up some rate limit states
    await limiter.check_rate_limit(scope, None, None)
    
    # Start cleanup
    await limiter.start()
    
    # Wait for cleanup cycle
    await asyncio.sleep(2)
    
    # Stop cleanup
    await limiter.stop()
    
    # Verify cleanup occurred
    client_id = limiter._get_client_identifier(scope)
    assert client_id not in limiter.storage or not limiter.storage[client_id]

# Validation Middleware Tests

@pytest.mark.asyncio
async def test_validation_basic_rules():
    """Test basic validation rules."""
    validator = RequestValidator([
        ValidationRule(
            field="username",
            rule_type=ValidationType.STRING.value,
            params={"min_length": 3}
        ),
        ValidationRule(
            field="age",
            rule_type=ValidationType.NUMBER.value,
            params={"min_value": 18}
        ),
        ValidationRule(
            field="email",
            rule_type=ValidationType.EMAIL.value
        )
    ])
    
    # Valid data
    valid_data = {
        "username": "john_doe",
        "age": 25,
        "email": "john@example.com"
    }
    errors = await validator.validate_request(
        {"type": "http"},
        valid_data
    )
    assert errors is None
    
    # Invalid data
    invalid_data = {
        "username": "jo",  # Too short
        "age": 16,  # Under minimum
        "email": "invalid-email"  # Invalid format
    }
    errors = await validator.validate_request(
        {"type": "http"},
        invalid_data
    )
    assert errors is not None
    assert "username" in errors
    assert "age" in errors
    assert "email" in errors

@pytest.mark.asyncio
async def test_validation_custom_rules():
    """Test custom validation rules."""
    def validate_password(value):
        return (
            len(value) >= 8 and
            any(c.isupper() for c in value) and
            any(c.isdigit() for c in value)
        )
    
    validator = RequestValidator(
        rules=[
            ValidationRule(
                field="password",
                rule_type=ValidationType.CUSTOM.value,
                error_message="Password must be at least 8 characters with 1 uppercase and 1 number"
            )
        ],
        custom_validators={"password": validate_password}
    )
    
    # Valid password
    errors = await validator.validate_request(
        {"type": "http"},
        {"password": "SecurePass123"}
    )
    assert errors is None
    
    # Invalid password
    errors = await validator.validate_request(
        {"type": "http"},
        {"password": "weak"}
    )
    assert errors is not None
    assert "password" in errors

@pytest.mark.asyncio
async def test_validation_content_type():
    """Test content type validation."""
    validator = RequestValidator(
        rules=[],
        allowed_content_types=["application/json"]
    )
    
    # Valid content type
    scope = {
        "type": "http",
        "headers": [(b"content-type", b"application/json")]
    }
    errors = await validator.validate_request(scope, {})
    assert errors is None
    
    # Invalid content type
    scope["headers"] = [(b"content-type", b"text/plain")]
    errors = await validator.validate_request(scope, {})
    assert errors is not None
    assert "content_type" in errors

# Health Check Middleware Tests

@pytest.mark.asyncio
async def test_health_check_basic_endpoint():
    """Test basic health check endpoint."""
    status = HealthStatus()
    middleware = HealthCheckMiddleware(None, status=status)
    
    # Track sent responses
    sent_messages = []
    async def send(message):
        sent_messages.append(message)
    
    # Test basic health endpoint
    await middleware(
        {"type": "http", "path": "/health"},
        None,
        send
    )
    
    assert len(sent_messages) == 2
    response_body = json.loads(sent_messages[1]["body"])
    assert response_body["status"] == "healthy"
    assert "timestamp" in response_body

@pytest.mark.asyncio
async def test_health_check_detailed():
    """Test detailed health check endpoint."""
    status = HealthStatus()
    
    # Add custom health checks
    async def check_database():
        return {"connection": "active", "latency_ms": 50}
    
    async def check_cache():
        return {"status": "connected", "used_memory_mb": 100}
    
    status.add_check("database", check_database)
    status.add_check("cache", check_cache)
    
    middleware = HealthCheckMiddleware(
        None,
        status=status,
        required_checks=["database"]
    )
    
    # Track sent responses
    sent_messages = []
    async def send(message):
        sent_messages.append(message)
    
    # Test detailed health endpoint
    await middleware(
        {"type": "http", "path": "/health/detailed"},
        None,
        send
    )
    
    response_body = json.loads(sent_messages[1]["body"])
    assert "checks" in response_body
    assert "database" in response_body["checks"]
    assert "cache" in response_body["checks"]
    assert "system" in response_body

@pytest.mark.asyncio
async def test_health_check_caching():
    """Test health check response caching."""
    status = HealthStatus()
    middleware = HealthCheckMiddleware(
        None,
        status=status,
        cache_duration=1
    )
    
    # First request
    sent_messages = []
    async def send(message):
        sent_messages.append(message)
    
    await middleware(
        {"type": "http", "path": "/health"},
        None,
        send
    )
    
    first_response = json.loads(sent_messages[1]["body"])
    first_timestamp = first_response["timestamp"]
    
    # Immediate second request (should use cache)
    sent_messages.clear()
    await middleware(
        {"type": "http", "path": "/health"},
        None,
        send
    )
    
    second_response = json.loads(sent_messages[1]["body"])
    assert second_response["timestamp"] == first_timestamp
    
    # Wait for cache to expire
    await asyncio.sleep(1.1)
    
    # Third request (should bypass cache)
    sent_messages.clear()
    await middleware(
        {"type": "http", "path": "/health"},
        None,
        send
    )
    
    third_response = json.loads(sent_messages[1]["body"])
    assert third_response["timestamp"] > first_timestamp

# Compression Middleware Tests

@pytest.mark.asyncio
async def test_compression_gzip():
    """Test gzip compression."""
    middleware = CompressionMiddleware(
        app=None,
        minimum_size=0
    )
    
    # Create test response
    response_data = b"Hello" * 1000  # Large enough to trigger compression
    
    sent_messages = []
    async def send(message):
        sent_messages.append(message)
    
    async def app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")]
        })
        await send({
            "type": "http.response.body",
            "body": response_data
        })
    
    middleware.app = app
    
    # Test with gzip encoding
    await middleware(
        {
            "type": "http",
            "path": "/test",
            "headers": [(b"accept-encoding", b"gzip")]
        },
        None,
        send
    )
    
    # Verify compression
    headers_dict = dict(sent_messages[0]["headers"])
    assert headers_dict[b"content-encoding"] == b"gzip"
    
    # Verify compressed data
    compressed_data = sent_messages[1]["body"]
    decompressed = gzip.decompress(compressed_data)
    assert decompressed == response_data

@pytest.mark.asyncio
async def test_compression_brotli():
    """Test brotli compression."""
    middleware = CompressionMiddleware(
        app=None,
        minimum_size=0
    )
    
    # Create test response
    response_data = b"Hello" * 1000
    
    sent_messages = []
    async def send(message):
        sent_messages.append(message)
    
    async def app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")]
        })
        await send({
            "type": "http.response.body",
            "body": response_data
        })
    
    middleware.app = app
    
    # Test with brotli encoding
    await middleware(
        {
            "type": "http",
            "path": "/test",
            "headers": [(b"accept-encoding", b"br")]
        },
        None,
        send
    )
    
    # Verify compression
    headers_dict = dict(sent_messages[0]["headers"])
    assert headers_dict[b"content-encoding"] == b"br"
    
    # Verify compressed data
    compressed_data = sent_messages[1]["body"]
    decompressed = brotli.decompress(compressed_data)
    assert decompressed == response_data

@pytest.mark.asyncio
async def test_compression_exclusions():
    """Test compression exclusions."""
    middleware = CompressionMiddleware(
        app=None,
        minimum_size=0,
        excluded_paths={"/health"},
        excluded_extensions={".jpg"},
        compressible_types={"text/plain"}
    )
    
    sent_messages = []
    async def send(message):
        sent_messages.append(message)
    
    async def app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")]
        })
        await send({
            "type": "http.response.body",
            "body": b"test data"
        })
    
    middleware.app = app
    
    # Test excluded path
    await middleware(
        {
            "type": "http",
            "path": "/health",
            "headers": [(b"accept-encoding", b"gzip")]
        },
        None,
        send
    )
    
    # Verify no compression
    headers_dict = dict(sent_messages[0]["headers"])
    assert b"content-encoding" not in headers_dict
    
    # Test excluded extension
    sent_messages.clear()
    await middleware(
        {
            "type": "http",
            "path": "/image.jpg",
            "headers": [(b"accept-encoding", b"gzip")]
        },
        None,
        send
    )
    
    # Verify no compression
    headers_dict = dict(sent_messages[0]["headers"])
    assert b"content-encoding" not in headers_dict
