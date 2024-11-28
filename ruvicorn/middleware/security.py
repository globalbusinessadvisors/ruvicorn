"""
Enhanced security headers middleware implementation.
"""

from typing import Dict, Optional, List, Set, Any, Union
import json

class SecurityHeaders:
    """
    Enhanced security headers middleware with comprehensive security
    header management and configuration options.
    """
    
    def __init__(
        self,
        hsts_enabled: bool = True,
        hsts_max_age: int = 31536000,  # 1 year
        hsts_include_subdomains: bool = True,
        hsts_preload: bool = False,
        xss_protection: bool = True,
        content_security_policy: Optional[Dict[str, List[str]]] = None,
        content_security_policy_report_only: bool = False,
        content_security_policy_report_uri: Optional[str] = None,
        frame_options: str = "DENY",
        content_type_options: bool = True,
        referrer_policy: str = "strict-origin-when-cross-origin",
        permissions_policy: Optional[Dict[str, Union[List[str], bool]]] = None,
        cross_origin_embedder_policy: bool = True,
        cross_origin_opener_policy: bool = True,
        cross_origin_resource_policy: str = "same-origin",
        expect_ct: bool = False,
        expect_ct_max_age: int = 86400,  # 1 day
        expect_ct_report_uri: Optional[str] = None,
        expect_ct_enforce: bool = False,
        trusted_types: bool = False,
        trusted_types_policies: Optional[List[str]] = None,
        require_trusted_types_for: Optional[List[str]] = None
    ):
        self.hsts_enabled = hsts_enabled
        self.hsts_max_age = hsts_max_age
        self.hsts_include_subdomains = hsts_include_subdomains
        self.hsts_preload = hsts_preload
        
        self.xss_protection = xss_protection
        
        self.content_security_policy = content_security_policy or {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "img-src": ["'self'"],
            "font-src": ["'self'"],
            "form-action": ["'self'"],
            "frame-ancestors": ["'none'"],
            "base-uri": ["'self'"],
            "object-src": ["'none'"]
        }
        self.content_security_policy_report_only = content_security_policy_report_only
        self.content_security_policy_report_uri = content_security_policy_report_uri
        
        self.frame_options = frame_options
        self.content_type_options = content_type_options
        self.referrer_policy = referrer_policy
        
        self.permissions_policy = permissions_policy or {
            "geolocation": [],
            "microphone": [],
            "camera": [],
            "payment": [],
            "usb": [],
            "accelerometer": [],
            "autoplay": [],
            "document-domain": [],
            "encrypted-media": [],
            "fullscreen": ["self"],
            "gyroscope": [],
            "magnetometer": [],
            "midi": [],
            "picture-in-picture": ["self"],
            "sync-xhr": ["self"]
        }
        
        self.cross_origin_embedder_policy = cross_origin_embedder_policy
        self.cross_origin_opener_policy = cross_origin_opener_policy
        self.cross_origin_resource_policy = cross_origin_resource_policy
        
        self.expect_ct = expect_ct
        self.expect_ct_max_age = expect_ct_max_age
        self.expect_ct_report_uri = expect_ct_report_uri
        self.expect_ct_enforce = expect_ct_enforce
        
        self.trusted_types = trusted_types
        self.trusted_types_policies = trusted_types_policies
        self.require_trusted_types_for = require_trusted_types_for
    
    def _build_csp_header(self) -> str:
        """Build the Content Security Policy header value."""
        parts = []
        
        for directive, sources in self.content_security_policy.items():
            if sources:
                parts.append(f"{directive} {' '.join(sources)}")
            else:
                parts.append(directive)
        
        if self.content_security_policy_report_uri:
            parts.append(
                f"report-uri {self.content_security_policy_report_uri}"
            )
        
        return "; ".join(parts)
    
    def _build_permissions_policy(self) -> str:
        """Build the Permissions Policy header value."""
        parts = []
        
        for feature, allowed in self.permissions_policy.items():
            if isinstance(allowed, bool):
                if allowed:
                    parts.append(f"{feature}=(self)")
                else:
                    parts.append(f"{feature}=()")
            else:
                if allowed:
                    origins = " ".join(allowed)
                    parts.append(f"{feature}=({origins})")
                else:
                    parts.append(f"{feature}=()")
        
        return ", ".join(parts)
    
    def _build_expect_ct(self) -> str:
        """Build the Expect-CT header value."""
        parts = [f"max-age={self.expect_ct_max_age}"]
        
        if self.expect_ct_enforce:
            parts.append("enforce")
        
        if self.expect_ct_report_uri:
            parts.append(f"report-uri=\"{self.expect_ct_report_uri}\"")
        
        return ", ".join(parts)
    
    def _build_trusted_types(self) -> str:
        """Build the Trusted-Types header value."""
        parts = []
        
        if self.trusted_types_policies:
            policies = " ".join(self.trusted_types_policies)
            parts.append(policies)
        
        return " ".join(parts)
    
    def get_security_headers(self, is_https: bool = True) -> List[tuple]:
        """Generate security headers based on configuration."""
        headers = []
        
        # HSTS (HTTP Strict Transport Security)
        if is_https and self.hsts_enabled:
            hsts_value = f"max-age={self.hsts_max_age}"
            if self.hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            if self.hsts_preload:
                hsts_value += "; preload"
            headers.append((
                b"strict-transport-security",
                hsts_value.encode()
            ))
        
        # X-XSS-Protection
        if self.xss_protection:
            headers.append((
                b"x-xss-protection",
                b"1; mode=block"
            ))
        
        # Content Security Policy
        csp_header = (
            "content-security-policy-report-only"
            if self.content_security_policy_report_only
            else "content-security-policy"
        )
        headers.append((
            csp_header.encode(),
            self._build_csp_header().encode()
        ))
        
        # X-Frame-Options
        if self.frame_options:
            headers.append((
                b"x-frame-options",
                self.frame_options.encode()
            ))
        
        # X-Content-Type-Options
        if self.content_type_options:
            headers.append((
                b"x-content-type-options",
                b"nosniff"
            ))
        
        # Referrer-Policy
        if self.referrer_policy:
            headers.append((
                b"referrer-policy",
                self.referrer_policy.encode()
            ))
        
        # Permissions-Policy
        headers.append((
            b"permissions-policy",
            self._build_permissions_policy().encode()
        ))
        
        # Cross-Origin-Embedder-Policy
        if self.cross_origin_embedder_policy:
            headers.append((
                b"cross-origin-embedder-policy",
                b"require-corp"
            ))
        
        # Cross-Origin-Opener-Policy
        if self.cross_origin_opener_policy:
            headers.append((
                b"cross-origin-opener-policy",
                b"same-origin"
            ))
        
        # Cross-Origin-Resource-Policy
        if self.cross_origin_resource_policy:
            headers.append((
                b"cross-origin-resource-policy",
                self.cross_origin_resource_policy.encode()
            ))
        
        # Expect-CT
        if self.expect_ct:
            headers.append((
                b"expect-ct",
                self._build_expect_ct().encode()
            ))
        
        # Trusted-Types
        if self.trusted_types:
            headers.append((
                b"trusted-types",
                self._build_trusted_types().encode()
            ))
            
            if self.require_trusted_types_for:
                headers.append((
                    b"require-trusted-types-for",
                    " ".join(self.require_trusted_types_for).encode()
                ))
        
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
        
        # Determine if request is over HTTPS
        is_https = scope.get("scheme", "") == "https"
        
        # Get security headers
        security_headers = self.get_security_headers(is_https)
        
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = message.get("headers", [])
                message["headers"] = headers + security_headers
            
            await send(message)
        
        await self.app(scope, receive, send_wrapper)
    
    def wrap(self, app: Any) -> "SecurityHeaders":
        """Wrap an ASGI application with security headers middleware."""
        self.app = app
        return self
