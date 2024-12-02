"""
Request validation middleware with comprehensive error handling.
"""

from typing import Dict, Optional, List, Any, Union, Callable
import json
from dataclasses import dataclass
from enum import Enum
import re

class ValidationError(Exception):
    """Custom exception for validation errors."""
    def __init__(self, message: str, details: Dict = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)

@dataclass
class ValidationRule:
    """Defines a validation rule for request data."""
    field: str
    rule_type: str
    params: Dict[str, Any] = None
    error_message: str = None

class ValidationType(Enum):
    """Supported validation types."""
    REQUIRED = "required"
    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    EMAIL = "email"
    URL = "url"
    REGEX = "regex"
    MIN_LENGTH = "min_length"
    MAX_LENGTH = "max_length"
    MIN_VALUE = "min_value"
    MAX_VALUE = "max_value"
    ENUM = "enum"
    CUSTOM = "custom"

class RequestValidator:
    """
    Validates request data against defined rules and schemas.
    """
    
    def __init__(
        self,
        rules: Optional[List[ValidationRule]] = None,
        custom_validators: Optional[Dict[str, Callable]] = None,
        strict_mode: bool = False,
        max_body_size: int = 1024 * 1024,  # 1MB
        allowed_content_types: Optional[List[str]] = None
    ):
        self.rules = rules or []
        self.custom_validators = custom_validators or {}
        self.strict_mode = strict_mode
        self.max_body_size = max_body_size
        self.allowed_content_types = allowed_content_types or [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data"
        ]
        
        # Compile regex patterns
        self.email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        self.url_pattern = re.compile(
            r'^https?:\/\/'
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
            r'localhost|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            r'(?::\d+)?'
            r'(?:/?|[/?]\S+)$',
            re.IGNORECASE
        )
    
    def _validate_type(self, value: Any, expected_type: ValidationType) -> bool:
        """Validate value against expected type."""
        if expected_type == ValidationType.STRING:
            return isinstance(value, str)
        elif expected_type == ValidationType.NUMBER:
            return isinstance(value, (int, float))
        elif expected_type == ValidationType.BOOLEAN:
            return isinstance(value, bool)
        elif expected_type == ValidationType.EMAIL:
            return isinstance(value, str) and bool(self.email_pattern.match(value))
        elif expected_type == ValidationType.URL:
            return isinstance(value, str) and bool(self.url_pattern.match(value))
        return True
    
    def _validate_rule(self, value: Any, rule: ValidationRule) -> Optional[str]:
        """Validate a single rule against a value."""
        if rule.rule_type == ValidationType.REQUIRED.value:
            if value is None or (isinstance(value, str) and not value.strip()):
                return rule.error_message or f"Field '{rule.field}' is required"
        
        if value is not None:
            if rule.rule_type == ValidationType.REGEX.value:
                pattern = rule.params.get("pattern")
                if pattern and not re.match(pattern, str(value)):
                    return rule.error_message or f"Field '{rule.field}' does not match pattern"
            
            elif rule.rule_type == ValidationType.MIN_LENGTH.value:
                min_length = rule.params.get("length", 0)
                if len(str(value)) < min_length:
                    return rule.error_message or f"Field '{rule.field}' must be at least {min_length} characters"
            
            elif rule.rule_type == ValidationType.MAX_LENGTH.value:
                max_length = rule.params.get("length", float("inf"))
                if len(str(value)) > max_length:
                    return rule.error_message or f"Field '{rule.field}' must not exceed {max_length} characters"
            
            elif rule.rule_type == ValidationType.MIN_VALUE.value:
                min_value = rule.params.get("value", float("-inf"))
                if not isinstance(value, (int, float)) or value < min_value:
                    return rule.error_message or f"Field '{rule.field}' must be at least {min_value}"
            
            elif rule.rule_type == ValidationType.MAX_VALUE.value:
                max_value = rule.params.get("value", float("inf"))
                if not isinstance(value, (int, float)) or value > max_value:
                    return rule.error_message or f"Field '{rule.field}' must not exceed {max_value}"
            
            elif rule.rule_type == ValidationType.ENUM.value:
                allowed_values = rule.params.get("values", [])
                if value not in allowed_values:
                    return rule.error_message or f"Field '{rule.field}' must be one of: {', '.join(map(str, allowed_values))}"
            
            elif rule.rule_type == ValidationType.CUSTOM.value:
                validator = self.custom_validators.get(rule.field)
                if validator and not validator(value):
                    return rule.error_message or f"Field '{rule.field}' failed custom validation"
        
        return None
    
    async def validate_request(self, scope: Dict, body: Dict) -> Optional[Dict[str, List[str]]]:
        """Validate request data against all rules."""
        errors = {}
        
        # Validate content type
        content_type = dict(scope.get("headers", {})).get(b"content-type", b"").decode()
        if content_type and not any(allowed in content_type for allowed in self.allowed_content_types):
            errors["content_type"] = [f"Unsupported content type. Allowed types: {', '.join(self.allowed_content_types)}"]
        
        # Validate body size
        content_length = int(dict(scope.get("headers", {})).get(b"content-length", 0))
        if content_length > self.max_body_size:
            errors["body_size"] = [f"Request body too large. Maximum size: {self.max_body_size} bytes"]
        
        # Apply validation rules
        for rule in self.rules:
            value = body.get(rule.field)
            error = self._validate_rule(value, rule)
            if error:
                if rule.field not in errors:
                    errors[rule.field] = []
                errors[rule.field].append(error)
        
        return errors if errors else None

class ValidationMiddleware:
    """
    ASGI middleware for request validation and error handling.
    """
    
    def __init__(
        self,
        app: Any,
        validator: RequestValidator,
        error_handler: Optional[Callable] = None
    ):
        self.app = app
        self.validator = validator
        self.error_handler = error_handler
    
    async def _handle_validation_error(self, send: Any, errors: Dict[str, List[str]]):
        """Handle validation errors with a proper response."""
        error_response = {
            "status": "error",
            "message": "Validation failed",
            "errors": errors
        }
        
        if self.error_handler:
            await self.error_handler(error_response, send)
        else:
            await send({
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"application/json")
                ]
            })
            
            await send({
                "type": "http.response.body",
                "body": json.dumps(error_response).encode()
            })
    
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
        
        # Read request body
        body = b""
        more_body = True
        
        while more_body:
            message = await receive()
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
        
        # Parse request body
        try:
            request_data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            await self._handle_validation_error(
                send,
                {"body": ["Invalid JSON format"]}
            )
            return
        
        # Validate request
        validation_errors = await self.validator.validate_request(scope, request_data)
        if validation_errors:
            await self._handle_validation_error(send, validation_errors)
            return
        
        # Continue with valid request
        async def receive_wrapper():
            return {
                "type": "http.request",
                "body": body,
                "more_body": False
            }
        
        await self.app(scope, receive_wrapper, send)
