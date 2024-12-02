"""
Response compression middleware with support for multiple algorithms.
"""

from typing import Dict, Optional, List, Any, Set
import gzip
import zlib
import brotli
from io import BytesIO

class CompressionMiddleware:
    """
    ASGI middleware for response compression.
    """
    
    def __init__(
        self,
        app: Any,
        minimum_size: int = 500,  # Minimum size in bytes to compress
        compression_level: int = 6,  # Default compression level
        excluded_paths: Optional[Set[str]] = None,
        excluded_extensions: Optional[Set[str]] = None,
        compressible_types: Optional[Set[str]] = None
    ):
        self.app = app
        self.minimum_size = minimum_size
        self.compression_level = compression_level
        self.excluded_paths = excluded_paths or {
            "/health",
            "/metrics",
            "/favicon.ico"
        }
        self.excluded_extensions = excluded_extensions or {
            ".jpg", ".jpeg", ".png", ".gif", ".webp",
            ".mp3", ".mp4", ".avi", ".mov",
            ".zip", ".gz", ".br", ".pdf"
        }
        self.compressible_types = compressible_types or {
            "text/",
            "application/json",
            "application/javascript",
            "application/xml",
            "application/x-yaml",
            "application/ld+json"
        }
    
    def _should_compress(
        self,
        path: str,
        headers: List[tuple],
        content_length: int
    ) -> bool:
        """Determine if response should be compressed."""
        # Check path exclusions
        if any(path.startswith(excluded) for excluded in self.excluded_paths):
            return False
        
        # Check file extension exclusions
        if any(path.endswith(ext) for ext in self.excluded_extensions):
            return False
        
        # Check content type
        content_type = None
        for name, value in headers:
            if name.lower() == b"content-type":
                content_type = value.decode().lower()
                break
        
        if not content_type or not any(
            t in content_type for t in self.compressible_types
        ):
            return False
        
        # Check content length
        if content_length < self.minimum_size:
            return False
        
        return True
    
    def _get_accepted_encoding(self, headers: List[tuple]) -> Optional[str]:
        """Get the best compression algorithm based on Accept-Encoding header."""
        accept_encoding = None
        for name, value in headers:
            if name.lower() == b"accept-encoding":
                accept_encoding = value.decode().lower()
                break
        
        if not accept_encoding:
            return None
        
        # Parse accept-encoding header
        encodings = {}
        for encoding in accept_encoding.split(","):
            encoding = encoding.strip()
            if ";q=" in encoding:
                encoding, quality = encoding.split(";q=")
                quality = float(quality)
            else:
                quality = 1.0
            encodings[encoding] = quality
        
        # Select best supported encoding
        supported = {
            "br": brotli.compress if "brotli" in globals() else None,
            "gzip": gzip.compress,
            "deflate": zlib.compress
        }
        
        best_encoding = None
        best_quality = -1
        
        for encoding, quality in encodings.items():
            if (
                encoding in supported and
                supported[encoding] is not None and
                quality > best_quality
            ):
                best_encoding = encoding
                best_quality = quality
        
        return best_encoding
    
    def _compress_data(
        self,
        data: bytes,
        encoding: str
    ) -> bytes:
        """Compress data using specified encoding."""
        if encoding == "br":
            return brotli.compress(
                data,
                quality=self.compression_level
            )
        elif encoding == "gzip":
            return gzip.compress(
                data,
                compresslevel=self.compression_level
            )
        elif encoding == "deflate":
            return zlib.compress(
                data,
                level=self.compression_level
            )
        return data
    
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
        request_headers = scope.get("headers", [])
        encoding = self._get_accepted_encoding(request_headers)
        
        if not encoding:
            await self.app(scope, receive, send)
            return
        
        response_body = BytesIO()
        send_buffer = []
        initial_message = None
        
        async def send_wrapper(message):
            nonlocal initial_message
            
            if message["type"] == "http.response.start":
                initial_message = message
                send_buffer.append(message)
            
            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                response_body.write(body)
                
                if not message.get("more_body", False):
                    # Get final response data
                    response_data = response_body.getvalue()
                    
                    # Check if we should compress
                    headers = initial_message.get("headers", [])
                    if self._should_compress(path, headers, len(response_data)):
                        # Compress the data
                        compressed_data = self._compress_data(response_data, encoding)
                        
                        # Update headers
                        new_headers = []
                        for name, value in headers:
                            if name.lower() == b"content-length":
                                new_headers.append((
                                    b"content-length",
                                    str(len(compressed_data)).encode()
                                ))
                            else:
                                new_headers.append((name, value))
                        
                        new_headers.extend([
                            (b"content-encoding", encoding.encode()),
                            (b"vary", b"accept-encoding")
                        ])
                        
                        # Send compressed response
                        initial_message["headers"] = new_headers
                        await send(initial_message)
                        await send({
                            "type": "http.response.body",
                            "body": compressed_data
                        })
                    else:
                        # Send uncompressed response
                        for buffered in send_buffer:
                            await send(buffered)
                        await send({
                            "type": "http.response.body",
                            "body": response_data
                        })
        
        await self.app(scope, receive, send_wrapper)
