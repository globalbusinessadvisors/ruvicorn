"""
Streaming file upload middleware implementation.
"""

import os
import tempfile
from typing import Dict, Set, Optional, Any, List
import asyncio
import mimetypes

class StreamingFileUpload:
    """
    Streaming file upload middleware that efficiently handles large file uploads
    by processing them in chunks to control memory usage.
    """
    
    def __init__(
        self,
        max_file_size: int = 1024 * 1024 * 50,  # 50MB default
        allowed_types: Optional[Set[str]] = None,
        chunk_size: int = 1024 * 64,  # 64KB chunks
        temp_dir: Optional[str] = None,
        max_memory_buffer: int = 1024 * 512,  # 512KB memory buffer
        cleanup_timeout: int = 3600,  # 1 hour
    ):
        self.max_file_size = max_file_size
        self.allowed_types = allowed_types or {
            'image/jpeg', 'image/png', 'image/gif',
            'application/pdf', 'text/plain',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }
        self.chunk_size = chunk_size
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.max_memory_buffer = max_memory_buffer
        self.cleanup_timeout = cleanup_timeout
        self._temp_files: List[str] = []

    async def process_upload(
        self,
        body: bytes,
        content_type: str,
        filename: str
    ) -> Dict[str, Any]:
        """Process an uploaded file in chunks."""
        if not self._is_allowed_type(content_type):
            raise ValueError(f"File type {content_type} not allowed")

        if len(body) > self.max_file_size:
            raise ValueError(f"File size exceeds maximum allowed size of {self.max_file_size} bytes")

        temp_path = os.path.join(self.temp_dir, f"upload_{filename}")
        self._temp_files.append(temp_path)

        try:
            # Process file in chunks to control memory usage
            with open(temp_path, 'wb') as f:
                for i in range(0, len(body), self.chunk_size):
                    chunk = body[i:i + self.chunk_size]
                    if len(chunk) > self.max_memory_buffer:
                        # If chunk is too large, process it in smaller pieces
                        for j in range(0, len(chunk), self.max_memory_buffer):
                            f.write(chunk[j:j + self.max_memory_buffer])
                            await asyncio.sleep(0)  # Yield control
                    else:
                        f.write(chunk)
                        await asyncio.sleep(0)  # Yield control

            return {
                'success': True,
                'path': temp_path,
                'size': os.path.getsize(temp_path),
                'content_type': content_type,
                'filename': filename
            }

        except Exception as e:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise RuntimeError(f"Failed to process upload: {str(e)}")

    def _is_allowed_type(self, content_type: str) -> bool:
        """Check if the file type is allowed."""
        return content_type in self.allowed_types

    async def cleanup_temp_files(self):
        """Clean up temporary files after the cleanup timeout."""
        await asyncio.sleep(self.cleanup_timeout)
        for temp_file in self._temp_files:
            if os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass
        self._temp_files.clear()

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

        if scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        content_type = None
        for name, value in scope.get("headers", []):
            if name.decode().lower() == "content-type":
                content_type = value.decode()
                break

        if not content_type or not content_type.startswith("multipart/form-data"):
            await self.app(scope, receive, send)
            return

        # Create a modified receive function that processes file uploads
        async def receive_wrapper():
            message = await receive()
            
            if message["type"] == "http.request":
                body = message.get("body", b"")
                more_body = message.get("more_body", False)

                if body and content_type:
                    try:
                        # Extract filename from content-disposition header
                        filename = "uploaded_file"  # Default filename
                        for name, value in scope.get("headers", []):
                            if name.decode().lower() == "content-disposition":
                                parts = value.decode().split(";")
                                for part in parts:
                                    if "filename=" in part:
                                        filename = part.split("=")[1].strip('"')
                                        break

                        result = await self.process_upload(
                            body,
                            content_type,
                            filename
                        )
                        
                        # Add upload result to scope for application use
                        scope["file_upload"] = result
                        
                        # Start cleanup task
                        asyncio.create_task(self.cleanup_temp_files())
                        
                    except Exception as e:
                        # Add error to scope
                        scope["file_upload_error"] = str(e)

            return message

        await self.app(scope, receive_wrapper, send)

    def wrap(self, app: Any) -> "StreamingFileUpload":
        """Wrap an ASGI application with file upload middleware."""
        self.app = app
        return self
