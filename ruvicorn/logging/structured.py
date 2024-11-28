"""
Structured logging implementation with enhanced formatting and filtering.
"""

import logging
import json
import datetime
import traceback
import sys
import os
from pathlib import Path
from typing import Any, Dict, Optional, Union
from logging.handlers import RotatingFileHandler
import threading
import queue
import asyncio
from concurrent.futures import ThreadPoolExecutor

class AsyncRotatingFileHandler(RotatingFileHandler):
    """
    An asynchronous rotating file handler that writes logs in a separate thread.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.queue = queue.Queue()
        self.thread = threading.Thread(target=self._async_writer, daemon=True)
        self.thread.start()
        self._shutdown = threading.Event()
    
    def emit(self, record):
        """Queue the record for writing in the background thread."""
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            sys.stderr.write("WARNING: Log queue is full, dropping log record\n")
    
    def _async_writer(self):
        """Background thread that writes queued logs to file."""
        while not self._shutdown.is_set() or not self.queue.empty():
            try:
                record = self.queue.get(timeout=0.1)
                super().emit(record)
                self.queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                sys.stderr.write(f"ERROR: Failed to write log record: {e}\n")
    
    def close(self):
        """Shut down the background thread and close the file."""
        self._shutdown.set()
        if self.thread.is_alive():
            self.thread.join()
        super().close()

class StructuredFormatter(logging.Formatter):
    """
    Custom formatter that supports both structured (JSON) and traditional logging.
    """
    
    def __init__(self, format_type: str = "json", structured: bool = True):
        super().__init__()
        self.format_type = format_type
        self.structured = structured
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the log record according to the configured format type."""
        if self.structured and self.format_type == "json":
            return self._format_json(record)
        return self._format_text(record)
    
    def _format_json(self, record: logging.LogRecord) -> str:
        """Format the log record as JSON."""
        data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "thread": record.threadName,
            "process": record.process
        }
        
        # Add exception info if present
        if record.exc_info:
            data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info)
            }
        
        # Add extra fields
        if hasattr(record, "extra_fields"):
            data.update(record.extra_fields)
        
        return json.dumps(data)
    
    def _format_text(self, record: logging.LogRecord) -> str:
        """Format the log record as text."""
        parts = [
            f"[{self.formatTime(record)}]",
            f"[{record.levelname}]",
            f"[{record.name}]",
            record.getMessage()
        ]
        
        if record.exc_info:
            parts.append(self.formatException(record.exc_info))
        
        if hasattr(record, "extra_fields"):
            extras = [f"{k}={v}" for k, v in record.extra_fields.items()]
            parts.append(f"[{' '.join(extras)}]")
        
        return " ".join(parts)

class StructuredLogger(logging.Logger):
    """
    Enhanced logger that provides structured logging capabilities.
    """
    
    def __init__(
        self,
        name: str = "ruvicorn",
        level: Union[str, int] = logging.INFO,
        format: str = "json",
        structured: bool = True,
        log_file: Optional[str] = None,
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
        correlation_id_provider: Optional[callable] = None
    ):
        super().__init__(name, level)
        
        self.structured = structured
        self.format = format.lower()
        self.correlation_id_provider = correlation_id_provider
        self._thread_context = threading.local()
        self._executor = ThreadPoolExecutor(max_workers=1)
        
        # Set up handlers
        handlers = []
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            StructuredFormatter(self.format, structured)
        )
        handlers.append(console_handler)
        
        # File handler if specified
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = AsyncRotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            file_handler.setFormatter(
                StructuredFormatter(self.format, structured)
            )
            handlers.append(file_handler)
        
        for handler in handlers:
            self.addHandler(handler)
    
    def _log(
        self,
        level: int,
        msg: str,
        args: tuple,
        exc_info: Optional[Exception] = None,
        extra: Optional[Dict[str, Any]] = None,
        stack_info: bool = False,
        **kwargs
    ) -> None:
        """
        Enhanced logging with additional context and structured data.
        """
        if extra is None:
            extra = {}
        
        # Add correlation ID if available
        if self.correlation_id_provider:
            correlation_id = self.correlation_id_provider()
            if correlation_id:
                extra["correlation_id"] = correlation_id
        
        # Add context from thread local storage
        if hasattr(self._thread_context, "context"):
            extra.update(self._thread_context.context)
        
        # Add source code information
        if stack_info:
            frame = sys._getframe(2)
            extra.update({
                "file": frame.f_code.co_filename,
                "function": frame.f_code.co_name,
                "line": frame.f_lineno
            })
        
        # Store extra fields for formatter
        kwargs["extra"] = {"extra_fields": extra}
        
        super()._log(level, msg, args, exc_info, extra=kwargs.get("extra"), stack_info=stack_info)
    
    def with_context(self, **context) -> "ContextLogger":
        """
        Create a context manager that adds the given context to all logs
        within its scope.
        """
        return ContextLogger(self, context)
    
    async def alog(
        self,
        level: int,
        msg: str,
        *args,
        **kwargs
    ) -> None:
        """
        Asynchronous logging that doesn't block the event loop.
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self._executor,
            partial(self._log, level, msg, args, **kwargs)
        )

class ContextLogger:
    """
    Context manager for adding context to logs within a scope.
    """
    
    def __init__(self, logger: StructuredLogger, context: Dict[str, Any]):
        self.logger = logger
        self.context = context
        self.previous_context = None
    
    def __enter__(self):
        if not hasattr(self.logger._thread_context, "context"):
            self.logger._thread_context.context = {}
        
        self.previous_context = self.logger._thread_context.context.copy()
        self.logger._thread_context.context.update(self.context)
        return self.logger
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger._thread_context.context = self.previous_context

# Register the enhanced logger
logging.setLoggerClass(StructuredLogger)
