"""
Connection draining implementation for graceful server shutdown.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Set, Optional, Callable, Awaitable, List

class DrainState(Enum):
    """States for the connection drainer."""
    ACTIVE = "active"
    DRAINING = "draining"
    DRAINED = "drained"

@dataclass
class ConnectionInfo:
    """Information about an active connection."""
    id: str
    start_time: float
    path: str
    method: str
    client: str
    
@dataclass
class DrainStats:
    """Statistics about the draining process."""
    total_connections: int = 0
    active_connections: int = 0
    drained_connections: int = 0
    rejected_connections: int = 0
    longest_connection: float = 0.0
    start_time: Optional[float] = None
    end_time: Optional[float] = None

class ConnectionDrainer:
    """
    Handles graceful connection draining during shutdown.
    
    Features:
    - Configurable drain timeout
    - Connection state tracking
    - Graceful rejection of new connections during draining
    - Resource cleanup hooks
    - Detailed statistics
    """
    
    def __init__(
        self,
        drain_timeout: float = 30.0,
        grace_period: float = 5.0,
        logger: Optional[logging.Logger] = None
    ):
        self.drain_timeout = drain_timeout
        self.grace_period = grace_period
        self.logger = logger or logging.getLogger(__name__)
        
        self.state = DrainState.ACTIVE
        self.stats = DrainStats()
        self._connections: Dict[str, ConnectionInfo] = {}
        self._cleanup_hooks: List[Callable[[], Awaitable[None]]] = []
        self._drain_complete = asyncio.Event()
        
    def add_cleanup_hook(self, hook: Callable[[], Awaitable[None]]) -> None:
        """Add a cleanup hook to be called during draining."""
        self._cleanup_hooks.append(hook)
        
    def start_connection(
        self,
        conn_id: str,
        path: str,
        method: str,
        client: str
    ) -> bool:
        """
        Track a new connection. Returns False if connection should be rejected.
        """
        if self.state != DrainState.ACTIVE:
            self.stats.rejected_connections += 1
            return False
            
        self._connections[conn_id] = ConnectionInfo(
            id=conn_id,
            start_time=time.time(),
            path=path,
            method=method,
            client=client
        )
        self.stats.total_connections += 1
        self.stats.active_connections += 1
        return True
        
    def end_connection(self, conn_id: str) -> None:
        """Mark a connection as complete."""
        if conn_id in self._connections:
            conn = self._connections.pop(conn_id)
            duration = time.time() - conn.start_time
            self.stats.longest_connection = max(
                self.stats.longest_connection,
                duration
            )
            self.stats.active_connections -= 1
            self.stats.drained_connections += 1
            
            if self.state == DrainState.DRAINING and not self._connections:
                self._drain_complete.set()
                
    async def start_draining(self) -> None:
        """
        Initiate connection draining process.
        """
        if self.state != DrainState.ACTIVE:
            return
            
        self.state = DrainState.DRAINING
        self.stats.start_time = time.time()
        self.logger.info(
            f"Starting connection drain with {self.stats.active_connections} "
            f"active connections. Timeout: {self.drain_timeout}s"
        )
        
        # Run cleanup hooks
        for hook in self._cleanup_hooks:
            try:
                await hook()
            except Exception as e:
                self.logger.error(f"Cleanup hook failed: {e}")
                
        # Wait for connections to drain or timeout
        try:
            await asyncio.wait_for(
                self._drain_complete.wait(),
                timeout=self.drain_timeout
            )
            self.logger.info("All connections drained successfully")
        except asyncio.TimeoutError:
            remaining = len(self._connections)
            self.logger.warning(
                f"Drain timeout reached with {remaining} connections remaining"
            )
            
        # Give remaining connections a grace period
        if self._connections:
            self.logger.info(
                f"Waiting {self.grace_period}s grace period for "
                f"{len(self._connections)} connections"
            )
            await asyncio.sleep(self.grace_period)
            
        self.state = DrainState.DRAINED
        self.stats.end_time = time.time()
        
    @property
    def is_draining(self) -> bool:
        """Check if draining is in progress."""
        return self.state == DrainState.DRAINING
        
    @property
    def active_connections(self) -> Set[str]:
        """Get IDs of currently active connections."""
        return set(self._connections.keys())
        
    @property
    def drain_duration(self) -> Optional[float]:
        """Get the total drain duration if complete."""
        if self.stats.start_time and self.stats.end_time:
            return self.stats.end_time - self.stats.start_time
        return None
