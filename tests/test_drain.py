"""
Tests for connection draining functionality.
"""

import asyncio
import pytest
from ruvicorn.drain import ConnectionDrainer, DrainState

@pytest.fixture
async def drainer():
    """Create a test connection drainer."""
    return ConnectionDrainer(drain_timeout=1.0, grace_period=0.5)

async def test_connection_lifecycle(drainer):
    """Test basic connection tracking lifecycle."""
    # Start a connection
    assert drainer.start_connection("conn1", "/test", "GET", "127.0.0.1:1234")
    assert drainer.stats.active_connections == 1
    assert drainer.stats.total_connections == 1
    
    # End the connection
    drainer.end_connection("conn1")
    assert drainer.stats.active_connections == 0
    assert drainer.stats.drained_connections == 1

async def test_drain_process(drainer):
    """Test the draining process."""
    # Add some test connections
    assert drainer.start_connection("conn1", "/test1", "GET", "127.0.0.1:1234")
    assert drainer.start_connection("conn2", "/test2", "POST", "127.0.0.1:5678")
    
    # Start draining
    drain_task = asyncio.create_task(drainer.start_draining())
    
    # Verify state
    assert drainer.is_draining
    assert drainer.state == DrainState.DRAINING
    
    # New connections should be rejected during drain
    assert not drainer.start_connection("conn3", "/test3", "GET", "127.0.0.1:9012")
    assert drainer.stats.rejected_connections == 1
    
    # End existing connections
    drainer.end_connection("conn1")
    drainer.end_connection("conn2")
    
    # Wait for drain to complete
    await drain_task
    
    # Verify final state
    assert drainer.state == DrainState.DRAINED
    assert drainer.stats.active_connections == 0
    assert drainer.stats.drained_connections == 2
    assert drainer.drain_duration is not None
    assert drainer.drain_duration > 0

async def test_drain_timeout(drainer):
    """Test draining timeout behavior."""
    # Add a connection that won't end
    assert drainer.start_connection("conn1", "/test", "GET", "127.0.0.1:1234")
    
    # Start draining with short timeout
    start_time = asyncio.get_event_loop().time()
    await drainer.start_draining()
    duration = asyncio.get_event_loop().time() - start_time
    
    # Verify timeout behavior
    assert duration >= drainer.drain_timeout
    assert duration <= drainer.drain_timeout + drainer.grace_period + 0.1
    assert drainer.state == DrainState.DRAINED

async def test_cleanup_hooks(drainer):
    """Test cleanup hooks execution."""
    cleanup_called = False
    
    async def cleanup_hook():
        nonlocal cleanup_called
        cleanup_called = True
    
    # Add cleanup hook
    drainer.add_cleanup_hook(cleanup_hook)
    
    # Start draining
    await drainer.start_draining()
    
    # Verify hook was called
    assert cleanup_called

async def test_connection_stats(drainer):
    """Test connection statistics tracking."""
    # Add some connections with delays
    assert drainer.start_connection("conn1", "/test1", "GET", "127.0.0.1:1234")
    await asyncio.sleep(0.1)
    assert drainer.start_connection("conn2", "/test2", "POST", "127.0.0.1:5678")
    await asyncio.sleep(0.2)
    
    # End connections
    drainer.end_connection("conn2")
    await asyncio.sleep(0.1)
    drainer.end_connection("conn1")
    
    # Verify stats
    assert drainer.stats.total_connections == 2
    assert drainer.stats.drained_connections == 2
    assert drainer.stats.longest_connection > 0.3  # conn1 duration
    
    # Start draining to get complete stats
    await drainer.start_draining()
    assert drainer.drain_duration is not None
    assert drainer.stats.end_time is not None
    assert drainer.stats.start_time is not None
