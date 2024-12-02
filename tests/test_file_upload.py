import os
import pytest
import tempfile
from ruvicorn.middleware.file_upload import StreamingFileUpload

@pytest.fixture
def file_upload_middleware():
    return StreamingFileUpload()

@pytest.fixture
def mock_scope():
    return {
        "type": "http",
        "method": "POST",
        "headers": [
            (b"content-type", b"multipart/form-data; boundary=boundary"),
            (b"content-disposition", b'form-data; name="file"; filename="test.txt"')
        ]
    }

@pytest.fixture
def mock_receive():
    async def receive():
        return {
            "type": "http.request",
            "body": b"test content",
            "more_body": False
        }
    return receive

@pytest.fixture
def mock_send():
    async def send(message):
        return message
    return send

async def test_file_upload_processing(
    file_upload_middleware,
    mock_scope,
    mock_receive,
    mock_send
):
    # Create test file content
    content = b"test file content"
    
    # Configure middleware
    middleware = file_upload_middleware
    middleware.app = lambda s, r, send: None
    
    # Process upload
    result = await middleware.process_upload(
        content,
        "text/plain",
        "test.txt"
    )
    
    assert result["success"] is True
    assert os.path.exists(result["path"])
    assert result["size"] == len(content)
    assert result["content_type"] == "text/plain"
    assert result["filename"] == "test.txt"
    
    # Clean up
    os.unlink(result["path"])

async def test_file_size_limit(file_upload_middleware):
    # Create content larger than max size
    content = b"x" * (file_upload_middleware.max_file_size + 1)
    
    with pytest.raises(ValueError) as exc_info:
        await file_upload_middleware.process_upload(
            content,
            "text/plain",
            "large.txt"
        )
    
    assert "exceeds maximum allowed size" in str(exc_info.value)

async def test_invalid_file_type(file_upload_middleware):
    content = b"test content"
    
    with pytest.raises(ValueError) as exc_info:
        await file_upload_middleware.process_upload(
            content,
            "invalid/type",
            "test.txt"
        )
    
    assert "not allowed" in str(exc_info.value)

async def test_middleware_call(
    file_upload_middleware,
    mock_scope,
    mock_receive,
    mock_send
):
    called = False
    
    async def mock_app(scope, receive, send):
        nonlocal called
        called = True
        assert "file_upload" in scope
        
        message = await receive()
        assert message["type"] == "http.request"
    
    middleware = file_upload_middleware
    middleware.app = mock_app
    
    await middleware(mock_scope, mock_receive, mock_send)
    assert called is True

async def test_cleanup(file_upload_middleware):
    # Create test file
    content = b"test content"
    result = await file_upload_middleware.process_upload(
        content,
        "text/plain",
        "cleanup_test.txt"
    )
    
    assert os.path.exists(result["path"])
    
    # Run cleanup with short timeout
    file_upload_middleware.cleanup_timeout = 0.1
    await file_upload_middleware.cleanup_temp_files()
    
    assert not os.path.exists(result["path"])
