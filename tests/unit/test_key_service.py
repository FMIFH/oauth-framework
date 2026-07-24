from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from src.models.keys import SigningKey
from src.services.key_service import KeyService, get_key_service


@pytest.fixture
def mock_key_repo():
    return AsyncMock()


@pytest.fixture
def key_service(mock_key_repo):
    return KeyService(key_repo=mock_key_repo)


@pytest.mark.asyncio
async def test_get_signing_key_by_kid(mock_key_repo, key_service):
    # Arrange
    kid = "test-kid"
    mock_key = SigningKey(kid=kid, algorithm="RS256")
    mock_key_repo.get_by_kid.return_value = mock_key

    # Act
    result = await key_service.get_signing_key_by_kid(kid)

    # Assert
    assert result == mock_key
    mock_key_repo.get_by_kid.assert_called_once_with(kid)


@pytest.mark.asyncio
async def test_get_active_signing_key(mock_key_repo, key_service):
    # Arrange
    mock_key = SigningKey(kid="active-kid", is_active=True)
    mock_key_repo.get_active_key.return_value = mock_key

    # Act
    result = await key_service.get_active_signing_key()

    # Assert
    assert result == mock_key
    mock_key_repo.get_active_key.assert_called_once()


@pytest.mark.asyncio
async def test_get_active_or_recent_keys(mock_key_repo, key_service):
    # Arrange
    grace_cutoff = datetime.now(timezone.utc)
    mock_keys = [SigningKey(kid="active-1"), SigningKey(kid="recent-2")]
    mock_key_repo.get_active_or_recent_keys.return_value = mock_keys

    # Act
    result = await key_service.get_active_or_recent_keys(grace_cutoff)

    # Assert
    assert result == mock_keys
    mock_key_repo.get_active_or_recent_keys.assert_called_once_with(grace_cutoff)


@pytest.mark.asyncio
async def test_get_all_active_keys(mock_key_repo, key_service):
    # Arrange
    mock_keys = [SigningKey(kid="active-1"), SigningKey(kid="active-2")]
    mock_key_repo.get_all_active_keys.return_value = mock_keys

    # Act
    result = await key_service.get_all_active_keys()

    # Assert
    assert result == mock_keys
    mock_key_repo.get_all_active_keys.assert_called_once()


@pytest.mark.asyncio
async def test_create_key(mock_key_repo, key_service):
    # Arrange
    mock_key = SigningKey(kid="new-kid")
    mock_key_repo.create_key.return_value = mock_key

    # Act
    result = await key_service.create_key(mock_key)

    # Assert
    assert result == mock_key
    mock_key_repo.create_key.assert_called_once_with(mock_key)


@pytest.mark.asyncio
async def test_update_key(mock_key_repo, key_service):
    # Arrange
    mock_key = SigningKey(kid="existing-kid")
    mock_key_repo.update_key.return_value = mock_key

    # Act
    result = await key_service.update_key(mock_key)

    # Assert
    assert result == mock_key
    mock_key_repo.update_key.assert_called_once_with(mock_key)


@pytest.mark.asyncio
async def test_get_key_service():

    mock_repo = AsyncMock()
    service = await get_key_service(mock_repo)
    assert isinstance(service, KeyService)
    assert service.key_repo is mock_repo
