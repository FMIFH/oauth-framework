from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.models.keys import SigningKey
from src.repositories.key_repo import KeyRepository, get_key_repository


@pytest.mark.asyncio
async def test_get_by_kid():
    # Arrange
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_key = SigningKey(kid="test-kid", algorithm="RS256")
    mock_result.scalars.return_value.first.return_value = mock_key
    mock_db.execute = AsyncMock(return_value=mock_result)

    repo = KeyRepository(mock_db)

    # Act
    key = await repo.get_by_kid("test-kid")

    # Assert
    assert key == mock_key
    mock_db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_get_active_key():
    # Arrange
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_key = SigningKey(kid="active-kid", is_active=True)
    mock_result.scalars.return_value.first.return_value = mock_key
    mock_db.execute = AsyncMock(return_value=mock_result)

    repo = KeyRepository(mock_db)

    # Act
    key = await repo.get_active_key()

    # Assert
    assert key == mock_key
    mock_db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_get_active_or_recent_keys():
    # Arrange
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_keys = [
        SigningKey(kid="active-1", is_active=True),
        SigningKey(kid="recent-2", is_active=False, deactivated_at=datetime.now(timezone.utc)),
    ]
    mock_result.scalars.return_value.all.return_value = mock_keys
    mock_db.execute = AsyncMock(return_value=mock_result)

    repo = KeyRepository(mock_db)
    grace_cutoff = datetime.now(timezone.utc)

    # Act
    keys = await repo.get_active_or_recent_keys(grace_cutoff)

    # Assert
    assert keys == mock_keys
    mock_db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_get_all_active_keys():
    # Arrange
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_keys = [SigningKey(kid="active-1", is_active=True)]
    mock_result.scalars.return_value.all.return_value = mock_keys
    mock_db.execute = AsyncMock(return_value=mock_result)

    repo = KeyRepository(mock_db)

    # Act
    keys = await repo.get_all_active_keys()

    # Assert
    assert keys == mock_keys
    mock_db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_create_key():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    repo = KeyRepository(mock_db)
    mock_key = SigningKey(kid="new-kid", algorithm="RS256")

    # Act
    key = await repo.create_key(mock_key)

    # Assert
    assert key == mock_key
    mock_db.add.assert_called_once_with(mock_key)
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(mock_key)


@pytest.mark.asyncio
async def test_update_key():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    repo = KeyRepository(mock_db)
    mock_key = SigningKey(kid="existing-kid", algorithm="RS256")

    # Act
    key = await repo.update_key(mock_key)

    # Assert
    assert key == mock_key
    mock_db.add.assert_called_once_with(mock_key)
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(mock_key)


@pytest.mark.asyncio
async def test_get_key_repository():

    mock_db = AsyncMock()
    repo = await get_key_repository(mock_db)
    assert isinstance(repo, KeyRepository)
    assert repo.db is mock_db
