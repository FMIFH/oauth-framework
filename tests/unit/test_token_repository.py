import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.models.token import RefreshToken
from src.repositories.token_repo import TokenRepository, get_token_repository


@pytest.mark.asyncio
async def test_create_refresh_token():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    repo = TokenRepository(mock_db)
    token = "ref_test_token_123"
    client_id = uuid.uuid4()
    user_id = uuid.uuid4()
    parent_family_id = uuid.uuid4()
    expires_at = datetime.now(timezone.utc)

    # Act
    db_token = await repo.create_refresh_token(
        token=token,
        client_id=client_id,
        user_id=user_id,
        parent_family_id=parent_family_id,
        expires_at=expires_at,
    )

    # Assert
    assert db_token.token == token
    assert db_token.client_id == client_id
    assert db_token.user_id == user_id
    assert db_token.parent_family_id == parent_family_id
    assert db_token.expires_at == expires_at
    assert db_token.is_revoked is False

    mock_db.add.assert_called_once_with(db_token)
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(db_token)


@pytest.mark.asyncio
async def test_get_by_token():
    # Arrange
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_token = RefreshToken(token="test_token")
    mock_result.scalar_one_or_none.return_value = mock_token
    mock_db.execute = AsyncMock(return_value=mock_result)

    repo = TokenRepository(mock_db)

    # Act
    result = await repo.get_by_token("test_token")

    # Assert
    assert result == mock_token
    mock_db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_revoke_token():
    # Arrange
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()
    repo = TokenRepository(mock_db)
    token_id = uuid.uuid4()

    # Act
    await repo.revoke_token(token_id)

    # Assert
    mock_db.execute.assert_called_once()
    mock_db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_revoke_family():
    # Arrange
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()
    repo = TokenRepository(mock_db)
    family_id = uuid.uuid4()

    # Act
    await repo.revoke_family(family_id)

    # Assert
    mock_db.execute.assert_called_once()
    mock_db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_get_token_repository():

    mock_db = AsyncMock()
    repo = await get_token_repository(mock_db)
    assert isinstance(repo, TokenRepository)
    assert repo.db is mock_db
