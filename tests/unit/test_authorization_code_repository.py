import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.models.token import AuthorizationCode
from src.repositories.authorization_code_repo import AuthorizationCodeRepository, get_authorization_code_repo


@pytest.mark.asyncio
async def test_create_authorization_code():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()

    repo = AuthorizationCodeRepository(mock_db)
    code = "test_auth_code_xyz"
    client_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    code_challenge = "challenge_123"
    code_challenge_method = "S256"
    scope = "openid profile"
    redirect_uri = "https://example.com/callback"
    expires_at = datetime.now(timezone.utc)

    # Act
    auth_code = await repo.create(
        code=code,
        client_id=client_id,
        user_id=user_id,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=scope,
        redirect_uri=redirect_uri,
        expires_at=expires_at,
    )

    # Assert
    assert auth_code.code == code
    assert auth_code.client_id == client_id
    assert auth_code.user_id == user_id
    assert auth_code.code_challenge == code_challenge
    assert auth_code.code_challenge_method == code_challenge_method
    assert auth_code.scope == scope
    assert auth_code.redirect_uri == redirect_uri
    assert auth_code.expires_at == expires_at

    mock_db.add.assert_called_once_with(auth_code)
    mock_db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_consume_code_exists():
    # Arrange
    mock_db = AsyncMock()
    mock_db.delete = AsyncMock()
    mock_db.commit = AsyncMock()

    mock_result = MagicMock()
    code_obj = AuthorizationCode(
        id=uuid.uuid4(),
        code="test_code",
        client_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        code_challenge="challenge",
        code_challenge_method="S256",
        scope="openid",
        redirect_uri="https://example.com/callback",
        expires_at=datetime.now(timezone.utc),
    )
    mock_result.scalar_one_or_none.return_value = code_obj
    mock_db.execute = AsyncMock(return_value=mock_result)

    repo = AuthorizationCodeRepository(mock_db)

    # Act
    result = await repo.consume_code("test_code")

    # Assert
    assert result == code_obj
    mock_db.execute.assert_called_once()
    mock_db.delete.assert_called_once_with(code_obj)
    mock_db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_consume_code_not_found():
    # Arrange
    mock_db = AsyncMock()
    mock_db.delete = AsyncMock()
    mock_db.commit = AsyncMock()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)

    repo = AuthorizationCodeRepository(mock_db)

    # Act
    result = await repo.consume_code("test_code")

    # Assert
    assert result is None
    mock_db.execute.assert_called_once()
    mock_db.delete.assert_not_called()
    mock_db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_delete_expired_codes():
    mock_db = AsyncMock()
    repo = AuthorizationCodeRepository(mock_db)
    await repo.delete_expired_codes()
    mock_db.execute.assert_called_once()
    mock_db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_get_authorization_code_repo():

    mock_db = AsyncMock()
    repo = await get_authorization_code_repo(mock_db)
    assert isinstance(repo, AuthorizationCodeRepository)
    assert repo.session is mock_db
