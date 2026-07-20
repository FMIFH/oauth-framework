import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.models import User
from src.repositories.user_repo import UserRepository


@pytest.mark.asyncio
async def test_create_user():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    repo = UserRepository(mock_db)
    email = "test@example.com"
    password_hash = "hashed_pw"

    # Act
    user = await repo.create_user(email=email, password_hash=password_hash, is_active=True)

    # Assert
    assert user.email == email
    assert user.password_hash == password_hash
    assert user.is_active is True
    mock_db.add.assert_called_once_with(user)
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(user)


@pytest.mark.asyncio
async def test_get_by_email():
    # Arrange
    mock_db = AsyncMock()
    repo = UserRepository(mock_db)
    email = "test@example.com"

    mock_result = MagicMock()
    mock_user = User(email=email, password_hash="hash")
    mock_result.scalar_one_or_none.return_value = mock_user
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Act
    user = await repo.get_by_email(email)

    # Assert
    assert user == mock_user
    mock_db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_get_by_id():
    # Arrange
    mock_db = AsyncMock()
    repo = UserRepository(mock_db)
    user_id = uuid.uuid4()

    mock_result = MagicMock()
    mock_user = User(id=user_id, email="test@example.com", password_hash="hash")
    mock_result.scalar_one_or_none.return_value = mock_user
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Act
    user = await repo.get_by_id(user_id)

    # Assert
    assert user == mock_user
    mock_db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_update_user():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    repo = UserRepository(mock_db)
    user = User(email="test@example.com", password_hash="hash")

    # Act
    updated_user = await repo.update_user(user)

    # Assert
    assert updated_user == user
    mock_db.add.assert_called_once_with(user)
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(user)


@pytest.mark.asyncio
async def test_lock_and_unlock_user():
    # Arrange
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    repo = UserRepository(mock_db)
    user_id = uuid.uuid4()
    mock_user = User(id=user_id, email="test@example.com", password_hash="hash")

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_user
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Act - Lock
    locked_user = await repo.lock_user(user_id)

    # Assert - Lock
    assert locked_user is not None
    assert locked_user.is_locked is True
    assert locked_user.locked_at is not None
    mock_db.commit.assert_called_once()

    # Reset mock calls for unlock
    mock_db.commit.reset_mock()

    # Act - Unlock
    unlocked_user = await repo.unlock_user(user_id)

    # Assert - Unlock
    assert unlocked_user is not None
    assert unlocked_user.is_locked is False
    assert unlocked_user.locked_at is None
    mock_db.commit.assert_called_once()
