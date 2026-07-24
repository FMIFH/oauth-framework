import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.models import User
from src.repositories.user_repo import UserRepository, get_user_repository


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


@pytest.mark.asyncio
async def test_activate_and_deactivate_user():
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    repo = UserRepository(mock_db)
    user_id = uuid.uuid4()
    mock_user = User(id=user_id, email="test@example.com", password_hash="hash", is_active=False)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_user
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Act - Activate
    activated_user = await repo.activate_user(user_id)
    assert activated_user is not None
    assert activated_user.is_active is True

    # Act - Deactivate
    deactivated_user = await repo.deactivate_user(user_id)
    assert deactivated_user is not None
    assert deactivated_user.is_active is False


@pytest.mark.asyncio
async def test_delete_user():
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()
    repo = UserRepository(mock_db)
    user_id = uuid.uuid4()
    mock_user = User(id=user_id, email="test@example.com", password_hash="hash")

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_user
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Delete existing
    success = await repo.delete_user(user_id)
    assert success is True
    mock_db.delete.assert_called_once_with(mock_user)

    # Delete non-existing
    mock_result.scalar_one_or_none.return_value = None
    success_not_found = await repo.delete_user(uuid.uuid4())
    assert success_not_found is False


@pytest.mark.asyncio
async def test_user_repo_methods_not_found():
    mock_db = AsyncMock()
    repo = UserRepository(mock_db)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)

    user_id = uuid.uuid4()
    assert await repo.lock_user(user_id) is None
    assert await repo.unlock_user(user_id) is None
    assert await repo.activate_user(user_id) is None
    assert await repo.deactivate_user(user_id) is None


@pytest.mark.asyncio
async def test_get_user_repository():

    mock_db = AsyncMock()
    repo = await get_user_repository(mock_db)
    assert isinstance(repo, UserRepository)
    assert repo.db is mock_db
