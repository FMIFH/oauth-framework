import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.models import Client, ClientSecret
from src.repositories.client_repo import ClientRepository


@pytest.mark.asyncio
async def test_create_client_with_list_inputs():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    repo = ClientRepository(mock_db)
    client_name = "Test Client"
    client_type = "confidential"
    redirect_uris = [
        "https://app.example.com/callback",
        "https://app2.example.com/callback",
    ]
    grant_types = ["authorization_code", "refresh_token"]
    scope = ["openid", "profile", "email"]

    # Act
    client = await repo.create_client(
        client_name=client_name,
        client_type=client_type,
        redirect_uris=redirect_uris,
        grant_types=grant_types,
        scope=scope,
    )

    # Assert
    assert client.client_name == client_name
    assert client.client_type == client_type
    assert client.redirect_uris == json.dumps(redirect_uris)
    assert client.grant_types == "authorization_code,refresh_token"
    assert client.scope == "openid profile email"
    mock_db.add.assert_called_once_with(client)
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(client)


@pytest.mark.asyncio
async def test_create_client_with_string_inputs():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    repo = ClientRepository(mock_db)
    client_name = "Test Client"
    client_type = "public"
    redirect_uris = '["https://app.example.com/callback"]'
    grant_types = "authorization_code"
    scope = "openid"

    # Act
    client = await repo.create_client(
        client_name=client_name,
        client_type=client_type,
        redirect_uris=redirect_uris,
        grant_types=grant_types,
        scope=scope,
    )

    # Assert
    assert client.client_name == client_name
    assert client.client_type == client_type
    assert client.redirect_uris == redirect_uris
    assert client.grant_types == grant_types
    assert client.scope == scope
    mock_db.add.assert_called_once_with(client)


@pytest.mark.asyncio
async def test_get_by_id():
    # Arrange
    mock_db = AsyncMock()
    repo = ClientRepository(mock_db)
    client_id = uuid.uuid4()

    mock_result = MagicMock()
    mock_client = Client(id=client_id, client_name="Test", client_type="confidential")
    mock_result.scalar_one_or_none.return_value = mock_client
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Act
    client = await repo.get_by_id(client_id)

    # Assert
    assert client == mock_client
    mock_db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_update_client():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    repo = ClientRepository(mock_db)
    client = Client(client_name="Test", client_type="confidential")

    # Act
    updated_client = await repo.update_client(client)

    # Assert
    assert updated_client == client
    mock_db.add.assert_called_once_with(client)
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(client)


@pytest.mark.asyncio
async def test_delete_client_exists():
    # Arrange
    mock_db = AsyncMock()
    mock_db.delete = AsyncMock()
    mock_db.commit = AsyncMock()

    repo = ClientRepository(mock_db)
    client_id = uuid.uuid4()
    mock_client = Client(id=client_id, client_name="Test")

    # Mock get_by_id call within delete_client
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_client
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Act
    success = await repo.delete_client(client_id)

    # Assert
    assert success is True
    mock_db.delete.assert_called_once_with(mock_client)
    mock_db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_delete_client_not_exists():
    # Arrange
    mock_db = AsyncMock()
    repo = ClientRepository(mock_db)
    client_id = uuid.uuid4()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Act
    success = await repo.delete_client(client_id)

    # Assert
    assert success is False
    mock_db.delete.assert_not_called()


@pytest.mark.asyncio
async def test_create_client_secret():
    # Arrange
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    repo = ClientRepository(mock_db)
    client_id = uuid.uuid4()
    secret_hash = "hashedsecret"
    expires_at = datetime.now(timezone.utc)

    # Act
    secret = await repo.create_client_secret(
        client_id=client_id,
        secret_hash=secret_hash,
        expires_at=expires_at,
    )

    # Assert
    assert secret.client_id == client_id
    assert secret.secret_hash == secret_hash
    assert secret.expires_at == expires_at
    mock_db.add.assert_called_once_with(secret)
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(secret)


@pytest.mark.asyncio
async def test_get_client_secrets():
    # Arrange
    mock_db = AsyncMock()
    repo = ClientRepository(mock_db)
    client_id = uuid.uuid4()

    mock_result = MagicMock()
    secret1 = ClientSecret(id=uuid.uuid4(), client_id=client_id, secret_hash="hash1")
    secret2 = ClientSecret(id=uuid.uuid4(), client_id=client_id, secret_hash="hash2")
    mock_result.scalars.return_value.all.return_value = [secret1, secret2]
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Act
    secrets = await repo.get_client_secrets(client_id)

    # Assert
    assert len(secrets) == 2
    assert secrets[0] == secret1
    assert secrets[1] == secret2
    mock_db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_get_active_secrets():
    # Arrange
    mock_db = AsyncMock()
    repo = ClientRepository(mock_db)
    client_id = uuid.uuid4()

    mock_result = MagicMock()
    secret = ClientSecret(id=uuid.uuid4(), client_id=client_id, secret_hash="hash")
    mock_result.scalars.return_value.all.return_value = [secret]
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Act
    active_secrets = await repo.get_active_secrets(client_id)

    # Assert
    assert len(active_secrets) == 1
    assert active_secrets[0] == secret
    mock_db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_delete_client_secret_exists():
    # Arrange
    mock_db = AsyncMock()
    mock_db.delete = AsyncMock()
    mock_db.commit = AsyncMock()

    repo = ClientRepository(mock_db)
    secret_id = uuid.uuid4()
    mock_secret = ClientSecret(id=secret_id, secret_hash="hash")

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_secret
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Act
    success = await repo.delete_client_secret(secret_id)

    # Assert
    assert success is True
    mock_db.delete.assert_called_once_with(mock_secret)
    mock_db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_delete_client_secret_not_exists():
    # Arrange
    mock_db = AsyncMock()
    repo = ClientRepository(mock_db)
    secret_id = uuid.uuid4()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)

    # Act
    success = await repo.delete_client_secret(secret_id)

    # Assert
    assert success is False
    mock_db.delete.assert_not_called()
