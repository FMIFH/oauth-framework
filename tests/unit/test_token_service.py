import uuid
from datetime import datetime
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest

from src.models.keys import SigningKey
from src.services.token_service import TokenService, get_token_service


@pytest.fixture
def mock_token_repo():
    return AsyncMock()


@pytest.fixture
def mock_key_repo():
    return AsyncMock()


@pytest.fixture
def mock_db_session():
    return AsyncMock()


@pytest.fixture
def token_service(mock_token_repo, mock_key_repo, mock_db_session):
    return TokenService(
        token_repo=mock_token_repo,
        key_repo=mock_key_repo,
        db_session=mock_db_session,
    )


@pytest.mark.asyncio
async def test_generate_access_token_active_key_exists(mock_key_repo, token_service):
    # Arrange
    client_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    scope = "openid profile"

    # Mock an active signing key
    mock_key = SigningKey(
        kid="test-kid",
        algorithm="RS256",
        encrypted_private_key="encrypted_pem_data",
    )
    mock_key_repo.get_active_key.return_value = mock_key

    # Patch decrypt_private_key and jwt.encode to verify behaviour
    dummy_private_key = "dummy_private_key_pem"
    with (
        patch(
            "src.services.token_service.decrypt_private_key",
            return_value=dummy_private_key,
        ) as mock_decrypt,
        patch(
            "src.services.token_service.jwt.encode",
            return_value="mocked.access.token",
        ) as mock_jwt_encode,
    ):
        # Act
        token, ttl = await token_service.generate_access_token(client_id, user_id, scope)

        # Assert
        assert token == "mocked.access.token"
        assert ttl == 3600  # assuming access_token_ttl defaults to 3600
        mock_key_repo.get_active_key.assert_called_once()
        mock_decrypt.assert_called_once_with("encrypted_pem_data", ANY)
        mock_jwt_encode.assert_called_once()
        args, kwargs = mock_jwt_encode.call_args
        payload = args[0]
        assert payload["client_id"] == client_id
        assert payload["sub"] == user_id
        assert payload["scope"] == scope
        assert kwargs["headers"] == {"kid": "test-kid"}


@pytest.mark.asyncio
async def test_generate_access_token_active_key_missing_triggers_publish(
    mock_key_repo, mock_db_session, token_service
):
    # Arrange
    client_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    scope = "openid"

    mock_key_repo.get_active_key.return_value = None

    # Mock publish_new_key
    mock_new_key = SigningKey(
        kid="new-kid",
        algorithm="RS256",
        encrypted_private_key="new_encrypted_pem",
    )

    dummy_private_key = "dummy_private_key_pem"
    with (
        patch(
            "src.services.token_service.publish_new_key",
            return_value=mock_new_key,
        ) as mock_publish,
        patch(
            "src.services.token_service.decrypt_private_key",
            return_value=dummy_private_key,
        ) as mock_decrypt,
        patch(
            "src.services.token_service.jwt.encode",
            return_value="new.mocked.token",
        ) as mock_jwt_encode,
    ):
        # Act
        token, ttl = await token_service.generate_access_token(client_id, user_id, scope)

        # Assert
        assert token == "new.mocked.token"
        mock_key_repo.get_active_key.assert_called_once()
        mock_publish.assert_called_once_with(
            db=mock_db_session,
            algorithm="RS256",
            master_key_hex=ANY,
        )
        mock_decrypt.assert_called_once_with("new_encrypted_pem", ANY)
        mock_jwt_encode.assert_called_once()


@pytest.mark.asyncio
async def test_generate_refresh_token(mock_token_repo, token_service):
    # Arrange
    client_id = uuid.uuid4()
    user_id = uuid.uuid4()

    # Act
    token_str = await token_service.generate_refresh_token(client_id, user_id)

    # Assert
    assert token_str.startswith("ref_")
    assert len(token_str) > 10
    mock_token_repo.create_refresh_token.assert_called_once()
    kwargs = mock_token_repo.create_refresh_token.call_args[1]
    assert kwargs["token"] == token_str
    assert kwargs["client_id"] == client_id
    assert kwargs["user_id"] == user_id
    assert isinstance(kwargs["parent_family_id"], uuid.UUID)
    assert isinstance(kwargs["expires_at"], datetime)


@pytest.mark.asyncio
async def test_get_refresh_token(mock_token_repo, token_service):
    # Arrange
    token_str = "ref_abc"
    mock_token_record = MagicMock()
    mock_token_repo.get_by_token.return_value = mock_token_record

    # Act
    result = await token_service.get_refresh_token(token_str)

    # Assert
    assert result == mock_token_record
    mock_token_repo.get_by_token.assert_called_once_with(token_str)


@pytest.mark.asyncio
async def test_revoke_refresh_token(mock_token_repo, token_service):
    # Arrange
    token_id = uuid.uuid4()

    # Act
    await token_service.revoke_refresh_token(token_id)

    # Assert
    mock_token_repo.revoke_token.assert_called_once_with(token_id)


@pytest.mark.asyncio
async def test_revoke_refresh_token_family(mock_token_repo, token_service):
    # Arrange
    family_id = uuid.uuid4()

    # Act
    await token_service.revoke_refresh_token_family(family_id)

    # Assert
    mock_token_repo.revoke_family.assert_called_once_with(family_id)


@pytest.mark.asyncio
async def test_get_token_service():

    mock_token_repo = AsyncMock()
    mock_key_repo = AsyncMock()
    mock_db = AsyncMock()
    service = await get_token_service(mock_token_repo, mock_key_repo, mock_db)
    assert isinstance(service, TokenService)
    assert service.token_repo is mock_token_repo
    assert service.key_repo is mock_key_repo
    assert service.db_session is mock_db
