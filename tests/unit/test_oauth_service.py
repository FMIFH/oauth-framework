import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from src.config import settings
from src.core.security import hash_password
from src.exceptions.invalid_scope_exception import InvalidScopeError
from src.models.client import Client, ClientSecret
from src.models.keys import SigningKey
from src.models.token import AuthorizationCode
from src.services.oauth_service import OAuthService, get_oauth_service


@pytest.fixture
def mock_client_repo():
    return AsyncMock()


@pytest.fixture
def mock_auth_code_repo():
    return AsyncMock()


@pytest.fixture
def mock_redis():
    mock = AsyncMock()

    async def getdel_side_effect(key):
        return await mock.get(key)

    mock.getdel.side_effect = getdel_side_effect
    return mock


@pytest.fixture
def service(mock_client_repo, mock_auth_code_repo, mock_redis):
    return OAuthService(
        client_repo=mock_client_repo,
        authorization_code_repo=mock_auth_code_repo,
        redis_pool=mock_redis,
    )


@pytest.mark.asyncio
async def test_get_and_validate_client_success(mock_client_repo, service):
    # Arrange
    client_id = str(uuid.uuid4())
    redirect_uri = "https://example.com/callback"

    mock_client = Client(
        id=uuid.UUID(client_id),
        client_name="Test Client",
        client_type="public",
        redirect_uris=json.dumps([redirect_uri]),
        grant_types="authorization_code",
        scope="openid profile",
    )
    mock_client_repo.get_by_id = AsyncMock(return_value=mock_client)

    # Act
    client = await service.get_and_validate_client(client_id, redirect_uri)

    # Assert
    assert client == mock_client
    mock_client_repo.get_by_id.assert_called_once_with(uuid.UUID(client_id))


@pytest.mark.asyncio
async def test_get_and_validate_client_invalid_uuid(service):
    # Arrange

    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        await service.get_and_validate_client("not-a-uuid", "https://example.com/callback")

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Invalid client ID format"


@pytest.mark.asyncio
async def test_get_and_validate_client_not_found(mock_client_repo, service):
    # Arrange
    client_id = str(uuid.uuid4())
    mock_client_repo.get_by_id = AsyncMock(return_value=None)

    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        await service.get_and_validate_client(client_id, "https://example.com/callback")

    assert exc_info.value.status_code == 400
    assert "Client not found" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_and_validate_client_invalid_redirect_uri(mock_client_repo, service):
    # Arrange
    client_id = str(uuid.uuid4())
    mock_client = Client(
        id=uuid.UUID(client_id),
        client_name="Test Client",
        client_type="public",
        redirect_uris=json.dumps(["https://example.com/callback"]),
        grant_types="authorization_code",
        scope="openid",
    )
    mock_client_repo.get_by_id = AsyncMock(return_value=mock_client)

    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        await service.get_and_validate_client(client_id, "https://evil.com/callback")

    assert exc_info.value.status_code == 400
    assert "Invalid redirect URI" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_and_validate_client_corrupt_uris(mock_client_repo, service):
    # Arrange
    client_id = str(uuid.uuid4())
    mock_client = Client(
        id=uuid.UUID(client_id),
        client_name="Test Client",
        client_type="public",
        redirect_uris="invalid-json-string",
        grant_types="authorization_code",
        scope="openid",
    )
    mock_client_repo.get_by_id = AsyncMock(return_value=mock_client)

    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        await service.get_and_validate_client(client_id, "https://example.com/callback")

    assert exc_info.value.status_code == 500
    assert "Client configuration error" in exc_info.value.detail


def test_validate_scope_success(service):
    # Arrange
    client = Client(scope="openid profile email")

    # Act & Assert
    service.validate_scope("openid email", client)  # Should not raise exception
    service.validate_scope("", client)  # Empty scope should be fine


def test_validate_scope_failure(service):
    # Arrange
    client = Client(scope="openid profile")

    # Act & Assert
    with pytest.raises(InvalidScopeError) as exc_info:
        service.validate_scope("openid offline_access", client)

    assert "Requested scope is not allowed" in str(exc_info.value)


@pytest.mark.asyncio
async def test_create_authorization_code(mock_auth_code_repo, service):
    # Arrange
    client_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    redirect_uri = "https://example.com/callback"
    scope = "openid"
    challenge = "challenge_str"
    method = "S256"

    # Act
    code = await service.create_authorization_code(client_id, user_id, redirect_uri, scope, challenge, method)

    # Assert
    assert len(code) > 20
    mock_auth_code_repo.create.assert_called_once()
    create_args, create_kwargs = mock_auth_code_repo.create.call_args
    assert create_kwargs["code"] == code
    assert create_kwargs["client_id"] == uuid.UUID(client_id)
    assert create_kwargs["user_id"] == uuid.UUID(user_id)
    assert create_kwargs["code_challenge"] == challenge
    assert create_kwargs["code_challenge_method"] == method
    assert create_kwargs["scope"] == scope
    assert create_kwargs["redirect_uri"] == redirect_uri
    assert isinstance(create_kwargs["expires_at"], datetime)


@pytest.mark.asyncio
async def test_consume_authorization_code_exists(mock_auth_code_repo, service):
    # Arrange
    code = "test_auth_code"
    mock_auth_code = AuthorizationCode(
        id=uuid.uuid4(),
        code=code,
        client_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        code_challenge="challenge",
        code_challenge_method="S256",
        scope="openid",
        redirect_uri="https://example.com/callback",
        expires_at=datetime.now(timezone.utc),
    )
    mock_auth_code_repo.consume_code = AsyncMock(return_value=mock_auth_code)

    # Act
    consumed = await service.consume_authorization_code(code)

    # Assert
    assert consumed is not None
    assert consumed["client_id"] == str(mock_auth_code.client_id)
    assert consumed["user_id"] == str(mock_auth_code.user_id)
    assert consumed["redirect_uri"] == mock_auth_code.redirect_uri
    assert consumed["scope"] == mock_auth_code.scope
    assert consumed["code_challenge"] == mock_auth_code.code_challenge
    assert consumed["code_challenge_method"] == mock_auth_code.code_challenge_method

    mock_auth_code_repo.consume_code.assert_called_once_with(code)


@pytest.mark.asyncio
async def test_consume_authorization_code_missing(mock_auth_code_repo, service):
    # Arrange
    code = "test_auth_code"
    mock_auth_code_repo.consume_code = AsyncMock(return_value=None)

    # Act
    consumed = await service.consume_authorization_code(code)

    # Assert
    assert consumed is None
    mock_auth_code_repo.consume_code.assert_called_once_with(code)


def test_verify_pkce_plain_success(service):
    # Arrange
    with patch("src.services.oauth_service.settings") as mock_settings:
        mock_settings.enable_plain_pkce = True
        assert service.verify_pkce("verifier", "verifier", "plain") is True


def test_verify_pkce_plain_disabled(service):
    # Arrange
    with patch("src.services.oauth_service.settings") as mock_settings:
        mock_settings.enable_plain_pkce = False
        assert service.verify_pkce("verifier", "verifier", "plain") is False


def test_verify_pkce_s256_success(service):
    # Arrange
    # S256 test vectors:
    # Verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    # Challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    assert service.verify_pkce(verifier, challenge, "S256") is True
    assert service.verify_pkce(verifier, challenge, "s256") is True
    assert service.verify_pkce(verifier, challenge, "SHA-256") is True
    assert service.verify_pkce(verifier, challenge, "sha-256") is True


def test_verify_pkce_s256_failure(service):
    # Arrange
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    assert service.verify_pkce(verifier, "different_challenge", "S256") is False
    assert service.verify_pkce(verifier, "different_challenge", "SHA-256") is False


@pytest.mark.asyncio
async def test_exchange_token_auth_code_success(mock_client_repo, service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        client_type="public",
        grant_types="authorization_code",
        scope="openid",
    )
    mock_client_repo.get_by_id.return_value = mock_client

    payload = {
        "client_id": str(client_id),
        "user_id": str(uuid.uuid4()),
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "code_challenge": "challenge_str",
        "code_challenge_method": "S256",
    }

    # Mock token service
    mock_token_service = AsyncMock()
    mock_token_service.generate_access_token.return_value = ("access-token-123", 3600)
    mock_token_service.generate_refresh_token.return_value = "refresh-token-123"

    # Act
    with (
        patch.object(service, "verify_pkce", return_value=True),
        patch.object(service, "consume_authorization_code", return_value=payload),
    ):
        result = await service.exchange_token(
            grant_type="authorization_code",
            token_service=mock_token_service,
            code="auth_code_xyz",
            redirect_uri="https://example.com/callback",
            client_id=str(client_id),
            code_verifier="verifier_xyz",
        )

    # Assert
    assert result["access_token"] == "access-token-123"
    assert result["refresh_token"] == "refresh-token-123"
    assert result["expires_in"] == 3600
    assert result["scope"] == "openid"


@pytest.mark.asyncio
async def test_process_authorization_request_unsupported_response_type(service):
    # Arrange
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        await service.process_authorization_request(
            user_id="test-user",
            response_type="token",  # unsupported
            client_id=str(uuid.uuid4()),
            redirect_uri="https://example.com/callback",
            scope="openid",
            state="xyz",
            code_challenge="challenge",
            code_challenge_method="S256",
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "unsupported_response_type"


@pytest.mark.asyncio
async def test_process_authorization_request_redirect_to_login(mock_client_repo, service):
    # Arrange
    client_id = str(uuid.uuid4())
    redirect_uri = "https://example.com/callback"
    mock_client = Client(
        id=uuid.UUID(client_id),
        client_name="Test Client",
        client_type="public",
        redirect_uris=json.dumps([redirect_uri]),
        grant_types="authorization_code",
        scope="openid",
    )
    mock_client_repo.get_by_id.return_value = mock_client

    # Act
    response = await service.process_authorization_request(
        user_id=None,
        response_type="code",
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope="openid",
        state="xyz",
        code_challenge="challenge",
        code_challenge_method="S256",
    )

    # Assert
    assert response.status_code == 303
    assert "/users/login" in response.headers["location"]


@pytest.mark.asyncio
async def test_revoke_token_no_token(service):
    # Arrange
    mock_token_service = AsyncMock()

    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        await service.revoke_token(
            token="",
            token_service=mock_token_service,
        )
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "invalid_request"


@pytest.mark.asyncio
async def test_revoke_token_client_auth_failure(service):
    # Arrange
    mock_token_service = AsyncMock()

    client_id = uuid.uuid4()
    # Mock authenticate_client to raise invalid_client HTTPException
    service.authenticate_client = AsyncMock(
        side_effect=HTTPException(status_code=401, detail="Invalid client credentials")
    )

    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        await service.revoke_token(
            token="ref_some_token",
            token_service=mock_token_service,
            client_id=str(client_id),
            client_secret="wrong_secret",
        )
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid_client"


@pytest.mark.asyncio
async def test_revoke_token_success_refresh_token_hint(service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        client_type="public",
    )
    service.authenticate_client = AsyncMock(return_value=mock_client)

    # Mock token record and service methods
    token_record = MagicMock()
    token_record.id = uuid.uuid4()
    token_record.client_id = client_id
    token_record.parent_family_id = uuid.uuid4()

    mock_token_service = AsyncMock()
    mock_token_service.get_refresh_token.return_value = token_record

    # Act
    result = await service.revoke_token(
        token="ref_valid_token",
        token_service=mock_token_service,
        token_type_hint="refresh_token",
        client_id=str(client_id),
    )

    # Assert
    assert result == {}
    mock_token_service.get_refresh_token.assert_called_once_with("ref_valid_token")
    mock_token_service.revoke_refresh_token_family.assert_called_once_with(token_record.parent_family_id)
    mock_token_service.revoke_refresh_token.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_token_success_no_hint(service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        client_type="public",
    )
    service.authenticate_client = AsyncMock(return_value=mock_client)

    # Mock token record and service methods
    token_record = MagicMock()
    token_record.id = uuid.uuid4()
    token_record.client_id = client_id
    token_record.parent_family_id = uuid.uuid4()

    mock_token_service = AsyncMock()
    mock_token_service.get_refresh_token.return_value = token_record

    # Act
    result = await service.revoke_token(
        token="ref_valid_token",
        token_service=mock_token_service,
        client_id=str(client_id),
    )

    # Assert
    assert result == {}
    mock_token_service.get_refresh_token.assert_called_once_with("ref_valid_token")
    mock_token_service.revoke_refresh_token_family.assert_called_once_with(token_record.parent_family_id)
    mock_token_service.revoke_refresh_token.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_token_not_found_graceful(service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        client_type="public",
    )
    service.authenticate_client = AsyncMock(return_value=mock_client)

    mock_token_service = AsyncMock()
    mock_token_service.get_refresh_token.return_value = None

    # Act
    result = await service.revoke_token(
        token="ref_nonexistent_token",
        token_service=mock_token_service,
        client_id=str(client_id),
    )

    # Assert
    assert result == {}
    mock_token_service.get_refresh_token.assert_called_once_with("ref_nonexistent_token")
    mock_token_service.revoke_refresh_token.assert_not_called()
    mock_token_service.revoke_refresh_token_family.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_token_different_client_graceful(service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        client_type="public",
    )
    service.authenticate_client = AsyncMock(return_value=mock_client)

    # Token belongs to another client
    token_record = MagicMock()
    token_record.id = uuid.uuid4()
    token_record.client_id = uuid.uuid4()  # different client ID

    mock_token_service = AsyncMock()
    mock_token_service.get_refresh_token.return_value = token_record

    # Act
    result = await service.revoke_token(
        token="ref_other_client_token",
        token_service=mock_token_service,
        client_id=str(client_id),
    )

    # Assert
    assert result == {}
    mock_token_service.get_refresh_token.assert_called_once_with("ref_other_client_token")
    mock_token_service.revoke_refresh_token.assert_not_called()
    mock_token_service.revoke_refresh_token_family.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_token_different_client_refresh_token_hint_graceful(service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        client_type="public",
    )
    service.authenticate_client = AsyncMock(return_value=mock_client)

    # Token belongs to another client
    token_record = MagicMock()
    token_record.id = uuid.uuid4()
    token_record.client_id = uuid.uuid4()  # different client ID

    mock_token_service = AsyncMock()
    mock_token_service.get_refresh_token.return_value = token_record

    # Act
    result = await service.revoke_token(
        token="ref_other_client_token",
        token_service=mock_token_service,
        client_id=str(client_id),
        token_type_hint="refresh_token",
    )

    # Assert
    assert result == {}
    mock_token_service.get_refresh_token.assert_called_once_with("ref_other_client_token")
    mock_token_service.revoke_refresh_token.assert_not_called()
    mock_token_service.revoke_refresh_token_family.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_token_access_token_hint_success(mock_redis, service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        client_type="public",
    )
    service.authenticate_client = AsyncMock(return_value=mock_client)

    # Generate a fake JWT access token matching the client ID
    future_time = int(datetime.now(timezone.utc).timestamp()) + 100
    access_token_payload = {
        "jti": "jti_12345",
        "exp": future_time,
        "client_id": str(client_id),
    }
    # Encode with some dummy key since we mock the decode method
    access_token = jwt.encode(access_token_payload, "secret", algorithm="HS256")

    mock_token_service = AsyncMock()

    # Mock the signature verification to bypass actual RSA key verification
    service._decode_and_validate_jwt = AsyncMock(return_value=access_token_payload)

    # Act
    result = await service.revoke_token(
        token=access_token,
        token_service=mock_token_service,
        token_type_hint="access_token",
        client_id=str(client_id),
    )

    # Assert
    assert result == {}
    mock_redis.setex.assert_called_once()
    key, ttl, value = mock_redis.setex.call_args[0]
    assert key == "token:blacklist:jti_12345"
    assert ttl > 0
    assert value == "true"


@pytest.mark.asyncio
async def test_revoke_token_access_token_no_hint_success(mock_redis, service):
    # Arrange

    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        client_type="public",
    )
    service.authenticate_client = AsyncMock(return_value=mock_client)

    # Generate a fake JWT access token matching the client ID
    future_time = int(datetime.now(timezone.utc).timestamp()) + 100
    access_token_payload = {
        "jti": "jti_abcde",
        "exp": future_time,
        "client_id": str(client_id),
    }
    access_token = jwt.encode(access_token_payload, "secret", algorithm="HS256")

    mock_token_service = AsyncMock()

    # Mock the signature verification to bypass actual RSA key verification
    service._decode_and_validate_jwt = AsyncMock(return_value=access_token_payload)

    # Act
    result = await service.revoke_token(
        token=access_token,
        token_service=mock_token_service,
        client_id=str(client_id),
    )

    # Assert
    assert result == {}
    mock_redis.setex.assert_called_once()
    key, ttl, value = mock_redis.setex.call_args[0]
    assert key == "token:blacklist:jti_abcde"
    assert ttl > 0
    assert value == "true"


@pytest.mark.asyncio
async def test_revoke_token_access_token_expired_no_blacklist(mock_redis, service):
    # Arrange

    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        client_type="public",
    )
    service.authenticate_client = AsyncMock(return_value=mock_client)

    # Generate a fake expired JWT
    past_time = int(datetime.now(timezone.utc).timestamp()) - 100
    access_token_payload = {
        "jti": "jti_expired",
        "exp": past_time,
        "client_id": str(client_id),
    }
    access_token = jwt.encode(access_token_payload, "secret", algorithm="HS256")

    mock_token_service = AsyncMock()

    # Mock signature verification to return None since expired tokens are not validated/blacklisted
    service._decode_and_validate_jwt = AsyncMock(return_value=None)

    # Act
    result = await service.revoke_token(
        token=access_token,
        token_service=mock_token_service,
        client_id=str(client_id),
    )

    # Assert
    assert result == {}
    mock_redis.setex.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_token_access_token_wrong_client_no_blacklist(mock_redis, service):
    # Arrange

    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        client_type="public",
    )
    service.authenticate_client = AsyncMock(return_value=mock_client)

    # Generate a fake JWT belonging to another client
    future_time = int(datetime.now(timezone.utc).timestamp()) + 100
    access_token_payload = {
        "jti": "jti_wrong_client",
        "exp": future_time,
        "client_id": str(uuid.uuid4()),  # different client ID
    }
    access_token = jwt.encode(access_token_payload, "secret", algorithm="HS256")

    mock_token_service = AsyncMock()

    # Mock signature verification to return None since it belongs to a different client
    service._decode_and_validate_jwt = AsyncMock(return_value=None)

    # Act
    result = await service.revoke_token(
        token=access_token,
        token_service=mock_token_service,
        client_id=str(client_id),
    )

    # Assert
    assert result == {}
    mock_redis.setex.assert_not_called()


@pytest.mark.asyncio
async def test_decode_and_validate_jwt_valid_signature(service):
    # Arrange

    # Generate real RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    client_id = uuid.uuid4()
    kid = "test-key-id"

    mock_signing_key = SigningKey(
        kid=kid,
        algorithm="RS256",
        public_key_pem=public_pem.decode("utf-8"),
    )

    mock_key_service = AsyncMock()
    mock_key_service.get_signing_key_by_kid.return_value = mock_signing_key

    # Generate a real RS256 token
    future_time = int(datetime.now(timezone.utc).timestamp()) + 100
    access_token_payload = {
        "jti": "jti_real_rsa",
        "exp": future_time,
        "client_id": str(client_id),
        "aud": str(client_id),
    }
    access_token = jwt.encode(
        access_token_payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )

    # Act
    payload = await service._decode_and_validate_jwt(
        token=access_token,
        client_id_str=str(client_id),
        key_service=mock_key_service,
    )

    # Assert
    assert payload is not None
    assert payload["jti"] == "jti_real_rsa"
    assert payload["client_id"] == str(client_id)
    mock_key_service.get_signing_key_by_kid.assert_called_once_with(kid)


@pytest.mark.asyncio
async def test_decode_and_validate_jwt_invalid_signature(service):
    # Generate real RSA key pair
    private_key_1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem_1 = private_key_1.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    private_key_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem_2 = private_key_2.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    client_id = uuid.uuid4()
    kid = "test-key-id"

    # Database has public_key_2, but token is signed with private_key_1
    mock_signing_key = SigningKey(
        kid=kid,
        algorithm="RS256",
        public_key_pem=public_pem_2.decode("utf-8"),
    )

    mock_key_service = AsyncMock()
    mock_key_service.get_signing_key_by_kid.return_value = mock_signing_key

    future_time = int(datetime.now(timezone.utc).timestamp()) + 100
    access_token_payload = {
        "jti": "jti_forged",
        "exp": future_time,
        "client_id": str(client_id),
        "aud": str(client_id),
    }
    access_token = jwt.encode(
        access_token_payload,
        private_pem_1,
        algorithm="RS256",
        headers={"kid": kid},
    )

    # Act
    payload = await service._decode_and_validate_jwt(
        token=access_token,
        client_id_str=str(client_id),
        key_service=mock_key_service,
    )

    # Assert
    assert payload is None
    mock_key_service.get_signing_key_by_kid.assert_called_once_with(kid)


@pytest.mark.asyncio
async def test_authenticate_client_invalid_format(service):
    with pytest.raises(HTTPException) as exc:
        await service.authenticate_client("not-a-uuid")
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid client ID format"


@pytest.mark.asyncio
async def test_authenticate_client_not_found(mock_client_repo, service):
    mock_client_repo.get_by_id.return_value = None
    with pytest.raises(HTTPException) as exc:
        await service.authenticate_client(str(uuid.uuid4()))
    assert exc.value.status_code == 401
    assert exc.value.detail == "Client not found"


@pytest.mark.asyncio
async def test_authenticate_client_confidential_no_secret(mock_client_repo, service):
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Confidential Client",
        client_type="confidential",
    )
    mock_client_repo.get_by_id.return_value = mock_client
    with pytest.raises(HTTPException) as exc:
        await service.authenticate_client(str(client_id), None)
    assert exc.value.status_code == 401
    assert "Client secret is required" in exc.value.detail


@pytest.mark.asyncio
async def test_authenticate_client_confidential_invalid_credentials(mock_client_repo, service):
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Confidential Client",
        client_type="confidential",
    )
    mock_client_repo.get_by_id.return_value = mock_client

    mock_secret = ClientSecret(id=uuid.uuid4(), client_id=client_id, secret_hash="hashed_wrong_password")
    mock_client_repo.get_active_secrets.return_value = [mock_secret]

    with pytest.raises(HTTPException) as exc:
        await service.authenticate_client(str(client_id), "wrong_password")
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid client credentials"


@pytest.mark.asyncio
async def test_process_authorization_request_invalid_scope(mock_client_repo, service):
    client_id = uuid.uuid4()
    redirect_uri = "https://example.com/callback"
    mock_client = Client(
        id=client_id,
        client_name="Test",
        client_type="public",
        redirect_uris=json.dumps([redirect_uri]),
        grant_types="authorization_code",
        scope="openid",
    )
    mock_client_repo.get_by_id.return_value = mock_client

    # Force validate_scope to raise InvalidScopeError
    with patch.object(service, "validate_scope", side_effect=InvalidScopeError("invalid_scope")):
        with pytest.raises(HTTPException) as exc:
            await service.process_authorization_request(
                user_id="test-user",
                response_type="code",
                client_id=str(client_id),
                redirect_uri=redirect_uri,
                scope="invalid",
                state="xyz",
                code_challenge="challenge",
                code_challenge_method="S256",
            )
        assert exc.value.status_code == 400
        assert exc.value.detail == "invalid_scope"


@pytest.mark.asyncio
async def test_process_authorization_request_authenticated_success(mock_client_repo, mock_redis, service):
    client_id = uuid.uuid4()
    redirect_uri = "https://example.com/callback"
    mock_client = Client(
        id=client_id,
        client_name="Test",
        client_type="public",
        redirect_uris=json.dumps([redirect_uri]),
        grant_types="authorization_code",
        scope="openid",
    )
    mock_client_repo.get_by_id.return_value = mock_client

    with (
        patch.object(service, "validate_scope"),
        patch.object(service, "create_authorization_code", return_value="my_generated_code"),
    ):
        response = await service.process_authorization_request(
            user_id="test-user-id",
            response_type="code",
            client_id=str(client_id),
            redirect_uri=redirect_uri,
            scope="openid",
            state="xyz",
            code_challenge="challenge",
            code_challenge_method="S256",
        )
    assert response.status_code == 303
    location = response.headers["location"]
    assert "code=my_generated_code" in location
    assert "state=xyz" in location


def test_pkce_plain_disabled(service):

    orig = settings.enable_plain_pkce
    settings.enable_plain_pkce = False
    try:
        assert service.verify_pkce("verifier", "challenge", "PLAIN") is False
    finally:
        settings.enable_plain_pkce = orig


def test_extract_client_credentials_basic_auth_mismatch(service):

    auth_str = "client1:secret"
    b64_auth = base64.b64encode(auth_str.encode()).decode()

    # client_id mismatch
    with pytest.raises(HTTPException) as exc:
        service._extract_client_credentials(f"Basic {b64_auth}", "different_client", "secret")
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid_client"

    # bad format/decoding raises Exception
    with pytest.raises(HTTPException) as exc:
        service._extract_client_credentials("Basic bad_base64", None, None)
    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid_client"

    # no client_id
    with pytest.raises(HTTPException) as exc:
        service._extract_client_credentials(None, None, None)
    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid_client"


@pytest.mark.asyncio
async def test_process_authorization_code_grant_failures(service):
    mock_client = Client(id=uuid.uuid4(), grant_types="authorization_code")
    mock_token_srv = AsyncMock()

    # no code
    with pytest.raises(HTTPException) as exc:
        await service._process_authorization_code_grant(
            mock_client, mock_token_srv, None, "http://uri", "verifier"
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid_request"

    # consume returns None
    with patch.object(service, "consume_authorization_code", return_value=None):
        with pytest.raises(HTTPException) as exc:
            await service._process_authorization_code_grant(
                mock_client, mock_token_srv, "code123", "http://uri", "verifier"
            )
        assert exc.value.status_code == 400
        assert exc.value.detail == "invalid_grant"

    # client mismatch
    payload = {"client_id": str(uuid.uuid4()), "redirect_uri": "http://uri"}
    with patch.object(service, "consume_authorization_code", return_value=payload):
        with pytest.raises(HTTPException) as exc:
            await service._process_authorization_code_grant(
                mock_client, mock_token_srv, "code123", "http://uri", "verifier"
            )
        assert exc.value.status_code == 400
        assert exc.value.detail == "invalid_grant"

    # PKCE code_verifier missing
    payload = {
        "client_id": str(mock_client.id),
        "redirect_uri": "http://uri",
        "code_challenge": "challenge_123",
    }
    with patch.object(service, "consume_authorization_code", return_value=payload):
        with pytest.raises(HTTPException) as exc:
            await service._process_authorization_code_grant(
                mock_client, mock_token_srv, "code123", "http://uri", None
            )
        assert exc.value.status_code == 400
        assert exc.value.detail == "invalid_grant"

    # verify_pkce returns False
    payload = {
        "client_id": str(mock_client.id),
        "redirect_uri": "http://uri",
        "code_challenge": "challenge_123",
    }
    with (
        patch.object(service, "consume_authorization_code", return_value=payload),
        patch.object(service, "verify_pkce", return_value=False),
    ):
        with pytest.raises(HTTPException) as exc:
            await service._process_authorization_code_grant(
                mock_client, mock_token_srv, "code123", "http://uri", "verifier"
            )
        assert exc.value.status_code == 400
        assert exc.value.detail == "invalid_grant"

    # user_id missing
    payload = {"client_id": str(mock_client.id), "redirect_uri": "http://uri"}
    with patch.object(service, "consume_authorization_code", return_value=payload):
        with pytest.raises(HTTPException) as exc:
            await service._process_authorization_code_grant(
                mock_client, mock_token_srv, "code123", "http://uri", "verifier"
            )
        assert exc.value.status_code == 400
        assert exc.value.detail == "invalid_grant"

    # user_id not a valid UUID
    payload = {"client_id": str(mock_client.id), "redirect_uri": "http://uri", "user_id": "not-a-uuid"}
    with patch.object(service, "consume_authorization_code", return_value=payload):
        with pytest.raises(HTTPException) as exc:
            await service._process_authorization_code_grant(
                mock_client, mock_token_srv, "code123", "http://uri", "verifier"
            )
        assert exc.value.status_code == 400
        assert exc.value.detail == "invalid_grant"


@pytest.mark.asyncio
async def test_process_refresh_token_grant_failures(service):

    mock_client = Client(id=uuid.uuid4(), grant_types="refresh_token")
    mock_token_srv = AsyncMock()

    # no refresh_token
    with pytest.raises(HTTPException) as exc:
        await service._process_refresh_token_grant(mock_client, mock_token_srv, None, "openid")
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid_request"

    # token not found
    mock_token_srv.get_refresh_token.return_value = None
    with pytest.raises(HTTPException) as exc:
        await service._process_refresh_token_grant(mock_client, mock_token_srv, "ref_token", "openid")
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid_grant"

    # token expired
    mock_token_record = MagicMock()
    mock_token_record.client_id = mock_client.id
    mock_token_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)

    mock_token_srv.get_refresh_token.return_value = mock_token_record
    with pytest.raises(HTTPException) as exc:
        await service._process_refresh_token_grant(mock_client, mock_token_srv, "ref_token", "openid")
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid_grant"


@pytest.mark.asyncio
async def test_exchange_token_failures(mock_client_repo, service):
    mock_token_srv = AsyncMock()

    # authenticate_client raises HTTPException
    with patch.object(
        service, "authenticate_client", side_effect=HTTPException(status_code=401, detail="auth error")
    ):
        with pytest.raises(HTTPException) as exc:
            await service.exchange_token(
                grant_type="client_credentials", token_service=mock_token_srv, client_id=str(uuid.uuid4())
            )
        assert exc.value.status_code == 401
        assert exc.value.detail == "invalid_client"

    # grant_type not in client's grant_types
    mock_client = Client(id=uuid.uuid4(), grant_types="client_credentials")
    mock_client_repo.get_by_id.return_value = mock_client
    with pytest.raises(HTTPException) as exc:
        await service.exchange_token(
            grant_type="authorization_code", token_service=mock_token_srv, client_id=str(mock_client.id)
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "unsupported_grant_type"

    # unsupported grant type (not known by server)
    mock_client.grant_types = "client_credentials,implicit"
    with pytest.raises(HTTPException) as exc:
        await service.exchange_token(
            grant_type="implicit", token_service=mock_token_srv, client_id=str(mock_client.id)
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "unsupported_grant_type"


@pytest.mark.asyncio
async def test_decode_and_validate_jwt_failures(service):
    # key_service is None
    res = await service._decode_and_validate_jwt("token", "client_id", None)
    assert res is None

    # JWT has no kid

    token_no_kid = jwt.encode({"sub": "123"}, "secret", algorithm="HS256")
    mock_key_srv = AsyncMock()
    res = await service._decode_and_validate_jwt(token_no_kid, "client_id", mock_key_srv)
    assert res is None

    # signing_key is None in DB
    token_with_kid = jwt.encode({"sub": "123"}, "secret", algorithm="HS256", headers={"kid": "missing-kid"})
    mock_key_srv.get_signing_key_by_kid.return_value = None
    res = await service._decode_and_validate_jwt(token_with_kid, "client_id", mock_key_srv)
    assert res is None

    # jwt signature/aud invalid raises Exception, caught and returns None

    mock_signing_key = SigningKey(kid="kid", algorithm="RS256", public_key_pem="bad-pem")
    mock_key_srv.get_signing_key_by_kid.return_value = mock_signing_key
    res = await service._decode_and_validate_jwt(token_with_kid, "client_id", mock_key_srv)
    assert res is None


@pytest.mark.asyncio
async def test_revoke_token_edge_cases(service):
    mock_token_srv = AsyncMock()
    # unsupported hint
    with pytest.raises(HTTPException) as exc:
        await service.revoke_token("token", mock_token_srv, token_type_hint="invalid_hint")
    assert exc.value.status_code == 400
    assert exc.value.detail == "unsupported_token_type"

    # access token hint fallback to refresh token
    mock_client = Client(id=uuid.uuid4(), client_type="public")
    service.authenticate_client = AsyncMock(return_value=mock_client)

    with (
        patch.object(service, "_revoke_access_token", return_value=False) as mock_access,
        patch.object(service, "_revoke_refresh_token", return_value=True) as mock_refresh,
    ):
        res = await service.revoke_token(
            "some-token", mock_token_srv, token_type_hint="access_token", client_id=str(mock_client.id)
        )
        assert res == {}
        mock_access.assert_called_once()
        mock_refresh.assert_called_once()


@pytest.mark.asyncio
async def test_get_oauth_service():

    mock_client_repo = AsyncMock()
    mock_auth_repo = AsyncMock()
    mock_redis = AsyncMock()

    service_inst = await get_oauth_service(mock_client_repo, mock_auth_repo, mock_redis)
    assert isinstance(service_inst, OAuthService)
    assert service_inst.client_repo is mock_client_repo
    assert service_inst.authorization_code_repo is mock_auth_repo
    assert service_inst.redis_pool is mock_redis


@pytest.mark.asyncio
async def test_authenticate_client_confidential_success(mock_client_repo, service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Confidential Client",
        client_type="confidential",
    )
    mock_client_repo.get_by_id.return_value = mock_client

    secret_str = "super-secret-123"
    hashed = hash_password(secret_str)
    mock_secret = ClientSecret(id=uuid.uuid4(), client_id=client_id, secret_hash=hashed)
    mock_client_repo.get_active_secrets.return_value = [mock_secret]

    # Act
    client = await service.authenticate_client(str(client_id), secret_str)

    # Assert
    assert client == mock_client


def test_verify_pkce_unsupported_method(service):
    # Arrange
    # Act & Assert
    assert service.verify_pkce("verifier", "challenge", "INVALID_METHOD") is False


def test_extract_client_credentials_basic_auth_success(service):

    # Arrange
    auth_str = "client123:secret456"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    auth_header = f"Basic {b64_auth}"

    # Act
    extracted_id, extracted_secret = service._extract_client_credentials(auth_header, "client123", None)

    # Assert
    assert extracted_id == "client123"
    assert extracted_secret == "secret456"

    # Also test when client_id is None (not passed but extracted from basic auth)
    extracted_id2, extracted_secret2 = service._extract_client_credentials(auth_header, None, None)
    assert extracted_id2 == "client123"
    assert extracted_secret2 == "secret456"


@pytest.mark.asyncio
async def test_process_client_credentials_grant_success(service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Client Credentials Client",
        scope="read write",
    )
    mock_token_srv = AsyncMock()
    mock_token_srv.generate_access_token.return_value = ("client-credentials-token", 3600)

    # Act - Requesting allowed scope
    res = await service._process_client_credentials_grant(mock_client, mock_token_srv, "read")

    # Assert
    assert res["access_token"] == "client-credentials-token"
    assert res["token_type"] == "Bearer"
    assert res["expires_in"] == 3600
    assert res["scope"] == "read"
    mock_token_srv.generate_access_token.assert_called_once_with(
        client_id=str(client_id),
        user_id=None,
        scope="read",
    )


@pytest.mark.asyncio
async def test_process_client_credentials_grant_invalid_scope(service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Client Credentials Client",
        scope="read write",
    )
    mock_token_srv = AsyncMock()

    # Act & Assert
    with pytest.raises(HTTPException) as exc:
        await service._process_client_credentials_grant(mock_client, mock_token_srv, "admin")
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid_scope"


@pytest.mark.asyncio
async def test_process_refresh_token_grant_naive_expiry(service):

    mock_client = Client(id=uuid.uuid4(), grant_types="refresh_token")
    mock_token_srv = AsyncMock()

    # Token expired, with naive datetime (no timezone info)
    mock_token_record = MagicMock()
    mock_token_record.client_id = mock_client.id
    mock_token_record.expires_at = datetime.now() - timedelta(days=1)  # naive datetime

    mock_token_srv.get_refresh_token.return_value = mock_token_record

    with pytest.raises(HTTPException) as exc:
        await service._process_refresh_token_grant(mock_client, mock_token_srv, "ref_token", "openid")
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid_grant"


@pytest.mark.asyncio
async def test_process_refresh_token_grant_success(service):

    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Refresh Token Client",
        scope="read write",
    )
    mock_token_record = MagicMock()
    mock_token_record.client_id = client_id
    mock_token_record.user_id = uuid.uuid4()
    mock_token_record.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    mock_token_record.is_revoked = False
    mock_token_record.parent_family_id = uuid.uuid4()
    mock_token_record.id = uuid.uuid4()

    mock_token_srv = AsyncMock()
    mock_token_srv.get_refresh_token.return_value = mock_token_record
    mock_token_srv.generate_access_token.return_value = ("new-access-token", 3600)
    mock_token_srv.generate_refresh_token.return_value = "new-refresh-token"

    # Act
    res = await service._process_refresh_token_grant(mock_client, mock_token_srv, "ref_token", "read")

    # Assert
    assert res["access_token"] == "new-access-token"
    assert res["refresh_token"] == "new-refresh-token"
    assert res["expires_in"] == 3600
    assert res["scope"] == "read"
    mock_token_srv.revoke_refresh_token.assert_called_once_with(mock_token_record.id)


@pytest.mark.asyncio
async def test_process_refresh_token_grant_revoked(service):

    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Refresh Token Client",
        scope="read write",
    )
    mock_token_record = MagicMock()
    mock_token_record.client_id = client_id
    mock_token_record.user_id = uuid.uuid4()
    mock_token_record.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    mock_token_record.is_revoked = True
    mock_token_record.parent_family_id = uuid.uuid4()
    mock_token_record.id = uuid.uuid4()

    mock_token_srv = AsyncMock()
    mock_token_srv.get_refresh_token.return_value = mock_token_record

    # Act & Assert
    with pytest.raises(HTTPException) as exc:
        await service._process_refresh_token_grant(mock_client, mock_token_srv, "ref_token", "read")
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid_grant"
    mock_token_srv.revoke_refresh_token_family.assert_called_once_with(mock_token_record.parent_family_id)


@pytest.mark.asyncio
async def test_process_refresh_token_grant_invalid_scope(service):

    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Refresh Token Client",
        scope="read write",
    )
    mock_token_record = MagicMock()
    mock_token_record.client_id = client_id
    mock_token_record.user_id = uuid.uuid4()
    mock_token_record.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    mock_token_record.is_revoked = False
    mock_token_record.parent_family_id = uuid.uuid4()
    mock_token_record.id = uuid.uuid4()

    mock_token_srv = AsyncMock()
    mock_token_srv.get_refresh_token.return_value = mock_token_record

    # Act & Assert
    with pytest.raises(HTTPException) as exc:
        await service._process_refresh_token_grant(mock_client, mock_token_srv, "ref_token", "admin")
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid_scope"


@pytest.mark.asyncio
async def test_exchange_token_unsupported_grant_type_by_server(mock_client_repo, service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        grant_types="unsupported_grant_type_xyz",  # Allowed by client
    )
    mock_client_repo.get_by_id.return_value = mock_client
    service.authenticate_client = AsyncMock(return_value=mock_client)
    mock_token_srv = AsyncMock()

    # Act & Assert
    with pytest.raises(HTTPException) as exc:
        await service.exchange_token(
            grant_type="unsupported_grant_type_xyz",
            token_service=mock_token_srv,
            client_id=str(client_id),
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "unsupported_grant_type"


@pytest.mark.asyncio
async def test_decode_and_validate_jwt_expired_signature_error(service):
    # Arrange
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    client_id = uuid.uuid4()
    kid = "expired-key-id"

    mock_signing_key = SigningKey(
        kid=kid,
        algorithm="RS256",
        public_key_pem=public_pem.decode("utf-8"),
    )

    mock_key_service = AsyncMock()
    mock_key_service.get_signing_key_by_kid.return_value = mock_signing_key

    # Generate a real RS256 token that is expired (exp in the past)
    past_time = int(datetime.now(timezone.utc).timestamp()) - 100
    access_token_payload = {
        "jti": "jti_expired_rsa",
        "exp": past_time,
        "client_id": str(client_id),
        "aud": str(client_id),
    }
    access_token = jwt.encode(
        access_token_payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )

    # Act
    payload = await service._decode_and_validate_jwt(
        token=access_token,
        client_id_str=str(client_id),
        key_service=mock_key_service,
    )

    # Assert
    assert payload is None


@pytest.mark.asyncio
async def test_blacklist_jwt_non_positive_ttl(mock_redis, service):
    # Arrange
    # exp is in the past, so ttl <= 0
    past_time = int(datetime.now(timezone.utc).timestamp()) - 10
    payload = {
        "jti": "jti_past",
        "exp": past_time,
    }

    # Act
    await service._blacklist_jwt(payload)

    # Assert
    mock_redis.setex.assert_not_called()


@pytest.mark.asyncio
async def test_blacklist_jwt_missing_fields(mock_redis, service):
    # Missing jti
    await service._blacklist_jwt({"exp": 123456})
    # Missing exp
    await service._blacklist_jwt({"jti": "some_jti"})
    mock_redis.setex.assert_not_called()


@pytest.mark.asyncio
async def test_exchange_token_client_credentials_success(mock_client_repo, service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        grant_types="client_credentials",
        scope="read write",
    )
    mock_client_repo.get_by_id.return_value = mock_client
    service.authenticate_client = AsyncMock(return_value=mock_client)
    mock_token_srv = AsyncMock()
    mock_token_srv.generate_access_token.return_value = ("cc-token", 3600)

    # Act
    res = await service.exchange_token(
        grant_type="client_credentials",
        token_service=mock_token_srv,
        client_id=str(client_id),
        scope="read",
    )

    # Assert
    assert res["access_token"] == "cc-token"
    assert res["scope"] == "read"


@pytest.mark.asyncio
async def test_exchange_token_refresh_token_success(mock_client_repo, service):
    # Arrange
    client_id = uuid.uuid4()
    mock_client = Client(
        id=client_id,
        client_name="Test Client",
        grant_types="refresh_token",
        scope="read write",
    )
    mock_client_repo.get_by_id.return_value = mock_client
    service.authenticate_client = AsyncMock(return_value=mock_client)

    mock_token_record = MagicMock()
    mock_token_record.client_id = client_id
    mock_token_record.user_id = uuid.uuid4()
    mock_token_record.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    mock_token_record.is_revoked = False
    mock_token_record.parent_family_id = uuid.uuid4()
    mock_token_record.id = uuid.uuid4()

    mock_token_srv = AsyncMock()
    mock_token_srv.get_refresh_token.return_value = mock_token_record
    mock_token_srv.generate_access_token.return_value = ("new-access", 3600)
    mock_token_srv.generate_refresh_token.return_value = "new-refresh"

    # Act
    res = await service.exchange_token(
        grant_type="refresh_token",
        token_service=mock_token_srv,
        client_id=str(client_id),
        refresh_token="some-ref-token",
        scope="read",
    )

    # Assert
    assert res["access_token"] == "new-access"
    assert res["refresh_token"] == "new-refresh"
