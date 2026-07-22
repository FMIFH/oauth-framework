import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from src.exceptions.invalid_scope_exception import InvalidScopeError
from src.models.client import Client
from src.services.oauth_service import OAuthService


@pytest.mark.asyncio
async def test_get_and_validate_client_success():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_get_and_validate_client_invalid_uuid():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        await service.get_and_validate_client("not-a-uuid", "https://example.com/callback")

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Invalid client ID format"


@pytest.mark.asyncio
async def test_get_and_validate_client_not_found():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

    client_id = str(uuid.uuid4())
    mock_client_repo.get_by_id = AsyncMock(return_value=None)

    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        await service.get_and_validate_client(client_id, "https://example.com/callback")

    assert exc_info.value.status_code == 400
    assert "Client not found" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_and_validate_client_invalid_redirect_uri():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_get_and_validate_client_corrupt_uris():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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


def test_validate_scope_success():
    # Arrange
    mock_client_repo = MagicMock()
    mock_redis = MagicMock()
    service = OAuthService(mock_client_repo, mock_redis)

    client = Client(scope="openid profile email")

    # Act & Assert
    service.validate_scope("openid email", client)  # Should not raise exception
    service.validate_scope("", client)  # Empty scope should be fine


def test_validate_scope_failure():
    # Arrange
    mock_client_repo = MagicMock()
    mock_redis = MagicMock()
    service = OAuthService(mock_client_repo, mock_redis)

    client = Client(scope="openid profile")

    # Act & Assert
    with pytest.raises(InvalidScopeError) as exc_info:
        service.validate_scope("openid offline_access", client)

    assert "Requested scope is not allowed" in str(exc_info.value)


@pytest.mark.asyncio
async def test_create_authorization_code():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
    key = f"auth:code:{code}"
    mock_redis.setex.assert_called_once()
    args, _ = mock_redis.setex.call_args
    assert args[0] == key
    # Check TTL (from settings, default 60s)
    assert args[1] == 60
    # Check payload structure
    payload = json.loads(args[2])
    assert payload["client_id"] == client_id
    assert payload["user_id"] == user_id
    assert payload["redirect_uri"] == redirect_uri
    assert payload["scope"] == scope
    assert payload["code_challenge"] == challenge
    assert payload["code_challenge_method"] == method


@pytest.mark.asyncio
async def test_consume_authorization_code_exists():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

    code = "test_auth_code"
    payload = {"client_id": "test_client"}
    mock_redis.get = AsyncMock(return_value=json.dumps(payload))
    mock_redis.delete = AsyncMock()

    # Act
    consumed = await service.consume_authorization_code(code)

    # Assert
    assert consumed == payload
    mock_redis.get.assert_called_once_with(f"auth:code:{code}")
    mock_redis.delete.assert_called_once_with(f"auth:code:{code}")


@pytest.mark.asyncio
async def test_consume_authorization_code_missing():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

    code = "test_auth_code"
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.delete = AsyncMock()

    # Act
    consumed = await service.consume_authorization_code(code)

    # Assert
    assert consumed is None
    mock_redis.get.assert_called_once_with(f"auth:code:{code}")
    mock_redis.delete.assert_not_called()


def test_verify_pkce_plain_success():
    # Arrange
    mock_client_repo = MagicMock()
    mock_redis = MagicMock()
    service = OAuthService(mock_client_repo, mock_redis)

    with patch("src.services.oauth_service.settings") as mock_settings:
        mock_settings.enable_plain_pkce = True
        assert service.verify_pkce("verifier", "verifier", "plain") is True


def test_verify_pkce_plain_disabled():
    # Arrange
    mock_client_repo = MagicMock()
    mock_redis = MagicMock()
    service = OAuthService(mock_client_repo, mock_redis)

    with patch("src.services.oauth_service.settings") as mock_settings:
        mock_settings.enable_plain_pkce = False
        assert service.verify_pkce("verifier", "verifier", "plain") is False


def test_verify_pkce_s256_success():
    # Arrange
    mock_client_repo = MagicMock()
    mock_redis = MagicMock()
    service = OAuthService(mock_client_repo, mock_redis)

    # S256 test vectors:
    # Verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    # Challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    assert service.verify_pkce(verifier, challenge, "S256") is True
    assert service.verify_pkce(verifier, challenge, "s256") is True
    assert service.verify_pkce(verifier, challenge, "SHA-256") is True
    assert service.verify_pkce(verifier, challenge, "sha-256") is True


def test_verify_pkce_s256_failure():
    # Arrange
    mock_client_repo = MagicMock()
    mock_redis = MagicMock()
    service = OAuthService(mock_client_repo, mock_redis)

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    assert service.verify_pkce(verifier, "different_challenge", "S256") is False
    assert service.verify_pkce(verifier, "different_challenge", "SHA-256") is False


@pytest.mark.asyncio
async def test_exchange_token_auth_code_success():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
    mock_redis.get.return_value = json.dumps(payload)

    # Mock token service
    mock_token_service = AsyncMock()
    mock_token_service.generate_access_token.return_value = ("access-token-123", 3600)
    mock_token_service.generate_refresh_token.return_value = "refresh-token-123"

    # Act
    with patch.object(service, "verify_pkce", return_value=True):
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
async def test_process_authorization_request_unsupported_response_type():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_process_authorization_request_redirect_to_login():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_revoke_token_no_token():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)
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
async def test_revoke_token_client_auth_failure():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)
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
async def test_revoke_token_success_refresh_token_hint():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_revoke_token_success_no_hint():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_revoke_token_not_found_graceful():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_revoke_token_different_client_graceful():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_revoke_token_different_client_refresh_token_hint_graceful():
    # Arrange
    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_revoke_token_access_token_hint_success():
    # Arrange
    import jwt

    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_revoke_token_access_token_no_hint_success():
    # Arrange
    import jwt

    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_revoke_token_access_token_expired_no_blacklist():
    # Arrange
    import jwt

    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_revoke_token_access_token_wrong_client_no_blacklist():
    # Arrange
    import jwt

    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_decode_and_validate_jwt_valid_signature():
    # Arrange
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from src.models.keys import SigningKey

    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
async def test_decode_and_validate_jwt_invalid_signature():
    # Arrange
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from src.models.keys import SigningKey

    mock_client_repo = AsyncMock()
    mock_redis = AsyncMock()
    service = OAuthService(mock_client_repo, mock_redis)

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
