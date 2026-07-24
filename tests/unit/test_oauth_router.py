import base64
import urllib.parse
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient

from src.core.security import sign_cookie_value
from src.main_as import app
from src.services.key_service import KeyService, get_key_service
from src.services.oauth_service import OAuthService, get_oauth_service
from src.services.token_service import TokenService, get_token_service


@pytest.fixture
def mock_oauth_service():
    service = AsyncMock(spec=OAuthService)
    # Since validate_scope is a synchronous method, mock it accordingly
    service.validate_scope = MagicMock()
    return service


@pytest.fixture
def mock_token_service():
    service = AsyncMock(spec=TokenService)
    return service


@pytest.fixture
def mock_key_service():
    service = AsyncMock(spec=KeyService)
    return service


@pytest.fixture
def client(mock_oauth_service, mock_token_service, mock_key_service):
    # Override dependencies
    app.dependency_overrides[get_oauth_service] = lambda: mock_oauth_service
    app.dependency_overrides[get_token_service] = lambda: mock_token_service
    app.dependency_overrides[get_key_service] = lambda: mock_key_service
    with TestClient(app) as c:
        yield c
    # Clean up overrides
    app.dependency_overrides.clear()


def test_authorize_redirects_to_login_when_unauthenticated(client, mock_oauth_service):
    # Arrange
    params = {
        "response_type": "code",
        "client_id": "test-client-id",
        "redirect_uri": "http://localhost/callback",
        "scope": "openid email",
        "state": "xyz",
        "code_challenge": "challenge_string",
        "code_challenge_method": "S256",
    }
    mock_oauth_service.process_authorization_request = AsyncMock(
        return_value=RedirectResponse(
            url="/users/login?response_type=code&client_id=test-client-id&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&scope=openid+email&state=xyz&code_challenge=challenge_string&code_challenge_method=S256",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    )

    # Act
    response = client.get("/oauth/authorize", params=params, follow_redirects=False)

    # Assert
    assert response.status_code == status.HTTP_303_SEE_OTHER
    location = response.headers["location"]
    assert "/users/login" in location
    # Verify all query params were forwarded
    parsed = urllib.parse.urlparse(location)
    forwarded_params = urllib.parse.parse_qs(parsed.query)
    for k, v in params.items():
        assert forwarded_params[k][0] == v


@pytest.mark.asyncio
async def test_authorize_success_when_authenticated(client, mock_oauth_service):
    # Arrange
    params = {
        "response_type": "code",
        "client_id": "test-client-id",
        "redirect_uri": "http://localhost/callback",
        "scope": "openid email",
        "state": "xyz",
        "code_challenge": "challenge_string",
        "code_challenge_method": "S256",
    }

    mock_oauth_service.process_authorization_request = AsyncMock(
        return_value=RedirectResponse(
            url="http://localhost/callback?code=generated_auth_code_123&state=xyz",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    )

    # Set the authenticated session cookie
    client.cookies.set("user_session", sign_cookie_value("test-user-id"))

    # Act
    response = client.get("/oauth/authorize", params=params, follow_redirects=False)

    # Assert
    assert response.status_code == status.HTTP_303_SEE_OTHER
    location = response.headers["location"]
    assert "http://localhost/callback" in location
    assert "code=generated_auth_code_123" in location
    assert "state=xyz" in location

    # Verify service interactions
    mock_oauth_service.process_authorization_request.assert_called_once_with(
        user_id="test-user-id",
        response_type="code",
        client_id="test-client-id",
        redirect_uri="http://localhost/callback",
        scope="openid email",
        state="xyz",
        code_challenge="challenge_string",
        code_challenge_method="S256",
    )


@pytest.mark.asyncio
async def test_authorize_invalid_scope(client, mock_oauth_service):
    # Arrange
    params = {
        "response_type": "code",
        "client_id": "test-client-id",
        "redirect_uri": "http://localhost/callback",
        "scope": "invalid-scope",
        "state": "xyz",
        "code_challenge": "challenge_string",
        "code_challenge_method": "S256",
    }

    mock_oauth_service.process_authorization_request = AsyncMock(
        side_effect=HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scope not allowed")
    )

    # Set the authenticated session cookie
    client.cookies.set("user_session", sign_cookie_value("test-user-id"))

    # Act
    response = client.get("/oauth/authorize", params=params, follow_redirects=False)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Scope not allowed"


@pytest.mark.asyncio
async def test_token_auth_code_public_success(client, mock_oauth_service):

    # Arrange
    client_uuid = uuid.uuid4()
    mock_oauth_service.exchange_token = AsyncMock(
        return_value={
            "access_token": "access-token-123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-token-123",
            "scope": "openid profile",
        }
    )

    form_data = {
        "grant_type": "authorization_code",
        "code": "auth-code-123",
        "redirect_uri": "http://localhost/callback",
        "client_id": str(client_uuid),
        "code_verifier": "verifier-123",
    }

    # Act
    response = client.post("/oauth/token", data=form_data)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    res_data = response.json()
    assert res_data["access_token"] == "access-token-123"
    assert res_data["token_type"] == "Bearer"
    assert res_data["expires_in"] == 3600
    assert res_data["refresh_token"] == "refresh-token-123"
    assert res_data["scope"] == "openid profile"

    mock_oauth_service.exchange_token.assert_called_once()


@pytest.mark.asyncio
async def test_token_auth_code_confidential_success(client, mock_oauth_service):

    # Arrange
    client_uuid = uuid.uuid4()
    mock_oauth_service.exchange_token = AsyncMock(
        return_value={
            "access_token": "access-token-abc",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-token-abc",
            "scope": "openid",
        }
    )

    form_data = {
        "grant_type": "authorization_code",
        "code": "auth-code-abc",
        "redirect_uri": "http://localhost/callback",
    }

    auth_str = f"{client_uuid}:mysecret"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    headers = {"Authorization": f"Basic {b64_auth}"}

    # Act
    response = client.post("/oauth/token", data=form_data, headers=headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    res_data = response.json()
    assert res_data["access_token"] == "access-token-abc"
    assert res_data["refresh_token"] == "refresh-token-abc"

    mock_oauth_service.exchange_token.assert_called_once()


@pytest.mark.asyncio
async def test_token_auth_code_invalid_client(client, mock_oauth_service):
    # Arrange

    mock_oauth_service.exchange_token = AsyncMock(
        side_effect=HTTPException(status_code=401, detail="invalid_client")
    )

    form_data = {
        "grant_type": "authorization_code",
        "code": "auth-code-123",
        "redirect_uri": "http://localhost/callback",
        "client_id": "bad-client-id",
    }

    # Act
    response = client.post("/oauth/token", data=form_data)

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "invalid_client"


@pytest.mark.asyncio
async def test_token_auth_code_invalid_code(client, mock_oauth_service):

    # Arrange
    client_uuid = uuid.uuid4()
    mock_oauth_service.exchange_token = AsyncMock(
        side_effect=HTTPException(status_code=400, detail="invalid_grant")
    )

    form_data = {
        "grant_type": "authorization_code",
        "code": "auth-code-bad",
        "redirect_uri": "http://localhost/callback",
        "client_id": str(client_uuid),
    }

    # Act
    response = client.post("/oauth/token", data=form_data)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "invalid_grant"


@pytest.mark.asyncio
async def test_token_auth_code_redirect_mismatch(client, mock_oauth_service):

    # Arrange
    client_uuid = uuid.uuid4()
    mock_oauth_service.exchange_token = AsyncMock(
        side_effect=HTTPException(status_code=400, detail="invalid_grant")
    )

    form_data = {
        "grant_type": "authorization_code",
        "code": "auth-code-123",
        "redirect_uri": "http://localhost/wrong-callback",
        "client_id": str(client_uuid),
    }

    # Act
    response = client.post("/oauth/token", data=form_data)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "invalid_grant"


@pytest.mark.asyncio
async def test_token_client_credentials_success(client, mock_oauth_service):

    # Arrange
    client_uuid = uuid.uuid4()
    mock_oauth_service.exchange_token = AsyncMock(
        return_value={
            "access_token": "access-token-cc",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read:profile",
        }
    )

    form_data = {
        "grant_type": "client_credentials",
        "client_id": str(client_uuid),
        "client_secret": "mysecret",
        "scope": "read:profile",
    }

    # Act
    response = client.post("/oauth/token", data=form_data)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    res_data = response.json()
    assert res_data["access_token"] == "access-token-cc"
    assert "refresh_token" not in res_data
    assert res_data["scope"] == "read:profile"

    mock_oauth_service.exchange_token.assert_called_once()


@pytest.mark.asyncio
async def test_token_refresh_token_success(client, mock_oauth_service):

    # Arrange
    client_uuid = uuid.uuid4()
    mock_oauth_service.exchange_token = AsyncMock(
        return_value={
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new-refresh-token",
            "scope": "openid profile",
        }
    )

    form_data = {
        "grant_type": "refresh_token",
        "client_id": str(client_uuid),
        "client_secret": "mysecret",
        "refresh_token": "old-refresh-token",
    }

    # Act
    response = client.post("/oauth/token", data=form_data)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    res_data = response.json()
    assert res_data["access_token"] == "new-access-token"
    assert res_data["refresh_token"] == "new-refresh-token"

    mock_oauth_service.exchange_token.assert_called_once()


@pytest.mark.asyncio
async def test_token_unsupported_grant(client, mock_oauth_service):

    # Arrange
    client_uuid = uuid.uuid4()
    mock_oauth_service.exchange_token = AsyncMock(
        side_effect=HTTPException(status_code=400, detail="unsupported_grant_type")
    )

    form_data = {
        "grant_type": "implicit",  # Unsupported
        "client_id": str(client_uuid),
    }

    # Act
    response = client.post("/oauth/token", data=form_data)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "unsupported_grant_type"


@pytest.mark.asyncio
async def test_revoke_token_form_auth_success(client, mock_oauth_service):
    # Arrange
    mock_oauth_service.revoke_token = AsyncMock(return_value={})

    form_data = {
        "token": "ref_valid_token",
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "token_type_hint": "refresh_token",
    }

    # Act
    response = client.post("/oauth/revoke", data=form_data)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {}

    mock_oauth_service.revoke_token.assert_called_once()
    kwargs = mock_oauth_service.revoke_token.call_args[1]
    assert kwargs["token"] == "ref_valid_token"
    assert kwargs["token_type_hint"] == "refresh_token"
    assert kwargs["auth_header"] is None
    assert kwargs["client_id"] == "test-client-id"
    assert kwargs["client_secret"] == "test-client-secret"
    assert kwargs["token_service"] is not None
    assert kwargs["key_service"] is not None


@pytest.mark.asyncio
async def test_revoke_token_basic_auth_success(client, mock_oauth_service):

    # Arrange
    mock_oauth_service.revoke_token = AsyncMock(return_value={})

    form_data = {
        "token": "ref_valid_token",
        "token_type_hint": "refresh_token",
    }

    auth_str = "test-client-id:test-client-secret"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    headers = {"Authorization": f"Basic {b64_auth}"}

    # Act
    response = client.post("/oauth/revoke", data=form_data, headers=headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {}

    mock_oauth_service.revoke_token.assert_called_once()
    kwargs = mock_oauth_service.revoke_token.call_args[1]
    assert kwargs["token"] == "ref_valid_token"
    assert kwargs["token_type_hint"] == "refresh_token"
    assert kwargs["auth_header"] == f"Basic {b64_auth}"
    assert kwargs["client_id"] is None
    assert kwargs["client_secret"] is None
    assert kwargs["token_service"] is not None
    assert kwargs["key_service"] is not None


@pytest.mark.asyncio
async def test_revoke_token_invalid_client_error(client, mock_oauth_service):
    # Arrange
    mock_oauth_service.revoke_token = AsyncMock(
        side_effect=HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_client")
    )

    form_data = {
        "token": "ref_valid_token",
        "client_id": "test-client-id",
        "client_secret": "wrong-secret",
    }

    # Act
    response = client.post("/oauth/revoke", data=form_data)

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "invalid_client"


def test_jwks_endpoint(client):

    # Arrange
    with patch("src.routers.oauth.jwks", new_callable=AsyncMock) as mock_jwks:
        mock_jwks.return_value = {"keys": []}

        # Act
        response = client.get("/oauth/jwks")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"keys": []}
        mock_jwks.assert_called_once()
