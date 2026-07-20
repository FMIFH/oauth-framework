import urllib.parse
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.exceptions.invalid_scope_exception import InvalidScopeException
from src.main_as import app
from src.models.client import Client
from src.services.oauth_service import OAuthService, get_oauth_service


@pytest.fixture
def mock_oauth_service():
    service = AsyncMock(spec=OAuthService)
    # Since validate_scope is a synchronous method, mock it accordingly
    service.validate_scope = MagicMock()
    return service


@pytest.fixture
def client(mock_oauth_service):
    # Override dependency
    app.dependency_overrides[get_oauth_service] = lambda: mock_oauth_service
    with TestClient(app) as c:
        yield c
    # Clean up overrides
    app.dependency_overrides.clear()


def test_authorize_redirects_to_login_when_unauthenticated(client):
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

    # Mocking the service calls
    mock_client = MagicMock(spec=Client)
    mock_oauth_service.get_and_validate_client.return_value = mock_client
    mock_oauth_service.create_authorization_code.return_value = "generated_auth_code_123"

    # Set the authenticated session cookie
    client.cookies.set("user_session", "test-user-id")

    # Act
    response = client.get("/oauth/authorize", params=params, follow_redirects=False)

    # Assert
    assert response.status_code == status.HTTP_303_SEE_OTHER
    location = response.headers["location"]
    assert "http://localhost/callback" in location
    assert "code=generated_auth_code_123" in location
    assert "state=xyz" in location

    # Verify service interactions
    mock_oauth_service.get_and_validate_client.assert_called_once_with(
        "test-client-id", "http://localhost/callback"
    )
    mock_oauth_service.validate_scope.assert_called_once_with("openid email", mock_client)
    mock_oauth_service.create_authorization_code.assert_called_once_with(
        client_id="test-client-id",
        user_id="test-user-id",
        redirect_uri="http://localhost/callback",
        scope="openid email",
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

    # Mocking the service calls
    mock_client = MagicMock(spec=Client)
    mock_oauth_service.get_and_validate_client.return_value = mock_client
    mock_oauth_service.validate_scope.side_effect = InvalidScopeException("Scope not allowed")

    # Set the authenticated session cookie
    client.cookies.set("user_session", "test-user-id")

    # Act
    response = client.get("/oauth/authorize", params=params, follow_redirects=False)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Scope not allowed"
