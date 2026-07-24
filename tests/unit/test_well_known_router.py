from fastapi.testclient import TestClient

from src.main_as import app


def test_well_known_oauth_authorization_server():
    # Arrange & Act
    with TestClient(app) as client:
        response = client.get("/.well-known/oauth-authorization-server")

    # Assert
    assert response.status_code == 200
    data = response.json()
    assert "issuer" in data
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "jwks_uri" in data
    assert "registration_endpoint" in data
    assert "revocation_endpoint" in data
    assert "introspection_endpoint" in data
    assert "scopes_supported" in data
    assert "response_types_supported" in data
    assert "grant_types_supported" in data
    assert "token_endpoint_auth_methods_supported" in data
    assert "code_challenge_methods_supported" in data
    assert data["response_types_supported"] == ["code"]
    assert "authorization_code" in data["grant_types_supported"]
