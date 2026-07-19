from fastapi import APIRouter

from src.config import settings

router = APIRouter(prefix="/.well-known", tags=["well-known"])

BASE_URL = settings.issuer_url.rstrip("/")


@router.get("/oauth-authorization-server")
def oauth_authorization_server():
    return {
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/oauth/authorize",
        "token_endpoint": f"{BASE_URL}/oauth/token",
        "jwks_uri": f"{BASE_URL}/oauth/jwks",
        "registration_endpoint": f"{BASE_URL}/api/v1/clients/register",
        "revocation_endpoint": f"{BASE_URL}/oauth/revoke",
        "introspection_endpoint": f"{BASE_URL}/oauth/introspect",
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "code_challenge_methods_supported": ["S256"],
    }
