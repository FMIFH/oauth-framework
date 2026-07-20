import base64
import hashlib
import json
import secrets
import uuid

from fastapi import Depends, HTTPException, status
from redis.asyncio import Redis

from src.config import settings
from src.core.redis import get_redis
from src.exceptions.invalid_scope_exception import InvalidScopeException
from src.models.client import Client
from src.repositories.client_repo import ClientRepository, get_client_repository


class OAuthService:
    def __init__(self, client_repo: ClientRepository, redis_pool: Redis):
        self.client_repo = client_repo
        self.redis_pool = redis_pool

    async def get_and_validate_client(
        self, client_id: str, redirect_uri: str
    ) -> Client:
        """Validate the client ID and redirect URI."""
        try:
            client_uuid = uuid.UUID(client_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid client ID format",
            )

        client = await self.client_repo.get_by_id(client_uuid)
        if not client:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Client not found",
            )

        try:
            allowed_redirect_uris = json.loads(client.redirect_uris)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Client configuration error (redirect_uris)",
            )

        if redirect_uri not in allowed_redirect_uris:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid redirect URI",
            )

        return client

    def validate_scope(self, requested_scope: str, client: Client) -> None:
        """Validate the requested scope against the client's allowed scopes."""
        if not requested_scope:
            return
        allowed_scopes = set(client.scope.split())
        requested_scopes = set(requested_scope.split())
        if not requested_scopes.issubset(allowed_scopes):
            raise InvalidScopeException(
                "Requested scope is not allowed for this client."
            )

    async def create_authorization_code(
        self,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> str:
        """Generate an authorization code and persist it in Redis."""
        auth_code = secrets.token_urlsafe(32)
        payload = {
            "client_id": client_id,
            "user_id": user_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        key = f"auth:code:{auth_code}"
        await self.redis_pool.setex(
            key,
            settings.auth_code_ttl,
            json.dumps(payload),
        )
        return auth_code

    async def consume_authorization_code(self, code: str) -> dict | None:
        """Retrieve and delete the authorization code from Redis (one-time use)."""
        key = f"auth:code:{code}"
        data = await self.redis_pool.get(key)
        if data:
            await self.redis_pool.delete(key)
            return json.loads(data)
        return None

    def verify_pkce(
        self,
        code_verifier: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> bool:
        """Verify the code verifier against the code challenge."""
        if code_challenge_method == "plain":
            if not settings.enable_plain_pkce:
                return False
            return secrets.compare_digest(code_verifier, code_challenge)
        elif code_challenge_method == "S256":
            sha256_hash = hashlib.sha256(code_verifier.encode("utf-8")).digest()
            calculated_challenge = (
                base64.urlsafe_b64encode(sha256_hash).decode("utf-8").replace("=", "")
            )
            return secrets.compare_digest(calculated_challenge, code_challenge)
        return False


async def get_oauth_service(
    client_repo: ClientRepository = Depends(get_client_repository),
    redis: Redis = Depends(get_redis),
) -> OAuthService:
    """Dependency provider for OAuthService."""
    return OAuthService(client_repo=client_repo, redis_pool=redis)
