import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.core.database import get_db
from src.repositories.key_repo import KeyRepository, get_key_repository
from src.repositories.token_repo import TokenRepository, get_token_repository
from src.services.key_manager import decrypt_private_key, publish_new_key


class TokenService:
    def __init__(self, token_repo: TokenRepository, key_repo: KeyRepository, db_session: AsyncSession):
        self.token_repo = token_repo
        self.key_repo = key_repo
        self.db_session = db_session

    async def generate_access_token(self, client_id: str, user_id: str | None, scope: str) -> tuple[str, int]:
        """Generate a signed JWT access token."""
        # Query for an active signing key
        signing_key = await self.key_repo.get_active_key()
        if not signing_key:
            # Resiliently publish a new RS256 key if none exists
            signing_key = await publish_new_key(
                db=self.db_session,
                algorithm="RS256",
                master_key_hex=settings.master_encryption_key,
            )

        # Decrypt private key
        private_key_pem = decrypt_private_key(
            signing_key.encrypted_private_key, settings.master_encryption_key
        )

        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=settings.access_token_ttl)

        payload = {
            "iss": settings.issuer_url.rstrip("/"),
            "sub": str(user_id) if user_id else str(client_id),
            "aud": str(client_id),
            "client_id": str(client_id),
            "exp": int(exp.timestamp()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "jti": uuid.uuid4().hex,
            "scope": scope,
        }

        access_token = jwt.encode(
            payload,
            private_key_pem,
            algorithm=signing_key.algorithm,
            headers={"kid": signing_key.kid},
        )
        return access_token, settings.access_token_ttl

    async def generate_refresh_token(
        self,
        client_id: uuid.UUID,
        user_id: uuid.UUID,
        parent_family_id: uuid.UUID | None = None,
    ) -> str:
        """Generate and persist an opaque refresh token."""
        token_str = "ref_" + secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.refresh_token_ttl)
        family_id = parent_family_id or uuid.uuid4()

        await self.token_repo.create_refresh_token(
            token=token_str,
            client_id=client_id,
            user_id=user_id,
            parent_family_id=family_id,
            expires_at=expires_at,
        )
        return token_str

    async def get_refresh_token(self, token: str):
        """Retrieve a refresh token by its token string."""
        return await self.token_repo.get_by_token(token)

    async def revoke_refresh_token(self, token_id: uuid.UUID) -> None:
        """Mark a single refresh token as revoked."""
        await self.token_repo.revoke_token(token_id)

    async def revoke_refresh_token_family(self, parent_family_id: uuid.UUID) -> None:
        """Revoke all refresh tokens in a given family."""
        await self.token_repo.revoke_family(parent_family_id)


async def get_token_service(
    token_repo: TokenRepository = Depends(get_token_repository),
    key_repo: KeyRepository = Depends(get_key_repository),
    db: AsyncSession = Depends(get_db),
) -> TokenService:
    """Dependency provider for TokenService."""
    return TokenService(token_repo=token_repo, key_repo=key_repo, db_session=db)
