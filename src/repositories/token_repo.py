import uuid
from datetime import datetime

from fastapi import Depends
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.models.token import RefreshToken


class TokenRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_refresh_token(
        self,
        token: str,
        client_id: uuid.UUID,
        user_id: uuid.UUID,
        parent_family_id: uuid.UUID,
        expires_at: datetime,
    ) -> RefreshToken:
        """Create a new refresh token in the database."""
        db_token = RefreshToken(
            token=token,
            client_id=client_id,
            user_id=user_id,
            parent_family_id=parent_family_id,
            is_revoked=False,
            expires_at=expires_at,
        )
        self.db.add(db_token)
        await self.db.commit()
        await self.db.refresh(db_token)
        return db_token

    async def get_by_token(self, token: str) -> RefreshToken | None:
        """Retrieve a refresh token by its token string."""
        result = await self.db.execute(select(RefreshToken).where(RefreshToken.token == token))
        return result.scalar_one_or_none()

    async def revoke_token(self, token_id: uuid.UUID) -> None:
        """Mark a single refresh token as revoked."""
        await self.db.execute(update(RefreshToken).where(RefreshToken.id == token_id).values(is_revoked=True))
        await self.db.commit()

    async def revoke_family(self, parent_family_id: uuid.UUID) -> None:
        """Revoke all refresh tokens in a given family."""
        await self.db.execute(
            update(RefreshToken)
            .where(RefreshToken.parent_family_id == parent_family_id)
            .values(is_revoked=True)
        )
        await self.db.commit()


async def get_token_repository(
    db: AsyncSession = Depends(get_db),
) -> TokenRepository:
    """Dependency provider for TokenRepository."""
    return TokenRepository(db)
