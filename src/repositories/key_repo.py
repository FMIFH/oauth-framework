from fastapi import Depends
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.models.keys import SigningKey


class KeyRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_kid(self, kid: str) -> SigningKey | None:
        """Retrieve a signing key by its key ID (kid)."""
        result = await self.db.execute(select(SigningKey).where(SigningKey.kid == kid))
        return result.scalars().first()

    async def get_active_key(self) -> SigningKey | None:
        """Retrieve the currently active signing key."""
        result = await self.db.execute(select(SigningKey).where(SigningKey.is_active))
        return result.scalars().first()

    async def get_active_or_recent_keys(self, grace_cutoff) -> list[SigningKey]:
        """Retrieve active keys or those deactivated after the grace cutoff."""
        result = await self.db.execute(
            select(SigningKey).where(
                or_(
                    SigningKey.is_active,
                    and_(
                        SigningKey.is_active.is_(False),
                        SigningKey.deactivated_at.isnot(None),
                        SigningKey.deactivated_at >= grace_cutoff,
                    ),
                )
            )
        )
        return list(result.scalars().all())

    async def get_all_active_keys(self) -> list[SigningKey]:
        """Retrieve all active signing keys."""
        result = await self.db.execute(select(SigningKey).where(SigningKey.is_active))
        return list(result.scalars().all())

    async def create_key(self, signing_key: SigningKey) -> SigningKey:
        """Persist a new signing key to the database."""
        self.db.add(signing_key)
        await self.db.commit()
        await self.db.refresh(signing_key)
        return signing_key

    async def update_key(self, signing_key: SigningKey) -> SigningKey:
        """Update an existing signing key in the database."""
        self.db.add(signing_key)
        await self.db.commit()
        await self.db.refresh(signing_key)
        return signing_key


async def get_key_repository(db: AsyncSession = Depends(get_db)) -> KeyRepository:
    """Dependency provider for KeyRepository."""
    return KeyRepository(db)
