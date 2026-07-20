import uuid
from datetime import datetime, timezone

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.models import User


class UserRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_user(self, email: str, password_hash: str, is_active: bool = False) -> User:
        """Create a new user in the database."""
        user = User(
            email=email,
            password_hash=password_hash,
            is_active=is_active,
        )
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        """Retrieve a user by their UUID."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        """Retrieve a user by their email address."""
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def update_user(self, user: User) -> User:
        """Save any updates made to a user object."""
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def lock_user(self, user_id: uuid.UUID) -> User | None:
        """Lock a user account."""
        user = await self.get_by_id(user_id)
        if user:
            user.is_locked = True
            user.locked_at = datetime.now(timezone.utc)
            await self.db.commit()
            await self.db.refresh(user)
        return user

    async def unlock_user(self, user_id: uuid.UUID) -> User | None:
        """Unlock a user account."""
        user = await self.get_by_id(user_id)
        if user:
            user.is_locked = False
            user.locked_at = None
            await self.db.commit()
            await self.db.refresh(user)
        return user

    async def activate_user(self, user_id: uuid.UUID) -> User | None:
        """Activate a user account."""
        user = await self.get_by_id(user_id)
        if user:
            user.is_active = True
            await self.db.commit()
            await self.db.refresh(user)
        return user

    async def deactivate_user(self, user_id: uuid.UUID) -> User | None:
        """Deactivate a user account."""
        user = await self.get_by_id(user_id)
        if user:
            user.is_active = False
            await self.db.commit()
            await self.db.refresh(user)
        return user

    async def delete_user(self, user_id: uuid.UUID) -> bool:
        """Delete a user from the database."""
        user = await self.get_by_id(user_id)
        if user:
            await self.db.delete(user)
            await self.db.commit()
            return True
        return False


async def get_user_repository(db: AsyncSession = Depends(get_db)) -> UserRepository:
    """Dependency provider for UserRepository."""
    return UserRepository(db)
