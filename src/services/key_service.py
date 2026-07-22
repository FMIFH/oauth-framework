from fastapi import Depends

from src.models.keys import SigningKey
from src.repositories.key_repo import KeyRepository, get_key_repository


class KeyService:
    def __init__(self, key_repo: KeyRepository):
        self.key_repo = key_repo

    async def get_signing_key_by_kid(self, kid: str) -> SigningKey | None:
        """Retrieve a signing key by its key ID (kid)."""
        return await self.key_repo.get_by_kid(kid)

    async def get_active_signing_key(self) -> SigningKey | None:
        """Retrieve the currently active signing key."""
        return await self.key_repo.get_active_key()

    async def get_active_or_recent_keys(self, grace_cutoff) -> list[SigningKey]:
        """Retrieve active keys or those deactivated after the grace cutoff."""
        return await self.key_repo.get_active_or_recent_keys(grace_cutoff)

    async def get_all_active_keys(self) -> list[SigningKey]:
        """Retrieve all active signing keys."""
        return await self.key_repo.get_all_active_keys()

    async def create_key(self, signing_key: SigningKey) -> SigningKey:
        """Persist a new signing key."""
        return await self.key_repo.create_key(signing_key)

    async def update_key(self, signing_key: SigningKey) -> SigningKey:
        """Update an existing signing key."""
        return await self.key_repo.update_key(signing_key)


async def get_key_service(
    key_repo: KeyRepository = Depends(get_key_repository),
) -> KeyService:
    """Dependency provider for KeyService."""
    return KeyService(key_repo=key_repo)
