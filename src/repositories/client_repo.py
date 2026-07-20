import json
import uuid
from datetime import datetime, timezone

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.models import Client, ClientSecret


class ClientRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_client(
        self,
        client_name: str,
        client_type: str,
        redirect_uris: str | list[str],
        grant_types: str | list[str],
        scope: str | list[str],
    ) -> Client:
        """Create a new OAuth client in the database."""
        serialized_redirect_uris = (
            json.dumps(redirect_uris) if isinstance(redirect_uris, list) else redirect_uris
        )
        serialized_grant_types = ",".join(grant_types) if isinstance(grant_types, list) else grant_types
        serialized_scope = " ".join(scope) if isinstance(scope, list) else scope

        client = Client(
            client_name=client_name,
            client_type=client_type,
            redirect_uris=serialized_redirect_uris,
            grant_types=serialized_grant_types,
            scope=serialized_scope,
        )
        self.db.add(client)
        await self.db.commit()
        await self.db.refresh(client)
        return client

    async def get_by_id(self, client_id: uuid.UUID) -> Client | None:
        """Retrieve a client by their UUID."""
        result = await self.db.execute(select(Client).where(Client.id == client_id))
        return result.scalar_one_or_none()

    async def update_client(self, client: Client) -> Client:
        """Save any updates made to a client object."""
        self.db.add(client)
        await self.db.commit()
        await self.db.refresh(client)
        return client

    async def delete_client(self, client_id: uuid.UUID) -> bool:
        """Delete a client from the database."""
        client = await self.get_by_id(client_id)
        if client:
            await self.db.delete(client)
            await self.db.commit()
            return True
        return False

    async def create_client_secret(
        self,
        client_id: uuid.UUID,
        secret_hash: str,
        expires_at: datetime | None = None,
    ) -> ClientSecret:
        """Create a new client secret linked to an OAuth client."""
        secret = ClientSecret(
            client_id=client_id,
            secret_hash=secret_hash,
            expires_at=expires_at,
        )
        self.db.add(secret)
        await self.db.commit()
        await self.db.refresh(secret)
        return secret

    async def get_client_secrets(self, client_id: uuid.UUID) -> list[ClientSecret]:
        """Retrieve all secrets associated with a client ID."""
        result = await self.db.execute(select(ClientSecret).where(ClientSecret.client_id == client_id))
        return list(result.scalars().all())

    async def get_active_secrets(self, client_id: uuid.UUID) -> list[ClientSecret]:
        """Retrieve all non-expired secrets associated with a client ID."""
        now = datetime.now(timezone.utc)
        result = await self.db.execute(
            select(ClientSecret).where(
                ClientSecret.client_id == client_id,
                (ClientSecret.expires_at.is_(None)) | (ClientSecret.expires_at > now),
            )
        )
        return list(result.scalars().all())

    async def delete_client_secret(self, secret_id: uuid.UUID) -> bool:
        """Delete a client secret from the database."""
        result = await self.db.execute(select(ClientSecret).where(ClientSecret.id == secret_id))
        secret = result.scalar_one_or_none()
        if secret:
            await self.db.delete(secret)
            await self.db.commit()
            return True
        return False


async def get_client_repository(
    db: AsyncSession = Depends(get_db),
) -> ClientRepository:
    """Dependency provider for ClientRepository."""
    return ClientRepository(db)
