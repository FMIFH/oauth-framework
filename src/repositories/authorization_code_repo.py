from datetime import datetime, timezone

from fastapi import Depends
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.models.token import AuthorizationCode


class AuthorizationCodeRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        code: str,
        client_id: str,
        user_id: str,
        code_challenge: str,
        code_challenge_method: str,
        scope: str,
        redirect_uri: str,
        expires_at: datetime,
    ) -> AuthorizationCode:

        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user_id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            redirect_uri=redirect_uri,
            expires_at=expires_at,
        )
        self.session.add(auth_code)
        await self.session.commit()
        return auth_code

    async def consume_code(self, code: str) -> AuthorizationCode | None:
        result = await self.session.execute(
            select(AuthorizationCode).where(AuthorizationCode.code == code).with_for_update()
        )
        auth_code = result.scalar_one_or_none()
        if auth_code:
            await self.session.delete(auth_code)
            await self.session.commit()
        return auth_code

    async def delete_expired_codes(self) -> None:
        await self.session.execute(
            delete(AuthorizationCode).where(AuthorizationCode.expires_at < datetime.now(timezone.utc))
        )
        await self.session.commit()


async def get_authorization_code_repo(
    db: AsyncSession = Depends(get_db),
) -> AuthorizationCodeRepository:
    """Dependency provider for AuthorizationCodeRepository."""
    return AuthorizationCodeRepository(db)
