from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.config import settings

# Global engine and sessionmaker references for late/lazy initialization
engine: AsyncEngine | None = None
AsyncSessionLocal: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Retrieve or initialize the SQLAlchemy async engine."""
    global engine
    if engine is None:
        engine = create_async_engine(
            settings.postgres_dsn,
            pool_size=20,
            max_overflow=10,
            pool_recycle=1800,
            pool_pre_ping=True,
            echo=False,  # Set to True for SQL logging in development
        )
    return engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Retrieve or initialize the async session factory."""
    global AsyncSessionLocal
    if AsyncSessionLocal is None:
        AsyncSessionLocal = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
    return AsyncSessionLocal


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency generator for FastAPI endpoints to obtain an AsyncSession.

    Ensures that the session is always closed after use and rolls back the
    transaction in case of an unhandled exception.
    """
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def health_check() -> bool:
    """Perform a simple health check on the database connection."""
    current_engine = get_engine()
    try:
        async with current_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def close_db() -> None:
    """Dispose of the database engine to cleanly release all connections in the pool."""
    global engine, AsyncSessionLocal
    if engine is not None:
        await engine.dispose()
        engine = None
    AsyncSessionLocal = None
