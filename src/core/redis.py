import logging
from collections.abc import AsyncGenerator

from redis.asyncio import ConnectionPool, Redis

from src.config import settings

logger = logging.getLogger(__name__)

# Global connection pool and client reference.
# We use decode_responses=True so that we get python strings instead of raw bytes,
# which is generally what's needed for JSON and OAuth models.
redis_pool: ConnectionPool | None = None


def get_redis_pool() -> ConnectionPool:
    """Retrieve or initialize the Redis connection pool."""
    global redis_pool
    if redis_pool is None:
        logger.info("Initializing Redis connection pool...")
        redis_pool = ConnectionPool.from_url(
            settings.redis_dsn,
            decode_responses=True,
            max_connections=50,       # Adjust based on expected load
            socket_timeout=5.0,        # Fail fast if connection drops
            socket_connect_timeout=5.0,# Connection establishment timeout
            retry_on_timeout=True,     # Retry on transient failures
        )
    return redis_pool


def get_redis_client() -> Redis:
    """Get a Redis client instance bound to the global connection pool."""
    pool = get_redis_pool()
    return Redis(connection_pool=pool)


async def get_redis() -> AsyncGenerator[Redis, None]:
    """FastAPI Dependency generator to retrieve an async Redis client.

    Yields a Redis client instance from the pool and automatically
    closes the client connection back to the pool upon completion.
    """
    client = get_redis_client()
    try:
        yield client
    finally:
        await client.close()


async def close_redis() -> None:
    """Close the Redis connection pool during application shutdown."""
    global redis_pool
    if redis_pool is not None:
        logger.info("Disconnecting and closing Redis connection pool...")
        await redis_pool.disconnect()
        redis_pool = None


async def health_check() -> bool:
    """Perform a simple health check (PING) to verify the Redis connection."""
    client = get_redis_client()
    try:
        return await client.ping()
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return False
