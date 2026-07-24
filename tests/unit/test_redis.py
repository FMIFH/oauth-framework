from unittest.mock import AsyncMock, patch

import pytest
from redis.asyncio import ConnectionPool, Redis

import src.core.redis as rds


@pytest.fixture(autouse=True)
def reset_redis_globals():
    # Save original global
    orig_pool = rds.redis_pool
    # Reset before test
    rds.redis_pool = None
    yield
    # Restore after test
    rds.redis_pool = orig_pool


def test_get_redis_pool():
    # First call initializes pool
    pool1 = rds.get_redis_pool()
    assert isinstance(pool1, ConnectionPool)

    # Second call returns cached pool
    pool2 = rds.get_redis_pool()
    assert pool1 is pool2


def test_get_redis_client():
    client = rds.get_redis_client()
    assert isinstance(client, Redis)


@pytest.mark.asyncio
async def test_get_redis():
    mock_client = AsyncMock()
    with patch("src.core.redis.get_redis_client", return_value=mock_client):
        redis_gen = rds.get_redis()
        client = await anext(redis_gen)
        assert client is mock_client

        try:
            await anext(redis_gen)
        except StopAsyncIteration:
            pass

    mock_client.close.assert_called_once()


@pytest.mark.asyncio
async def test_close_redis_not_initialized():
    rds.redis_pool = None
    await rds.close_redis()
    assert rds.redis_pool is None


@pytest.mark.asyncio
async def test_close_redis_success():
    mock_pool = AsyncMock()
    rds.redis_pool = mock_pool

    await rds.close_redis()
    mock_pool.disconnect.assert_called_once()
    assert rds.redis_pool is None


@pytest.mark.asyncio
async def test_close_redis_exception():
    mock_pool = AsyncMock()
    mock_pool.disconnect.side_effect = Exception("disconnect failed")
    rds.redis_pool = mock_pool

    await rds.close_redis()
    mock_pool.disconnect.assert_called_once()
    assert rds.redis_pool is None


@pytest.mark.asyncio
async def test_health_check_success():
    mock_client = AsyncMock()
    mock_client.ping = AsyncMock(return_value=True)

    with patch("src.core.redis.get_redis_client", return_value=mock_client):
        result = await rds.health_check()
        assert result is True
        mock_client.ping.assert_called_once()


@pytest.mark.asyncio
async def test_health_check_failure():
    mock_client = AsyncMock()
    mock_client.ping = AsyncMock(side_effect=Exception("ping failed"))

    with patch("src.core.redis.get_redis_client", return_value=mock_client):
        result = await rds.health_check()
        assert result is False
