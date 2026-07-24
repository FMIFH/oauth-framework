from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import src.core.database as db


@pytest.fixture(autouse=True)
def reset_db_globals():
    # Save original globals
    orig_engine = db.engine
    orig_sessionmaker = db.AsyncSessionLocal
    # Reset globals before test
    db.engine = None
    db.AsyncSessionLocal = None
    yield
    # Restore original globals after test
    db.engine = orig_engine
    db.AsyncSessionLocal = orig_sessionmaker


def test_get_engine():
    # Call get_engine first time (initializes)
    engine1 = db.get_engine()
    assert isinstance(engine1, AsyncEngine)

    # Call get_engine second time (returns cached instance)
    engine2 = db.get_engine()
    assert engine1 is engine2


def test_get_sessionmaker():
    # Call get_sessionmaker first time
    sm1 = db.get_sessionmaker()
    assert isinstance(sm1, async_sessionmaker)

    # Call get_sessionmaker second time
    sm2 = db.get_sessionmaker()
    assert sm1 is sm2


@pytest.mark.asyncio
async def test_get_db_success():
    # Mock the sessionmaker to return a mock session
    mock_session = AsyncMock(spec=AsyncSession)
    mock_sessionmaker = MagicMock() if "MagicMock" in globals() else None
    if not mock_sessionmaker:
        mock_sessionmaker = MagicMock()

    mock_sessionmaker.return_value.__aenter__.return_value = mock_session

    with patch("src.core.database.get_sessionmaker", return_value=mock_sessionmaker):
        db_gen = db.get_db()
        session = await anext(db_gen)
        assert session is mock_session

        # Complete the generator
        try:
            await anext(db_gen)
        except StopAsyncIteration:
            pass

    mock_session.close.assert_called_once()


@pytest.mark.asyncio
async def test_get_db_exception():
    mock_session = AsyncMock(spec=AsyncSession)

    mock_sessionmaker = MagicMock()
    mock_sessionmaker.return_value.__aenter__.return_value = mock_session

    with patch("src.core.database.get_sessionmaker", return_value=mock_sessionmaker):
        db_gen = db.get_db()
        session = await anext(db_gen)
        assert session is mock_session

        with pytest.raises(ValueError, match="test error"):
            await db_gen.athrow(ValueError("test error"))

    mock_session.rollback.assert_called_once()
    mock_session.close.assert_called_once()


@pytest.mark.asyncio
async def test_health_check_success():
    mock_conn = AsyncMock()
    mock_engine = AsyncMock(spec=AsyncEngine)
    mock_engine.connect.return_value.__aenter__.return_value = mock_conn

    with patch("src.core.database.get_engine", return_value=mock_engine):
        result = await db.health_check()
        assert result is True
        mock_conn.execute.assert_called_once()


@pytest.mark.asyncio
async def test_health_check_failure():
    mock_engine = AsyncMock(spec=AsyncEngine)
    mock_engine.connect.side_effect = Exception("connection failed")

    with patch("src.core.database.get_engine", return_value=mock_engine):
        result = await db.health_check()
        assert result is False


@pytest.mark.asyncio
async def test_close_db_not_initialized():
    db.engine = None
    db.AsyncSessionLocal = MagicMock() if "MagicMock" in globals() else None
    if not db.AsyncSessionLocal:
        db.AsyncSessionLocal = MagicMock()

    await db.close_db()
    assert db.engine is None
    assert db.AsyncSessionLocal is None


@pytest.mark.asyncio
async def test_close_db_initialized_success():
    mock_engine = AsyncMock(spec=AsyncEngine)
    db.engine = mock_engine
    db.AsyncSessionLocal = MagicMock() if "MagicMock" in globals() else None
    if not db.AsyncSessionLocal:
        db.AsyncSessionLocal = MagicMock()

    await db.close_db()
    mock_engine.dispose.assert_called_once()
    assert db.engine is None
    assert db.AsyncSessionLocal is None


@pytest.mark.asyncio
async def test_close_db_initialized_exception():
    mock_engine = AsyncMock(spec=AsyncEngine)
    mock_engine.dispose.side_effect = Exception("dispose failed")
    db.engine = mock_engine
    db.AsyncSessionLocal = MagicMock() if "MagicMock" in globals() else None
    if not db.AsyncSessionLocal:
        db.AsyncSessionLocal = MagicMock()

    await db.close_db()
    mock_engine.dispose.assert_called_once()
    assert db.engine is None
    assert db.AsyncSessionLocal is None
