from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI

from src.core.database import close_db, get_engine
from src.core.database import health_check as db_health_check
from src.core.redis import close_redis, get_redis_pool
from src.core.redis import health_check as redis_health_check
from src.routers.user import router as user_router
from src.schemas.health_schema import HealthCheckResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize DB Engine and Redis Connection Pool
    get_engine()
    get_redis_pool()
    yield
    # Shutdown: Close Redis Connection Pool and DB Engine
    await close_redis()
    await close_db()


app = FastAPI(
    title="Oauth2.0 Authorization Server",
    version="1.0.0",
    description="This is a sample OAuth2.0 Authorization Server.",
    lifespan=lifespan,
)


@app.get("/")
async def root():
    return {"message": "Welcome to the OAuth2.0 Authorization Server!"}


@app.get("/health", tags=["health"], response_model=HealthCheckResponse)
async def health_check():
    db_ok = await db_health_check()
    redis_ok = await redis_health_check()
    status = "healthy" if db_ok and redis_ok else "unhealthy"

    return HealthCheckResponse(
        status=status,
        database=db_ok,
        redis=redis_ok,
        timestamp=datetime.now(timezone.utc).isoformat()
    )


# Register routers
app.include_router(user_router)
