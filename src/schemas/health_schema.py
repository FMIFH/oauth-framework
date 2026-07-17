from pydantic import BaseModel, Field


class HealthCheckResponse(BaseModel):
    status: str = Field(..., description="Health check status")
    database: bool = Field(..., description="Database connection status")
    redis: bool = Field(..., description="Redis connection status")
    timestamp: str = Field(..., description="Timestamp of the health check")
