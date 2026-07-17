from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SecuritySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OAUTH_", env_file=".env")

    # Core Infrastructure
    postgres_dsn: str = Field(..., description="PostgreSQL async connection string")
    redis_dsn: str = Field(..., description="Redis connection string")
    issuer_url: str = Field(
        "https://auth.example.com", description="Authorization Server Issuer URL"
    )
    master_encryption_key: str = Field(
        ..., description="64-character Hex string for private key encryption"
    )

    # Token Lifetimes (seconds)
    access_token_ttl: int = Field(3600, description="1 hour default")
    refresh_token_ttl: int = Field(2592000, description="30 days default")
    auth_code_ttl: int = Field(60, description="1 minute default")

    # Security Policies
    cookie_secure: bool = Field(
        True, description="Enforces Secure flag on cookie storage"
    )
    cookie_samesite: str = Field(
        "Lax", description="SameSite configuration cookie flag"
    )
    rate_limit_per_minute: int = Field(
        100, description="API Gateway rate limit per client/IP"
    )
    enable_plain_pkce: bool = Field(False, description="Disable plain PKCE by default")


settings = SecuritySettings()
