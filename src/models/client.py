import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_name: Mapped[str] = mapped_column(String(100), nullable=False)
    client_type: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # 'confidential' or 'public'
    redirect_uris: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # JSON-serialized list
    grant_types: Mapped[str] = mapped_column(
        String(255), nullable=False
    )  # Comma-separated
    scope: Mapped[str] = mapped_column(Text, nullable=False)  # Space-separated
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class ClientSecret(Base):
    __tablename__ = "client_secrets"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
