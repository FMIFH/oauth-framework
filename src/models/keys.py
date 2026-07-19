import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base


class SigningKey(Base):
    __tablename__ = "signing_keys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    kid: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )
    algorithm: Mapped[str] = mapped_column(
        String(10), nullable=False
    )  # 'RS256' or 'ES256'
    encrypted_private_key: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # AES-GCM encrypted PEM
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    deactivated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None, nullable=True
    )
