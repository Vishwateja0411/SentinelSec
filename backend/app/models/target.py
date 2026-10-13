import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Enum, String
from sqlalchemy.orm import relationship
from backend.app.db.base import Base


class TargetType(str, enum.Enum):
    IP = "ip"
    URL = "url"


class Target(Base):
    """
    SQLAlchemy model for registered targets and authorization records.
    All targets are treated as inert strings; no network requests, scans,
    or execution are performed on them.
    """
    __tablename__ = "targets"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    target = Column(String(2048), nullable=False, index=True)
    type = Column(
        Enum(TargetType, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    authorization_attestation = Column(Boolean, nullable=False, default=False)
    attestation_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # Relationships
    assessments = relationship("Assessment", back_populates="target", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Target id={self.id} type={self.type} target={self.target[:30]}>"
