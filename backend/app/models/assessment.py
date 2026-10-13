import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Enum, ForeignKey, JSON, String, Text
from sqlalchemy.orm import relationship
from backend.app.db.base import Base


class AssessmentStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssessmentMode(str, enum.Enum):
    DEMONSTRATION = "demonstration"
    REAL = "real"


class Assessment(Base):
    """
    SQLAlchemy model for authorized security assessments.
    Enforces reference to an authorized target.
    """
    __tablename__ = "assessments"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    target_id = Column(
        String(36),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status = Column(
        Enum(AssessmentStatus, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        default=AssessmentStatus.QUEUED,
        index=True,
    )
    mode = Column(
        Enum(AssessmentMode, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        default=AssessmentMode.DEMONSTRATION,
        index=True,
    )
    profile = Column(String(64), nullable=False, default="standard_baseline")
    scope = Column(String(1024), nullable=False, default="Single Host / Endpoint")
    target_ip = Column(String(64), nullable=True)
    open_ports = Column(JSON, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    tool_execution_status = Column(JSON, nullable=True, default=dict)
    finding_counts = Column(JSON, nullable=True, default=dict)
    owasp_coverage_matrix = Column(JSON, nullable=True, default=dict)
    executed_methods = Column(JSON, nullable=True, default=list)
    error_summary = Column(Text, nullable=True)
    incomplete_checks = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # Relationships
    target = relationship("Target", back_populates="assessments")
    findings = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Assessment id={self.id} target_id={self.target_id} status={self.status} mode={self.mode}>"
