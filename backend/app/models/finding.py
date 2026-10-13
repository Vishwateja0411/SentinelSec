import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from backend.app.db.base import Base


class FindingSeverity(str, enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class ValidationStatus(str, enum.Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    UNVERIFIED = "unverified"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"


class Finding(Base):
    """
    SQLAlchemy model for persistent vulnerability findings with comprehensive
    OWASP Top 10:2025 evidence, code locations, safe reproduction, and regression tests.
    """
    __tablename__ = "findings"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    assessment_id = Column(
        String(36),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_id = Column(
        String(36),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title = Column(String(512), nullable=False, index=True)
    description = Column(Text, nullable=False)
    severity = Column(
        Enum(FindingSeverity, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        index=True,
    )
    cvss_score = Column(Float, nullable=True)
    cvss_rationale = Column(Text, nullable=True)
    cwe_id = Column(String(64), nullable=True, index=True)
    owasp_category = Column(String(128), nullable=False, index=True)
    tool = Column(String(128), nullable=False, index=True)
    tool_version = Column(String(64), nullable=True, default="1.0.0")
    check_method = Column(String(64), nullable=False, default="configuration_checks")
    affected_endpoint = Column(String(2048), nullable=False)
    target_ip = Column(String(64), nullable=True)
    open_ports = Column(JSON, nullable=True)

    # Source code analysis metadata
    source_file = Column(String(1024), nullable=True)
    source_line_start = Column(Integer, nullable=True)
    source_line_end = Column(Integer, nullable=True)

    # Technical evidence & provenance
    evidence = Column(Text, nullable=False)
    evidence_provenance = Column(String(512), nullable=True)
    why_vulnerable = Column(Text, nullable=True)
    impact = Column(Text, nullable=False)
    root_cause = Column(Text, nullable=True)

    # Safe local reproduction & behavior
    reproduction_steps = Column(Text, nullable=True)
    expected_insecure_behavior = Column(Text, nullable=True)

    # Defensive remediation & verified regression tests
    remediation = Column(Text, nullable=False)
    secure_code_example = Column(Text, nullable=True)
    verification_steps = Column(Text, nullable=False)
    regression_test = Column(Text, nullable=True)
    remediation_verification_status = Column(String(64), nullable=False, default="unverified")

    # Quality & state
    confidence = Column(String(32), nullable=False, default="High")
    validation_status = Column(
        Enum(ValidationStatus, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        default=ValidationStatus.CONFIRMED,
        index=True,
    )
    first_seen_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    discovered_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    raw_output_reference = Column(Text, nullable=True)

    # Relationships
    assessment = relationship("Assessment", back_populates="findings")
    target = relationship("Target")

    def __repr__(self) -> str:
        return f"<Finding id={self.id} severity={self.severity} title={self.title[:30]}>"
