import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.logging import get_logger, log_structured
from backend.app.core.owasp import build_owasp_coverage_matrix
from backend.app.models.assessment import Assessment, AssessmentMode, AssessmentStatus
from backend.app.models.finding import Finding, FindingSeverity, ValidationStatus
from backend.app.models.target import Target
from backend.app.schemas.assessment import AssessmentCreate
from backend.app.services.providers.dast_provider import DASTScannerProvider
from backend.app.services.providers.demonstration_provider import DemonstrationProvider
from backend.app.services.report_service import ReportService

logger = get_logger(__name__)


class AssessmentService:
    @staticmethod
    async def create_assessment(
        db: AsyncSession, payload: AssessmentCreate
    ) -> Assessment:
        """
        Create and execute a security assessment for an authorized target.
        Enforces affirmative authorization record check prior to assessment execution.
        """
        # 1. Verify target exists
        stmt = select(Target).where(Target.id == payload.target_id)
        result = await db.execute(stmt)
        target = result.scalar_one_or_none()

        if not target:
            log_structured(
                logger,
                logging.WARNING,
                "Assessment creation rejected: target not found",
                target_id=payload.target_id,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target with ID '{payload.target_id}' not found.",
            )

        # 2. Verify target authorization attestation
        if not target.authorization_attestation:
            log_structured(
                logger,
                logging.WARNING,
                "Assessment creation rejected: target lacks affirmative authorization attestation",
                target_id=target.id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Assessment denied: Target has not confirmed affirmative ownership or written authorization.",
            )

        # 3. Mode validation: Real assessment mode barrier
        if payload.mode == AssessmentMode.REAL:
            log_structured(
                logger,
                logging.WARNING,
                "Real assessment mode requested but currently disabled",
                target_id=target.id,
            )
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail=(
                    "Real assessment mode is disabled in this phase. "
                    "Live network scanning requires dedicated scanner workers, "
                    "sandboxed execution, and approved scope boundaries."
                ),
            )

        # 4. Initialize Assessment record
        now = datetime.now(timezone.utc)
        assessment_id = str(uuid.uuid4())

        assessment = Assessment(
            id=assessment_id,
            target_id=target.id,
            status=AssessmentStatus.RUNNING,
            mode=payload.mode,
            profile=payload.profile,
            scope=f"Target asset: {target.target}",
            started_at=now,
            created_at=now,
            tool_execution_status={},
            finding_counts={},
        )
        db.add(assessment)
        await db.flush()

        # 5. Execute Provider
        context = {
            "source_repository_path": payload.source_repository_path,
        }
        if payload.profile == "dynamic_dast":
            provider = DASTScannerProvider()
        else:
            provider = DemonstrationProvider()

        findings_to_create, tool_status, meta = await provider.execute_assessment(
            assessment, target, context=context
        )

        # 6. Persist Findings with comprehensive technical fields
        finding_records: List[Finding] = []
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        }

        for f_schema in findings_to_create:
            f_record = Finding(
                id=str(uuid.uuid4()),
                assessment_id=assessment.id,
                target_id=target.id,
                title=f_schema.title,
                description=f_schema.description,
                severity=f_schema.severity,
                cvss_score=f_schema.cvss_score,
                cvss_rationale=f_schema.cvss_rationale,
                cwe_id=f_schema.cwe_id,
                owasp_category=f_schema.owasp_category,
                tool=f_schema.tool,
                tool_version=f_schema.tool_version,
                check_method=f_schema.check_method,
                affected_endpoint=f_schema.affected_endpoint,
                target_ip=f_schema.target_ip or meta.get("target_ip"),
                open_ports=f_schema.open_ports or meta.get("open_ports"),
                source_file=f_schema.source_file,
                source_line_start=f_schema.source_line_start,
                source_line_end=f_schema.source_line_end,
                evidence=f_schema.evidence,
                evidence_provenance=f_schema.evidence_provenance,
                why_vulnerable=f_schema.why_vulnerable,
                impact=f_schema.impact,
                root_cause=f_schema.root_cause,
                reproduction_steps=f_schema.reproduction_steps,
                expected_insecure_behavior=f_schema.expected_insecure_behavior,
                remediation=f_schema.remediation,
                secure_code_example=f_schema.secure_code_example,
                verification_steps=f_schema.verification_steps,
                regression_test=f_schema.regression_test,
                remediation_verification_status=f_schema.remediation_verification_status,
                confidence=f_schema.confidence,
                validation_status=f_schema.validation_status,
                first_seen_at=now,
                discovered_at=now,
                raw_output_reference=f_schema.raw_output_reference,
            )
            db.add(f_record)
            finding_records.append(f_record)
            severity_counts[f_schema.severity.value] = (
                severity_counts.get(f_schema.severity.value, 0) + 1
            )

        # 7. Finalize Assessment state & calculate OWASP Top 10:2025 Coverage Matrix
        completion_time = datetime.now(timezone.utc)
        executed_methods = meta.get(
            "executed_methods",
            list({f.check_method for f in finding_records})
        )

        matrix = build_owasp_coverage_matrix(finding_records, executed_methods)

        assessment.status = AssessmentStatus.COMPLETED
        assessment.completed_at = completion_time
        assessment.tool_execution_status = tool_status
        assessment.finding_counts = severity_counts
        assessment.incomplete_checks = meta.get("incomplete_checks")
        assessment.target_ip = meta.get("target_ip")
        assessment.open_ports = meta.get("open_ports")
        assessment.executed_methods = executed_methods
        assessment.owasp_coverage_matrix = matrix

        await db.commit()
        await db.refresh(assessment)

        # Load target relationship
        assessment.target = target

        log_structured(
            logger,
            logging.INFO,
            "Assessment completed and persisted",
            assessment_id=assessment.id,
            target_id=target.id,
            mode=assessment.mode.value,
            findings_count=len(finding_records),
            severity_counts=severity_counts,
        )

        return assessment

    @staticmethod
    async def get_assessments(
        db: AsyncSession,
        skip: int = 0,
        limit: int = 20,
        target_id: Optional[str] = None,
    ) -> Tuple[List[Assessment], int]:
        """Query paginated assessments, optionally filtered by target."""
        base_query = select(Assessment).options(selectinload(Assessment.target))
        count_query = select(func.count()).select_from(Assessment)

        if target_id:
            base_query = base_query.where(Assessment.target_id == target_id)
            count_query = count_query.where(Assessment.target_id == target_id)

        total_res = await db.execute(count_query)
        total = total_res.scalar_one()

        stmt = base_query.order_by(Assessment.created_at.desc()).offset(skip).limit(limit)
        items_res = await db.execute(stmt)
        items = list(items_res.scalars().all())

        return items, total

    @staticmethod
    async def get_assessment_by_id(
        db: AsyncSession, assessment_id: str
    ) -> Optional[Assessment]:
        """Query assessment by UUID with target loaded."""
        stmt = (
            select(Assessment)
            .options(selectinload(Assessment.target))
            .where(Assessment.id == assessment_id)
        )
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @staticmethod
    async def get_findings(
        db: AsyncSession,
        assessment_id: str,
        severity: Optional[FindingSeverity] = None,
        tool: Optional[str] = None,
        validation_status: Optional[ValidationStatus] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Finding], int]:
        """Query paginated findings for an assessment with optional filtering."""
        base_query = select(Finding).where(Finding.assessment_id == assessment_id)
        count_query = (
            select(func.count())
            .select_from(Finding)
            .where(Finding.assessment_id == assessment_id)
        )

        if severity:
            base_query = base_query.where(Finding.severity == severity)
            count_query = count_query.where(Finding.severity == severity)
        if tool:
            base_query = base_query.where(Finding.tool == tool)
            count_query = count_query.where(Finding.tool == tool)
        if validation_status:
            base_query = base_query.where(Finding.validation_status == validation_status)
            count_query = count_query.where(Finding.validation_status == validation_status)

        total_res = await db.execute(count_query)
        total = total_res.scalar_one()

        stmt = base_query.order_by(Finding.discovered_at.desc()).offset(skip).limit(limit)
        items_res = await db.execute(stmt)
        items = list(items_res.scalars().all())

        return items, total

    @staticmethod
    async def get_finding_by_id(
        db: AsyncSession, finding_id: str
    ) -> Optional[Finding]:
        """Query finding by ID."""
        stmt = select(Finding).where(Finding.id == finding_id)
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @staticmethod
    async def get_assessment_report_markdown(
        db: AsyncSession, assessment_id: str
    ) -> Tuple[Assessment, str]:
        """Generate markdown report for assessment."""
        assessment = await AssessmentService.get_assessment_by_id(db, assessment_id)
        if not assessment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Assessment '{assessment_id}' not found.",
            )

        findings_stmt = (
            select(Finding)
            .where(Finding.assessment_id == assessment_id)
            .order_by(Finding.discovered_at.desc())
        )
        findings_res = await db.execute(findings_stmt)
        findings = list(findings_res.scalars().all())

        md = ReportService.generate_markdown(assessment, assessment.target, findings)
        return assessment, md

    @staticmethod
    async def get_assessment_report_pdf(
        db: AsyncSession, assessment_id: str
    ) -> Tuple[Assessment, bytes]:
        """Generate PDF report for assessment."""
        assessment = await AssessmentService.get_assessment_by_id(db, assessment_id)
        if not assessment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Assessment '{assessment_id}' not found.",
            )

        findings_stmt = (
            select(Finding)
            .where(Finding.assessment_id == assessment_id)
            .order_by(Finding.discovered_at.desc())
        )
        findings_res = await db.execute(findings_stmt)
        findings = list(findings_res.scalars().all())

        pdf_bytes = ReportService.generate_pdf(assessment, assessment.target, findings)
        return assessment, pdf_bytes
