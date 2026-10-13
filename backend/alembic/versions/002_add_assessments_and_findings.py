"""002_add_assessments_and_findings

Revision ID: 002_add_assessments_and_findings
Revises: 001_initial_targets
Create Date: 2026-10-11 15:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '002_add_assessments_and_findings'
down_revision: Union[str, None] = '001_initial_targets'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create assessments table
    op.create_table(
        'assessments',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=False),
        sa.Column(
            'status',
            sa.Enum('queued', 'running', 'completed', 'completed_with_errors', 'failed', 'cancelled', name='assessmentstatus'),
            nullable=False,
        ),
        sa.Column(
            'mode',
            sa.Enum('demonstration', 'real', name='assessmentmode'),
            nullable=False,
        ),
        sa.Column('profile', sa.String(length=64), nullable=False),
        sa.Column('scope', sa.String(length=1024), nullable=False),
        sa.Column('target_ip', sa.String(length=64), nullable=True),
        sa.Column('open_ports', sa.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('tool_execution_status', sa.JSON(), nullable=True),
        sa.Column('finding_counts', sa.JSON(), nullable=True),
        sa.Column('owasp_coverage_matrix', sa.JSON(), nullable=True),
        sa.Column('executed_methods', sa.JSON(), nullable=True),
        sa.Column('error_summary', sa.Text(), nullable=True),
        sa.Column('incomplete_checks', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_assessments_id'), 'assessments', ['id'], unique=False)
    op.create_index(op.f('ix_assessments_target_id'), 'assessments', ['target_id'], unique=False)
    op.create_index(op.f('ix_assessments_status'), 'assessments', ['status'], unique=False)
    op.create_index(op.f('ix_assessments_mode'), 'assessments', ['mode'], unique=False)
    op.create_index(op.f('ix_assessments_created_at'), 'assessments', ['created_at'], unique=False)

    # 2. Create findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('assessment_id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=512), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column(
            'severity',
            sa.Enum('Critical', 'High', 'Medium', 'Low', 'Informational', name='findingseverity'),
            nullable=False,
        ),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_rationale', sa.Text(), nullable=True),
        sa.Column('cwe_id', sa.String(length=64), nullable=True),
        sa.Column('owasp_category', sa.String(length=128), nullable=False),
        sa.Column('tool', sa.String(length=128), nullable=False),
        sa.Column('tool_version', sa.String(length=64), nullable=True),
        sa.Column('check_method', sa.String(length=64), nullable=False, server_default='configuration_checks'),
        sa.Column('affected_endpoint', sa.String(length=2048), nullable=False),
        sa.Column('target_ip', sa.String(length=64), nullable=True),
        sa.Column('open_ports', sa.JSON(), nullable=True),
        sa.Column('source_file', sa.String(length=1024), nullable=True),
        sa.Column('source_line_start', sa.Integer(), nullable=True),
        sa.Column('source_line_end', sa.Integer(), nullable=True),
        sa.Column('evidence', sa.Text(), nullable=False),
        sa.Column('evidence_provenance', sa.String(length=512), nullable=True),
        sa.Column('why_vulnerable', sa.Text(), nullable=True),
        sa.Column('impact', sa.Text(), nullable=False),
        sa.Column('root_cause', sa.Text(), nullable=True),
        sa.Column('reproduction_steps', sa.Text(), nullable=True),
        sa.Column('expected_insecure_behavior', sa.Text(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=False),
        sa.Column('secure_code_example', sa.Text(), nullable=True),
        sa.Column('verification_steps', sa.Text(), nullable=False),
        sa.Column('regression_test', sa.Text(), nullable=True),
        sa.Column('remediation_verification_status', sa.String(length=64), nullable=False, server_default='unverified'),
        sa.Column('confidence', sa.String(length=32), nullable=False),
        sa.Column(
            'validation_status',
            sa.Enum('confirmed', 'potential', 'unverified', 'false_positive', 'fixed', name='validationstatus'),
            nullable=False,
        ),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('raw_output_reference', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['assessment_id'], ['assessments.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_findings_id'), 'findings', ['id'], unique=False)
    op.create_index(op.f('ix_findings_assessment_id'), 'findings', ['assessment_id'], unique=False)
    op.create_index(op.f('ix_findings_target_id'), 'findings', ['target_id'], unique=False)
    op.create_index(op.f('ix_findings_title'), 'findings', ['title'], unique=False)
    op.create_index(op.f('ix_findings_severity'), 'findings', ['severity'], unique=False)
    op.create_index(op.f('ix_findings_cwe_id'), 'findings', ['cwe_id'], unique=False)
    op.create_index(op.f('ix_findings_owasp_category'), 'findings', ['owasp_category'], unique=False)
    op.create_index(op.f('ix_findings_tool'), 'findings', ['tool'], unique=False)
    op.create_index(op.f('ix_findings_validation_status'), 'findings', ['validation_status'], unique=False)


def downgrade() -> None:
    op.drop_table('findings')
    op.drop_table('assessments')
