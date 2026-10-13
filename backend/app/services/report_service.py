import html
import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from backend.app.core.owasp import OWASP_METADATA, CoverageStatus
from backend.app.models.assessment import Assessment, AssessmentMode
from backend.app.models.finding import Finding
from backend.app.models.target import Target


class ReportService:
    @staticmethod
    def generate_markdown(
        assessment: Assessment, target: Target, findings: List[Finding]
    ) -> str:
        """
        Generate a comprehensive, structured Markdown report.
        Includes disclaimers, executive summary, OWASP Top 10:2025 coverage matrix,
        metrics, source code locations, secure code examples, and regression tests.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        is_demo = assessment.mode == AssessmentMode.DEMONSTRATION

        # Severity count breakdown
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        md: List[str] = []

        # Title & Header
        md.append("# SentinelSec Security Assessment Report")
        md.append(f"**Assessment ID:** `{assessment.id}`  ")
        md.append(f"**Report Generated:** {now}  ")
        md.append(f"**Target Asset:** `{target.target}` ({target.type.value.upper()})  ")
        if assessment.target_ip:
            md.append(f"**Target IP:** `{assessment.target_ip}`  ")
        if assessment.open_ports:
            ports_summary = ", ".join(
                [f"{p.get('port')}/{p.get('protocol', 'tcp')} ({p.get('service', 'unknown')})" for p in assessment.open_ports]
            )
            md.append(f"**Identified Ports & Services:** `{ports_summary}`  ")
        md.append(f"**Authorized Scope:** {assessment.scope}  ")
        md.append(f"**Execution Mode:** `{assessment.mode.value.upper()}`  ")
        md.append(f"**Assessment Status:** `{assessment.status.value}`  ")
        md.append("")

        # Prominent Demo Disclaimer
        if is_demo:
            md.append("> [!WARNING]")
            md.append("> **DEMONSTRATION DATA — NOT A REAL SCAN**")
            md.append("> This report was produced using synthetic demonstration fixtures to showcase SentinelSec's reporting and findings workflows. No unauthorized network connections, scans, or tests were executed against the registered target.")
            md.append("")

        # Executive Summary
        md.append("## 1. Executive Summary")
        if is_demo:
            md.append(
                f"SentinelSec executed a simulated baseline assessment for authorized target **{target.target}** "
                f"under profile `{assessment.profile}` in **Demonstration Mode**. "
                f"A total of **{len(findings)} synthetic illustrative findings** were populated to demonstrate remediation tracking."
            )
        else:
            md.append(
                f"SentinelSec conducted an authorized defensive security assessment against target **{target.target}** "
                f"under scope `{assessment.scope}`. "
                f"A total of **{len(findings)} findings** were logged."
            )
        md.append("")

        # Severity Table
        md.append("### Severity Distribution")
        md.append("| Severity | Count | Impact Description |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| **Critical** | {counts['Critical']} | Immediate threat to data or operational integrity |")
        md.append(f"| **High** | {counts['High']} | Significant vulnerability with direct exploit vector |")
        md.append(f"| **Medium** | {counts['Medium']} | Moderate vulnerability requiring specific preconditions |")
        md.append(f"| **Low** | {counts['Low']} | Minor configuration defect or defense-in-depth weakness |")
        md.append(f"| **Informational** | {counts['Informational']} | Architecture observation or technology disclosure |")
        md.append("")

        # OWASP Top 10:2025 Coverage Matrix
        md.append("## 2. OWASP Top 10:2025 Coverage Matrix")
        md.append("> [!NOTE]")
        md.append("> **Evidence-Based Coverage Standard:** An application is **never** labeled secure simply because an automated scanner returned zero findings. "
                  "Coverage is recorded separately across assessment methods. Categories without dedicated checks remain marked as `Not assessed` or `Manual review required`.")
        md.append("")
        md.append("| Category ID | OWASP Top 10:2025 Category | Status | Findings | Evaluated Methods | Evaluation Notes |")
        md.append("| :--- | :--- | :--- | :---: | :--- | :--- |")

        matrix = assessment.owasp_coverage_matrix or {}
        for code, meta in OWASP_METADATA.items():
            row = matrix.get(code, {})
            status_val = row.get("status", CoverageStatus.NOT_ASSESSED.value)
            count = row.get("findings_count", 0)
            methods = ", ".join(row.get("methods_evaluated", [])) or "None"
            notes = row.get("notes", "No active checks executed.")

            status_display = {
                CoverageStatus.FINDINGS_IDENTIFIED.value: "🔴 Findings identified",
                CoverageStatus.NO_FINDINGS_IDENTIFIED.value: "🟢 No findings identified",
                CoverageStatus.NOT_ASSESSED.value: "⚪ Not assessed",
                CoverageStatus.INCONCLUSIVE.value: "🟡 Inconclusive",
                CoverageStatus.MANUAL_REVIEW_REQUIRED.value: "🟠 Manual review required",
            }.get(status_val, status_val)

            md.append(f"| **{code}** | {meta['name']} | {status_display} | {count} | `{methods}` | {notes} |")
        md.append("")

        # Methodology & Execution Details
        md.append("## 3. Assessment Methodology & Inventory Scope")
        md.append(f"- **Scan Profile:** `{assessment.profile}`")
        if assessment.profile == "dynamic_dast" or "runtime_observations" in (assessment.executed_methods or []):
            md.append("- **Evaluation Engine:** Dynamic Application Security Testing (DAST - Runtime Observation)")
        md.append(f"- **Started At:** {assessment.started_at or 'N/A'}")
        md.append(f"- **Completed At:** {assessment.completed_at or 'N/A'}")
        if assessment.target_ip:
            md.append(f"- **Target IP Address:** `{assessment.target_ip}`")
        if assessment.open_ports:
            md.append(f"- **Open Ports Inventory:** `{ports_summary}`")
        md.append(f"- **Executed Assessment Methods:** `{', '.join(assessment.executed_methods or []) or 'N/A'}`")

        md.append(f"- **Incomplete Checks / Exceptions:** {assessment.error_summary or assessment.incomplete_checks or 'None'}")
        md.append("")

        # Detailed Technical Findings
        md.append("## 4. Detailed Technical Findings")
        if not findings:
            md.append("*No findings recorded for this assessment.*")
            md.append("> Note: An empty findings list does not imply an absence of vulnerabilities outside tested controls.")
        else:
            for idx, f in enumerate(findings, 1):
                md.append(f"### 4.{idx}. [{f.severity.value.upper()}] {f.title}")
                md.append(f"- **Finding ID:** `{f.id}`")
                md.append(f"- **Affected Component / URL:** `{f.affected_endpoint}`")
                if f.target_ip:
                    md.append(f"- **Target IP:** `{f.target_ip}`")
                if f.source_file:
                    loc = f"{f.source_file}"
                    if f.source_line_start:
                        loc += f":L{f.source_line_start}"
                        if f.source_line_end and f.source_line_end != f.source_line_start:
                            loc += f"-L{f.source_line_end}"
                    md.append(f"- **Source Code Location:** `{loc}`")
                md.append(f"- **OWASP Top 10:2025 Category:** {f.owasp_category}")
                md.append(f"- **CWE Identifier:** {f.cwe_id or 'N/A'}")
                md.append(f"- **CVSS v3.1 Score:** `{f.cvss_score if f.cvss_score is not None else 'N/A'}`")
                if f.cvss_rationale:
                    md.append(f"- **CVSS Vector & Rationale:** {f.cvss_rationale}")
                md.append(f"- **Detection Tool:** `{f.tool}` (v{f.tool_version or '1.0.0'})")
                md.append(f"- **Check Method:** `{f.check_method}`")
                md.append(f"- **Validation Status:** `{f.validation_status.value}` (Confidence: {f.confidence})")
                md.append(f"- **Remediation Verification Status:** `{f.remediation_verification_status}`")
                md.append("")

                md.append("**Description:**")
                md.append(f"{f.description}")
                md.append("")

                if f.why_vulnerable:
                    md.append("**Why The Implementation Is Vulnerable:**")
                    md.append(f"{f.why_vulnerable}")
                    md.append("")

                md.append("**Observed Technical Evidence:**")
                if f.evidence_provenance:
                    md.append(f"*Evidence Provenance:* `{f.evidence_provenance}`")
                md.append("```")
                md.append(f"{f.evidence}")
                md.append("```")
                md.append("")

                md.append("**Security Impact:**")
                md.append(f"{f.impact}")
                md.append("")

                if f.reproduction_steps:
                    md.append("**Safe Local Reproduction Instructions:**")
                    md.append(f"{f.reproduction_steps}")
                    md.append("")

                if f.expected_insecure_behavior:
                    md.append("**Expected Insecure Behavior:**")
                    md.append(f"{f.expected_insecure_behavior}")
                    md.append("")

                md.append("**Secure Remediation Guidance:**")
                md.append(f"{f.remediation}")
                md.append("")

                if f.secure_code_example:
                    md.append("**Secure Code Example (Remediated):**")
                    md.append("```python")
                    md.append(f"{f.secure_code_example}")
                    md.append("```")
                    md.append("")

                md.append("**Verification Steps:**")
                md.append("```bash")
                md.append(f"{f.verification_steps}")
                md.append("```")
                md.append("")

                if f.regression_test:
                    md.append("**Executable Regression Test:**")
                    md.append("```python")
                    md.append(f"{f.regression_test}")
                    md.append("```")
                    md.append("")

                md.append("---")
                md.append("")

        # Limitations and Legal Notice
        md.append("## 5. Limitations & Evidence Disclaimers")
        md.append("1. **Defensive Assessment Scope:** This report reflects automated and manual security checks within the documented profile and scope.")
        md.append("2. **Zero Findings Disclaimer:** Scanning tools test only known patterns and rulesets. Zero findings does not imply complete absence of zero-day or logic vulnerabilities.")
        md.append("3. **Confidentiality:** This report contains defensive technical vulnerability data. Distribute strictly on a need-to-know basis.")
        if is_demo:
            md.append("4. **Demonstration Notice:** This document was generated using synthetic demonstration data.")

        return "\n".join(md)

    @staticmethod
    def generate_pdf(
        assessment: Assessment, target: Target, findings: List[Finding]
    ) -> bytes:
        """
        Generate a professional PDF assessment report using ReportLab.
        Includes OWASP Top 10:2025 Coverage Matrix, technical findings, and code blocks.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )

        styles = getSampleStyleSheet()
        normal = styles["Normal"]
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Title"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            alignment=0,
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=normal,
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=10,
            spaceAfter=6,
        )
        demo_style = ParagraphStyle(
            "DemoNotice",
            parent=normal,
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#b91c1c"),
            backColor=colors.HexColor("#fee2e2"),
            borderColor=colors.HexColor("#ef4444"),
            borderWidth=1,
            borderPadding=5,
            spaceBefore=4,
            spaceAfter=8,
        )
        code_style = ParagraphStyle(
            "CodeBlock",
            parent=normal,
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
            backColor=colors.HexColor("#f1f5f9"),
            borderPadding=4,
            spaceBefore=3,
            spaceAfter=5,
        )

        story = []

        # Header Title
        story.append(Paragraph("SentinelSec Security Assessment Report", title_style))
        story.append(Spacer(1, 3))
        story.append(
            Paragraph(
                f"Assessment ID: <b>{assessment.id}</b> | Target: <b>{target.target}</b>",
                subtitle_style,
            )
        )
        story.append(Spacer(1, 6))

        # Demo Banner
        if assessment.mode == AssessmentMode.DEMONSTRATION:
            story.append(
                Paragraph(
                    "<b>DEMONSTRATION DATA — NOT A REAL SCAN</b><br/>"
                    "This report was generated using synthetic baseline fixtures for platform demonstration. "
                    "No real scans or network requests were conducted against the target.",
                    demo_style,
                )
            )

        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))

        # Target & Metadata Table
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        meta_data = [
            ["Target Asset:", target.target, "Target Type:", target.type.value.upper()],
            ["Assessment Mode:", assessment.mode.value.upper(), "Status:", assessment.status.value],
            ["Target IP:", assessment.target_ip or "N/A", "Generated At:", now_str],
            ["Scan Profile:", assessment.profile, "Total Findings:", str(len(findings))],
        ]
        meta_table = Table(meta_data, colWidths=[1.3 * inch, 2.3 * inch, 1.3 * inch, 2.3 * inch])
        meta_table.setStyle(
            TableStyle([
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748b")),
                ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#64748b")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        story.append(meta_table)
        story.append(Spacer(1, 8))

        # OWASP Top 10:2025 Coverage Table
        story.append(Paragraph("OWASP Top 10:2025 Category Coverage Matrix", h2_style))
        matrix = assessment.owasp_coverage_matrix or {}
        owasp_data = [
            ["ID", "Category", "Status", "Findings", "Evaluated Methods"]
        ]
        for code, m in OWASP_METADATA.items():
            row = matrix.get(code, {})
            status_val = row.get("status", "not_assessed")
            count = str(row.get("findings_count", 0))
            methods = ", ".join(row.get("methods_evaluated", [])) or "None"
            owasp_data.append([code, m["name"][:30], status_val.replace("_", " ").title(), count, methods[:30]])

        owasp_table = Table(owasp_data, colWidths=[0.6 * inch, 2.2 * inch, 1.8 * inch, 0.7 * inch, 1.9 * inch])
        owasp_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ALIGN", (0, 0), (0, -1), "CENTER"),
                ("ALIGN", (3, 0), (3, -1), "CENTER"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
            ])
        )
        story.append(owasp_table)
        story.append(Spacer(1, 10))

        # Severity Summary
        story.append(Paragraph("Findings Summary by Severity", h2_style))
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        sev_data = [
            ["Severity", "Count", "Severity", "Count"],
            ["Critical", str(counts["Critical"]), "Low", str(counts["Low"])],
            ["High", str(counts["High"]), "Informational", str(counts["Informational"])],
            ["Medium", str(counts["Medium"]), "Total", str(len(findings))],
        ]
        sev_table = Table(sev_data, colWidths=[1.8 * inch, 1.8 * inch, 1.8 * inch, 1.8 * inch])
        sev_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ("ALIGN", (3, 0), (3, -1), "CENTER"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ])
        )
        story.append(sev_table)
        story.append(Spacer(1, 10))

        # Technical Findings Details
        story.append(Paragraph("Technical Findings & Remediation", h2_style))

        if not findings:
            story.append(Paragraph("No vulnerability findings recorded for this assessment.", normal))
        else:
            for idx, f in enumerate(findings, 1):
                sev_color = {
                    "Critical": "#991b1b",
                    "High": "#dc2626",
                    "Medium": "#d97706",
                    "Low": "#2563eb",
                    "Informational": "#475569",
                }.get(f.severity.value, "#334155")

                finding_header = f"<b>{idx}. [{f.severity.value.upper()}] {f.title}</b>"
                story.append(
                    Paragraph(
                        f"<font color='{sev_color}'>{finding_header}</font>",
                        ParagraphStyle("FHeader", parent=normal, fontSize=10, leading=13, spaceBefore=6),
                    )
                )

                loc_str = f.source_file or "N/A"
                if f.source_file and f.source_line_start:
                    loc_str += f":L{f.source_line_start}"
                f_meta = [
                    [
                        f"CVSS: {f.cvss_score if f.cvss_score is not None else 'N/A'}",
                        f"CWE: {f.cwe_id or 'N/A'}",
                        f"OWASP: {f.owasp_category.split(':')[0] if f.owasp_category else 'N/A'}",
                        f"Source: {loc_str[:25]}",
                    ]
                ]
                fmt_table = Table(f_meta, colWidths=[1.3 * inch, 1.8 * inch, 1.8 * inch, 2.3 * inch])
                fmt_table.setStyle(
                    TableStyle([
                        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#475569")),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ])
                )
                story.append(fmt_table)

                safe_endpoint = html.escape(f.affected_endpoint or "")
                safe_desc = html.escape(f.description or "")
                story.append(Paragraph(f"<b>Affected:</b> {safe_endpoint}", normal))
                story.append(Paragraph(f"<b>Description:</b> {safe_desc}", normal))
                if f.why_vulnerable:
                    safe_why = html.escape(f.why_vulnerable)
                    story.append(Paragraph(f"<b>Root Cause:</b> {safe_why}", normal))
                story.append(Paragraph("<b>Observed Evidence:</b>", normal))
                evidence_text = html.escape(f.evidence[:600]).replace("\n", "<br/>")
                story.append(Paragraph(evidence_text, code_style))

                if f.secure_code_example:
                    story.append(Paragraph("<b>Remediated Code Example:</b>", normal))
                    example_text = html.escape(f.secure_code_example[:600]).replace("\n", "<br/>")
                    story.append(Paragraph(example_text, code_style))

                safe_remediation = html.escape(f.remediation or "")
                story.append(Paragraph(f"<b>Remediation:</b> {safe_remediation}", normal))
                story.append(Spacer(1, 3))
                story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=5))


        # Disclaimer Footer
        story.append(Spacer(1, 8))
        story.append(Paragraph("<b>Confidentiality & Limitations Notice</b>", normal))
        story.append(
            Paragraph(
                "This document is intended strictly for authorized security personnel. "
                "Assessments represent a point-in-time evaluation under declared scope and methodologies. "
                "Zero automated findings does not certify immunity from undetected vulnerabilities.",
                ParagraphStyle("Disc", parent=normal, fontSize=7.5, leading=10, textColor=colors.HexColor("#64748b")),
            )
        )

        doc.build(story)
        return buffer.getvalue()
