"""
PDF Report Generator
Shared module for generating professional PDF security reports.
"""

from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#C0392B"),
    "High": colors.HexColor("#E74C3C"),
    "Medium": colors.HexColor("#F39C12"),
    "Low": colors.HexColor("#3498DB"),
    "Info": colors.HexColor("#7F8C8D"),
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle", fontSize=22, leading=26,
        textColor=colors.HexColor("#1A1A2E"), spaceAfter=6,
        alignment=TA_CENTER, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle", fontSize=11, leading=14,
        textColor=colors.HexColor("#555555"), alignment=TA_CENTER, spaceAfter=20,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", fontSize=14, leading=18,
        textColor=colors.white, backColor=colors.HexColor("#1A1A2E"),
        spaceBefore=14, spaceAfter=10, leftIndent=6,
        fontName="Helvetica-Bold", borderPadding=(6, 6, 6, 6),
    ))
    styles.add(ParagraphStyle(
        name="FindingTitle", fontSize=11, leading=14,
        fontName="Helvetica-Bold", spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="FindingDetail", fontSize=9.5, leading=13,
        textColor=colors.HexColor("#333333"), fontName="Courier", spaceAfter=10,
    ))
    styles.add(ParagraphStyle(
        name="MetaLabel", fontSize=9,
        textColor=colors.HexColor("#777777"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="MetaValue", fontSize=9, textColor=colors.HexColor("#222222"),
    ))
    styles.add(ParagraphStyle(
        name="FooterNote", fontSize=8,
        textColor=colors.HexColor("#999999"), alignment=TA_CENTER,
    ))
    return styles


def _severity_badge(severity, styles):
    color = SEVERITY_COLORS.get(severity, colors.grey)
    hex_color = color.hexval()[2:] if hasattr(color, "hexval") else "777777"
    return Paragraph(
        f'<font color="#{hex_color}"><b>[{severity.upper()}]</b></font>',
        styles["FindingTitle"]
    )


def _summary_table(findings):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get("severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1

    header = ["Critical", "High", "Medium", "Low", "Info", "Total"]
    values = [str(counts[k]) for k in ["Critical", "High", "Medium", "Low", "Info"]] + [str(len(findings))]

    table = Table([header, values], colWidths=[0.85 * inch] * 6)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), SEVERITY_COLORS["Critical"]),
        ("BACKGROUND", (1, 0), (1, 0), SEVERITY_COLORS["High"]),
        ("BACKGROUND", (2, 0), (2, 0), SEVERITY_COLORS["Medium"]),
        ("BACKGROUND", (3, 0), (3, 0), SEVERITY_COLORS["Low"]),
        ("BACKGROUND", (4, 0), (4, 0), SEVERITY_COLORS["Info"]),
        ("BACKGROUND", (5, 0), (5, 0), colors.HexColor("#1A1A2E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.white),
    ]))
    return table


def _meta_table(meta_pairs, styles):
    rows = [[Paragraph(label, styles["MetaLabel"]), Paragraph(str(value), styles["MetaValue"])]
            for label, value in meta_pairs]
    table = Table(rows, colWidths=[1.6 * inch, 4.9 * inch])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def generate_pdf_report(report_data, output_path, report_title="Security Scan Report"):
    """
    Generate a PDF report from scan/analysis findings.

    report_data expects:
        - target (str)
        - scan_date (str, ISO format)
        - tool_name (str)
        - findings (list of dicts with: type, severity, detail,
          and optionally url / source_ip / line / timestamp)
        - extra_meta (optional list of (label, value) tuples)
    """
    styles = _build_styles()
    findings = report_data.get("findings", [])
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 5))

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )
    story = []

    story.append(Paragraph(report_title, styles["ReportTitle"]))
    story.append(Paragraph(f"Generated by {report_data.get('tool_name', 'Security Tool')}", styles["ReportSubtitle"]))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#1A1A2E"), thickness=1.2))
    story.append(Spacer(1, 14))

    scan_date = report_data.get("scan_date", datetime.now().isoformat())
    try:
        date_display = datetime.fromisoformat(scan_date).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        date_display = str(scan_date)

    meta_pairs = [
        ("Target / Source:", report_data.get("target", "N/A")),
        ("Scan Date:", date_display),
        ("Total Findings:", len(findings)),
    ]
    if report_data.get("extra_meta"):
        meta_pairs.extend(report_data["extra_meta"])

    story.append(_meta_table(meta_pairs, styles))
    story.append(Spacer(1, 16))

    story.append(Paragraph("SEVERITY SUMMARY", styles["SectionHeading"]))
    story.append(Spacer(1, 6))
    story.append(_summary_table(findings))
    story.append(Spacer(1, 20))

    story.append(Paragraph("DETAILED FINDINGS", styles["SectionHeading"]))
    story.append(Spacer(1, 8))

    if not sorted_findings:
        story.append(Paragraph("No findings were identified during this scan.", styles["Normal"]))
    else:
        for idx, finding in enumerate(sorted_findings, 1):
            severity = finding.get("severity", "Info")
            title_para = Paragraph(f"{idx}. {finding.get('type', 'Unknown')}", styles["FindingTitle"])
            badge = _severity_badge(severity, styles)

            row_table = Table([[title_para, badge]], colWidths=[4.6 * inch, 1.9 * inch])
            row_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
            ]))
            story.append(row_table)

            sub_bits = []
            if finding.get("url"): sub_bits.append(f"URL: {finding['url']}")
            if finding.get("source_ip"): sub_bits.append(f"Source IP: {finding['source_ip']}")
            if finding.get("line") is not None: sub_bits.append(f"Line: {finding['line']}")
            if finding.get("timestamp"): sub_bits.append(f"Time: {finding['timestamp']}")
            if sub_bits:
                story.append(Paragraph(" | ".join(sub_bits), styles["MetaValue"]))

            safe_detail = str(finding.get("detail", "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            story.append(Paragraph(safe_detail, styles["FindingDetail"]))
            story.append(HRFlowable(width="100%", color=colors.HexColor("#E0E0E0"), thickness=0.5))
            story.append(Spacer(1, 8))

    story.append(Spacer(1, 24))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#CCCCCC"), thickness=0.5))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"For authorized security testing and review purposes only.",
        styles["FooterNote"]
    ))

    doc.build(story)
    return output_path