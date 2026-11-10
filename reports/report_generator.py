
import json
from io import BytesIO
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether
)


# ============================================================
# REPORT CONFIGURATION
# ============================================================

NAVY = colors.HexColor("#101A2D")
BLUE = colors.HexColor("#1769A9")
CYAN = colors.HexColor("#20BFD9")
LIGHT_BLUE = colors.HexColor("#EAF3FA")
GREY = colors.HexColor("#64748B")
LIGHT_GREY = colors.HexColor("#F1F5F9")
RED = colors.HexColor("#D9435F")
ORANGE = colors.HexColor("#D97706")
GREEN = colors.HexColor("#15966D")


def safe_get(data, key, default=None):
    if isinstance(data, dict):
        return data.get(key, default)
    return default


def clean_text(value):
    """Convert data into safe printable text."""
    if value is None:
        return "Not available"

    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, indent=2, default=str)

    return escape(str(value)).replace("\n", "<br/>")


def format_list(value):
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return [value]


def risk_color(level):
    level = str(level).lower()

    if "high" in level:
        return RED

    if "medium" in level or "suspicious" in level:
        return ORANGE

    if "low" in level:
        return GREEN

    return BLUE


# ============================================================
# PDF REPORT GENERATOR
# ============================================================

def generate_investigation_report(
    investigation,
    output_path=None
):
    """
    Generate a PDF SOC investigation report.

    Parameters:
        investigation: Complete result dictionary returned
                       by run_investigation().
        output_path: Optional path to save the PDF.

    Returns:
        PDF file bytes.
    """

    if not isinstance(investigation, dict):
        raise ValueError("Investigation data must be a dictionary.")

    parsed = investigation.get("parsed", {}) or {}
    rules = investigation.get("rules", {}) or {}
    headers = investigation.get("headers", {}) or {}
    urls = investigation.get("urls", {}) or {}
    vt = investigation.get("vt", {}) or {}
    ai = investigation.get("ai", {}) or {}
    correlation = investigation.get("correlation", {}) or {}
    timings = investigation.get("timing", {}) or {}

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title="PHISHINTEL AI - SOC Investigation Report",
        author="PHISHINTEL AI",
        subject="Phishing Email Security Investigation"
    )

    # --------------------------------------------------------
    # STYLES
    # --------------------------------------------------------

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=29,
            textColor=NAVY,
            alignment=TA_CENTER,
            spaceAfter=5
        )
    )

    styles.add(
        ParagraphStyle(
            name="Subtitle",
            parent=styles["Normal"],
            fontSize=9,
            textColor=GREY,
            alignment=TA_CENTER,
            spaceAfter=18
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=NAVY,
            spaceBefore=13,
            spaceAfter=8
        )
    )

    styles.add(
        ParagraphStyle(
            name="BodyCustom",
            parent=styles["BodyText"],
            fontSize=9,
            leading=14,
            textColor=colors.HexColor("#263449"),
            spaceAfter=5
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallCustom",
            parent=styles["BodyText"],
            fontSize=8,
            leading=11,
            textColor=GREY
        )
    )

    styles.add(
        ParagraphStyle(
            name="WhiteHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=colors.white
        )
    )

    story = []

    def add_heading(text):
        story.append(
            Paragraph(
                escape(text),
                styles["SectionHeading"]
            )
        )

    def add_body(text):
        story.append(
            Paragraph(
                clean_text(text),
                styles["BodyCustom"]
            )
        )

    def add_table(rows, widths=None):
        table = Table(
            rows,
            colWidths=widths,
            repeatRows=1,
            hAlign="LEFT"
        )

        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEADING", (0, 0), (-1, -1), 11),
                ("BACKGROUND", (0, 1), (-1, -1), LIGHT_GREY),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D8E1EB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ])
        )

        story.append(table)
        story.append(Spacer(1, 8))

    def add_data_table(data, empty_message="No data available"):
        if not isinstance(data, dict) or not data:
            add_body(empty_message)
            return

        rows = [
            [
                Paragraph("Field", styles["WhiteHeader"]),
                Paragraph("Details", styles["WhiteHeader"])
            ]
        ]

        for key, value in data.items():
            rows.append([
                Paragraph(clean_text(str(key).replace("_", " ").title()), styles["BodyCustom"]),
                Paragraph(clean_text(value), styles["BodyCustom"])
            ])

        add_table(rows, [48 * mm, 126 * mm])

    # --------------------------------------------------------
    # COVER / HEADER
    # --------------------------------------------------------

    story.append(Spacer(1, 15 * mm))

    story.append(
        Paragraph(
            "PHISHINTEL AI",
            styles["ReportTitle"]
        )
    )

    story.append(
        Paragraph(
            "SECURITY OPERATIONS CENTER<br/>"
            "PHISHING EMAIL INVESTIGATION REPORT",
            styles["Subtitle"]
        )
    )

    report_time = datetime.now().strftime(
        "%d %B %Y | %H:%M:%S"
    )

    story.append(
        Paragraph(
            f"<b>Report generated:</b> {escape(report_time)}",
            styles["BodyCustom"]
        )
    )

    story.append(
        Paragraph(
            "<b>Report type:</b> Email Security Investigation",
            styles["BodyCustom"]
        )
    )

    story.append(Spacer(1, 8))

    # --------------------------------------------------------
    # FINAL INVESTIGATION VERDICT
    # --------------------------------------------------------

    verdict = safe_get(
        correlation,
        "verdict",
        "Inconclusive"
    )

    risk_level = safe_get(
        correlation,
        "risk_level",
        "Unknown"
    )

    risk_score = safe_get(
        correlation,
        "risk_score",
        0
    )

    evidence_coverage = safe_get(
        correlation,
        "confidence_score",
        0
    )

    summary = safe_get(
        correlation,
        "summary",
        "No investigation summary available."
    )

    add_heading("1. Executive Summary")

    verdict_table = Table(
        [[
            Paragraph(
                "<b>FINAL VERDICT</b><br/><br/>"
                + clean_text(verdict),
                styles["BodyCustom"]
            ),
            Paragraph(
                "<b>RISK SCORE</b><br/><br/>"
                + clean_text(f"{risk_score}/100"),
                styles["BodyCustom"]
            ),
            Paragraph(
                "<b>RISK LEVEL</b><br/><br/>"
                + clean_text(risk_level),
                styles["BodyCustom"]
            )
        ]],
        colWidths=[70 * mm, 52 * mm, 52 * mm]
    )

    verdict_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BLUE),
            ("BOX", (0, 0), (-1, -1), 1, BLUE),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.white),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ])
    )

    story.append(verdict_table)
    story.append(Spacer(1, 10))

    add_body(summary)

    add_body(
        f"Evidence coverage: {evidence_coverage}/100. "
        "This is a coverage indicator, not a statistical probability."
    )

    # --------------------------------------------------------
    # EMAIL DETAILS
    # --------------------------------------------------------

    add_heading("2. Email Information")

    email_info = {
        "Sender": safe_get(parsed, "sender"),
        "Recipient": safe_get(parsed, "recipient"),
        "Subject": safe_get(parsed, "subject"),
        "Date": safe_get(parsed, "date"),
        "URLs extracted": len(format_list(safe_get(parsed, "urls", []))),
        "Domains extracted": len(format_list(safe_get(parsed, "domains", []))),
        "IP addresses extracted": len(format_list(safe_get(parsed, "ip_addresses", [])))
    }

    rows = [
        [
            Paragraph("Field", styles["WhiteHeader"]),
            Paragraph("Value", styles["WhiteHeader"])
        ]
    ]

    for key, value in email_info.items():
        rows.append([
            Paragraph(clean_text(key), styles["BodyCustom"]),
            Paragraph(clean_text(value), styles["BodyCustom"])
        ])

    add_table(rows, [48 * mm, 126 * mm])

    # --------------------------------------------------------
    # CORRELATED EVIDENCE
    # --------------------------------------------------------

    add_heading("3. Correlated Security Evidence")

    evidence = format_list(
        safe_get(correlation, "evidence", [])
    )

    if evidence:

        rows = [[
            Paragraph("Evidence", styles["WhiteHeader"]),
            Paragraph("Description", styles["WhiteHeader"]),
            Paragraph("Source", styles["WhiteHeader"])
        ]]

        for item in evidence:

            if isinstance(item, dict):

                title = item.get(
                    "title",
                    item.get("name", "Evidence item")
                )

                description = item.get(
                    "description",
                    item.get("detail", "")
                )

                source = item.get(
                    "source",
                    "Analysis engine"
                )

            else:

                title = str(item)
                description = ""
                source = "Analysis engine"

            rows.append([
                Paragraph(clean_text(title), styles["BodyCustom"]),
                Paragraph(clean_text(description), styles["BodyCustom"]),
                Paragraph(clean_text(source), styles["BodyCustom"])
            ])

        add_table(rows, [42 * mm, 85 * mm, 47 * mm])

    else:
        add_body("No correlated evidence was returned.")

    # --------------------------------------------------------
    # CATEGORY SCORES
    # --------------------------------------------------------

    add_heading("4. Evidence Category Scores")

    category_scores = safe_get(
        correlation,
        "category_scores",
        {}
    )

    add_data_table(category_scores)

    # --------------------------------------------------------
    # RULE ENGINE
    # --------------------------------------------------------

    add_heading("5. Rule-Based Detection")

    add_data_table(rules)

    # --------------------------------------------------------
    # HEADER ANALYSIS
    # --------------------------------------------------------

    add_heading("6. Email Header Analysis")

    add_data_table(headers)

    # --------------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------------

    add_heading("7. URL and DNS Analysis")

    add_data_table(urls)

    # --------------------------------------------------------
    # VIRUSTOTAL
    # --------------------------------------------------------

    add_heading("8. Threat Intelligence - VirusTotal")

    add_data_table(vt)

    # --------------------------------------------------------
    # AI ANALYSIS
    # --------------------------------------------------------

    add_heading("9. Local AI Assessment")

    add_data_table(ai)

    # --------------------------------------------------------
    # ANALYST RECOMMENDATIONS
    # --------------------------------------------------------

    add_heading("10. Recommended Analyst Actions")

    recommendations = format_list(
        safe_get(ai, "recommended_actions", [])
    )

    if recommendations:

        for index, recommendation in enumerate(
            recommendations,
            start=1
        ):

            add_body(
                f"{index}. {recommendation}"
            )

    else:

        add_body(
            "No AI recommendations were returned. "
            "The analyst should validate the evidence and "
            "follow the organization's incident response procedure."
        )

    # --------------------------------------------------------
    # LIMITATIONS
    # --------------------------------------------------------

    add_heading("11. Investigation Limitations")

    limitations = format_list(
        safe_get(correlation, "limitations", [])
    )

    default_limitations = [
        "Automated verdicts are preliminary and require analyst validation.",
        "Email authentication results supplied in pasted headers are not independently verified.",
        "VirusTotal results may be incomplete or outdated.",
        "AI-generated conclusions are advisory and may contain errors.",
        "A zero-detection result does not prove an indicator is safe."
    ]

    for item in limitations or default_limitations:
        add_body(f"• {item}")

    # --------------------------------------------------------
    # PERFORMANCE
    # --------------------------------------------------------

    add_heading("12. Analysis Performance")

    add_data_table(timings)

    # --------------------------------------------------------
    # FOOTER / DISCLAIMER
    # --------------------------------------------------------

    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "<b>Disclaimer:</b> This report was generated by "
            "PHISHINTEL AI, an educational SOC investigation project. "
            "It is intended to assist security analysts and does not "
            "replace manual investigation, trusted security telemetry, "
            "or organizational incident response procedures.",
            styles["SmallCustom"]
        )
    )

    story.append(Spacer(1, 8))

    story.append(
        Paragraph(
            "PHISHINTEL AI | SECURITY INVESTIGATION REPORT",
            styles["SmallCustom"]
        )
    )

    # --------------------------------------------------------
    # PAGE NUMBER FOOTER
    # --------------------------------------------------------

    def add_page_number(canvas, doc):
        canvas.saveState()

        canvas.setStrokeColor(
            colors.HexColor("#D8E1EB")
        )

        canvas.line(
            18 * mm,
            14 * mm,
            A4[0] - 18 * mm,
            14 * mm
        )

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GREY)

        canvas.drawString(
            18 * mm,
            9 * mm,
            "PHISHINTEL AI | SOC Investigation"
        )

        canvas.drawRightString(
            A4[0] - 18 * mm,
            9 * mm,
            f"Page {doc.page}"
        )

        canvas.restoreState()

    # --------------------------------------------------------
    # BUILD PDF
    # --------------------------------------------------------

    document.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    pdf_bytes = buffer.getvalue()

    buffer.close()

    if output_path:
        with open(output_path, "wb") as file:
            file.write(pdf_bytes)

    return pdf_bytes
