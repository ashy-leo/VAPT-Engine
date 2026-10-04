"""
reporting/pdf_generator.py

Generates a professional, beginner-friendly PDF security assessment report
for VAPT-Engine using ReportLab. All data is pulled defensively from a
scan_results dict -- nothing here is faked or hardcoded.
"""

from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# ---- Color palette -----------------------------------------------------
NAVY = colors.HexColor("#1A365D")
DARK_GRAY = colors.HexColor("#2D3748")
LIGHT_GREEN = colors.HexColor("#DFF5E1")
GREEN_TEXT = colors.HexColor("#1E7E34")
LIGHT_RED = colors.HexColor("#FBE1E1")
RED_TEXT = colors.HexColor("#B02A2A")
LIGHT_ORANGE = colors.HexColor("#FDEBD3")
LIGHT_YELLOW = colors.HexColor("#FFF6D6")
BORDER_GRAY = colors.HexColor("#CBD5E0")

CRITICAL_HEADERS = {"strict-transport-security", "content-security-policy"}


def _styles():
    """Build and return the paragraph styles used throughout the report."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        textColor=NAVY,
        fontSize=20
    ))

    styles.add(ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        textColor=NAVY,
        spaceBefore=16,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        "Meta",
        parent=styles["Normal"],
        textColor=DARK_GRAY,
        fontSize=10
    ))

    styles.add(ParagraphStyle(
        "CellText",
        parent=styles["Normal"],
        fontSize=9,
        textColor=DARK_GRAY
    ))

    return styles


def _table_style(header_bg=NAVY, header_fg=colors.white):
    """Base grid/header style shared by all tables."""
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), header_fg),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_GRAY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ])


def _cell(text, styles):
    """
    Wrap a value in a Paragraph safely.

    Dynamic scanner output can contain HTML/XML characters such as:
    < > &
    ReportLab's Paragraph parser interprets these as markup, so the
    value must be escaped before being passed to Paragraph().
    """
    if text in (None, ""):
        text = "-"

    return Paragraph(
        escape(str(text)),
        styles["CellText"]
    )


def _text_cell(value, styles):
    """
    Safely wrap dynamic scanner output as plain text.

    True/False values are displayed as Yes/No.
    Escaping is handled by _cell().
    """
    if isinstance(value, bool):
        value = "Yes" if value else "No"

    return _cell(value, styles)


def _build_summary(scan_results, styles):
    """Executive summary table of key counts, pulled safely from scan_results."""
    open_ports = scan_results.get("open_ports", []) or []
    endpoints = scan_results.get("endpoints", []) or []
    headers_info = scan_results.get("http_headers", {}) or {}
    missing_headers = headers_info.get("missing", []) or []
    leak_headers = headers_info.get("present", {}) or {}

    rows = [
        ["Metric", "Count"],
        ["Open Ports", str(len(open_ports))],
        ["Discovered Endpoints", str(len(endpoints))],
        ["Missing Security Headers", str(len(missing_headers))],
        ["Information-Leakage Headers", str(len(leak_headers))],
    ]

    table = Table(rows, colWidths=[280, 100])
    table.setStyle(_table_style())

    return table


def _build_port_table(scan_results, styles):
    open_ports = scan_results.get("open_ports", []) or []

    if not open_ports:
        return Paragraph(
            "No open ports detected.",
            styles["CellText"]
        )

    rows = [["Port", "State", "Service", "Banner"]]

    for entry in open_ports:
        rows.append([
            _cell(entry.get("port"), styles),
            _cell(entry.get("state", "open"), styles),
            _cell(entry.get("service"), styles),
            _cell(entry.get("banner"), styles),
        ])

    table = Table(
        rows,
        colWidths=[50, 60, 100, 260]
    )

    style = _table_style()

    for i, entry in enumerate(open_ports, start=1):
        if str(entry.get("state", "")).lower() == "open":
            style.add(
                "BACKGROUND",
                (0, i),
                (-1, i),
                LIGHT_GREEN
            )

            style.add(
                "TEXTCOLOR",
                (1, i),
                (1, i),
                GREEN_TEXT
            )

    table.setStyle(style)

    return table


def _build_missing_headers_table(missing_headers, styles):
    if not missing_headers:
        return Paragraph(
            "No missing security headers reported.",
            styles["CellText"]
        )

    rows = [["Missing Header", "Recommendation"]]

    for header in missing_headers:
        name = (
            header.get("name")
            if isinstance(header, dict)
            else header
        )

        recommendation = (
            header.get("recommendation", "-")
            if isinstance(header, dict)
            else "-"
        )

        rows.append([
            _cell(name, styles),
            _cell(recommendation, styles)
        ])

    table = Table(
        rows,
        colWidths=[220, 260],
        repeatRows=1
    )

    style = _table_style()

    for i, header in enumerate(missing_headers, start=1):
        name = (
            header.get("name")
            if isinstance(header, dict)
            else header
        )

        if str(name).lower() in CRITICAL_HEADERS:
            style.add(
                "BACKGROUND",
                (0, i),
                (-1, i),
                LIGHT_RED
            )

            style.add(
                "TEXTCOLOR",
                (0, i),
                (0, i),
                RED_TEXT
            )
        else:
            style.add(
                "BACKGROUND",
                (0, i),
                (-1, i),
                LIGHT_ORANGE
            )

    table.setStyle(style)

    return table


def _build_present_headers_table(present_headers, styles):
    if not present_headers:
        return Paragraph(
            "No header information-leakage data available.",
            styles["CellText"]
        )

    rows = [["Header Name", "Value"]]

    for name, value in present_headers.items():
        rows.append([
            _cell(name, styles),
            _cell(value, styles)
        ])

    table = Table(
        rows,
        colWidths=[180, 300],
        repeatRows=1
    )

    table.setStyle(_table_style())

    return table


def _build_endpoint_table(scan_results, styles):
    endpoints = scan_results.get("endpoints", []) or []

    if not endpoints:
        return Paragraph(
            "No endpoints discovered.",
            styles["CellText"]
        )

    rows = [["Endpoint", "Status Code", "Full URL"]]

    for endpoint in endpoints:
        rows.append([
            _cell(endpoint.get("path"), styles),
            _cell(endpoint.get("status"), styles),
            _cell(endpoint.get("url"), styles)
        ])

    table = Table(
        rows,
        colWidths=[130, 70, 270],
        repeatRows=1
    )

    style = _table_style()

    for i, entry in enumerate(endpoints, start=1):
        status = str(entry.get("status", ""))

        if status.startswith("2"):
            style.add(
                "BACKGROUND",
                (1, i),
                (1, i),
                LIGHT_GREEN
            )

            style.add(
                "TEXTCOLOR",
                (1, i),
                (1, i),
                GREEN_TEXT
            )

        elif status in ("301", "302"):
            style.add(
                "BACKGROUND",
                (1, i),
                (1, i),
                LIGHT_YELLOW
            )

        elif status in ("401", "403"):
            style.add(
                "BACKGROUND",
                (1, i),
                (1, i),
                LIGHT_RED
            )

            style.add(
                "TEXTCOLOR",
                (1, i),
                (1, i),
                RED_TEXT
            )

    table.setStyle(style)

    return table


# ---- CORS, technologies, XSS, SQLi, open redirect ---------------------

def _build_cors_section(cors, styles):
    """CORS result from check_cors(): a simple Field / Value table."""

    if not cors:
        return [
            Paragraph(
                "No results available.",
                styles["CellText"]
            )
        ]

    vulnerable = bool(
        cors.get("potentially_vulnerable")
    )

    allow_origin = cors.get("allow_origin")

    rows = [["Field", "Value"]]

    rows.append([
        _cell("Tested URL", styles),
        _text_cell(cors.get("target"), styles)
    ])

    rows.append([
        _cell("Access-Control-Allow-Origin", styles),
        _text_cell(
            allow_origin
            if allow_origin is not None
            else "Not set",
            styles
        )
    ])

    rows.append([
        _cell("Header Missing", styles),
        _text_cell(cors.get("missing"), styles)
    ])

    rows.append([
        _cell("Origin Reflection", styles),
        _text_cell(cors.get("origin_reflection"), styles)
    ])

    rows.append([
        _cell("Potentially Vulnerable", styles),
        _text_cell(vulnerable, styles)
    ])

    table = Table(
        rows,
        colWidths=[180, 300],
        repeatRows=1
    )

    style = _table_style()
    last_row = len(rows) - 1

    if vulnerable:
        style.add(
            "BACKGROUND",
            (0, last_row),
            (-1, last_row),
            LIGHT_RED
        )

        style.add(
            "TEXTCOLOR",
            (1, last_row),
            (1, last_row),
            RED_TEXT
        )
    else:
        style.add(
            "BACKGROUND",
            (0, last_row),
            (-1, last_row),
            LIGHT_GREEN
        )

        style.add(
            "TEXTCOLOR",
            (1, last_row),
            (1, last_row),
            GREEN_TEXT
        )

    table.setStyle(style)

    return [table]


def _build_technology_section(tech, styles):
    """Technology result from detect_technologies(): technologies + headers."""

    if not tech:
        return [
            Paragraph(
                "No results available.",
                styles["CellText"]
            )
        ]

    target = escape(
        str(tech.get("target", "-"))
    )

    parts = [
        Paragraph(
            f"<b>Tested URL:</b> {target}",
            styles["Meta"]
        ),
        Spacer(1, 6)
    ]

    technologies = tech.get("technologies", []) or []

    parts.append(
        Paragraph(
            "Detected Technologies",
            styles["Meta"]
        )
    )

    if technologies:
        rows = [["Technology"]]

        for technology in technologies:
            rows.append([
                _text_cell(technology, styles)
            ])

        table = Table(
            rows,
            colWidths=[480],
            repeatRows=1
        )

        table.setStyle(_table_style())

        parts.append(table)

    else:
        parts.append(
            Paragraph(
                "No technologies detected.",
                styles["CellText"]
            )
        )

    found_headers = tech.get("headers", {}) or {}

    parts.append(Spacer(1, 10))

    parts.append(
        Paragraph(
            "Headers That Revealed Technology",
            styles["Meta"]
        )
    )

    if found_headers:
        rows = [["Header Name", "Value"]]

        for name, value in found_headers.items():
            rows.append([
                _text_cell(name, styles),
                _text_cell(value, styles)
            ])

        table = Table(
            rows,
            colWidths=[180, 300],
            repeatRows=1
        )

        table.setStyle(_table_style())

        parts.append(table)

    else:
        parts.append(
            Paragraph(
                "No technology-revealing headers found.",
                styles["CellText"]
            )
        )

    return parts


def _build_findings_table(
    findings,
    headers,
    keys,
    flag_key,
    styles
):
    """
    Table of findings for XSS / SQLi / redirect.

    headers = column titles
    keys = dictionary keys to read for each column
    flag_key = the True/False key that marks a row as a real finding
    """

    rows = [headers]

    for finding in findings:
        rows.append([
            _text_cell(
                finding.get(key),
                styles
            )
            for key in keys
        ])

    column_width = 480 / len(headers)

    table = Table(
        rows,
        colWidths=[column_width] * len(headers),
        repeatRows=1
    )

    style = _table_style()

    for i, finding in enumerate(findings, start=1):
        if finding.get(flag_key):
            style.add(
                "BACKGROUND",
                (0, i),
                (-1, i),
                LIGHT_RED
            )

            style.add(
                "TEXTCOLOR",
                (-1, i),
                (-1, i),
                RED_TEXT
            )

    table.setStyle(style)

    return table


def _build_param_test_section(
    result,
    headers,
    keys,
    flag_key,
    styles
):
    """
    Shared layout for the XSS, SQLi and redirect results.

    All three return:
    "target", "tested_parameters" and "findings".
    """

    if not result:
        return [
            Paragraph(
                "No results available.",
                styles["CellText"]
            )
        ]

    tested = result.get(
        "tested_parameters",
        []
    ) or []

    tested_text = (
        ", ".join(str(parameter) for parameter in tested)
        if tested
        else "None (no URL parameters found to test)"
    )

    target = escape(
        str(result.get("target", "-"))
    )

    tested_text = escape(
        tested_text
    )

    parts = [
        Paragraph(
            f"<b>Tested URL:</b> {target}",
            styles["Meta"]
        ),

        Paragraph(
            f"<b>Parameters Tested:</b> {tested_text}",
            styles["Meta"]
        ),
    ]

    # Only the XSS result has this extra key.
    vulnerable = result.get(
        "vulnerable_parameters"
    )

    if vulnerable:
        vulnerable_text = escape(
            ", ".join(
                str(parameter)
                for parameter in vulnerable
            )
        )

        parts.append(
            Paragraph(
                f"<b>Parameters That Reflected the Payload:</b> "
                f"{vulnerable_text}",
                styles["Meta"]
            )
        )

    parts.append(
        Spacer(1, 6)
    )

    findings = result.get(
        "findings",
        []
    ) or []

    if findings:
        parts.append(
            _build_findings_table(
                findings,
                headers,
                keys,
                flag_key,
                styles
            )
        )

    else:
        parts.append(
            Paragraph(
                "No findings detected.",
                styles["CellText"]
            )
        )

    return parts


def generate_pdf(
    scan_results: dict,
    output_filename: str = "vapt_report.pdf"
) -> str:
    """
    Build a VAPT-Engine PDF report from scan_results and write it to disk.

    scan_results is expected to loosely follow this shape:

        {
            "target": "192.168.1.10",
            "open_ports": [
                {
                    "port": 22,
                    "state": "open",
                    "service": "ssh",
                    "banner": "..."
                }
            ],
            "endpoints": [
                {
                    "path": "/admin",
                    "status": 403,
                    "url": "http://.../admin"
                }
            ],
            "http_headers": {
                "missing": [
                    {
                        "name": "Strict-Transport-Security",
                        "recommendation": "..."
                    }
                ],
                "present": {
                    "Server": "nginx/1.18.0"
                },
            },
            "cors": check_cors() result,
            "technologies": detect_technologies() result,
            "xss": check_xss() result,
            "sqli": check_sqli() result,
            "redirect": check_redirect() result,
        }

    Returns the path to the generated PDF file.
    """

    styles = _styles()

    doc = SimpleDocTemplate(
        output_filename,
        pagesize=letter,
        topMargin=40,
        bottomMargin=40
    )

    story = []

    # -- Header & metadata ----------------------------------------------

    target = scan_results.get(
        "target",
        "Unknown Target"
    )

    scan_time = scan_results.get(
        "scan_time",
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    story.append(
        Paragraph(
            "VAPT-Engine Security Assessment Report",
            styles["ReportTitle"]
        )
    )

    story.append(
        Spacer(1, 6)
    )

    # Escape dynamic target data while preserving the <b> markup
    # intentionally used by the report.
    story.append(
        Paragraph(
            f"<b>Target:</b> {escape(str(target))}",
            styles["Meta"]
        )
    )

    story.append(
        Paragraph(
            f"<b>Scan Date/Time:</b> "
            f"{escape(str(scan_time))}",
            styles["Meta"]
        )
    )

    story.append(
        Paragraph(
            "<b>Tool:</b> VAPT-Engine",
            styles["Meta"]
        )
    )

    story.append(
        Spacer(1, 8)
    )

    story.append(
        HRFlowable(
            width="100%",
            thickness=2,
            color=NAVY
        )
    )

    story.append(
        Spacer(1, 12)
    )

    # -- Executive summary ----------------------------------------------

    story.append(
        Paragraph(
            "Executive Summary",
            styles["SectionHeading"]
        )
    )

    story.append(
        _build_summary(
            scan_results,
            styles
        )
    )

    story.append(
        Spacer(1, 14)
    )

    # -- Section 1: Port scan -------------------------------------------

    story.append(
        Paragraph(
            "1. Port Scanning Results",
            styles["SectionHeading"]
        )
    )

    story.append(
        _build_port_table(
            scan_results,
            styles
        )
    )

    story.append(
        Spacer(1, 14)
    )

    # -- Section 2: HTTP security headers -------------------------------

    story.append(
        Paragraph(
            "2. HTTP Security Header Analysis",
            styles["SectionHeading"]
        )
    )

    http_headers = scan_results.get(
        "http_headers",
        {}
    ) or {}

    story.append(
        Paragraph(
            "Missing Security Headers",
            styles["Meta"]
        )
    )

    story.append(
        _build_missing_headers_table(
            http_headers.get("missing", []) or [],
            styles
        )
    )

    story.append(
        Spacer(1, 10)
    )

    story.append(
        Paragraph(
            "Present / Information-Leakage Headers",
            styles["Meta"]
        )
    )

    story.append(
        _build_present_headers_table(
            http_headers.get("present", {}) or {},
            styles
        )
    )

    story.append(
        Spacer(1, 14)
    )

    # -- Section 3: Endpoint discovery ---------------------------------

    story.append(
        Paragraph(
            "3. Discovered Web Endpoints",
            styles["SectionHeading"]
        )
    )

    story.append(
        _build_endpoint_table(
            scan_results,
            styles
        )
    )

    story.append(
        Spacer(1, 14)
    )

    # -- Section 4: CORS ------------------------------------------------

    story.append(
        Paragraph(
            "4. CORS Testing",
            styles["SectionHeading"]
        )
    )

    story.extend(
        _build_cors_section(
            scan_results.get("cors", {}) or {},
            styles
        )
    )

    story.append(
        Spacer(1, 14)
    )

    # -- Section 5: Technology detection -------------------------------

    story.append(
        Paragraph(
            "5. Technology Detection",
            styles["SectionHeading"]
        )
    )

    story.extend(
        _build_technology_section(
            scan_results.get("technologies", {}) or {},
            styles
        )
    )

    story.append(
        Spacer(1, 14)
    )

    # -- Section 6: XSS -------------------------------------------------

    story.append(
        Paragraph(
            "6. XSS Testing",
            styles["SectionHeading"]
        )
    )

    story.extend(
        _build_param_test_section(
            scan_results.get("xss", {}) or {},
            ["Parameter", "Payload", "Reflected"],
            ["parameter", "payload", "reflected"],
            "reflected",
            styles,
        )
    )

    story.append(
        Spacer(1, 14)
    )

    # -- Section 7: SQL injection --------------------------------------

    story.append(
        Paragraph(
            "7. SQL Injection Testing",
            styles["SectionHeading"]
        )
    )

    story.extend(
        _build_param_test_section(
            scan_results.get("sqli", {}) or {},
            ["Parameter", "Payload", "SQL Error Detected"],
            ["parameter", "payload", "sql_error_detected"],
            "sql_error_detected",
            styles,
        )
    )

    story.append(
        Spacer(1, 14)
    )

    # -- Section 8: Open redirect ---------------------------------------

    story.append(
        Paragraph(
            "8. Open Redirect Testing",
            styles["SectionHeading"]
        )
    )

    story.extend(
        _build_param_test_section(
            scan_results.get("redirect", {}) or {},
            [
                "Parameter",
                "Redirect Location",
                "Potential Open Redirect"
            ],
            [
                "parameter",
                "redirect_location",
                "potential_open_redirect"
            ],
            "potential_open_redirect",
            styles,
        )
    )

    # -- Generate PDF ---------------------------------------------------

    doc.build(story)

    return output_filename
