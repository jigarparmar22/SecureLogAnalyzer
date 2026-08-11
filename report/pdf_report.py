from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


def generate_pdf(events, threats, output_path):

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["BodyText"]

    content = []

    # -------------------------------------------------
    # TITLE
    # -------------------------------------------------

    content.append(
        Paragraph(
            "Secure Log Analyzer - Security Report",
            title_style
        )
    )

    content.append(Spacer(1, 10))

    content.append(
        Paragraph(
            "Windows Security Event Analysis Report",
            normal_style
        )
    )

    content.append(Spacer(1, 15))

    # -------------------------------------------------
    # SUMMARY
    # -------------------------------------------------

    total_events = len(events)
    total_threats = len(threats)

    critical_count = sum(
        1 for threat in threats
        if threat["severity"] == "Critical"
    )

    high_count = sum(
        1 for threat in threats
        if threat["severity"] == "High"
    )

    medium_count = sum(
        1 for threat in threats
        if threat["severity"] == "Medium"
    )

    low_count = sum(
        1 for threat in threats
        if threat["severity"] == "Low"
    )

    content.append(
        Paragraph("Analysis Summary", heading_style)
    )

    summary_data = [
        ["Metric", "Value"],
        ["Total Events", str(total_events)],
        ["Total Threats", str(total_threats)],
        ["Critical Threats", str(critical_count)],
        ["High Threats", str(high_count)],
        ["Medium Threats", str(medium_count)],
        ["Low Threats", str(low_count)]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[80 * mm, 80 * mm]
    )

    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 6),
        ])
    )

    content.append(summary_table)

    content.append(Spacer(1, 20))

    # -------------------------------------------------
    # THREAT DETAILS
    # -------------------------------------------------

    content.append(
        Paragraph(
            "Detected Security Threats",
            heading_style
        )
    )

    if threats:

        threat_data = [
            [
                "Event ID",
                "Threat",
                "Severity",
                "Level",
                "Computer"
            ]
        ]

        for threat in threats:

            threat_data.append([
             str(threat.get("event_id", "N/A")),
            str(threat.get("threat", "N/A")),
             str(threat.get("severity", "N/A")),
            str(threat.get("level", "N/A")),
            str(threat.get("computer", "N/A"))
])

        threat_table = Table(
            threat_data,
            repeatRows=1,
            colWidths=[
                20 * mm,
                50 * mm,
                25 * mm,
                30 * mm,
                45 * mm
            ]
        )

        threat_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.black),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        content.append(threat_table)

    else:

        content.append(
            Paragraph(
                "No known security threats were detected.",
                normal_style
            )
        )

    content.append(Spacer(1, 20))

    # -------------------------------------------------
    # EVENT DETAILS
    # -------------------------------------------------

    content.append(
        Paragraph(
            "Parsed Windows Security Events",
            heading_style
        )
    )

    if events:

        event_data = [
            [
                "Event ID",
                "Level",
                "Time",
                "Provider",
                "Computer"
            ]
        ]

        # Limit report to first 500 events for now
        for event in events[:500]:

                event_data.append([
    str(event["event_id"]),
    str(event["level"]),
    str(event["time"]),
    str(event["provider"]),
    str(event["computer"])
])

        event_table = Table(
            event_data,
            repeatRows=1,
            colWidths=[
                20 * mm,
                25 * mm,
                45 * mm,
                45 * mm,
                40 * mm
            ]
        )

        event_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        content.append(event_table)

    # -------------------------------------------------
    # BUILD PDF
    # -------------------------------------------------

    document.build(content)