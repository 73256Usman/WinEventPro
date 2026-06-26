"""
WinEvent Pro — Report Generator
Produces PDF reports from scan sessions and threat alerts using fpdf2.
"""

import os
from datetime import datetime
from typing import List, Optional

from fpdf import FPDF, XPos, YPos

from threat_engine import ThreatAlert


# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------

DARK_BG        = (18,  18,  18)
HEADER_BG      = (26,  26,  46)
CRITICAL_CLR   = (220, 53,  53)
HIGH_CLR       = (220, 120, 40)
MEDIUM_CLR     = (220, 190, 40)
LOW_CLR        = (59,  130, 246)
INFO_CLR       = (100, 116, 139)
WHITE          = (255, 255, 255)
LIGHT_GRAY     = (220, 220, 220)
MID_GRAY       = (160, 160, 160)
DARK_GRAY      = (60,  60,  60)
ROW_ALT        = (240, 240, 245)
TEXT_DARK      = (30,  30,  30)

SEVERITY_COLORS = {
    "CRITICAL": CRITICAL_CLR,
    "HIGH":     HIGH_CLR,
    "MEDIUM":   MEDIUM_CLR,
    "LOW":      LOW_CLR,
    "INFO":     INFO_CLR,
}


# ---------------------------------------------------------------------------
# Text sanitizer
# ---------------------------------------------------------------------------

def _sanitize(text: str) -> str:
    """
    Make text safe for fpdf2's built-in Helvetica font, which uses Latin-1.
    Windows event descriptions frequently contain Unicode characters (em dashes,
    smart quotes, non-breaking spaces) that cause a UnicodeEncodeError when
    written to a PDF with a Latin-1 font.
    """
    if not text:
        return ""
    replacements = {
        "—": "-",    # em dash
        "–": "-",    # en dash
        "‘": "'",    # left single quote
        "’": "'",    # right single quote
        "“": '"',    # left double quote
        "”": '"',    # right double quote
        " ": " ",    # non-breaking space
        "•": "*",    # bullet point
        "…": "...",  # horizontal ellipsis
        "·": "*",    # middle dot
        "\r\n":   "\n",   # Windows line ending
        "\r":     "\n",   # old Mac line ending
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    # Final fallback: drop anything that still can't encode as Latin-1
    return text.encode("latin-1", errors="replace").decode("latin-1")


# ---------------------------------------------------------------------------
# PDF class
# ---------------------------------------------------------------------------

class ReportPDF(FPDF):

    def __init__(self, title: str = "WinEvent Pro — Threat Report"):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.report_title = title
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(15, 15, 15)

    # ── Header / footer ─────────────────────────────────────────────────────

    def header(self):
        self.set_fill_color(*HEADER_BG)
        self.rect(0, 0, 210, 22, "F")

        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*WHITE)
        self.set_xy(15, 5)
        self.cell(0, 12, _sanitize(self.report_title), align="L")

        self.set_font("Helvetica", "", 8)
        self.set_text_color(*LIGHT_GRAY)
        ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self.set_xy(0, 7)
        self.cell(195, 8, f"Generated: {ts}", align="R")

        self.ln(18)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*MID_GRAY)
        self.cell(0, 10, f"WinEvent Pro  |  Page {self.page_no()}", align="C")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def section_heading(self, text: str):
        self.ln(4)
        self.set_fill_color(*DARK_GRAY)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 8, f"  {_sanitize(text)}",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.ln(2)
        self.set_text_color(*TEXT_DARK)

    def key_value_row(self, key: str, value: str, alt: bool = False):
        fill_color = ROW_ALT if alt else WHITE
        self.set_fill_color(*fill_color)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*DARK_GRAY)
        self.cell(55, 7, _sanitize(key), fill=True)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*TEXT_DARK)
        self.cell(0, 7, _sanitize(str(value)),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)

    def severity_badge(self, severity: str, x: float, y: float,
                       w: float = 28, h: float = 6):
        color = SEVERITY_COLORS.get(severity.upper(), MID_GRAY)
        self.set_fill_color(*color)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 8)
        self.set_xy(x, y)
        self.cell(w, h, severity.upper(), align="C", fill=True)
        self.set_text_color(*TEXT_DARK)

    def stat_box(self, label: str, value: str, color: tuple,
                 x: float, y: float, w: float = 33):
        h = 20
        self.set_fill_color(*color)
        self.rect(x, y, w, h, "F")
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 14)
        self.set_xy(x, y + 2)
        self.cell(w, 8, _sanitize(str(value)), align="C")
        self.set_font("Helvetica", "", 7)
        self.set_xy(x, y + 11)
        self.cell(w, 6, _sanitize(label), align="C")
        self.set_text_color(*TEXT_DARK)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class ReportGenerator:

    def generate(
        self,
        alerts: List[ThreatAlert],
        session_info: dict,
        output_path: str,
    ) -> str:
        pdf = ReportPDF()
        pdf.add_page()

        self._summary_section(pdf, session_info, alerts)
        self._stats_section(pdf, alerts)

        if alerts:
            self._alerts_section(pdf, alerts)
        else:
            pdf.ln(6)
            pdf.set_font("Helvetica", "I", 10)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 10,
                     "No threats were detected in this scan session.",
                     align="C")

        pdf.output(output_path)
        return output_path

    # ── Sections ─────────────────────────────────────────────────────────────

    def _summary_section(self, pdf: ReportPDF, info: dict,
                         alerts: List[ThreatAlert]):
        pdf.section_heading("Scan Summary")

        hours = info.get("hours_back")
        time_window = f"Last {hours} hours" if hours else "Live Monitor Session"

        rows = [
            ("Scan Type",       info.get("scan_type", "N/A").title()),
            ("Channels",        info.get("channels", "N/A")),
            ("Time Window",     time_window),
            ("Started",         info.get("started_at", "N/A")),
            ("Ended",           info.get("ended_at") or "In progress"),
            ("Events Analysed", str(info.get("total_events", 0))),
            ("Threats Found",   str(len(alerts))),
        ]

        for i, (k, v) in enumerate(rows):
            pdf.key_value_row(k, v, alt=(i % 2 == 0))

    def _stats_section(self, pdf: ReportPDF, alerts: List[ThreatAlert]):
        pdf.section_heading("Threat Breakdown by Severity")

        counts = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
        for a in alerts:
            sev = a.severity.upper()
            if sev in counts:
                counts[sev] += 1

        boxes = [
            ("INFO",     str(counts["INFO"]),      INFO_CLR),
            ("LOW",      str(counts["LOW"]),       LOW_CLR),
            ("MEDIUM",   str(counts["MEDIUM"]),   MEDIUM_CLR),
            ("HIGH",     str(counts["HIGH"]),     HIGH_CLR),
            ("CRITICAL", str(counts["CRITICAL"]), CRITICAL_CLR),
        ]

        # Fit 5 boxes across the content area (210mm page - 15mm margins each side)
        n_boxes  = len(boxes)
        gap      = 3
        l_margin = 15
        box_w    = (210 - l_margin * 2 - (n_boxes - 1) * gap) // n_boxes  # 33mm
        y        = pdf.get_y() + 2

        for i, (label, value, color) in enumerate(boxes):
            x = l_margin + i * (box_w + gap)
            pdf.stat_box(label, value, color, x, y, box_w)

        pdf.ln(30)

    def _alerts_section(self, pdf: ReportPDF, alerts: List[ThreatAlert]):
        pdf.section_heading(f"Threat Alerts  ({len(alerts)} total)")

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        grouped: dict = {s: [] for s in severity_order}
        for alert in alerts:
            sev = alert.severity.upper()
            if sev in grouped:
                grouped[sev].append(alert)
            else:
                grouped["INFO"].append(alert)

        for severity in severity_order:
            group = grouped[severity]
            if not group:
                continue

            pdf.ln(3)
            color = SEVERITY_COLORS.get(severity, MID_GRAY)
            pdf.set_fill_color(*color)
            pdf.set_text_color(*WHITE)
            pdf.set_font("Helvetica", "B", 9)
            count_label = f"{len(group)} alert{'s' if len(group) != 1 else ''}"
            pdf.cell(
                0, 7,
                f"  {severity}  ({count_label})",
                new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True,
            )
            pdf.ln(1)

            for alert in group:
                self._alert_card(pdf, alert)

    def _alert_card(self, pdf: ReportPDF, alert: ThreatAlert):
        pdf.set_fill_color(*ROW_ALT)

        # Rule name
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*TEXT_DARK)
        pdf.cell(0, 6, _sanitize(alert.rule_name),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)

        # Meta row
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*DARK_GRAY)
        meta_parts = [
            f"Event ID: {alert.event_id}",
            f"Channel: {alert.channel}",
        ]
        if alert.computer:
            meta_parts.append(f"Computer: {_sanitize(alert.computer)}")
        if alert.user:
            meta_parts.append(f"User: {_sanitize(alert.user)}")
        meta_parts.append(
            f"Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        if alert.mitre:
            meta_parts.append(f"MITRE: {alert.mitre}")

        pdf.multi_cell(0, 5, "  |  ".join(meta_parts),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Description — sanitized to handle Windows event Unicode characters
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*TEXT_DARK)
        pdf.multi_cell(0, 5, _sanitize(alert.description))

        pdf.ln(3)
        pdf.set_draw_color(*LIGHT_GRAY)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(2)


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def generate_report(
    alerts: List[ThreatAlert],
    session_info: dict,
    output_dir: Optional[str] = None,
) -> str:
    """
    Generate a PDF report and return the full path to the saved file.
    If output_dir is None or empty, the report is saved to the user's Desktop.
    """
    if not output_dir:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop")

    os.makedirs(output_dir, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename    = f"WinEventPro_Report_{timestamp}.pdf"
    output_path = os.path.join(output_dir, filename)

    generator = ReportGenerator()
    return generator.generate(alerts, session_info, output_path)
