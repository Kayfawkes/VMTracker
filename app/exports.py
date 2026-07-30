"""Export engine: XLSX / CSV / PDF / PPTX for any filtered view.

Every exporter receives the same filter dict the console is showing, so what you
see on screen is exactly what lands in the file — including the filter set itself,
which is printed on the cover of every export for audit purposes.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
from typing import Any

from . import queries

SEV_COLOURS = {
    "Critical": "C62B3E", "High": "D9741F", "Medium": "C4A017",
    "Low": "2E7FB8", "Info": "5A6B7C",
}

EXPORT_COLUMNS = [
    ("id", "Finding ID"), ("hostname", "Hostname"), ("ip_address", "IP Address"),
    ("os_name", "Operating System"), ("department", "Department"),
    ("application", "Application / System"), ("system_owner", "System Owner"),
    ("owner_email", "Owner Email"), ("environment", "Environment"),
    ("criticality", "Asset Criticality"), ("location", "Location"),
    ("plugin_id", "Plugin / QID"), ("title", "Vulnerability"),
    ("category", "Type"), ("subcategory", "Sub-type"), ("cve", "CVE"),
    ("severity", "Severity"), ("cvss_score", "CVSS"), ("risk_score", "Risk Score"),
    ("exploit_available", "Exploitable"), ("port", "Port"), ("protocol", "Protocol"),
    ("service", "Service"), ("status", "Status"), ("first_detected", "First Detected"),
    ("last_detected", "Last Detected"), ("due_date", "Due Date"), ("sla_days", "SLA (days)"),
    ("age_days", "Age (days)"), ("sla_breached", "SLA Breached"),
    ("mitigated_date", "Mitigated"), ("closed_date", "Closed"),
    ("days_to_close", "Days to Close"), ("reopened_count", "Times Reopened"),
    ("remediation_owner", "Remediation Owner"), ("ticket_ref", "Ticket"),
    ("notes", "Notes"),
]


def filter_caption(f: dict[str, Any] | None) -> str:
    f = f or {}
    if not f:
        return "No filters — full data set"
    parts = []
    for key, val in f.items():
        if val in (None, "", []):
            continue
        label = key.replace("_", " ").title()
        parts.append(f"{label}: {', '.join(val) if isinstance(val, list) else val}")
    return " | ".join(parts) or "No filters — full data set"


def stamp() -> str:
    return dt.datetime.now().strftime("%d %b %Y %H:%M")


def _fname(prefix: str, ext: str) -> str:
    return f"{prefix}_{dt.datetime.now().strftime('%Y%m%d_%H%M')}.{ext}"


# ==========================================================================
# CSV
# ==========================================================================
def build_csv(rows: list[dict]) -> tuple[bytes, str, str]:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow([label for _k, label in EXPORT_COLUMNS])
    for r in rows:
        w.writerow([r.get(k, "") for k, _label in EXPORT_COLUMNS])
    return buf.getvalue().encode("utf-8-sig"), _fname("vulnerabilities", "csv"), "text/csv"


# ==========================================================================
# Excel
# ==========================================================================
def build_xlsx(rows: list[dict], data: dict, f: dict | None = None) -> tuple[bytes, str, str]:
    import xlsxwriter

    buf = io.BytesIO()
    wb = xlsxwriter.Workbook(buf, {"in_memory": True, "default_date_format": "yyyy-mm-dd"})
    base = {"font_name": "Arial", "font_size": 10}
    fmt = {
        "title": wb.add_format({**base, "font_size": 16, "bold": True, "font_color": "#12212F"}),
        "sub": wb.add_format({**base, "font_size": 9, "font_color": "#5A6B7C", "italic": True}),
        "head": wb.add_format({**base, "bold": True, "font_color": "#FFFFFF",
                               "bg_color": "#12212F", "border": 1, "border_color": "#2A3B4D",
                               "text_wrap": True, "valign": "vcenter"}),
        "cell": wb.add_format({**base, "border": 1, "border_color": "#D6DEE6"}),
        "num": wb.add_format({**base, "border": 1, "border_color": "#D6DEE6",
                              "num_format": "0.0"}),
        "int": wb.add_format({**base, "border": 1, "border_color": "#D6DEE6",
                              "num_format": "0"}),
        "kpi_label": wb.add_format({**base, "bold": True}),
        "kpi_value": wb.add_format({**base, "font_size": 14, "bold": True,
                                    "font_color": "#12212F"}),
        "breach": wb.add_format({**base, "border": 1, "border_color": "#D6DEE6",
                                 "bg_color": "#FDE7EA", "font_color": "#9B1C2C"}),
    }
    for sev, colour in SEV_COLOURS.items():
        fmt[f"sev_{sev}"] = wb.add_format({**base, "border": 1, "border_color": "#D6DEE6",
                                           "bold": True, "font_color": f"#{colour}"})

    # ---- Summary sheet
    ws = wb.add_worksheet("Summary")
    ws.set_column(0, 0, 30)
    ws.set_column(1, 8, 14)
    ws.write(0, 0, "Vulnerability Management Report", fmt["title"])
    ws.write(1, 0, f"Generated {stamp()}", fmt["sub"])
    ws.write(2, 0, f"Filters — {filter_caption(f)}", fmt["sub"])

    k = data.get("kpis", {})
    row = 4
    ws.write(row, 0, "Position", fmt["head"])
    ws.write(row, 1, "Value", fmt["head"])
    kpi_rows = [
        ("Open findings", k.get("open", 0)),
        ("Open critical", k.get("open_critical", 0)),
        ("Open high", k.get("open_high", 0)),
        ("Open past SLA", k.get("open_breached", 0)),
        ("SLA breach rate (%)", k.get("sla_breach_rate", 0)),
        ("Mean time to remediate (days)", k.get("mttr_days", 0)),
        ("Mitigated", k.get("mitigated", 0)),
        ("Closed", k.get("closed", 0)),
        ("Exploitable and open", k.get("open_exploitable", 0)),
        ("Affected hosts", k.get("affected_assets", 0)),
        ("Average age of open findings (days)", k.get("avg_open_age", 0)),
        ("Reporting period", f"{k.get('period', {}).get('from', '')} to "
                             f"{k.get('period', {}).get('to', '')}"),
    ]
    for i, (label, value) in enumerate(kpi_rows, start=row + 1):
        ws.write(i, 0, label, fmt["kpi_label"])
        ws.write(i, 1, value, fmt["kpi_value"])

    def table(sheet, start_row: int, heading: str, headers: list[str],
              body: list[list[Any]], col0_width: int = 26) -> int:
        sheet.write(start_row, 0, heading, fmt["title"])
        r = start_row + 1
        for c, h in enumerate(headers):
            sheet.write(r, c, h, fmt["head"])
        for line in body:
            r += 1
            for c, v in enumerate(line):
                style = fmt["cell"] if c == 0 or isinstance(v, str) else fmt["int"]
                sheet.write(r, c, v, style)
        sheet.set_column(0, 0, col0_width)
        return r + 2

    nxt = row + len(kpi_rows) + 3
    nxt = table(ws, nxt, "By severity",
                ["Severity", "Open", "Past SLA", "Avg age", "Exploitable"],
                [[s["severity"], s["n"], s["breached"], s["avg_age"], s["exploitable"]]
                 for s in data.get("severity", [])])
    nxt = table(ws, nxt, "SLA performance",
                ["Severity", "Target days", "Open", "Past SLA", "Remediated", "Late", "MTTR",
                 "Within SLA %"],
                [[s["severity"], s["target_days"], s["open"], s["open_breached"],
                  s["remediated"], s["remediated_late"], s["mttr"], s["within_sla_pct"]]
                 for s in data.get("sla", [])])
    nxt = table(ws, nxt, "By vulnerability type",
                ["Type", "Open", "Critical", "High", "Past SLA", "Avg age", "Closure %"],
                [[g["grp"], g["open"], g["critical"], g["high"], g["breached"], g["avg_age"],
                  g["closure_rate"]] for g in data.get("by_category", [])])
    nxt = table(ws, nxt, "By department",
                ["Department", "Open", "Critical", "High", "Past SLA", "MTTR", "Closure %"],
                [[g["grp"], g["open"], g["critical"], g["high"], g["breached"], g["mttr"],
                  g["closure_rate"]] for g in data.get("by_department", [])])
    table(ws, nxt, "Ageing profile",
          ["Bucket (days)", "Open", "Critical", "High", "Medium", "Low"],
          [[b["bucket"], b["n"], b.get("Critical", 0), b.get("High", 0), b.get("Medium", 0),
            b.get("Low", 0)] for b in data.get("aging", [])])

    # ---- Findings sheet
    fs = wb.add_worksheet("Findings")
    fs.freeze_panes(1, 0)
    for c, (_key, label) in enumerate(EXPORT_COLUMNS):
        fs.write(0, c, label, fmt["head"])
    widths = {"title": 52, "hostname": 26, "solution": 40, "notes": 30, "os_name": 24,
              "application": 22, "department": 20, "system_owner": 18, "owner_email": 24,
              "cve": 18, "subcategory": 20}
    for c, (key, _label) in enumerate(EXPORT_COLUMNS):
        fs.set_column(c, c, widths.get(key, 13))
    for i, r in enumerate(rows, start=1):
        for c, (key, _label) in enumerate(EXPORT_COLUMNS):
            v = r.get(key)
            if key == "severity":
                style = fmt.get(f"sev_{v}", fmt["cell"])
            elif key == "sla_breached" and v:
                style = fmt["breach"]
            elif isinstance(v, (int, float)) and v is not None:
                style = fmt["num"] if isinstance(v, float) else fmt["int"]
            else:
                style = fmt["cell"]
            if key in ("exploit_available", "sla_breached"):
                v = "Yes" if v else "No"
            fs.write(i, c, "" if v is None else v, style)
    fs.autofilter(0, 0, max(len(rows), 1), len(EXPORT_COLUMNS) - 1)

    # ---- Group sheets
    for label, key in [("By Department", "by_department"), ("By Application", "by_application"),
                       ("By Owner", "by_owner"), ("By Type", "by_category")]:
        grp = data.get(key)
        if not grp:
            continue
        gs = wb.add_worksheet(label[:31])
        headers = ["Group", "Open", "Critical", "High", "Medium", "Low", "Past SLA",
                   "Exploitable", "Avg age", "Max age", "MTTR", "Mitigated", "Closed",
                   "Closure %", "Hosts", "Risk"]
        for c, h in enumerate(headers):
            gs.write(0, c, h, fmt["head"])
        gs.set_column(0, 0, 28)
        gs.set_column(1, len(headers), 11)
        for i, g in enumerate(grp, start=1):
            vals = [g["grp"], g["open"], g["critical"], g["high"], g["medium"], g["low"],
                    g["breached"], g["exploitable"], g["avg_age"], g["max_age"], g["mttr"],
                    g["mitigated"], g["closed"], g["closure_rate"], g["assets"], g["risk"]]
            for c, v in enumerate(vals):
                gs.write(i, c, v if v is not None else 0,
                         fmt["cell"] if c == 0 else fmt["int"])
        gs.freeze_panes(1, 1)

    wb.close()
    return (buf.getvalue(), _fname("vm_report", "xlsx"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


# ==========================================================================
# PDF
# ==========================================================================
def build_pdf(rows: list[dict], data: dict, f: dict | None = None,
              title: str = "Vulnerability Management Report",
              include_detail: bool = True) -> tuple[bytes, str, str]:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=14 * mm,
                            rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=12 * mm,
                            title=title)
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=19,
                        alignment=0, textColor=colors.HexColor("#12212F"), spaceAfter=2)
    meta = ParagraphStyle("meta", parent=ss["Normal"], fontName="Helvetica", fontSize=8,
                          textColor=colors.HexColor("#5A6B7C"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=12,
                        textColor=colors.HexColor("#12212F"), spaceBefore=10, spaceAfter=4)
    cell = ParagraphStyle("cell", parent=ss["Normal"], fontName="Helvetica", fontSize=7,
                          leading=8.5)

    story: list[Any] = [Paragraph(title, h1),
                        Paragraph(f"Generated {stamp()}", meta),
                        Paragraph(f"Filters — {filter_caption(f)}", meta), Spacer(1, 8)]

    k = data.get("kpis", {})
    tiles = [
        ("OPEN", k.get("open", 0)), ("CRITICAL", k.get("open_critical", 0)),
        ("HIGH", k.get("open_high", 0)), ("PAST SLA", k.get("open_breached", 0)),
        ("BREACH RATE", f"{k.get('sla_breach_rate', 0)}%"),
        ("MTTR", f"{k.get('mttr_days', 0)}d"),
        ("MITIGATED", k.get("mitigated", 0)), ("CLOSED", k.get("closed", 0)),
        ("EXPLOITABLE", k.get("open_exploitable", 0)), ("HOSTS", k.get("affected_assets", 0)),
    ]
    kpi_table = Table([[t[0] for t in tiles], [str(t[1]) for t in tiles]],
                      colWidths=[26.5 * mm] * len(tiles))
    kpi_table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, 0), "Helvetica", 6.5),
        ("FONT", (0, 1), (-1, 1), "Helvetica-Bold", 15),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#5A6B7C")),
        ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#12212F")),
        ("TEXTCOLOR", (1, 1), (1, 1), colors.HexColor("#C62B3E")),
        ("TEXTCOLOR", (3, 1), (4, 1), colors.HexColor("#C62B3E")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, 0), 6), ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#C3CDD8")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E1E7ED")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2F5F8")),
    ]))
    story += [kpi_table, Spacer(1, 4)]

    def grid(headers: list[str], body: list[list[Any]], widths: list[float],
             highlight_col: int | None = None) -> Table:
        t = Table([headers] + [[str(x) if x is not None else "0" for x in r] for r in body],
                  colWidths=widths, repeatRows=1)
        style = [
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 7),
            ("FONT", (0, 1), (-1, -1), "Helvetica", 7),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12212F")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D6DEE6")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 1), (-1, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F9FB")]),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]
        if highlight_col is not None:
            style.append(("TEXTCOLOR", (highlight_col, 1), (highlight_col, -1),
                          colors.HexColor("#C62B3E")))
        t.setStyle(TableStyle(style))
        return t

    story += [Paragraph("SLA performance against configured targets", h2),
              grid(["Severity", "Target (days)", "Open", "Past SLA", "Remediated", "Late",
                    "MTTR (days)", "Within SLA %"],
                   [[s["severity"], s["target_days"], s["open"], s["open_breached"],
                     s["remediated"], s["remediated_late"], s["mttr"], s["within_sla_pct"]]
                    for s in data.get("sla", [])],
                   [34 * mm] + [24 * mm] * 7, highlight_col=3)]

    story += [Paragraph("Open findings by vulnerability type", h2),
              grid(["Type", "Open", "Critical", "High", "Medium", "Low", "Past SLA",
                    "Exploitable", "Avg age", "Closure %"],
                   [[g["grp"], g["open"], g["critical"], g["high"], g["medium"], g["low"],
                     g["breached"], g["exploitable"], g["avg_age"], g["closure_rate"]]
                    for g in data.get("by_category", [])],
                   [46 * mm] + [22 * mm] * 9, highlight_col=2)]

    story += [Paragraph("Open findings by department", h2),
              grid(["Department", "Open", "Critical", "High", "Past SLA", "MTTR", "Hosts",
                    "Closure %"],
                   [[g["grp"], g["open"], g["critical"], g["high"], g["breached"], g["mttr"],
                     g["assets"], g["closure_rate"]]
                    for g in data.get("by_department", [])[:12]],
                   [56 * mm] + [24 * mm] * 7, highlight_col=2)]

    top = data.get("top_vulnerabilities", [])
    if top:
        story += [PageBreak(), Paragraph("Most widespread open vulnerabilities", h2),
                  grid(["Vulnerability", "Severity", "Type", "Hosts", "Instances", "Avg age"],
                       [[Paragraph(str(v["title"])[:110], cell), v["severity"], v["category"],
                         v["assets"], v["instances"], v["avg_age"]] for v in top],
                       [118 * mm, 22 * mm, 30 * mm, 20 * mm, 22 * mm, 22 * mm])]

    if include_detail and rows:
        detail_cols = [("hostname", "Host", 40), ("title", "Vulnerability", 78),
                       ("category", "Type", 24), ("severity", "Sev", 15),
                       ("status", "Status", 20), ("department", "Department", 28),
                       ("application", "Application", 28), ("system_owner", "Owner", 24),
                       ("age_days", "Age", 12), ("due_date", "Due", 20)]
        story += [PageBreak(), Paragraph(f"Findings detail ({len(rows)} rows)", h2)]
        body = [[Paragraph(str(r.get(key, "") or ""), cell) if key in ("title", "hostname")
                 else str(r.get(key, "") or "") for key, _l, _w in detail_cols] for r in rows]
        story += [grid([lbl for _k, lbl, _w in detail_cols], body,
                       [w * mm for _k, _l, w in detail_cols])]

    doc.build(story)
    return buf.getvalue(), _fname("vm_report", "pdf"), "application/pdf"


# ==========================================================================
# PowerPoint
# ==========================================================================
def build_pptx(rows: list[dict], data: dict, f: dict | None = None,
               title: str = "Vulnerability Management Review") -> tuple[bytes, str, str]:
    from pptx import Presentation
    from pptx.dml.color import RGBColor
    from pptx.util import Emu, Inches, Pt

    INK = RGBColor(0x12, 0x21, 0x2F)
    MUTED = RGBColor(0x5A, 0x6B, 0x7C)
    RED = RGBColor(0xC6, 0x2B, 0x3E)
    PANEL = RGBColor(0xF2, 0xF5, 0xF8)

    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
    blank = prs.slide_layouts[6]

    def add_slide(heading: str, sub: str = ""):
        s = prs.slides.add_slide(blank)
        box = s.shapes.add_textbox(Inches(0.55), Inches(0.35), Inches(12.2), Inches(0.8))
        p = box.text_frame.paragraphs[0]
        p.text = heading
        p.font.size, p.font.bold, p.font.color.rgb = Pt(28), True, INK
        if sub:
            sp = box.text_frame.add_paragraph()
            sp.text = sub
            sp.font.size, sp.font.color.rgb = Pt(11), MUTED
        return s

    def add_table(slide, headers, body, left, top, width, height, col_widths=None):
        shape = slide.shapes.add_table(len(body) + 1, len(headers), left, top, width, height)
        tbl = shape.table
        if col_widths:
            total = sum(col_widths)
            for i, w in enumerate(col_widths):
                tbl.columns[i].width = Emu(int(width * w / total))
        for c, h in enumerate(headers):
            cell = tbl.cell(0, c)
            cell.text = str(h)
            para = cell.text_frame.paragraphs[0]
            para.font.size, para.font.bold = Pt(11), True
            para.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            cell.fill.solid()
            cell.fill.fore_color.rgb = INK
        for r, line in enumerate(body, start=1):
            for c, v in enumerate(line):
                cell = tbl.cell(r, c)
                cell.text = "" if v is None else str(v)
                para = cell.text_frame.paragraphs[0]
                para.font.size = Pt(10.5)
                para.font.color.rgb = INK
        return tbl

    k = data.get("kpis", {})
    period = k.get("period", {})

    # 1. Cover
    s = prs.slides.add_slide(blank)
    band = s.shapes.add_shape(1, Inches(0), Inches(0), prs.slide_width, Inches(2.6))
    band.fill.solid()
    band.fill.fore_color.rgb = INK
    band.line.fill.background()
    tb = s.shapes.add_textbox(Inches(0.7), Inches(0.75), Inches(11.9), Inches(1.6))
    p = tb.text_frame.paragraphs[0]
    p.text = title
    p.font.size, p.font.bold, p.font.color.rgb = Pt(40), True, RGBColor(0xFF, 0xFF, 0xFF)
    p2 = tb.text_frame.add_paragraph()
    p2.text = f"Reporting period {period.get('from', '')} to {period.get('to', '')}"
    p2.font.size, p2.font.color.rgb = Pt(14), RGBColor(0xB8, 0xC6, 0xD4)
    tb2 = s.shapes.add_textbox(Inches(0.7), Inches(3.1), Inches(11.9), Inches(1.0))
    p3 = tb2.text_frame.paragraphs[0]
    p3.text = f"{k.get('open', 0)} open findings — {k.get('open_critical', 0)} critical, " \
              f"{k.get('open_high', 0)} high"
    p3.font.size, p3.font.bold, p3.font.color.rgb = Pt(22), True, INK
    p4 = tb2.text_frame.add_paragraph()
    p4.text = f"Generated {stamp()}  |  Filters — {filter_caption(f)}"
    p4.font.size, p4.font.color.rgb = Pt(10), MUTED

    # 2. KPI tiles
    s = add_slide("Position at a glance", f"Period {period.get('from','')} to {period.get('to','')}")
    tiles = [("Open findings", k.get("open", 0), False),
             ("Critical open", k.get("open_critical", 0), True),
             ("High open", k.get("open_high", 0), True),
             ("Past SLA", k.get("open_breached", 0), True),
             ("SLA breach rate", f"{k.get('sla_breach_rate', 0)}%", True),
             ("Mean time to remediate", f"{k.get('mttr_days', 0)} d", False),
             ("Remediated in period", k.get("remediated_in_period", 0), False),
             ("New in period", k.get("new_in_period", 0), False),
             ("Exploitable and open", k.get("open_exploitable", 0), True),
             ("Hosts affected", k.get("affected_assets", 0), False)]
    for i, (label, value, alarm) in enumerate(tiles):
        col, row = i % 5, i // 5
        left, top = Inches(0.55 + col * 2.5), Inches(1.5 + row * 1.85)
        box = s.shapes.add_shape(1, left, top, Inches(2.3), Inches(1.55))
        box.fill.solid()
        box.fill.fore_color.rgb = PANEL
        box.line.color.rgb = RGBColor(0xC3, 0xCD, 0xD8)
        tf = box.text_frame
        tf.margin_left = tf.margin_right = Inches(0.14)
        vp = tf.paragraphs[0]
        vp.text = str(value)
        vp.font.size, vp.font.bold = Pt(30), True
        vp.font.color.rgb = RED if alarm else INK
        lp = tf.add_paragraph()
        lp.text = label
        lp.font.size, lp.font.color.rgb = Pt(10.5), MUTED

    # 3. Severity + SLA
    s = add_slide("Severity profile and SLA performance")
    add_table(s, ["Severity", "Open", "Past SLA", "Avg age", "Exploitable"],
              [[x["severity"], x["n"], x["breached"], x["avg_age"], x["exploitable"]]
               for x in data.get("severity", [])],
              Inches(0.55), Inches(1.5), Inches(5.7), Inches(2.6))
    add_table(s, ["Severity", "Target", "Open", "Late", "MTTR", "Within SLA"],
              [[x["severity"], f"{x['target_days']}d", x["open"], x["remediated_late"],
                x["mttr"], f"{x['within_sla_pct']}%"] for x in data.get("sla", [])],
              Inches(6.6), Inches(1.5), Inches(6.2), Inches(2.6))

    # 4. Trend
    trend = data.get("trend", [])
    if trend:
        s = add_slide("Risk and open-finding trend",
                      "Total risk score and open volume over the period")
        chart = _pptx_line_chart(s, trend, Inches(0.55), Inches(1.5), Inches(12.2), Inches(5.2))
        del chart

    # 5. Departments
    s = add_slide("Ownership: open findings by department")
    add_table(s, ["Department", "Open", "Critical", "High", "Past SLA", "MTTR", "Hosts",
                  "Closure %"],
              [[g["grp"], g["open"], g["critical"], g["high"], g["breached"], g["mttr"],
                g["assets"], f"{g['closure_rate']}%"]
               for g in data.get("by_department", [])[:10]],
              Inches(0.55), Inches(1.5), Inches(12.2), Inches(4.6),
              col_widths=[3.2, 1, 1, 1, 1.1, 1, 1, 1.2])

    # 6. Applications
    s = add_slide("Ownership: open findings by application / system")
    add_table(s, ["Application", "Open", "Critical", "High", "Past SLA", "Avg age", "Hosts"],
              [[g["grp"], g["open"], g["critical"], g["high"], g["breached"], g["avg_age"],
                g["assets"]] for g in data.get("by_application", [])[:10]],
              Inches(0.55), Inches(1.5), Inches(12.2), Inches(4.6),
              col_widths=[3.4, 1, 1, 1, 1.1, 1.1, 1])

    # 7. Type mix
    s = add_slide("Vulnerability type mix", "Classified by the built-in detection engine")
    add_table(s, ["Type", "Open", "Critical", "High", "Medium", "Low", "Past SLA", "Avg age"],
              [[g["grp"], g["open"], g["critical"], g["high"], g["medium"], g["low"],
                g["breached"], g["avg_age"]] for g in data.get("by_category", [])],
              Inches(0.55), Inches(1.5), Inches(12.2), Inches(4.6),
              col_widths=[3.0, 1, 1, 1, 1, 1, 1.1, 1.1])

    # 8. Top vulnerabilities
    top = data.get("top_vulnerabilities", [])
    if top:
        s = add_slide("Most widespread open vulnerabilities")
        add_table(s, ["Vulnerability", "Severity", "Type", "Hosts", "Instances", "Avg age"],
                  [[str(v["title"])[:80], v["severity"], v["category"], v["assets"],
                    v["instances"], v["avg_age"]] for v in top[:10]],
                  Inches(0.55), Inches(1.4), Inches(12.2), Inches(4.9),
                  col_widths=[6.0, 1.2, 1.6, 1, 1.2, 1.1])

    # 9. Ageing
    s = add_slide("Ageing profile of open findings")
    add_table(s, ["Age bucket (days)", "Open", "Critical", "High", "Medium", "Low"],
              [[b["bucket"], b["n"], b.get("Critical", 0), b.get("High", 0),
                b.get("Medium", 0), b.get("Low", 0)] for b in data.get("aging", [])],
              Inches(0.55), Inches(1.5), Inches(9.0), Inches(2.8))

    buf = io.BytesIO()
    prs.save(buf)
    return (buf.getvalue(), _fname("vm_review", "pptx"),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation")


def _pptx_line_chart(slide, trend: list[dict], left, top, width, height):
    from pptx.chart.data import CategoryChartData
    from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION

    cd = CategoryChartData()
    cd.categories = [t["date"][5:] for t in trend]
    cd.add_series("Open findings", [t["open"] for t in trend])
    cd.add_series("Critical", [t["critical"] for t in trend])
    cd.add_series("Total risk score", [t["total_risk"] for t in trend])
    gframe = slide.shapes.add_chart(XL_CHART_TYPE.LINE_MARKERS, left, top, width, height, cd)
    chart = gframe.chart
    chart.has_legend = True
    chart.legend.position = XL_LEGEND_POSITION.BOTTOM
    chart.legend.include_in_layout = False
    return chart


# ==========================================================================
# Dispatcher
# ==========================================================================
def export(fmt: str, filters: dict | None, scope: str = "executive",
           include_detail: bool = True, conn=None) -> tuple[bytes, str, str]:
    fmt = (fmt or "").lower()
    rows = queries.findings_all(filters, conn=conn) if fmt in ("csv", "xlsx") or include_detail \
        else []
    if fmt == "csv":
        return build_csv(rows)
    data = queries.executive(filters, conn=conn)
    if scope.startswith("group:"):
        dim = scope.split(":", 1)[1]
        data["by_category"] = queries.group_summary(dim, filters, conn=conn)
    if fmt == "xlsx":
        return build_xlsx(rows, data, filters)
    if fmt == "pdf":
        return build_pdf(rows, data, filters, include_detail=include_detail)
    if fmt == "pptx":
        return build_pptx(rows, data, filters)
    raise ValueError(f"unsupported export format '{fmt}' (use csv, xlsx, pdf or pptx)")
