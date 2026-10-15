"""Self-contained reportlab style helpers for the IR 1 Task 1 PDF.
Matches the Care Access Navigator house style (Letter, Helvetica, navy headings,
amber step badges, cream note boxes) used by the Compliance 1 / Cloud Security packages."""
import os, textwrap
from html import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (CondPageBreak, KeepTogether, PageBreak, Paragraph, Preformatted,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

NAVY = colors.HexColor("#1B2A4A"); AMBER = colors.HexColor("#E8A33D")
CREAM = colors.HexColor("#FFF4DE"); BROWN = colors.HexColor("#5C4200")
GREY_BG = colors.HexColor("#F3F4F6"); GREY_LINE = colors.HexColor("#CCCCCC")
TEXT = colors.HexColor("#444444"); MUTED = colors.HexColor("#555555")
GREEN = colors.HexColor("#1E7B45"); RED = colors.HexColor("#A3271F")
FULL_W = 6.5 * inch
fig_no = [0]

ss = {
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=22, leading=27, textColor=NAVY),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=NAVY),
    "subsub": ParagraphStyle("subsub", fontName="Helvetica-Oblique", fontSize=10.5, leading=14, textColor=MUTED),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=NAVY, spaceBefore=6, spaceAfter=6),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=NAVY, spaceBefore=2, spaceAfter=4),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10, leading=14, textColor=TEXT, spaceAfter=6, alignment=TA_LEFT),
    "bullet": ParagraphStyle("bullet", fontName="Helvetica", fontSize=10, leading=14, textColor=TEXT, leftIndent=14, bulletIndent=4, spaceAfter=2),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=9, leading=11.5, textColor=TEXT),
    "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=9, leading=11.5, textColor=NAVY),
    "cellh": ParagraphStyle("cellh", fontName="Helvetica-Bold", fontSize=9, leading=11.5, textColor=colors.white),
    "caption": ParagraphStyle("caption", fontName="Helvetica-Oblique", fontSize=9, leading=12, textColor=MUTED, spaceBefore=3, spaceAfter=10),
    "note": ParagraphStyle("note", fontName="Helvetica", fontSize=9.3, leading=13, textColor=BROWN),
    "badge": ParagraphStyle("badge", fontName="Helvetica-Bold", fontSize=9, leading=11, textColor=colors.white),
    "code": ParagraphStyle("code", fontName="Courier", fontSize=7.3, leading=9.0, textColor=colors.HexColor("#1F2933")),
}


def P(text, style="body"):
    return Paragraph(text, ss[style])


def bullets(items):
    return [Paragraph(t, ss["bullet"], bulletText="•") for t in items]


def note(text, label="Note"):
    t = Table([[Paragraph(f"<b>{label}:</b> {text}", ss["note"])]], colWidths=[FULL_W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), CREAM), ("LINEBEFORE", (0, 0), (0, -1), 3, AMBER),
                           ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                           ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    return [t, Spacer(1, 8)]


def step(num, title, prefix="STEP "):
    label = f"{prefix}{num}"
    bw = max(0.8 * inch, (len(label) * 5.6 + 14))
    badge = Table([[Paragraph(label, ss["badge"])]], colWidths=[bw])
    badge.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), AMBER), ("LEFTPADDING", (0, 0), (-1, -1), 6),
                               ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    row = Table([[badge, Paragraph(title, ss["h2"])]], colWidths=[bw + 0.15 * inch, FULL_W - bw - 0.15 * inch])
    row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    return [CondPageBreak(2.0 * inch), Spacer(1, 6), row, Spacer(1, 4)]


def code(text, title=None, width=104):
    lines = []
    for line in text.expandtabs(4).rstrip("\n").splitlines():
        line = "".join(ch for ch in line if ch == " " or ch.isprintable())
        if len(line) <= width:
            lines.append(line)
        else:
            lines += textwrap.wrap(line, width, subsequent_indent="    ", break_long_words=True,
                                   break_on_hyphens=False, drop_whitespace=False)
    pre = Preformatted("\n".join(lines) or " ", ss["code"])
    t = Table([[pre]], colWidths=[FULL_W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), GREY_BG), ("BOX", (0, 0), (-1, -1), 0.5, GREY_LINE),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    block = [t]
    if title:
        block.insert(0, Paragraph(f"<font name='Helvetica-Bold' size=8.5 color='#1B2A4A'>{escape(title)}</font>", ss["body"]))
    if len(lines) < 42:
        return [KeepTogether(block), Spacer(1, 8)]
    return block + [Spacer(1, 8)]


def table(rows, widths, header=True, zebra=True):
    data = []
    for r_i, row in enumerate(rows):
        sstyle = "cellh" if header and r_i == 0 else "cell"
        data.append([c if not isinstance(c, str) else Paragraph(c, ss[sstyle]) for c in row])
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    cmds = [("GRID", (0, 0), (-1, -1), 0.5, GREY_LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    if header:
        cmds.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if (i % 2 == 0) == header:
                cmds.append(("BACKGROUND", (0, i), (-1, i), GREY_BG))
    t.setStyle(TableStyle(cmds))
    return [t, Spacer(1, 10)]


def kv(rows):
    data = [[Paragraph(k, ss["cellb"]), Paragraph(v, ss["cell"])] for k, v in rows]
    t = Table(data, colWidths=[1.55 * inch, FULL_W - 1.55 * inch])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, GREY_LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                           ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    return [t, Spacer(1, 12)]


def ok(t="PASS"):
    return f"<font color='#1E7B45'><b>{t}</b></font>"


def bad(t="FAIL"):
    return f"<font color='#A3271F'><b>{t}</b></font>"


def footer_for(title):
    def _f(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8); canvas.setFillColor(MUTED)
        canvas.drawString(inch, 0.55 * inch, title)
        canvas.drawRightString(letter[0] - inch, 0.55 * inch, f"Page {doc.page}")
        canvas.setStrokeColor(GREY_LINE); canvas.line(inch, 0.7 * inch, letter[0] - inch, 0.7 * inch)
        canvas.restoreState()
    return _f


def build(path, story, title, footer_text):
    doc = SimpleDocTemplate(path, pagesize=letter, leftMargin=inch, rightMargin=inch, topMargin=0.85 * inch,
                            bottomMargin=0.95 * inch, title=title, author="Akhila Chennamaneni")
    f = footer_for(footer_text)
    doc.build(story, onFirstPage=f, onLaterPages=f)
    print("wrote", path)
