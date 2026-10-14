"""(Copied style helpers from cloud_security_1/pdf-build) Build the CloudSec1 'Cloud Infrastructure Security & Container Protection' evidence PDF.

Matches the style of the Criterion 4 IAM evidence package (Letter, Helvetica,
navy #1B2A4A headings, amber step badges, cream note boxes).
Optional screenshots (see optional_shot calls) are embedded when saved into
cloud_security_1/ under the expected filename; otherwise the section relies on
the captured command output alone. The helpers above the '# ---- Cover' marker
are reused by build_c4_addendum.py.
"""
import os
import textwrap
from html import escape

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (CondPageBreak, Image, KeepTogether, PageBreak, Paragraph, Preformatted,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

SCRATCH = os.path.dirname(os.path.abspath(__file__))          # compliance_1/pdf-build
DATA = os.path.join(SCRATCH, "data")
IMG = os.path.join(SCRATCH, ".cache")                        # downscaled screenshots (regenerated)
SHOTS = os.path.dirname(SCRATCH)                             # cloud_security_1
REPO = SHOTS                                                 # project folders live in cloud_security_1/
os.makedirs(IMG, exist_ok=True)
OUT = os.path.join(SHOTS, "Care_Access_Navigator_CloudSec1_Criterion_3_Infrastructure_Container_Security.pdf")

NAVY = colors.HexColor("#1B2A4A")
AMBER = colors.HexColor("#E8A33D")
CREAM = colors.HexColor("#FFF4DE")
BROWN = colors.HexColor("#5C4200")
GREY_BG = colors.HexColor("#F3F4F6")
GREY_LINE = colors.HexColor("#CCCCCC")
TEXT = colors.HexColor("#444444")
MUTED = colors.HexColor("#555555")
GREEN = colors.HexColor("#1E7B45")
RED = colors.HexColor("#A3271F")

ss = {
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=22, leading=27, textColor=NAVY),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=NAVY),
    "subsub": ParagraphStyle("subsub", fontName="Helvetica-Oblique", fontSize=10.5, leading=14, textColor=MUTED),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=NAVY,
                         spaceBefore=6, spaceAfter=6),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=NAVY,
                         spaceBefore=2, spaceAfter=4),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10, leading=14, textColor=TEXT,
                           spaceAfter=6, alignment=TA_LEFT),
    "bullet": ParagraphStyle("bullet", fontName="Helvetica", fontSize=10, leading=14, textColor=TEXT,
                             leftIndent=14, bulletIndent=4, spaceAfter=2),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=9, leading=11.5, textColor=TEXT),
    "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=9, leading=11.5, textColor=NAVY),
    "cellh": ParagraphStyle("cellh", fontName="Helvetica-Bold", fontSize=9, leading=11.5, textColor=colors.white),
    "caption": ParagraphStyle("caption", fontName="Helvetica-Oblique", fontSize=9, leading=12, textColor=MUTED,
                              spaceBefore=3, spaceAfter=10),
    "note": ParagraphStyle("note", fontName="Helvetica", fontSize=9.3, leading=13, textColor=BROWN),
    "badge": ParagraphStyle("badge", fontName="Helvetica-Bold", fontSize=9, leading=11, textColor=colors.white),
    "code": ParagraphStyle("code", fontName="Courier", fontSize=7.6, leading=9.4, textColor=colors.HexColor("#1F2933")),
}

FULL_W = 6.5 * inch
fig_no = [0]


def P(text, style="body"):
    return Paragraph(text, ss[style])


def bullets(items):
    return [Paragraph(t, ss["bullet"], bulletText="•") for t in items]


def note(text, label="Note"):
    t = Table([[Paragraph(f"<b>{label}:</b> {text}", ss["note"])]], colWidths=[FULL_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CREAM),
        ("LINEBEFORE", (0, 0), (0, -1), 3, AMBER),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return [t, Spacer(1, 8)]


def step(num, title, prefix="STEP "):
    label = f"{prefix}{num}"
    bw = max(0.8 * inch, (len(label) * 5.6 + 14))
    badge = Table([[Paragraph(label, ss["badge"])]], colWidths=[bw])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), AMBER),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    row = Table([[badge, Paragraph(title, ss["h2"])]], colWidths=[bw + 0.15 * inch, FULL_W - bw - 0.15 * inch])
    row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                             ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    return [CondPageBreak(2.2 * inch), Spacer(1, 6), row, Spacer(1, 4)]


FIG = {}
MISSING = []


def screenshot_jpg(num):
    """Downscaled copy of cloud_security_1/'Virtual Machine <num>.png' (any capitalisation)."""
    out = os.path.join(IMG, f"{num:02d}.jpg")
    if not os.path.exists(out):
        src = next(os.path.join(SHOTS, f) for f in os.listdir(SHOTS)
                   if f.lower() == f"virtual machine {num}.png")
        im = PILImage.open(src).convert("RGB")
        if im.width > 1800:
            im = im.resize((1800, round(im.height * 1800 / im.width)), PILImage.LANCZOS)
        im.save(out, quality=85, optimize=True)
    return out


def figure(num, caption, max_h=4.1 * inch, path=None):
    path = path or screenshot_jpg(num)
    w, h = PILImage.open(path).size
    scale = min(FULL_W / w, max_h / h)
    img = Image(path, width=w * scale, height=h * scale)
    img.hAlign = "CENTER"
    frame = Table([[img]], colWidths=[w * scale + 2])
    frame.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, GREY_LINE),
                               ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1),
                               ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
    fig_no[0] += 1
    FIG[num] = fig_no[0]
    return [KeepTogether([frame, Paragraph(f"Figure {fig_no[0]}. {caption}", ss["caption"])])]


def optional_shot(filename, key, caption, max_h=4.6 * inch):
    """Embed cloud_security_1/<filename> if it has been saved; otherwise add nothing,
    since the same evidence is already shown as captured command output."""
    src = os.path.join(SHOTS, filename)
    if not os.path.exists(src):
        MISSING.append(filename)
        return []
    out = os.path.join(IMG, key + ".jpg")
    im = PILImage.open(src).convert("RGB")
    if im.width > 1800:
        im = im.resize((1800, round(im.height * 1800 / im.width)), PILImage.LANCZOS)
    im.save(out, quality=85, optimize=True)
    return figure(key, caption, max_h=max_h, path=out)


def figs(*keys):
    nums = [FIG[k] for k in keys if k in FIG]
    if not nums:
        return ""
    if len(nums) > 2 and nums == list(range(nums[0], nums[-1] + 1)):
        return f"Fig. {nums[0]}–{nums[-1]}"
    return "Fig. " + ", ".join(map(str, nums))


def code(text, title=None, width=98):
    lines = []
    for line in text.expandtabs(4).rstrip("\n").splitlines():
        line = "".join(ch for ch in line if ch == " " or ch.isprintable())
        if len(line) <= width:
            lines.append(line)
        else:
            lines += textwrap.wrap(line, width, subsequent_indent="    ", break_long_words=True,
                                   break_on_hyphens=False, drop_whitespace=False)
    pre = Preformatted("\n".join(lines), ss["code"])
    t = Table([[pre]], colWidths=[FULL_W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), GREY_BG), ("BOX", (0, 0), (-1, -1), 0.5, GREY_LINE),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    block = [t]
    if title:
        block.insert(0, Paragraph(f"<font name='Helvetica-Bold' size=8.5 color='#1B2A4A'>{escape(title)}</font>",
                                  ss["body"]))
    # keep short blocks (and their title) on one page; long ones may split
    return [KeepTogether(block) if len(lines) < 45 else block[0]] + ([] if len(lines) < 45 else block[1:]) + [Spacer(1, 8)]


def table(rows, widths, header=True, zebra=True):
    data = []
    for r_i, row in enumerate(rows):
        style = "cellh" if header and r_i == 0 else "cell"
        data.append([c if not isinstance(c, str) else Paragraph(c, ss[style]) for c in row])
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


def read(rel):
    with open(os.path.join(SHOTS, rel)) as f:
        return f.read()


def ok(t="PASS"):
    return f"<font color='#1E7B45'><b>{t}</b></font>"


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(inch, 0.55 * inch,
                      "Care Access Navigator — CloudSec1 Criterion 3: Cloud Infrastructure Security & Container Protection")
    canvas.drawRightString(letter[0] - inch, 0.55 * inch, f"Page {doc.page}")
    canvas.setStrokeColor(GREY_LINE)
    canvas.line(inch, 0.7 * inch, letter[0] - inch, 0.7 * inch)
    canvas.restoreState()



def footer_for(title):
    def _f(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(inch, 0.55 * inch, title)
        canvas.drawRightString(letter[0] - inch, 0.55 * inch, f"Page {doc.page}")
        canvas.setStrokeColor(GREY_LINE)
        canvas.line(inch, 0.7 * inch, letter[0] - inch, 0.7 * inch)
        canvas.restoreState()
    return _f


def build(path, story, title, footer_text):
    doc = SimpleDocTemplate(path, pagesize=letter, leftMargin=inch, rightMargin=inch, topMargin=0.85 * inch,
                            bottomMargin=0.95 * inch, title=title, author="Akhila Chennamaneni")
    f = footer_for(footer_text)
    doc.build(story, onFirstPage=f, onLaterPages=f)
    print("wrote", path)
