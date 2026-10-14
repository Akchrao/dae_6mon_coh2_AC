"""Vector diagrams for the compliance PDFs (org charts, Gantt, swimlanes, matrices, charts)."""
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.units import inch

NAVY = colors.HexColor("#1B2A4A")
AMBER = colors.HexColor("#E8A33D")
CREAM = colors.HexColor("#FFF4DE")
GREY = colors.HexColor("#F3F4F6")
LINE = colors.HexColor("#9AA3AF")
TEXT = colors.HexColor("#333333")
GREEN = colors.HexColor("#2E8B57")
RED = colors.HexColor("#C0392B")
ORANGE = colors.HexColor("#E67E22")
YELLOW = colors.HexColor("#F1C40F")
W = 6.5 * inch


def _wrap(text, width_pt, size):
    """Very small word-wrapper for Helvetica (approx. 0.5em average glyph width)."""
    max_chars = max(4, int(width_pt / (size * 0.5)))
    out, cur = [], ""
    for word in text.split():
        if len(cur) + len(word) + (1 if cur else 0) > max_chars:
            out.append(cur)
            cur = word
        else:
            cur = (cur + " " + word).strip()
    if cur:
        out.append(cur)
    return out


def _box(d, x, y, w, h, title, sub=None, fill=GREY, stroke=NAVY, title_color=NAVY, size=7.5):
    d.add(Rect(x, y, w, h, rx=3, ry=3, fillColor=fill, strokeColor=stroke, strokeWidth=0.8))
    lines = [(t, "Helvetica-Bold", size, title_color) for t in _wrap(title, w - 6, size)]
    if sub:
        lines += [(t, "Helvetica", size - 1, TEXT) for t in _wrap(sub, w - 6, size - 1)]
    total = sum(l[2] + 1.5 for l in lines)
    cy = y + h / 2 + total / 2 - lines[0][2]
    for t, font, s, col in lines:
        d.add(String(x + w / 2, cy, t, fontName=font, fontSize=s, fillColor=col, textAnchor="middle"))
        cy -= s + 1.5


def _arrow(d, x1, y1, x2, y2, color=LINE):
    d.add(Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=0.9))
    import math
    a = math.atan2(y2 - y1, x2 - x1)
    s = 4
    d.add(Polygon([x2, y2, x2 - s * math.cos(a - 0.4), y2 - s * math.sin(a - 0.4),
                   x2 - s * math.cos(a + 0.4), y2 - s * math.sin(a + 0.4)], fillColor=color, strokeColor=color))


def org_chart(levels, parents, box_h=38, gap_y=22, highlight=(), width=W):
    """levels: list of lists of (title, subtitle). parents[i][j] = index of parent in level i (for level i+1)."""
    n = len(levels)
    h = n * box_h + (n - 1) * gap_y + 8
    d = Drawing(width, h)
    pos = []
    for li, level in enumerate(levels):
        k = len(level)
        bw = min(1.45 * inch, (width - (k - 1) * 8) / k)
        total = k * bw + (k - 1) * 8
        x0 = (width - total) / 2
        y = h - 4 - box_h - li * (box_h + gap_y)
        row = []
        for j, (t, sub) in enumerate(level):
            x = x0 + j * (bw + 8)
            hl = (li, j) in highlight
            _box(d, x, y, bw, box_h, t, sub, fill=CREAM if hl else (NAVY if li == 0 else GREY),
                 stroke=AMBER if hl else NAVY, title_color=colors.white if (li == 0 and not hl) else NAVY)
            if li == 0 and not hl:
                pass
            row.append((x + bw / 2, y, y + box_h))
        pos.append(row)
    for li in range(1, n):
        for j, p in enumerate(parents[li - 1]):
            px, py0, _ = pos[li - 1][p]
            cx, _, cy1 = pos[li][j]
            mid = (py0 + cy1) / 2
            d.add(Line(px, py0, px, mid, strokeColor=LINE, strokeWidth=0.8))
            d.add(Line(px, mid, cx, mid, strokeColor=LINE, strokeWidth=0.8))
            d.add(Line(cx, mid, cx, cy1, strokeColor=LINE, strokeWidth=0.8))
    return d


def gantt(tasks, periods, label_w=2.1 * inch, row_h=15, width=W, milestone=None):
    """tasks: (label, start_idx, length, color); periods: header labels."""
    n = len(tasks)
    h = (n + 1) * row_h + 10
    d = Drawing(width, h)
    cw = (width - label_w) / len(periods)
    top = h - row_h
    for i, p in enumerate(periods):
        x = label_w + i * cw
        d.add(Rect(x, top, cw, row_h, fillColor=NAVY, strokeColor=colors.white, strokeWidth=0.5))
        d.add(String(x + cw / 2, top + 4.5, p, fontName="Helvetica-Bold", fontSize=6.8, fillColor=colors.white,
                     textAnchor="middle"))
    for r, (label, s, ln, col) in enumerate(tasks):
        y = top - (r + 1) * row_h
        if r % 2 == 0:
            d.add(Rect(0, y, width, row_h, fillColor=GREY, strokeColor=None))
        d.add(String(3, y + 4.5, label, fontName="Helvetica", fontSize=7, fillColor=TEXT))
        d.add(Rect(label_w + s * cw + 1, y + 3, ln * cw - 2, row_h - 6, rx=2, ry=2, fillColor=col, strokeColor=None))
    for i in range(len(periods) + 1):
        x = label_w + i * cw
        d.add(Line(x, 0, x, top, strokeColor=colors.HexColor("#DDDDDD"), strokeWidth=0.4))
    if milestone is not None:
        x = label_w + milestone[0] * cw
        d.add(Line(x, 0, x, top, strokeColor=RED, strokeWidth=1, strokeDashArray=[2, 2]))
        d.add(String(x + 2, 2, milestone[1], fontName="Helvetica-Oblique", fontSize=6.5, fillColor=RED))
    return d


def swimlane(lanes, steps, arrows, cols, lane_h=46, label_w=1.05 * inch, width=W, zones=()):
    """steps: id -> (lane_idx, col, title, sub, fill). arrows: [(id_from, id_to)].
    zones: [(lane_from, lane_to, col_from, col_to, label)] shaded scope boxes."""
    h = len(lanes) * lane_h + 4
    d = Drawing(width, h)
    cw = (width - label_w) / cols
    for i, name in enumerate(lanes):
        y = h - (i + 1) * lane_h
        d.add(Rect(0, y, width, lane_h, fillColor=GREY if i % 2 == 0 else colors.white, strokeColor=LINE,
                   strokeWidth=0.4))
        d.add(Rect(0, y, label_w, lane_h, fillColor=NAVY, strokeColor=colors.white, strokeWidth=0.5))
        for k, t in enumerate(_wrap(name, label_w - 6, 7)):
            d.add(String(label_w / 2, y + lane_h / 2 + 3 - k * 8.5, t, fontName="Helvetica-Bold", fontSize=7,
                         fillColor=colors.white, textAnchor="middle"))
    for (l0, l1, c0, c1, label) in zones:
        y0 = h - (l1 + 1) * lane_h + 2
        y1 = h - l0 * lane_h - 2
        x0 = label_w + c0 * cw + 2
        x1 = label_w + (c1 + 1) * cw - 2
        d.add(Rect(x0, y0, x1 - x0, y1 - y0, fillColor=None, strokeColor=RED, strokeWidth=1,
                   strokeDashArray=[3, 2]))
        d.add(String(x1 - 3, y1 - 8, label, fontName="Helvetica-Bold", fontSize=6.5, fillColor=RED,
                     textAnchor="end"))
    bw, bh = cw - 12, lane_h - 16
    centers = {}
    for sid, (lane, col, title, sub, fill) in steps.items():
        x = label_w + col * cw + 6
        y = h - (lane + 1) * lane_h + 8
        _box(d, x, y, bw, bh, title, sub, fill=fill or colors.white, size=6.8)
        centers[sid] = (x, y, bw, bh)
    for a, b in arrows:
        xa, ya, wa, ha = centers[a]
        xb, yb, wb, hb = centers[b]
        if abs(ya - yb) < 1:                       # same lane: straight arrow
            _arrow(d, xa + wa, ya + ha / 2, xb, yb + hb / 2)
            continue
        sx, ex = xa + wa / 2, xb + wb / 2
        if ya > yb:                                # target lane is below
            y_start, y_end = ya, yb + hb
        else:                                      # target lane is above
            y_start, y_end = ya + ha, yb
        mid = (y_start + y_end) / 2
        if abs(sx - ex) < 1:
            _arrow(d, sx, y_start, ex, y_end)
        else:
            d.add(Line(sx, y_start, sx, mid, strokeColor=LINE, strokeWidth=0.9))
            d.add(Line(sx, mid, ex, mid, strokeColor=LINE, strokeWidth=0.9))
            _arrow(d, ex, mid, ex, y_end)
    return d


def flow(steps, width=W, box_h=40, fills=None):
    """Horizontal process flow: steps = [(title, sub)]."""
    n = len(steps)
    gap = 14
    bw = (width - (n - 1) * gap) / n
    d = Drawing(width, box_h + 6)
    for i, (t, sub) in enumerate(steps):
        x = i * (bw + gap)
        _box(d, x, 3, bw, box_h, t, sub, fill=(fills[i] if fills else GREY), size=7)
        if i < n - 1:
            _arrow(d, x + bw + 1, 3 + box_h / 2, x + bw + gap - 1, 3 + box_h / 2, color=NAVY)
    return d


def grid2x2(points, xlabel, ylabel, quads, width=W, size=3.0 * inch):
    """points: [(label, x0..1, y0..1)] ; quads: (top-left, top-right, bottom-left, bottom-right) titles."""
    d = Drawing(width, size + 24)
    x0 = (width - size) / 2
    y0 = 18
    half = size / 2
    fills = [CREAM, colors.HexColor("#FDE2E1"), GREY, colors.HexColor("#E3F2E9")]
    rects = [(x0, y0 + half), (x0 + half, y0 + half), (x0, y0), (x0 + half, y0)]
    for (rx, ry), f, q in zip(rects, fills, quads):
        d.add(Rect(rx, ry, half, half, fillColor=f, strokeColor=LINE, strokeWidth=0.6))
        d.add(String(rx + half / 2, ry + half - 11, q, fontName="Helvetica-Bold", fontSize=7.5, fillColor=NAVY,
                     textAnchor="middle"))
    for label, px, py in points:
        cx, cy = x0 + px * size, y0 + py * size
        d.add(Rect(cx - 2.5, cy - 2.5, 5, 5, fillColor=AMBER, strokeColor=NAVY, strokeWidth=0.5))
        d.add(String(cx + 5, cy - 2.5, label, fontName="Helvetica", fontSize=6.6, fillColor=TEXT))
    d.add(String(x0 + size / 2, 4, xlabel + "  →", fontName="Helvetica-Bold", fontSize=7.5, fillColor=NAVY,
                 textAnchor="middle"))
    d.add(String(x0 - 6, y0 + size + 6, ylabel + " ↑", fontName="Helvetica-Bold", fontSize=7.5, fillColor=NAVY,
                 textAnchor="start"))
    return d


def heatmap(items, width=W, cell=0.62 * inch, title_l="Likelihood", title_i="Impact"):
    """items: [(label, likelihood 1..5, impact 1..5)] placed on a 5x5 grid."""
    d = Drawing(width, 5 * cell + 30)
    x0 = (width - 5 * cell) / 2 + 10
    y0 = 22
    for li in range(1, 6):
        for im in range(1, 6):
            score = li * im
            col = GREEN if score <= 4 else (YELLOW if score <= 9 else (ORANGE if score <= 14 else RED))
            x = x0 + (im - 1) * cell
            y = y0 + (li - 1) * cell
            d.add(Rect(x, y, cell, cell, fillColor=col, strokeColor=colors.white, strokeWidth=1.2))
            d.add(String(x + cell - 4, y + 3, str(score), fontName="Helvetica", fontSize=6, fillColor=colors.white,
                         textAnchor="end"))
        d.add(String(x0 - 6, y0 + (li - 1) * cell + cell / 2 - 3, str(li), fontName="Helvetica-Bold", fontSize=7.5,
                     fillColor=NAVY, textAnchor="end"))
        d.add(String(x0 + (li - 1) * cell + cell / 2, y0 - 10, str(li), fontName="Helvetica-Bold", fontSize=7.5,
                     fillColor=NAVY, textAnchor="middle"))
    slots = {}
    for label, li, im in items:
        k = slots.get((li, im), 0)
        slots[(li, im)] = k + 1
        x = x0 + (im - 1) * cell + 4
        y = y0 + (li - 1) * cell + cell - 10 - k * 9
        d.add(String(x, y, label, fontName="Helvetica-Bold", fontSize=7, fillColor=NAVY))
    d.add(String(x0 + 2.5 * cell, 1, title_i + " →", fontName="Helvetica-Bold", fontSize=8, fillColor=NAVY,
                 textAnchor="middle"))
    d.add(String(x0 - 22, y0 + 5 * cell + 6, title_l + " ↑", fontName="Helvetica-Bold", fontSize=8,
                 fillColor=NAVY))
    return d


def kpi_bars(rows, width=W, row_h=18, label_w=2.3 * inch):
    """rows: [(label, actual%, target%)] horizontal bars 0..100 with target marker."""
    h = len(rows) * row_h + 18
    d = Drawing(width, h)
    bw = width - label_w - 40
    for i, (label, actual, target) in enumerate(rows):
        y = h - (i + 1) * row_h - 4
        d.add(String(0, y + 5, label, fontName="Helvetica", fontSize=7.3, fillColor=TEXT))
        d.add(Rect(label_w, y + 3, bw, row_h - 7, fillColor=GREY, strokeColor=None))
        col = GREEN if actual >= target else (ORANGE if actual >= target * 0.75 else RED)
        d.add(Rect(label_w, y + 3, bw * max(actual, 0) / 100, row_h - 7, fillColor=col, strokeColor=None))
        tx = label_w + bw * target / 100
        d.add(Line(tx, y + 1, tx, y + row_h - 2, strokeColor=NAVY, strokeWidth=1.2))
        d.add(String(label_w + bw + 4, y + 5, f"{actual:.0f}%", fontName="Helvetica-Bold", fontSize=7.3,
                     fillColor=NAVY))
    d.add(String(label_w, 2, "bar = actual   |   navy tick = target", fontName="Helvetica-Oblique", fontSize=6.5,
                 fillColor=TEXT))
    return d
