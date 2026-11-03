"""mdpdf.py - renders the playbook / tools Markdown into the house PDF style (pdfstyle.py).
Supports what those documents use: headings, paragraphs, bullet and numbered lists, pipe tables, fenced code,
and inline **bold**, *italic*, `code`. The Markdown files stay the single source; the PDF is generated from them."""
import re
from html import escape
from pdfstyle import P, bullets, code, table, Spacer, inch, FULL_W


def inline(t):
    t = escape(t.replace("\\|", "\x00"), quote=False).replace("\x00", "|")
    t = re.sub(r"`([^`]+)`", lambda m: f"<font face='Courier' size='8.3'>{m[1]}</font>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"(?<![*\w])\*([^*]+)\*(?!\*)", r"<i>\1</i>", t)
    return t


def _cells(line):
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


def _widths(rows):
    n = len(rows[0])
    w = [max(min(max(len(re.sub(r"`|\*", "", r[i])) for r in rows if i < len(r)), 70), len(rows[0][i]) + 6, 9) for i in range(n)]
    tot = sum(w)
    return [FULL_W * x / tot for x in w]


def render(md, skip_title=True, h1="h1", h2="h2"):
    out, lines, i = [], md.splitlines(), 0
    para = []

    def flush():
        if para:
            out.append(P(inline(" ".join(para)))); para.clear()

    while i < len(lines):
        l = lines[i]
        if l.startswith("```"):
            flush(); j = i + 1
            while j < len(lines) and not lines[j].startswith("```"):
                j += 1
            out.extend(code("\n".join(lines[i + 1:j]))); i = j + 1; continue
        if l.startswith("|"):
            flush(); rows = []
            while i < len(lines) and lines[i].startswith("|"):
                if not re.match(r"^\|[\s:|-]+\|$", lines[i].strip()):
                    rows.append(_cells(lines[i]))
                i += 1
            out.extend(table([[inline(c) for c in r] for r in rows], _widths(rows))); continue
        m = re.match(r"^(#{1,3}) (.*)", l)
        if m:
            flush()
            if not (skip_title and m[1] == "#"):
                out.append(P(inline(m[2]), h1 if m[1] == "##" else h2))
            i += 1; continue
        if re.match(r"^\s*(- |\d+\. )", l):
            flush(); items = []
            while i < len(lines) and re.match(r"^\s*(- |\d+\. )", lines[i]):
                num = re.match(r"^\s*(\d+)\. ", lines[i])
                txt = re.sub(r"^\s*(- |\d+\. )", "", lines[i])
                items.append((f"<b>{num[1]}.</b> " if num else "") + inline(txt)); i += 1
            out.extend(bullets(items)); continue
        if not l.strip():
            flush(); i += 1; continue
        para.append(l.strip()); i += 1
    flush()
    return out
