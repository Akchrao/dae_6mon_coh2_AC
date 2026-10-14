"""Render a PDF into contact sheets for visual QA: python render.py <pdf> <outprefix>"""
import sys
import pypdfium2 as pdfium
from PIL import Image
d = pdfium.PdfDocument(sys.argv[1])
pages = [d[i].render(scale=0.9).to_pil() for i in range(len(d))]
print("pages", len(d), [len(d[i].get_textpage().get_text_range()) for i in range(len(d))])
for k in range(0, len(pages), 6):
    grp = pages[k:k + 6]; w, h = grp[0].size
    sh = Image.new("RGB", (w * 3 + 40, h * 2 + 30), "#888")
    for j, p in enumerate(grp): sh.paste(p, (10 + (j % 3) * (w + 10), 10 + (j // 3) * (h + 10)))
    sh.save(f"{sys.argv[2]}_{k // 6 + 1}.png")
