"""Split a course's combined HTML into one standalone HTML per rubric criterion (rendered to PDF afterwards).
Usage: python3 split_criteria.py <combined.html> <out_dir> <file_prefix> <course title> <name1> <name2> ...
Each numbered <h2> section ("1. ...", "2. ...") becomes Criterion N; the header keeps the course meta and scenario note."""
import re, sys, pathlib

src, out_dir, prefix, course, names = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5:]
h = open(src).read()
head = h[:h.index("<body>") + 6]
body = h[h.index("<body>") + 6:h.rindex("</body>")]
meta = re.search(r'<div class="meta">.*?</div>', body, re.S).group(0)
note = re.search(r"<div class=\"note\">.*?</div>", re.split(r"(?=<h2[ >])", body)[0], re.S)
note = note.group(0) if note else ""
parts = re.split(r'(?=<h2[ >])', body)
secs = [p for p in parts if re.match(r'<h2[^>]*>\s*\d+\.', p)]
assert len(secs) == len(names), f"{len(secs)} numbered sections but {len(names)} names"
for i, (sec, name) in enumerate(zip(secs, names), 1):
    sec = re.sub(r'^<h2 class="pb">', "<h2>", sec)
    title = re.search(r'<h2[^>]*>(.*?)</h2>', sec, re.S).group(1)
    doc = (f"{head}<h1>{course}</h1><div class='crit'>Rubric criterion {i}: {title.split('. ', 1)[-1]}</div>{meta}{note}"
           f"{sec}</body></html>")
    fn = out_dir / f"{prefix}_Criterion_{i}_{name}.html"
    fn.write_text(doc.replace("</style>", ".crit{font-size:13pt;color:#C8553D;font-weight:bold;margin:2px 0 6px}</style>"))
    print(fn.name)
