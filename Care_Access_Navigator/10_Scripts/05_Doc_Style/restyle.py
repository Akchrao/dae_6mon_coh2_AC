#!/usr/bin/env python3
"""Re-lay out the HTML-built course documents in the Care Access Navigator house style.

For each course: one combined document plus one document per numbered rubric section, each with the house title block
("Care Access Navigator", "<Course> - Criterion N: <name>", description, details table) and house.css.
Writes the HTML next to the source and a manifest (render_manifest.json) for render.js (footer text per PDF).
"""
import json, pathlib, re, html as H

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]
CSS = (HERE / "house.css").read_text()
AUTHOR = "Akhila Chennamaneni, IAM &amp; GRC Analyst (author)"
ORG = "HealthLine Regional Medical Center (HRMC), Care Access Navigator (CAN) capstone"
PROGRAM = "DAE 6-Month Cybersecurity, Cohort 2"

COURSES = [
    dict(course="Security Operations Center 1", src="security_operations_center_1/build/soc1.html", out="security_operations_center_1",
         prefix="Care_Access_Navigator_SOC1", combined="Security_Operations_Center_1_Submission",
         names=["SOC_Operations_Documentation", "SIEM_Implementation", "Threat_Detection_Principles", "Incident_Response_Methodology"],
         desc="SOC operations, SIEM implementation, threat detection and incident response on a Wazuh SIEM fed with Care Access Navigator logs",
         env="Wazuh 4.9.2 single-node SIEM (manager, indexer, dashboard) in Docker; MailHog test mailbox; capstone Keycloak and EHR logs", date="November 18, 2026"),
    dict(course="Compliance 2", src="compliance_2/build/compliance2.html", out="compliance_2", prefix="Care_Access_Navigator_Compliance2",
         combined="Compliance_2_Submission",
         names=["Advanced_Compliance_Strategy", "Compliance_Automation_Implementation", "Process_Integration_Optimization",
                "Advanced_Auditing_Techniques", "Quantitative_Risk_Assessment", "Performance_Management_Continuous_Improvement"],
         desc="Enterprise compliance program for HRMC's multinational expansion: strategy, automation, process optimization, auditing, quantitative risk and performance",
         env="CISO Assistant (live, read-only sync), Python workflow with AI triage, Monte Carlo risk model, capstone evidence", date="November 18, 2026"),
    dict(course="Security Monitoring 1", src="security_monitoring_1/build/sm1.html", out="security_monitoring_1",
         prefix="Care_Access_Navigator_SecurityMonitoring1", combined="Security_Monitoring_1_Submission",
         names=["Monitoring_Environment_Setup", "Security_Event_Analysis", "Monitoring_Implementation", "Security_Reporting"],
         desc="Monitoring environment, security event analysis, monitoring implementation and reporting with Wazuh, a live Linux agent and imported Windows samples",
         env="Wazuh 4.9.2; live Linux agent hrmc-linux-srv01; Windows Security samples (option B, instructor-approved); capstone Keycloak and EHR logs", date="November 18, 2026"),
    dict(course="Cybersecurity Basics 2", src="cybersecurity_basics_2/build/cb2.html", out="cybersecurity_basics_2",
         prefix="Care_Access_Navigator_CybersecurityBasics2", combined="Cybersecurity_Basics_2_Submission",
         names=["Advanced_Defense_Strategies", "Incident_Response_Handling", "SOC_Fundamentals", "Security_Policies_Governance", "Security_Documentation"],
         desc="Defense strategies, incident response, SOC fundamentals, security policy and governance, and security documentation for HRMC",
         env="Entra ID + Keycloak (capstone), Wazuh with live Linux agent, IR1 forensic lab, CISO Assistant", date="November 19, 2026"),
    dict(course="Design 1", src="Care_Access_Navigator/10_Scripts/05_Doc_Style/sources/design_1/design1.html", out="design_1", prefix=None, combined="MoodBuddy_Design_1_Project_Document",
         names=None, desc="Design thinking behind the MoodBuddy Python mood tracker: empathy map, research, purpose statement, brainstorm and conversational prototype",
         env="MoodBuddy Python program (python_1/MoodBuddy.py) and Figma flowchart (figma_1/)", date="November 17, 2026"),
    dict(course="Design Documentation 1", src="Care_Access_Navigator/10_Scripts/05_Doc_Style/sources/design_documentation_1/dd1.html", out="design_documentation_1", prefix=None,
         combined="Care_Access_Navigator_Design_Documentation_1", names=None,
         desc="Single design document for Care Access Navigator: summary, problem, use case, goals, features, tech stack, algorithm, flowchart, timeline, risk, evaluation and future considerations",
         env="Entra ID + Keycloak, 4 simulated HRMC apps, Wazuh SIEM, CISO Assistant (capstone evidence)", date="November 23, 2026"),
    dict(course="Logic 1", src="Care_Access_Navigator/10_Scripts/05_Doc_Style/sources/logic_1/logic1.html", out="logic_1", prefix=None, combined="MoodBuddy_Logic_1_Project", names=None,
         desc="Algorithm, flowchart, Boolean logic and conditional logic behind the MoodBuddy Python mood tracker",
         env="MoodBuddy Python program (logic_1/MoodBuddy.py) and Figma flowchart", date="November 23, 2026"),
    dict(course="Prompt Engineering 1", src="Care_Access_Navigator/10_Scripts/05_Doc_Style/sources/prompt_engineering_1/pe1.html", out="prompt_engineering_1",
         prefix=None, combined="Prompt_Engineering_1_Project", names=None,
         desc="Documented ChatGPT interactions: tokenization, hallucination management, multiple domains, prompt iteration, text and image generation",
         env="ChatGPT (free account), six chats on November 23, 2026; tiktoken o200k_base for token counts; doi.org and Crossref for checks", date="November 23, 2026"),
    dict(course="Figma 1", src="Care_Access_Navigator/10_Scripts/05_Doc_Style/sources/figma_1/figma1.html", out="figma_1", prefix=None,
         combined="MoodBuddy_Figma_1_Project", names=None,
         desc="MoodBuddy algorithm flowchart in Figma: frames, image, styling and a grouped component",
         env="Figma (FigJam board MoodBuddy Algorithm Flowchart v3), Unsplash plugin", date="November 24, 2026"),
    dict(course="Unix 1", src="Care_Access_Navigator/10_Scripts/05_Doc_Style/sources/unix_1/unix1.html", out="unix_1", prefix=None, combined="Unix_1_Submission", names=None,
         desc="Commands, options, arguments, text editor and permissions in the macOS Terminal",
         env="macOS Terminal (zsh / bash), folder ~/Desktop/unix_demo", date="November 17, 2026"),
    dict(course="Unix 2", src="Care_Access_Navigator/10_Scripts/05_Doc_Style/sources/unix_2/unix2.html", out="unix_2", prefix=None, combined="Unix_2_Submission", names=None,
         desc="File commands, arguments, kernels and shells, aliases and prompt customization in the macOS Terminal",
         env="macOS Terminal (zsh / bash), folder ~/Desktop/unix_demo", date="November 17, 2026"),
]


def header(c, crit_label, subtitle):
    rows = [("Prepared by", AUTHOR), ("Organization", ORG), ("Course", f"{c['course']} ({PROGRAM})"),
            ("Rubric criterion" if crit_label.startswith("Criterion") else "Scope", crit_label), ("Environment", c["env"]), ("Date", c["date"])]
    kv = "".join(f"<tr><td class='k'>{k}:</td><td>{v}</td></tr>" for k, v in rows)
    return (f"<h1 class='brand'>Care Access Navigator</h1><div class='subtitle'>{subtitle}</div>"
            f"<div class='subsub'>{c['desc']}</div><table class='kv'>{kv}</table>")


def keep_short_tables(body):
    """keep tables of up to 12 rows on one page (house style: no header row left alone at a page end)"""
    def fix(m):
        t = m.group(0)
        return t.replace("<table>", "<table style='break-inside:avoid;page-break-inside:avoid'>", 1) if t.count("<tr") <= 12 else t
    return re.sub(r"<table>.*?</table>", fix, body, flags=re.S)


def page(body, title, combined=False):
    body = keep_short_tables(body)
    cls = " class='combined'" if combined else ""
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title><style>{CSS}</style></head><body{cls}>{body}</body></html>"


manifest = []
for c in COURSES:
    src = pathlib.Path(c["src"]) if c["src"].startswith("/") else REPO / c["src"]
    h = src.read_text()
    body = h[h.index("<body>") + 6:h.rindex("</body>")]
    first_h2 = re.search(r"<h2[ >]", body)
    intro = body[:first_h2.start()] if first_h2 else body
    note = re.search(r'<div class="note">.*?</div>', intro, re.S)
    note = note.group(0) if note else ""
    # drop the old title, meta and intro note from the front matter
    front = re.sub(r"<h1>.*?</h1>", "", intro, count=1, flags=re.S)
    front = re.sub(r'<div class="meta">.*?</div>', "", front, count=1, flags=re.S)
    front = front.replace(note, "", 1)
    rest = body[first_h2.start():] if first_h2 else ""
    html_dir = REPO / c.get("html_dir", str(pathlib.Path(c["src"]).parent))
    html_dir.mkdir(parents=True, exist_ok=True)
    out_dir = REPO / c["out"]
    # images in the sources are relative to their build folder; rewrite for the new html_dir when it differs
    if c.get("html_dir"):
        for ref in set(re.findall(r'src="([^"]+)"', body)):
            if not ref.startswith(("/", "http", "data:")):
                absimg = (src.parent / ref).resolve()
                body = body.replace(f'src="{ref}"', f'src="file://{absimg}"')
                front = front.replace(f'src="{ref}"', f'src="file://{absimg}"'); rest = rest.replace(f'src="{ref}"', f'src="file://{absimg}"')
    # combined document
    sub = f"{c['course']}: Final Project Submission"
    combined = header(c, "All rubric criteria" if c["names"] else "Final project", sub) + note + front + rest
    fn = html_dir / f"house_{c['combined']}.html"
    fn.write_text(page(combined, sub, combined=bool(c['names'])))
    manifest.append({"html": str(fn), "pdf": str(out_dir / f"{c['combined']}.pdf"), "footer": f"Care Access Navigator — {sub}"})
    # one document per criterion
    if c["names"]:
        secs = [p for p in re.split(r"(?=<h2[ >])", body) if re.match(r"<h2[^>]*>\s*\d+\.", p)]
        assert len(secs) == len(c["names"]), (c["course"], len(secs))
        for i, (sec, name) in enumerate(zip(secs, c["names"]), 1):
            sec = re.sub(r'^<h2 class="pb">', "<h2>", sec)
            title = re.sub(r"<[^>]+>", "", re.search(r"<h2[^>]*>(.*?)</h2>", sec, re.S).group(1)).split(". ", 1)[-1]
            sub = f"{c['course']} — Criterion {i}: {title}"
            doc = header(c, f"Criterion {i}: {title}", sub) + note + sec
            fn = html_dir / f"house_{c['prefix']}_Criterion_{i}_{name}.html"
            fn.write_text(page(doc, sub))
            manifest.append({"html": str(fn), "pdf": str(out_dir / f"{c['prefix']}_Criterion_{i}_{name}.pdf"),
                             "footer": f"Care Access Navigator — {c['course']}, Criterion {i}: {H.unescape(title)}"})
(HERE / "render_manifest.json").write_text(json.dumps(manifest, indent=1))
print(len(manifest), "documents prepared")
