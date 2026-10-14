"""Compliance 1 — Task 4: Documentation & Reporting."""
import os

from style import *  # noqa: F401,F403
from reportlab.platypus import CondPageBreak
from diagrams import AMBER as D_AMBER, CREAM as D_CREAM, GREEN as D_GREEN, GREY as D_GREY, NAVY as D_NAVY
from diagrams import flow, kpi_bars
from org import *  # noqa: F401,F403

OUT = os.path.join(SHOTS, "Care_Access_Navigator_Compliance1_Task4_Documentation_Reporting.pdf")
FOOT = "Care Access Navigator — Compliance 1, Task 4: Documentation & Reporting"
BR = CondPageBreak(3.5 * inch)


def fig(drawing, caption):
    fig_no[0] += 1
    return [KeepTogether([drawing, Paragraph(f"Figure {fig_no[0]}. {caption}", ss["caption"])])]


def status_of(k):
    kid, name, _, tgt, amber, cur, unit, *_ = k
    if cur is None:
        return "Pending"
    if unit in ("count", "min"):
        return "Green" if cur <= tgt else ("Amber" if cur <= amber else "Red")
    return "Green" if cur >= tgt else ("Amber" if cur >= amber else "Red")


def rag(t):
    col = {"Green": "#1E7B45", "Amber": "#B26A00", "Red": "#A3271F", "Pending": "#555555"}[t]
    return f"<font color='{col}'><b>{t}</b></font>"


counts = {x: sum(1 for k in KPIS if status_of(k) == x) for x in ("Green", "Amber", "Red", "Pending")}

s = []
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Compliance 1 — Task 4: Documentation &amp; Reporting", "subtitle"),
      P("Documentation package with templates, version control and distribution; management compliance status report; "
        "records management with retention schedule and access controls; KPI monitoring and reporting framework",
        "subsub"), Spacer(1, 12)]
s += kv([("Prepared by:", f"{AUTHOR}, {AUTHOR_ROLE}"), ("Organization:", f"{ORG} — {PLATFORM}"),
         ("Companion file:", "Care_Access_Navigator_Compliance1_Tracker.xlsx (KPI Monitor, Remediation, Evidence "
                             "Register, Retention Schedule, Document Register, Dashboard)"), ("Date:", DATE)])

# ------------------------------------------------------------------ 1 documentation package
s += [P("1. Documentation Package", "h1"),
      P("Every compliance document in the program follows one template and one control process, so readers always "
        "know whether they hold the current, approved version and who may receive it.")]
s += [P("1.1 Standard document template", "h2")]
s += table([
    ["Section", "Content", "Mandatory"],
    ["Header block", "Document ID, title, version, owner, approver, effective date, next review, classification",
     "Yes"],
    ["Version history", "Version, date, author, change summary, approved by", "Yes"],
    ["Purpose / scope", "Why the document exists; systems, people and data covered", "Yes"],
    ["Body", "Policy statements, procedure steps, or report content (numbered)", "Yes"],
    ["Roles and responsibilities", "RACI or named roles", "Policies, procedures"],
    ["References", "Regulatory citations (HIPAA, PCI DSS) and related documents", "Yes"],
    ["Footer", "Title, page X, classification label, 'Uncontrolled when printed'", "Yes"],
], [1.5 * inch, 4.1 * inch, 0.9 * inch])
s += [P("1.2 Document ID scheme", "h2")]
s += table([
    ["Pattern", "Meaning", "Example"],
    ["CAN-POL-xx-nnn", "Policy (xx = domain: AC access, LOG logging, IR incident)", "CAN-POL-AC-001"],
    ["CAN-PRC-xx-nnn", "Procedure implementing a policy", "CAN-PRC-AC-002"],
    ["CAN-COMP-xxx-nnn", "Program-level compliance document", "CAN-COMP-PLN-001"],
    ["CAN-AUD-yyyy-nn", "Audit report", "CAN-AUD-2026-01"],
    ["CAN-RPT-STS-Qn", "Periodic status report", "CAN-RPT-STS-Q4"],
], [1.6 * inch, 3.3 * inch, 1.6 * inch])
s += [P("1.3 Version control procedure", "h2")]
s += fig(flow([("Draft 0.x", "author"), ("Review", "SMEs + owner"), ("Approve", "per approval matrix"),
               ("Publish 1.0", "portal, PDF stamp"), ("Distribute", "per matrix"), ("Review cycle", "annual or "
               "triggered")], fills=[D_GREY, D_GREY, D_CREAM, D_CREAM, D_GREY, D_GREY]),
         "Document lifecycle and version control.")
s += bullets([
    "Major version (2.0) for changes in requirements or scope; minor (1.1) for clarifications; drafts are 0.x and never "
    "distributed outside the review group.",
    "The policy portal (versioned SharePoint library) is the single authoritative source; check-out/check-in prevents "
    "parallel edits and every save is retained.",
    "On approval the PDF is stamped with version and effective date; the previous version moves to a read-only "
    "archive (kept 6 years, HIPAA §164.316(b)(2)(i)).",
    "Annual review is scheduled from the 'Next review' date in the document register; a regulatory change, audit "
    "finding or incident triggers an earlier review.",
])
s += [P("1.4 Distribution procedure", "h2")]
s += table([
    ["Class", "Examples", "Who may receive", "Channel", "Ack."],
    ["Public", "Notice of Privacy Practices", "Anyone", "Website, front desk", "—"],
    ["Internal", "Policies, procedures, training plan", "All workforce; vendors as needed", "Policy portal / LMS",
     "Annual attestation in LMS"],
    ["Confidential", "Audit reports, status reports, incident records", "Named roles (committee, Board, owners)",
     "Portal with role-based access; encrypted email", "Read receipt"],
    ["Restricted", "Evidence packs containing system details or PHI", "GRC, Internal Audit, Privacy/Security Officer",
     "Evidence repository only", "Access logged"],
], [0.95 * inch, 1.6 * inch, 1.6 * inch, 1.45 * inch, 0.9 * inch])
s += [P("1.5 Document register (package contents)", "h2")]
s += table([["Doc ID", "Title", "V", "Owner", "Next review", "Class."]] +
           [[d[0], d[1], d[2], d[3], d[6], d[8]] for d in DOCS],
           [1.4 * inch, 2.05 * inch, 0.35 * inch, 1.0 * inch, 0.85 * inch, 0.85 * inch])

# ------------------------------------------------------------------ 2 status report
s += [PageBreak(), P("2. Compliance Status Report — Q4 2026", "h1")]
s += table([["To", "From", "Date", "Class", "Doc ID"],
            ["Program Sponsor (COO); Board Audit & Compliance Committee", "Chief Compliance Officer (prepared by GRC "
             "Analyst)", "October 20, 2026", "Confidential", "CAN-RPT-STS-Q4"]],
           [1.9 * inch, 1.6 * inch, 0.95 * inch, 0.85 * inch, 1.2 * inch])
s += [P("Executive summary", "h2"),
      P("<b>Overall status: AMBER.</b> HealthLine's Care Access Navigator now has a defined compliance program for "
        "HIPAA and PCI DSS, enforceable governance guardrails in Azure (100% compliant), and strong role-based access "
        "(every workforce account holds exactly one approved role). The first internal audit, however, found that "
        f"<b>authentication hardening and log retention lag behind requirements</b>: MFA is not enforced, account "
        f"lockout is off, and central logs are kept 90 days instead of 12 months. Of {len(KPIS)} key indicators, "
        f"<b>{counts['Green']} are green, {counts['Red']} red, {counts['Pending']} not yet measurable</b>. Three High "
        "findings have owners and target dates; none is overdue. <b>Two decisions are requested</b> (below).")]
s += [P("Scorecard", "h2")]
s += table([
    ["Area", "Framework", "Status", "Comment"],
    ["Governance and policy", "HIPAA 164.308(a)(1); PCI 12", rag("Green"), "Program plan, charter, Access Control "
     "Policy approved"],
    ["Authorization / least privilege", "HIPAA 164.308(a)(4); PCI 7", rag("Green"), "9/9 accounts least-privilege; "
     "client scopes enforced"],
    ["Authentication (MFA, lockout, passwords)", "HIPAA 164.312(d); PCI 8", rag("Red"), "F-01, F-02, F-04 open"],
    ["Logging and monitoring", "HIPAA 164.312(b); PCI 10", rag("Amber"), "Alerting works (MTTD 7.5 min); retention "
     "gap F-03; review records F-05"],
    ["Transmission security", "HIPAA 164.312(e); PCI 4", rag("Green"), "TLS 1.2 enforced by policy; lab IdP "
     "exception F-06"],
    ["Asset and cloud governance", "HIPAA 164.310(d); PCI 12.5", rag("Green"), "100% tagging; 7 deny guardrails"],
    ["Training", "HIPAA 164.530(b); PCI 12.6", rag("Pending"), "Rollout starts March 2027"],
], [1.75 * inch, 1.55 * inch, 0.7 * inch, 2.5 * inch])
s += [P("Key findings", "h2")]
s += table([["ID", "Finding", "Rating", "Owner", "Target"]] +
           [[f[0], f[1], f[2], f[4], f[5]] for f in FINDINGS],
           [0.5 * inch, 3.05 * inch, 0.7 * inch, 1.3 * inch, 0.95 * inch])
s += [P("Recommendations and decisions requested", "h2")]
s += table([
    ["#", "Recommendation", "Benefit", "Decision needed"],
    ["1", "Enforce MFA and lockout in Keycloak within 3 weeks (F-01, F-02, F-04)", "Closes the largest credential-"
     "compromise exposure; meets PCI 8.3/8.4", "None — within IAM budget"],
    ["2", "Fund a central log store with 12-month retention (F-03)", "Meets PCI 10.5.1 and HIPAA audit-control "
     "expectations; supports investigations", "<b>Approve ~$5–15/month</b> log-platform spend"],
    ["3", "Launch quarterly access reviews and daily log-review checklist (F-05)", "Produces the operating evidence "
     "auditors require", "Managers' time: ~30 min/quarter each"],
    ["4", "Accept lab-only HTTP for the IdP until production TLS (F-06)", "Avoids lab cost; no production exposure",
     "<b>Formal risk acceptance</b> by Program Sponsor until 2027-01-31"],
], [0.3 * inch, 2.35 * inch, 2.25 * inch, 1.6 * inch])
s += [P("Next report: January 2027 (after follow-up audit).", "caption")]

# ------------------------------------------------------------------ 3 records management
s += [BR, P("3. Records Management", "h1"),
      P("Compliance records must be retained long enough to prove compliance, protected from unauthorized access or "
        "alteration, and disposed of securely when no longer required. The schedule below is maintained in the "
        "tracker workbook (sheet <i>Retention Schedule</i>).")]
s += table([["Record type", "Driver", "Retention", "Owner", "Disposal"]] +
           [[r[0], r[1], r[2], r[5], r[6]] for r in RETENTION],
           [1.85 * inch, 1.45 * inch, 1.4 * inch, 0.9 * inch, 0.9 * inch])
s += [P("Access controls for records", "h2")]
s += table([
    ["Control", "Implementation"],
    ["Role-based access", "Repository permissions mirror the RBAC model: owners edit, defined roles read, everyone "
     "else denied; reviewed in the quarterly access review"],
    ["Integrity", "Evidence stored write-once (immutability policy) with SHA-256 hashes in the evidence register"],
    ["Encryption", "At rest (platform-managed keys, CMK planned) and in transit (TLS 1.2+, enforced by Azure Policy)"],
    ["Access logging", "All access to Confidential/Restricted records logged and retained per PCI 10.5.1"],
    ["Legal hold", "Privacy Officer or counsel can suspend disposal for any record linked to an investigation, "
     "audit or litigation; holds are listed in the register and reviewed quarterly"],
    ["Disposal", "Records past retention are reviewed by the owner, then destroyed per NIST SP 800-88 with a "
     "certificate of destruction kept 6 years"],
], [1.4 * inch, 5.1 * inch])

# ------------------------------------------------------------------ 4 monitoring
s += [BR, P("4. Monitoring System and Key Performance Indicators", "h1"),
      P("Monitoring is implemented in two layers: <b>automated control monitoring</b> in Azure (Azure Policy compliance, "
        "Azure Monitor alerts, Keycloak events) and a <b>KPI workbook</b> that turns those signals into indicators "
        "with targets, thresholds and automatic RAG status. KPIs below marked as measured use real values taken from "
        "the live environment.")]
s += table([["ID", "KPI", "Target", "Current", "Status", "Source / frequency"]] +
           [[k[0], k[1], (f"{k[3]}{'%' if k[6] == '%' else ' ' + k[6]}"),
             ("—" if k[5] is None else f"{k[5]:g}{'%' if k[6] == '%' else ' ' + k[6]}"), rag(status_of(k)),
             f"{k[7]}; {k[8].lower()}"] for k in KPIS],
           [0.45 * inch, 2.05 * inch, 0.65 * inch, 0.7 * inch, 0.7 * inch, 1.95 * inch])
s += fig(kpi_bars([(f"{k[0]} {k[1]}", k[5], k[3]) for k in KPIS if k[6] == "%" and k[5] is not None]),
         "Percentage KPIs: current value vs target (navy tick).")
s += [P("Reporting framework", "h2")]
s += table([
    ["Level", "Audience", "Content", "Frequency", "Mechanism"],
    ["Operational", "Control owners, Security Analyst", "Alerts, failed policy evaluations, overdue actions",
     "Real-time / weekly", "Azure Monitor email; tracker Remediation sheet"],
    ["Management", "Compliance & Privacy Committee", "KPI dashboard, findings status, exceptions", "Monthly",
     "Tracker Dashboard sheet + committee pack"],
    ["Executive", "Program Sponsor, Board committee", "Status report (Section 2), top risks, decisions",
     "Quarterly", "CAN-RPT-STS-Qn"],
    ["Regulatory", "HHS OCR, acquirer, NY AG", "Breach notices, SAQ/AOC, ASV results", "As required", "Formal "
     "submission"],
], [0.95 * inch, 1.35 * inch, 1.75 * inch, 0.95 * inch, 1.5 * inch])
s += [P("Escalation thresholds", "h2")]
s += bullets(["Any KPI <b>Red</b> for two consecutive months → corrective action plan to the committee.",
              "Any High finding <b>overdue</b> → Program Sponsor decides: extra resources or formal risk acceptance.",
              "Any suspected breach → Privacy Officer immediately (60-day notification clock, Task 5)."])
s += [P("Summary", "h1"),
      P("The documentation package standardizes every compliance document's template, numbering, versioning and "
        "distribution; the Q4 status report gives management a concise, decision-oriented view; the retention schedule "
        "and records controls meet HIPAA's six-year rule and PCI DSS log retention; and the KPI workbook provides a "
        "working monitoring system with live RAG formulas and a dashboard.")]

build(OUT, s, "CAN Compliance 1 - Task 4 Documentation & Reporting", FOOT)
