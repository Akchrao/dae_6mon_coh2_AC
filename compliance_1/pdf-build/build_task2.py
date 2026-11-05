"""Compliance 1 — Task 2: Compliance Program Development."""
import os

from style import *  # noqa: F401,F403
from reportlab.platypus import CondPageBreak
from diagrams import AMBER as D_AMBER, CREAM as D_CREAM, GREEN as D_GREEN, GREY as D_GREY, NAVY as D_NAVY
from diagrams import flow, gantt, grid2x2, org_chart
from org import *  # noqa: F401,F403

OUT = os.path.join(SHOTS, "Care_Access_Navigator_Compliance1_Task2_Compliance_Program_Development.pdf")
FOOT = "Care Access Navigator — Compliance 1, Task 2: Compliance Program Development"
BR = CondPageBreak(3.5 * inch)


def fig(drawing, caption):
    fig_no[0] += 1
    return [KeepTogether([drawing, Paragraph(f"Figure {fig_no[0]}. {caption}", ss["caption"])])]


def numbered(items, start=1):
    return [Paragraph(f"{i}. {t}", ss["bullet"]) for i, t in enumerate(items, start)]


def doc_control(doc_id, title, version, owner, approver, eff, review):
    return table([["Document ID", "Title", "Version", "Owner", "Approver", "Effective", "Next review"],
                  [doc_id, title, version, owner, approver, eff, review]],
                 [1.1 * inch, 1.3 * inch, 0.62 * inch, 0.8 * inch, 0.95 * inch, 0.8 * inch, 0.93 * inch])


s = []
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Compliance 1 — Task 2: Compliance Program Development", "subtitle"),
      P("Program governance model, stakeholders and communication strategy, Access Control Policy with approval "
        "workflow and version control, Quarterly Access Review procedure, and compliance training plan", "subsub"),
      Spacer(1, 12)]
s += kv([("Prepared by:", f"{AUTHOR}, {AUTHOR_ROLE}"), ("Organization:", f"{ORG} — {PLATFORM}"),
         ("Frameworks:", "HIPAA and PCI DSS v4.0.1 (see Task 1)"), ("Date:", DATE)])
s += [P("Purpose", "h1"),
      P("Task 1 established which obligations apply. This task builds the program that meets them day to day: who "
        "governs it, how it communicates, the written policy that sets the rules for access to ePHI and the "
        "cardholder data environment, the step-by-step procedure that proves the policy is followed, and the "
        "training that makes the workforce able to follow it.")]

# ------------------------------------------------------------------ 1 governance
s += [P("1. Program Structure and Governance Model", "h1"),
      P("Governance uses a three-tier model: the Board sets direction and receives assurance, a management committee "
        "makes decisions, and working groups execute. Internal Audit reports independently to the Board's audit and "
        "compliance committee so it can challenge management.")]
s += fig(org_chart(
    [[("Board Audit & Compliance Committee", "oversight, quarterly")],
     [("Compliance & Privacy Committee", "chair: CCO, monthly"), ("Internal Audit", "independent line")],
     [("Access Governance WG", "IAM, HR, managers"), ("Security Monitoring WG", "Security Officer + SOC"),
      ("Payments / PCI WG", "Revenue cycle, Billing App"), ("Training & Awareness WG", "Privacy Officer, HR")]],
    [[0, 0], [0, 0, 0, 0]], box_h=40), "Compliance governance model (three tiers).")
s += table([
    ["Body", "Members", "Decision rights", "Cadence / quorum", "Reports to"],
    ["Board Audit & Compliance Committee", "3 trustees, CCO and Internal Audit attend", "Approve charter, annual "
     "plan, risk appetite; receive breach reports", "Quarterly; 2 of 3 trustees", "Full Board"],
    ["Compliance & Privacy Committee", "CCO (chair), Privacy Officer, Security Officer, COO, Revenue Cycle, HR, "
     "Clinical Ops", "Approve policies, exceptions > 90 days, remediation priorities", "Monthly; chair + 4",
     "Board committee"],
    ["Working groups (4)", "Control owners and SMEs", "Operate controls, draft procedures, track actions",
     "Bi-weekly", "Compliance & Privacy Committee"],
    ["Internal Audit", "Head of Internal Audit", "Independent audit plan and opinions", "Per audit plan",
     "Board committee (directly)"],
], [1.35 * inch, 1.55 * inch, 1.55 * inch, 1.05 * inch, 1.0 * inch])
s += [P("Operational procedures of the program", "h2")]
s += table([
    ["Procedure", "Summary", "Owner"],
    ["Policy management", "Draft → review → approve → publish → attest; annual review (Section 4)",
     "GRC Analyst"],
    ["Exception management", "Written request, risk assessment, compensating control, expiry (max 12 months); "
     "logged in exception register", "CCO"],
    ["Issue and remediation tracking", "Findings logged with owner, due date and status; reviewed monthly",
     "GRC Analyst"],
    ["Reporting and hotline", "Anonymous compliance hotline; non-retaliation; triage within 2 business days",
     "CCO"],
    ["Monitoring and auditing", "Continuous control monitoring (Azure Policy, alerts) plus annual internal audit",
     "Security Officer / Internal Audit"],
    ["Enforcement and sanctions", "Consistent sanctions for violations (HIPAA §164.308(a)(1)(ii)(C))",
     "HR + Privacy Officer"],
], [1.6 * inch, 3.65 * inch, 1.25 * inch])

# ------------------------------------------------------------------ 2 stakeholders + comms
s += [BR, P("2. Stakeholder Identification", "h1")]
s += table([
    ["Stakeholder", "Type", "Interest in compliance", "Influence", "Engagement approach"],
    ["Patients", "External", "Privacy of their records; card security", "Medium", "Notice of Privacy Practices; "
     "portal messages"],
    ["Clinicians and nurses", "Internal", "Fast, reliable access to ePHI", "High", "Clinical champions; short "
     "workflow-friendly guidance"],
    ["Billing / revenue cycle", "Internal", "Payments must work; PCI scope", "Medium", "Payments/PCI working group"],
    ["IT Support and IAM", "Internal", "Operating the controls", "High", "Runbooks; working group membership"],
    ["Executives and Board", "Internal", "Penalty, reputational and financial risk", "High", "Quarterly dashboard "
     "and status report"],
    ["HHS Office for Civil Rights", "Regulator", "HIPAA enforcement", "High", "Breach reports; audit responses"],
    ["Acquiring bank / card brands", "External", "PCI DSS validation", "High", "Annual SAQ, ASV scan reports"],
    ["Vendors / business associates", "External", "Contract terms, access", "Medium", "BAAs; vendor onboarding "
     "and access rules"],
    ["NY Attorney General", "Regulator", "State breach law", "Medium", "Breach notifications when required"],
], [1.35 * inch, 0.75 * inch, 1.55 * inch, 0.8 * inch, 2.05 * inch])
s += fig(grid2x2([("Board", 0.88, 0.85), ("HHS OCR", 0.92, 0.62), ("Acquirer", 0.80, 0.70),
                  ("Clinicians", 0.62, 0.90), ("IT / IAM", 0.70, 0.78), ("Billing", 0.42, 0.72),
                  ("Patients", 0.30, 0.86), ("Vendors", 0.36, 0.40), ("NY AG", 0.58, 0.30)],
                 "Influence", "Interest", ("Keep informed", "Manage closely", "Monitor", "Keep satisfied")),
         "Stakeholder interest/influence grid.")
s += [CondPageBreak(2.5 * inch), P("3. Communication Strategy", "h1"),
      P("Principles: plain language, role-specific messages, one source of truth (the policy portal), and two-way "
        "channels so concerns reach the committee. Every message names an owner and a feedback path.")]
s += table([
    ["Audience", "Key message", "Channel", "Frequency", "Owner"],
    ["Board committee", "Program status, top risks, decisions needed", "Status report + dashboard (Task 4)",
     "Quarterly", "CCO"],
    ["Executives", "KPI trends, remediation progress", "Committee pack, email summary", "Monthly", "CCO"],
    ["All workforce", "Policy changes, reminders, how to report", "Intranet, LMS, all-staff email", "On change; "
     "monthly tip", "Privacy Officer"],
    ["Managers", "Access review tasks and deadlines", "Ticket + email + calendar hold", "Quarterly", "IAM Analyst"],
    ["Billing staff", "PCI do's and don'ts", "Team huddle, job aid", "Quarterly", "Revenue Cycle Mgr"],
    ["Vendors", "Access rules, BAA duties", "Onboarding pack, contract", "At onboarding; annually", "Vendor Mgr"],
    ["Regulators / acquirer", "Required reports and notices", "Formal letter / portal", "As required",
     "Privacy / Security Officer"],
], [1.15 * inch, 1.85 * inch, 1.45 * inch, 0.95 * inch, 1.1 * inch])

# ------------------------------------------------------------------ 4 policy
s += [BR, P("4. Compliance Policy: Access Control and Identity Management", "h1")]
s += doc_control("CAN-POL-AC-001", "Access Control and Identity Management Policy", "1.0", "Security Officer",
                 "Compliance & Privacy Committee", "2026-12-01", "2027-12-01")
s += [P("Approval workflow", "h2")]
s += fig(flow([("1 Draft", "GRC Analyst"), ("2 SME review", "IAM, Security, Privacy, Billing, HR"),
               ("3 Compliance & legal review", "CCO"), ("4 Committee approval", "minuted vote"),
               ("5 Executive sign-off", "COO"), ("6 Publish & attest", "LMS attestation, 30 days")],
              fills=[D_GREY, D_GREY, D_CREAM, D_CREAM, D_CREAM, D_GREY]),
         "Policy approval workflow; steps 3–5 are formal approval gates recorded in the version history.")
s += table([
    ["Version", "Date", "Author", "Change summary", "Approved by"],
    ["0.1", "2026-10-20", "GRC Analyst", "Initial draft from Task 1 requirements analysis", "—"],
    ["0.2", "2026-11-03", "GRC Analyst", "SME comments: vendor access window, break-glass procedure", "—"],
    ["0.9", "2026-11-17", "CCO", "Legal review: sanctions wording, regulatory references", "—"],
    ["1.0", "2026-11-24", "Committee", "Approved for publication; effective 2026-12-01", "Committee; COO"],
], [0.6 * inch, 0.85 * inch, 0.95 * inch, 3.0 * inch, 1.1 * inch])
s += [P("Version control procedure", "h2")]
s += bullets([
    "<b>Numbering:</b> drafts 0.x; approved releases 1.0, 2.0 (material change) or 1.1 (editorial/minor change).",
    "<b>Repository:</b> the policy portal (SharePoint library with versioning) is the only authoritative copy; "
    "PDFs carry the version and 'uncontrolled when printed'.",
    "<b>Change log:</b> every version records date, author, summary and approver (table above).",
    "<b>Review triggers:</b> annual review, or earlier after a regulatory change, audit finding, incident or system "
    "change (e.g., new identity provider).",
    "<b>Retention:</b> superseded versions archived read-only for 6 years from last effective date "
    "(HIPAA §164.316(b)(2)(i)).",
])
pol = [
    ("1. Purpose", "Protect the confidentiality, integrity and availability of ePHI and account data by ensuring "
     "that only authorized, authenticated people and services access HealthLine systems, and only to the minimum "
     "extent necessary."),
    ("2. Scope", "All workforce members, contractors and vendors; all systems in Care Access Navigator (EHR "
     "Simulator, Patient Portal, Billing App, HR App, Keycloak, Microsoft Entra ID and Azure resources), including "
     "the cardholder data environment."),
    ("3. Definitions", "<b>Privileged account</b>: an account that can change security settings or other users' "
     "access. <b>Break-glass account</b>: emergency privileged account sealed for urgent patient-care or outage "
     "use. <b>Access review</b>: periodic certification by a manager that each user's access is still needed."),
]
for h, t in pol:
    s += [P(f"<b>{h}</b>"), P(t)]
s += [P("<b>4. Policy statements</b>")]
s += table([
    ["#", "Statement", "Reference"],
    ["4.1", "Access is granted by role, on a least-privilege and minimum-necessary basis, using the approved role "
     "catalogue (Clinician, Nurse, Billing, HR, IT Support, Security Analyst, Vendor).", "§164.308(a)(4); "
     "§164.502(b); PCI 7.2.1–7.2.2"],
    ["4.2", "Every user has a unique ID; shared or generic accounts are prohibited except documented break-glass.",
     "§164.312(a)(2)(i); PCI 8.2.1–8.2.2"],
    ["4.3", "New access requires manager approval; access is removed by end of day on termination and within 5 "
     "business days of a role change.", "§164.308(a)(3)(ii)(C); PCI 8.2.5"],
    ["4.4", "Accounts inactive for 90 days are disabled.", "PCI 8.2.6"],
    ["4.5", "Passwords are at least 12 characters with complexity and history of 4; accounts lock after 10 failed "
     "attempts for at least 30 minutes.", "PCI 8.3.4, 8.3.6, 8.3.7"],
    ["4.6", "MFA is required for all remote access, all privileged access, and all access to the cardholder data "
     "environment.", "§164.312(d); PCI 8.4.1–8.4.3"],
    ["4.7", "Vendor access is time-bound, enabled only when needed, MFA-protected and monitored.", "PCI 8.2.7; "
     "§164.308(b)"],
    ["4.8", "Access is re-certified quarterly for privileged roles and at least every six months for all others "
     "(procedure CAN-PRC-AC-002).", "§164.308(a)(4)(ii)(C); PCI 7.2.4"],
    ["4.9", "Emergency (break-glass) access is used only when patient care or a critical outage requires it, is "
     "logged and alerted, and is reviewed by the Security Officer within 1 business day.", "§164.312(a)(2)(ii)"],
    ["4.10", "All access to ePHI and the CDE is logged and protected from alteration (policy CAN-POL-LOG-001).",
     "§164.312(b); PCI 10.2"],
], [0.4 * inch, 4.35 * inch, 1.75 * inch])
for h, t in [
    ("5. Roles and responsibilities", "Security Officer owns this policy; IAM Analyst operates identity systems; "
     "managers approve and re-certify access; HR triggers joiner/mover/leaver events; users protect credentials "
     "and report suspected misuse."),
    ("6. Compliance and enforcement", "Compliance is monitored by access reviews, Azure Policy, Keycloak event logs "
     "and internal audit. Violations lead to sanctions proportionate to severity, up to termination of employment "
     "or contract (HIPAA §164.308(a)(1)(ii)(C), §164.530(e))."),
    ("7. Exceptions", "Requests are made to the CCO with a business justification, risk assessment and "
     "compensating control; approved exceptions expire after at most 12 months and are logged."),
    ("8. Related documents", "CAN-PRC-AC-002 Quarterly User Access Review; CAN-POL-LOG-001 Logging and Monitoring; "
     "CAN-PLB-IR-001 Incident Response Playbook; Task 1 Compliance Requirements Analysis."),
]:
    s += [P(f"<b>{h}</b>"), P(t)]

# ------------------------------------------------------------------ 5 procedure
s += [BR, P("5. Procedure: Quarterly User Access Review", "h1")]
s += doc_control("CAN-PRC-AC-002", "Quarterly User Access Review", "1.0", "IAM Analyst", "Security Officer",
                 "2027-01-01", "2028-01-01")
s += [P("<b>Objective.</b> Confirm every account and role in Care Access Navigator is still required and "
        "authorized, and remove anything that is not — implementing policy statement 4.8 and control AC-01.")]
s += fig(flow([("Extract", "IAM, day 1"), ("Reconcile", "vs HR roster"), ("Certify", "managers, 10 days"),
               ("Revoke", "IAM, 2 days"), ("Validate", "GRC sample"), ("Report", "committee")]),
         "Quarterly access review process.")
s += [P("<b>Implementation steps</b>")]
s += table([
    ["#", "Action", "Owner", "Time limit", "Record produced"],
    ["1", "Export all Keycloak users with realm and client roles, and Entra ID app role assignments, to the review "
     "workbook (kcadm.sh / Graph export).", "IAM Analyst", "Day 1", "Signed extract with SHA-256 hash"],
    ["2", "Reconcile the extract with the HR active-workforce roster and vendor contract list; flag leavers, "
     "orphans and unknown accounts.", "IAM Analyst", "Day 2", "Reconciliation sheet"],
    ["3", "Send each manager the list of their staff and roles via ticket; manager marks Keep / Change / Remove.",
     "IAM Analyst", "Day 3", "Review tickets"],
    ["4", "Managers certify; non-responses escalate to the department head on day 8 and the CCO on day 11.",
     "Managers", "Days 3–12", "Certification decisions"],
    ["5", "Remove or change access as decided; immediately disable flagged leavers and orphans.", "IAM Analyst",
     "2 business days", "Change tickets; Keycloak admin events"],
    ["6", "Validate (see below) and close the review; report results to the committee.", "GRC Analyst",
     "Day 15", "Review report"],
], [0.4 * inch, 2.8 * inch, 0.85 * inch, 0.85 * inch, 1.6 * inch])
s += [P("<b>Testing protocols</b> (does the procedure work as designed?)")]
s += table([
    ["Test", "How", "Pass criterion"],
    ["Completeness", "Compare user count in the extract with a direct count in Keycloak and Entra ID", "Counts "
     "match exactly"],
    ["Accuracy", "Re-perform role lookup for 10 random users directly in Keycloak", "10/10 match the extract"],
    ["Timeliness", "Compare certification and removal timestamps with the time limits", "100% within limits or "
     "escalated"],
    ["Effectiveness", "For every 'Remove', confirm the account/role no longer exists (Keycloak admin event log)",
     "100% removed"],
], [1.2 * inch, 3.6 * inch, 1.7 * inch])
s += [P("<b>Validation procedures</b> (independent check by GRC)")]
s += numbered([
    "Select a sample of 25 certifications (or all if fewer) and confirm each has a named manager decision and date.",
    "Verify every revoked access in the sample against the live system; record pass/fail.",
    "Confirm leavers on the HR roster for the quarter have no active accounts (100% check).",
    "Record exceptions, open remediation items in the tracker, and file the evidence pack (extract, hash, tickets, "
    "results) in the evidence repository for 6 years.",
])
s += note("The capstone already has the data this procedure needs: the Task 3 audit extract (evidence E-AC-01) lists "
          "all ten Keycloak users and their single assigned role, and E-AC-02 lists Entra ID app-role assignments.",
          "Ready to run")

# ------------------------------------------------------------------ 6 training
s += [BR, P("6. Compliance Training Plan", "h1"),
      P("Goal: every person who touches ePHI or payment data understands their obligations and can apply them in "
        "their own workflow. HIPAA requires training for all workforce members (§164.530(b)) and security "
        "awareness (§164.308(a)(5)); PCI DSS requires awareness training at hire and at least annually "
        "(12.6.1–12.6.3).")]
s += table([
    ["Module", "Audience", "Content outline", "Time", "Delivery"],
    ["M1 HIPAA essentials", "All workforce", "PHI/ePHI, uses and disclosures, minimum necessary, patient rights, "
     "reporting", "30 min", "LMS e-learning"],
    ["M2 Access to ePHI in CAN", "All CAN users", "Roles and least privilege, sharing accounts, break-glass, how "
     "audit logs work", "20 min", "LMS + job aid"],
    ["M3 Security awareness", "All workforce", "Phishing, passwords and MFA, device security, incident reporting",
     "25 min", "LMS + phishing sims"],
    ["M4 PCI DSS for billing", "Billing staff", "Card data handling, hosted payment fields, never write down "
     "PAN/CVV, scripts on payment page", "20 min", "Live huddle + quiz"],
    ["M5 Privileged access", "IT Support, IAM, Security", "Admin duties, logging, change control, access reviews",
     "45 min", "Live workshop"],
    ["M6 Manager duties", "Department managers", "Approving access, quarterly reviews, sanctions process", "20 min",
     "Live / recorded"],
    ["M7 Vendor obligations", "Vendors", "BAA duties, remote-access rules, incident reporting", "15 min",
     "Onboarding pack + attestation"],
], [1.2 * inch, 1.05 * inch, 2.35 * inch, 0.6 * inch, 1.3 * inch])
s += [P("Delivery methodology and schedule", "h2")]
s += bullets(["<b>Onboarding:</b> M1–M3 (plus role modules) completed before access is granted to ePHI or the "
              "CDE, and no later than 30 days after hire.",
              "<b>Annual refresher</b> for all modules; <b>monthly micro-learning</b> tips; <b>quarterly phishing "
              "simulations</b> with just-in-time coaching for anyone who clicks.",
              "<b>Event-driven training</b> after a policy change or incident (e.g., a 10-minute refresher on access "
              "reviews after an audit finding).",
              "Accessibility: captions, screen-reader-friendly LMS content, Spanish versions of M1–M3."])
s += fig(gantt([("Build M1–M3 content", 1, 2, D_AMBER), ("Pilot with 20 users", 3, 1, D_AMBER),
                ("Rollout to all workforce", 4, 2, D_GREEN), ("Role modules M4–M7", 4, 3, D_GREEN),
                ("Phishing simulations", 5, 7, D_NAVY), ("Annual refresher cycle", 11, 1, D_NAVY)], MONTHS),
         "Training rollout timeline.")
s += [P("Assessment approach", "h2")]
s += table([
    ["Level (Kirkpatrick)", "Measure", "Target"],
    ["1 Reaction", "Post-course survey (relevance, clarity)", "≥ 4.0 / 5"],
    ["2 Learning", "Pre/post quiz; scenario questions", "≥ 80% pass mark; 2 attempts"],
    ["3 Behaviour", "Phishing click rate; access-review on-time rate; PHI-handling audit sample", "Click rate "
     "< 5%; reviews ≥ 95% on time"],
    ["4 Results", "Privacy incidents caused by human error; audit findings related to training", "Down 50% "
     "year on year"],
    ["Records", "Completion, scores and attestations kept in LMS", "Retained 6 years"],
], [1.4 * inch, 3.4 * inch, 1.7 * inch])
s += [P("Evidence of training design — Module M2 storyboard", "h2")]
s += table([
    ["Screen", "Content", "Interaction"],
    ["1", "Why access matters: a real-style story of a billing clerk viewing a neighbour's chart", "Video (60 s)"],
    ["2", "Your role in CAN: what Clinician, Nurse and Billing can see", "Click-to-reveal by role"],
    ["3", "Minimum necessary in practice", "Drag the data you need to the task"],
    ["4", "Everything you open is logged (Keycloak events, Azure Monitor alerts)", "Animated log trail"],
    ["5", "Break-glass: when it is and is not allowed", "Branching scenario"],
    ["6", "Knowledge check (5 questions) and attestation", "Quiz ≥ 80% + e-signature"],
], [0.6 * inch, 4.0 * inch, 1.9 * inch])
s += [P("Sample knowledge-check questions (with answer key)", "h2")]
s += table([
    ["#", "Question", "Correct answer and rationale"],
    ["1", "A colleague asks to use your login because theirs is locked. What do you do?", "Refuse and direct them to "
     "IT Support — unique IDs are required (policy 4.2)."],
    ["2", "You are in Billing. Can you open a patient's clinical notes to check a diagnosis code?", "No — use "
     "the coded claim data; clinical notes exceed minimum necessary."],
    ["3", "A patient reads their card number to you over the phone. Where do you record it?", "Nowhere — enter "
     "it only in the processor's hosted payment field (PCI 3.3)."],
    ["4", "You receive an urgent email asking you to re-enter your password at a new link.", "Report it with the "
     "'Report phish' button; do not click."],
    ["5", "When must you report a possible privacy incident?", "Immediately, to the Privacy Officer or hotline — "
     "the 60-day breach clock may already be running."],
], [0.3 * inch, 3.1 * inch, 3.1 * inch])
s += [KeepTogether([P("Summary", "h1"),
      P("The program now has a governance model with clear decision rights, an identified stakeholder map and "
        "communication matrix, an approved Access Control Policy with formal workflow and version control, an "
        "executable and testable Quarterly User Access Review procedure, and a role-based training plan with "
        "measurable assessment — each mapped to HIPAA and PCI DSS requirements.")])]

build(OUT, s, "CAN Compliance 1 - Task 2 Compliance Program Development", FOOT)
