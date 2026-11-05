"""Compliance 1 — Task 3: Compliance Auditing Basics (uses real evidence in ../audit-evidence)."""
import os

from style import *  # noqa: F401,F403
from reportlab.platypus import CondPageBreak
from diagrams import AMBER as D_AMBER, GREEN as D_GREEN, NAVY as D_NAVY, RED as D_RED
from diagrams import flow, gantt
from org import *  # noqa: F401,F403

OUT = os.path.join(SHOTS, "Care_Access_Navigator_Compliance1_Task3_Compliance_Auditing.pdf")
FOOT = "Care Access Navigator — Compliance 1, Task 3: Compliance Auditing Basics"
EV = os.path.join(SHOTS, "audit-evidence")
BR = CondPageBreak(3.5 * inch)


def ev(name):
    return open(os.path.join(EV, name)).read()


def fig(drawing, caption):
    fig_no[0] += 1
    return [KeepTogether([drawing, Paragraph(f"Figure {fig_no[0]}. {caption}", ss["caption"])])]


def rating(r):
    col = {"High": "#A3271F", "Medium": "#B26A00", "Low": "#1E7B45", "Effective": "#1E7B45",
           "Partially effective": "#B26A00", "Effective with exception": "#1E7B45"}.get(r, "#333333")
    return f"<font color='{col}'><b>{r}</b></font>"


# hash index -> dict
HASH = {}
for line in ev("EVIDENCE-INDEX-SHA256.txt").splitlines()[1:]:
    parts = line.split()
    if len(parts) >= 4:
        HASH[parts[-1]] = parts[0]

s = []
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Compliance 1 — Task 3: Compliance Auditing Basics", "subtitle"),
      P("Audit plan, evidence collection for three controls, compliance assessment with gap analysis, and "
        "remediation plan — executed against the live Care Access Navigator environment", "subsub"),
      Spacer(1, 12)]
s += kv([("Audit ID:", "CAN-IA-2026-01"), ("Prepared by:", f"{AUTHOR}, GRC Analyst (auditor)"),
         ("Auditee:", f"{ORG} — {PLATFORM}: Keycloak realm care-access-navigator, Microsoft Entra ID "
                      "application, Azure subscription governance and monitoring"),
         ("Criteria:", "HIPAA Security Rule; PCI DSS v4.0.1 Req. 4, 7, 8, 10; CAN-POL-AC-001; CAN-PRC-AC-002"),
         ("Fieldwork:", "October 13, 2026 (evidence timestamps 17:47–17:49 UTC)")])
s += [P("Audit opinion (summary)", "h1"),
      P("Of the three controls tested, <b>encryption in transit (ENC-01)</b> is effective for Azure data services, "
        "with a documented lab exception for the identity provider. <b>Role-based access (AC-01)</b> is well designed "
        "— every workforce account holds exactly one role and every application receives only the roles it needs — but "
        "authentication settings fall short of policy and PCI DSS (no enforced MFA, brute-force protection off, "
        "10-character passwords), and no completed access review exists yet. <b>Logging and alerting (LOG-01)</b> "
        "operated effectively during the period (50 alerts fired, including a detected incident), but a "
        "12-month central log store no longer exists. Six findings were raised: <b>3 High, 2 Medium, 1 Low</b>.")]

# ------------------------------------------------------------------ 1. audit plan
s += [BR, P("1. Audit Plan", "h1")]
s += table([
    ["Element", "Plan"],
    ["Objective", "Provide assurance that access to ePHI and the cardholder data environment is restricted to "
     "authorized, authenticated users, that security events are logged and alerted, and that data in transit is "
     "encrypted — as required by HIPAA, PCI DSS and HealthLine policy."],
    ["Compliance area", "Identity, access and monitoring (technical safeguards)"],
    ["In scope", "Keycloak realm <i>care-access-navigator</i> (users, roles, client scopes, authentication "
     "settings); Entra ID enterprise application <i>care-access-navigator-keycloak-broker</i>; Azure Policy "
     "guardrails; Azure Monitor alert rules and alert history"],
    ["Out of scope", "Physical safeguards; application source code; the payment processor's environment (covered by "
     "its PCI Attestation of Compliance); clinical workflows"],
    ["Criteria", "HIPAA §164.308(a)(4), §164.312(a)(1), (b), (d), (e)(1); PCI DSS 4.2.1, 7.2.1–7.2.5, "
     "8.3.4, 8.3.6, 8.3.7, 8.4.2, 10.2.1, 10.4.1, 10.5.1; policy CAN-POL-AC-001"],
    ["Methodology", "Risk-based approach aligned to IIA/ISACA audit standards: inquiry, inspection of system "
     "configuration, re-performance (validate-only policy tests), and computer-assisted extraction (kcadm.sh, "
     "Azure CLI, Microsoft Graph). Populations are small, so 100% of users and alert rules are tested (no sampling)."],
    ["Risk basis", "Capstone risk register: excessive RBAC privileges, credential compromise and logging weakness "
     "were rated Critical/High inherent risk"],
    ["Independence", "Performed by the GRC Analyst, who also helped design some controls. This limitation is "
     "disclosed; in production the audit would be performed or reviewed by Internal Audit."],
], [1.3 * inch, 5.2 * inch])
s += [P("Timeline and resources", "h2")]
s += fig(flow([("Plan", "Oct 12–13"), ("Fieldwork", "Oct 13"), ("Draft report", "Oct 14"),
               ("Mgmt responses", "Oct 16"), ("Final report", "Oct 20"), ("Follow-up", "Jan 2027")]),
         "Audit timeline.")
s += table([
    ["Resource", "Allocation"],
    ["People", "GRC Analyst (lead, 12 h); IAM Analyst (walkthrough, 1 h); Security Officer (responses, 1 h)"],
    ["Tools", "Keycloak admin CLI (read-only), Azure CLI + Resource Graph, Microsoft Graph, shasum -a 256, "
     "validate-only ARM deployments (no resources created, no cost)"],
    ["Access needed", "Read-only Keycloak admin, Azure Reader at subscription, Entra directory read"],
    ["Deliverables", "Evidence pack with hash index; this report; remediation tracker entries"],
], [1.3 * inch, 5.2 * inch])

# ------------------------------------------------------------------ 2. evidence
s += [BR, P("2. Evidence Collection", "h1"),
      P("Evidence follows documented standards: each item has an ID, the control it supports, the evidence type, "
        "the collection technique, who collected it and when (UTC), and a SHA-256 hash recorded at collection so its "
        "integrity can be verified later. System-generated evidence is preferred over screenshots because it is "
        "complete and reproducible. Items are stored read-only in <font name='Courier'>compliance_1/audit-evidence/"
        "</font> with the hash index.")]
s += table([
    ["ID", "Ctrl", "Evidence", "Type", "Technique", "Collected (UTC)"],
    ["E-AC-01", "AC-01", "Keycloak users, realm roles, client role scopes, IdP role mappers", "System extract",
     "Inspection (CAAT)", "2026-10-13 17:47"],
    ["E-AC-02", "AC-01", "Keycloak authentication settings; Entra ID app assignments", "System extract",
     "Inspection (CAAT)", "2026-10-13 17:48"],
    ["E-LOG-01", "LOG-01", "Alert rules, action group, 30-day alert history, log-store status", "System extract",
     "Inspection + inquiry", "2026-10-13 17:48"],
    ["E-ENC-01", "ENC-01", "Policy assignment and 3 validate-only deployment tests; IdP transport", "Test result",
     "Re-performance", "2026-10-13 17:49"],
    ["tpl-*.json", "ENC-01", "Test templates used for re-performance", "Supporting", "—", "2026-10-13 17:49"],
], [0.75 * inch, 0.6 * inch, 2.05 * inch, 0.9 * inch, 1.05 * inch, 1.15 * inch])
s += [CondPageBreak(2.2 * inch), P("Integrity record (SHA-256)", "h2")]
s += code("\n".join(f"{n}\n    {h}" for n, h in HASH.items()), "audit-evidence/EVIDENCE-INDEX-SHA256.txt")
s += [P("Chain of custody: collected by the GRC Analyst directly from the source systems via authenticated "
        "read-only sessions; written straight to the evidence folder; hashed within one minute; no manual editing. "
        "Any later change to a file changes its hash and invalidates the item.")]

# ------------------------------------------------------------------ 3. assessment
s += [BR, P("3. Compliance Assessment", "h1"),
      P("Each control was tested for <b>design effectiveness</b> (is the control capable of meeting the requirement?) "
        "and <b>operating effectiveness</b> (did it actually work during the period?).")]
s += step("AC-01", "Role-based access control and access review", prefix="")
s += table([
    ["#", "Test performed", "Expected", "Actual (evidence)", "Result"],
    ["1", "Inspect all 10 Keycloak accounts and their realm roles", "Each user has only the role for their job",
     "All 9 workforce test accounts hold exactly one role matching their function; the administrator's "
     "federated account holds no application role (E-AC-01)",
     ok("PASS")],
    ["2", "Inspect application client role scopes", "Each app receives only relevant roles; full scope off",
     "billing-app: billing; ehr-simulator / patient-portal: nurse, clinician; hr-app: hr, it-support; "
     "fullScopeAllowed = false on all (E-AC-01)", ok("PASS")],
    ["3", "Inspect Entra ID assignment model", "Assignment required; one app role per user", "Assignment required = "
     "true; Billing → Billing, Nurse → Nurse (E-AC-02)", ok("PASS")],
    ["4", "Inspect MFA enforcement", "MFA required for privileged / CDE access (policy 4.6)", "Custom flow "
     "<i>browser-mfa-privileged</i> exists but no client uses it; realm uses default browser flow (E-AC-02)",
     "<font color='#A3271F'><b>FAIL</b></font>"],
    ["5", "Inspect lockout and password policy", "Lockout ≤ 10 attempts; 12+ chars; history 4 (policy 4.5)",
     "bruteForceProtected = false; length(10); passwordHistory(3) (E-AC-02)",
     "<font color='#A3271F'><b>FAIL</b></font>"],
    ["6", "Request last completed access review", "Signed certification within 6 months", "None available — "
     "procedure CAN-PRC-AC-002 not yet run (inquiry)", "<font color='#A3271F'><b>FAIL</b></font>"],
], [0.25 * inch, 1.3 * inch, 1.3 * inch, 2.75 * inch, 0.9 * inch])
s += [P("<b>Conclusion:</b> design " + rating("Effective") + " for authorization; operating " +
        rating("Partially effective") + " because authentication hardening and periodic review are missing.")]
s += step("LOG-01", "Security event logging, alerting and log review", prefix="")
s += table([
    ["#", "Test performed", "Expected", "Actual (evidence)", "Result"],
    ["1", "Inspect alert rules and routing", "Rules for high-risk events, routed to security", "7 activity-log "
     "rules enabled, routed to action group ag-can-secops (email) (E-LOG-01)", ok("PASS")],
    ["2", "Inspect 30-day alert history", "Alerts fire when events occur", "50 alerts across 6 rules, incl. the "
     "Oct 8 incident (NSG change, key listing) and SSH brute force (E-LOG-01)", ok("PASS")],
    ["3", "Inspect central log retention", "12 months, 3 months online (PCI 10.5.1)", "No Log Analytics workspace or "
     "Activity Log export since 2026-10-13; native retention 90 days only (E-LOG-01)",
     "<font color='#A3271F'><b>FAIL</b></font>"],
    ["4", "Request daily log review records", "Documented review each business day (PCI 10.4.1)", "Alerts were "
     "triaged during the Oct 8 incident, but no routine daily review record exists (inquiry)",
     "<font color='#A3271F'><b>FAIL</b></font>"],
], [0.25 * inch, 1.3 * inch, 1.3 * inch, 2.75 * inch, 0.9 * inch])
s += [P("<b>Conclusion:</b> alerting operated " + rating("Effective") + "; overall control " +
        rating("Partially effective") + " due to retention and review gaps.")]
s += step("ENC-01", "Encryption of data in transit", prefix="")
s += table([
    ["#", "Test performed", "Expected", "Actual (evidence)", "Result"],
    ["1", "Re-perform: deploy storage allowing HTTP (validate-only)", "Blocked", "DENIED by storage-secure-transfer "
     "(E-ENC-01)", ok("PASS")],
    ["2", "Re-perform: deploy storage allowing TLS 1.0", "Blocked", "DENIED by storage-min-tls12 (E-ENC-01)",
     ok("PASS")],
    ["3", "Control test: compliant HTTPS + TLS 1.2 storage", "Allowed", "Validation passed; nothing deployed "
     "(E-ENC-01)", ok("PASS")],
    ["4", "Inspect identity provider transport", "TLS for all connections", "sslRequired = external; lab instance "
     "served over HTTP on localhost only (E-ENC-01)", "<font color='#B26A00'><b>EXCEPTION</b></font>"],
], [0.25 * inch, 1.3 * inch, 1.3 * inch, 2.75 * inch, 0.9 * inch])
s += [P("<b>Conclusion:</b> " + rating("Effective with exception") + " (lab IdP must use TLS in production).")]

# ------------------------------------------------------------------ 4. findings + gap analysis
s += [BR, P("4. Findings and Gap Analysis", "h1")]
FINDINGS = [
    ("F-01", "High", "MFA not enforced", "HIPAA §164.312(d); PCI 8.4.2; policy 4.6",
     "MFA required for privileged and CDE access", "MFA flow defined but not bound to any client"),
    ("F-02", "High", "Account lockout disabled", "PCI 8.3.4; policy 4.5", "Lock after ≤ 10 failures for "
     "≥ 30 min", "bruteForceProtected = false (failureFactor 30 unused)"),
    ("F-03", "High", "No 12-month central log retention", "HIPAA §164.312(b); PCI 10.5.1",
     "12 months retained, 3 online", "Central workspace removed; 90-day native retention"),
    ("F-04", "Medium", "Password standard below PCI minimum", "PCI 8.3.6, 8.3.7; policy 4.5",
     "≥ 12 characters; history 4", "length(10); passwordHistory(3)"),
    ("F-05", "Medium", "No completed access review / daily log review records",
     "HIPAA §164.308(a)(4)(ii)(C), §164.308(a)(1)(ii)(D); PCI 7.2.4, 10.4.1",
     "Signed reviews on schedule", "Procedures defined (Task 2) but not yet executed"),
    ("F-06", "Low", "Identity provider over HTTP in lab", "HIPAA §164.312(e)(1); PCI 4.2.1",
     "TLS 1.2+ end to end", "HTTP on localhost; sslRequired=external"),
]
s += table([["ID", "Rating", "Finding", "Requirement", "Expected state", "Current state (gap)"]] +
           [[f, rating(r), t, q, e, c] for f, r, t, q, e, c in FINDINGS],
           [0.45 * inch, 0.72 * inch, 1.2 * inch, 1.33 * inch, 1.3 * inch, 1.5 * inch])
s += [P("Rating: <b>High</b> = direct non-compliance with a required control protecting ePHI/CDE; <b>Medium</b> = "
        "partial compliance or missing evidence; <b>Low</b> = limited exposure or lab-only.", "caption")]
s += [P("Compliance coverage after testing", "h2")]
s += table([
    ["Requirement area", "Tested items", "Compliant", "Gaps", "Coverage"],
    ["Authorization / least privilege (HIPAA §164.308(a)(4); PCI 7.2)", "3", "3", "0", "100%"],
    ["Authentication (HIPAA §164.312(d); PCI 8.3–8.4)", "3", "0", "3", "0%"],
    ["Periodic review (PCI 7.2.4, 10.4.1)", "2", "0", "2", "0%"],
    ["Audit logging and alerting (HIPAA §164.312(b); PCI 10.2)", "2", "2", "0", "100%"],
    ["Log retention (PCI 10.5.1)", "1", "0", "1", "0%"],
    ["Transmission security (HIPAA §164.312(e); PCI 4.2.1)", "4", "3", "1 (exception)", "75%"],
    ["<b>Total</b>", "<b>15</b>", "<b>8</b>", "<b>7</b>", "<b>53%</b>"],
], [3.0 * inch, 0.85 * inch, 0.8 * inch, 0.95 * inch, 0.9 * inch])

# ------------------------------------------------------------------ 5. remediation
s += [BR, P("5. Remediation Plan", "h1"),
      P("Recommendations are prioritized by risk rating, then by effort. Each action has an owner, a target date and "
        "a measurable completion test so progress can be tracked objectively.")]
s += table([
    ["#", "Ref", "Recommendation", "Owner", "Target", "Done when"],
    ["1", "F-01", "Bind <i>browser-mfa-privileged</i> to billing-app, hr-app and admin console; require OTP for "
     "Security Analyst, IT Support, Billing roles", "IAM Analyst", "2026-11-06", "Test login prompts for OTP; "
     "E-AC-02 shows flow bound"],
    ["2", "F-02", "Enable brute-force detection: failureFactor 10, wait ≥ 30 min", "IAM Analyst", "2026-10-23",
     "11th bad password locks account"],
    ["3", "F-03", "Restore Activity Log + Keycloak event export to a log store with 12-month retention (cost "
     "approval needed)", "Security Officer", "2026-11-30", "Oldest log ≥ 90 days online, archive to 12 months"],
    ["4", "F-04", "Set password policy length(12), passwordHistory(4)", "IAM Analyst", "2026-10-23",
     "Realm passwordPolicy shows new values"],
    ["5", "F-05", "Run first quarterly access review (CAN-PRC-AC-002); start daily log-review checklist",
     "IAM Analyst / Security Analyst", "2026-12-15", "Signed review pack; 10 consecutive daily records"],
    ["6", "F-06", "Front Keycloak with TLS 1.2+ reverse proxy; sslRequired=all in production", "IT Support",
     "2027-01-31", "HTTPS only; HTTP redirects"],
], [0.3 * inch, 0.45 * inch, 2.15 * inch, 1.0 * inch, 0.9 * inch, 1.7 * inch])
s += fig(gantt([("F-02 lockout (High)", 0, 1, D_RED), ("F-04 password policy (Medium)", 0, 1, D_AMBER),
                ("F-01 MFA enforcement (High)", 0, 2, D_RED), ("F-03 log retention (High)", 1, 3, D_RED),
                ("F-05 first reviews (Medium)", 2, 3, D_AMBER), ("F-06 TLS for IdP (Low)", 4, 4, D_GREEN),
                ("Follow-up audit", 6, 2, D_NAVY)],
               ["Oct 13", "Oct 20", "Oct 27", "Nov 3", "Nov 10", "Nov 17", "Dec 1", "Dec 15", "Jan 27"]),
         "Remediation timeline (weeks from report).")
s += [P("Progress tracking", "h2")]
s += bullets([
    "Each finding is an entry in the <b>remediation tracker</b> (workbook <font name='Courier'>"
    "Care_Access_Navigator_Compliance1_Tracker.xlsx</font>, sheet <i>Remediation</i>) with owner, target date, "
    "percent complete and automatic RAG status: <b>Green</b> on track, <b>Amber</b> due within 7 days and < 75% "
    "complete, <b>Red</b> overdue.",
    "Owners update status weekly; the GRC Analyst reviews evidence before closing an item (closure requires the "
    "'done when' test to pass and new evidence to be hashed into the index).",
    "The Compliance & Privacy Committee reviews open High findings monthly; anything Red for two consecutive "
    "months escalates to the Program Sponsor for risk acceptance or extra resources.",
    "A follow-up audit (January 2027) re-performs the failed tests and closes findings formally.",
])

# ------------------------------------------------------------------ appendix
s += [BR, P("Appendix — Evidence Extracts", "h1")]
for f in ("E-AC-01_keycloak_users_roles.txt", "E-AC-02_authn_settings_and_entra_assignments.txt",
          "E-LOG-01_alerting_and_log_retention.txt", "E-ENC-01_tls_enforcement.txt"):
    s += code(ev(f), f"audit-evidence/{f}  (SHA-256 {HASH.get(f, '')[:16]}…)")

build(OUT, s, "CAN Compliance 1 - Task 3 Compliance Auditing Basics", FOOT)
