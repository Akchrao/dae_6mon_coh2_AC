"""Compliance 1 — Task 1: Compliance Fundamentals."""
import os

from style import *  # noqa: F401,F403  (shared visual style)
from reportlab.platypus import CondPageBreak
from diagrams import CREAM as D_CREAM, GREY as D_GREY, AMBER as D_AMBER, GREEN as D_GREEN, NAVY as D_NAVY
from diagrams import gantt, org_chart, swimlane
from reportlab.lib import colors as C
from org import *  # noqa: F401,F403

OUT = os.path.join(SHOTS, "Care_Access_Navigator_Compliance1_Task1_Compliance_Fundamentals.pdf")
FOOT = "Care Access Navigator — Compliance 1, Task 1: Compliance Fundamentals"


def doc_control(doc_id, title, version="1.0", status="Approved for course submission"):
    return table([
        ["Document ID", "Title", "Version", "Owner", "Approver", "Classification"],
        [doc_id, title, version, "GRC Analyst", "Chief Compliance Officer", "Internal"],
    ], [1.05 * inch, 1.85 * inch, 0.65 * inch, 0.85 * inch, 1.1 * inch, 1.0 * inch])


def fig(drawing, caption):
    fig_no[0] += 1
    return [KeepTogether([drawing, Paragraph(f"Figure {fig_no[0]}. {caption}", ss["caption"])])]


s = []
# ------------------------------------------------------------------ cover
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Compliance 1 — Task 1: Compliance Fundamentals", "subtitle"),
      P("Applicable regulations, compliance requirements analysis with business process mapping, compliance program "
        "plan, and two documented controls", "subsub"), Spacer(1, 12)]
s += kv([("Prepared by:", f"{AUTHOR}, {AUTHOR_ROLE}"), ("Organization:", ORG), ("Scope:", PLATFORM),
         ("Frameworks:", "HIPAA (Privacy, Security and Breach Notification Rules, as amended by HITECH) and "
                         "PCI DSS v4.0.1"), ("Date:", DATE)])
s += [P("Purpose", "h1"),
      P("This document applies two major regulatory frameworks to Care Access Navigator, the identity-and-access "
        "platform built for HealthLine Regional Medical Center throughout the capstone. It identifies which "
        "regulations apply and why, defines the regulatory vocabulary used across the compliance program, maps the "
        "organization's business processes to concrete requirements, sets out a compliance program plan with roles "
        "and a timeline, and documents two controls with implementation and testing procedures. Where a control "
        "already exists in the capstone (Keycloak RBAC, Azure governance, monitoring), the evidence is referenced "
        "rather than invented.")]
s += [P("Organization profile", "h2")]
s += table([["Attribute", "Care Access Navigator / HealthLine"]] + [list(r) for r in PROFILE],
           [1.6 * inch, 4.9 * inch])

# ------------------------------------------------------------------ 1. regulations
s += [CondPageBreak(3.5 * inch), P("1. Applicable Regulations", "h1"),
      P("Candidate frameworks were screened against HealthLine's legal status, data and business activities. Two "
        "frameworks apply directly and form the basis of this program; the others were considered and documented "
        "as out of scope so the decision can be revisited if the business changes.")]
s += table([["Framework", "Type", "Status", "Applicability rationale"]] + [list(f) for f in FRAMEWORKS],
           [1.15 * inch, 1.45 * inch, 0.85 * inch, 3.05 * inch])
s += [P("1.1 HIPAA at a glance", "h2")]
s += table([
    ["Rule", "Citation", "What it requires of HealthLine / CAN"],
    ["Privacy Rule", "45 CFR 164.500–534", "Uses and disclosures of PHI, minimum necessary, patient rights, "
     "privacy official, workforce training, sanctions"],
    ["Security Rule", "45 CFR 164.302–318", "Administrative, physical and technical safeguards for ePHI; risk "
     "analysis; documentation retained 6 years"],
    ["Breach Notification Rule", "45 CFR 164.400–414", "Notify individuals, HHS and (if >500 in a state) media "
     "after a breach of unsecured PHI"],
    ["Enforcement Rule", "45 CFR 160 Subparts C–E", "HHS OCR investigations and tiered civil money penalties "
     "(inflation-adjusted annually)"],
], [1.4 * inch, 1.45 * inch, 3.65 * inch])
s += [P("1.2 PCI DSS v4.0.1 at a glance", "h2")]
s += table([
    ["Goal", "Req.", "Relevance to CAN"],
    ["Build and maintain a secure network", "1–2", "Network security controls around the cardholder data "
     "environment (CDE); secure configurations"],
    ["Protect account data", "3–4", "Do not store sensitive authentication data; encrypt PAN in transit (4.2.1)"],
    ["Vulnerability management", "5–6", "Anti-malware, secure development of the Billing App, patching"],
    ["Strong access control", "7–9", "Least-privilege roles (7.2), unique IDs and MFA (8.3, 8.4), physical access"],
    ["Monitor and test networks", "10–11", "Audit logs, daily review, 12-month retention (10.5.1); scanning, "
     "penetration tests"],
    ["Information security policy", "12", "Policies, risk analysis, awareness training, incident response (12.10)"],
], [2.0 * inch, 0.95 * inch, 3.55 * inch])
s += note("CAN reduces PCI scope by never storing card numbers: the Billing App embeds a PCI-validated payment "
          "processor's hosted payment fields, so card data goes directly to the processor and only a token and the "
          "last four digits return to HealthLine. The Billing App web server still affects the security of the "
          "payment page, so it stays in scope (assessed with a Self-Assessment Questionnaire rather than a full "
          "Report on Compliance).", "Scope decision")

# ------------------------------------------------------------------ 2. terminology
s += [P("2. Regulatory Terminology (applied)", "h1")]
s += table([
    ["Term", "Definition", "In Care Access Navigator"],
    ["Covered entity (CE)", "Health plan, clearinghouse, or provider that transmits health information "
     "electronically in standard transactions", "HealthLine Regional Medical Center"],
    ["Business associate (BA) / BAA", "A person or vendor that handles PHI on a CE's behalf; bound by a business "
     "associate agreement", "Cloud/identity providers, the payment processor (for PHI-bearing data), IT vendors"],
    ["PHI / ePHI", "Individually identifiable health information; ePHI is PHI in electronic form",
     "EHR Simulator records, Patient Portal messages, billing statements with diagnosis/visit data"],
    ["Minimum necessary", "Use or disclose only the PHI needed for the purpose", "Billing role sees billing data, not "
     "clinical notes (Keycloak client scopes)"],
    ["Required vs addressable", "Security Rule specifications that must be implemented vs those implemented if "
     "reasonable and appropriate (or documented alternative)", "Encryption (§164.312(e)(2)(ii)) is "
     "addressable; HealthLine chooses to implement it"],
    ["Breach / unsecured PHI", "Impermissible use or disclosure that compromises PHI, unless a low probability of "
     "compromise is shown; unsecured = not encrypted to HHS guidance", "Triggers the incident and notification "
     "process (Task 5)"],
    ["Cardholder data (CHD) / PAN", "Primary account number plus name, expiry, service code", "Entered by patients "
     "into processor-hosted fields only"],
    ["Sensitive authentication data (SAD)", "CVV, PIN, full track data — never stored after authorization",
     "Never touches HealthLine systems"],
    ["Cardholder data environment (CDE)", "People, processes and technology that store, process or transmit CHD or "
     "can affect its security", "Billing App web tier and payment page"],
    ["SAQ / QSA / ASV", "Self-assessment questionnaire / qualified security assessor / approved scanning vendor",
     "Annual SAQ; quarterly external ASV scans"],
    ["Compensating control", "Alternative control meeting the intent of a PCI requirement when the original cannot "
     "be met", "Documented via the controls worksheet if ever used"],
], [1.35 * inch, 2.75 * inch, 2.4 * inch])

# ------------------------------------------------------------------ 3. requirements analysis
s += [CondPageBreak(3.5 * inch), P("3. Compliance Requirements Analysis", "h1"),
      P("The analysis uses a standard template (below) and maps each core business process to the data it touches, "
        "the systems and roles involved, and the specific HIPAA and PCI DSS requirements that apply. Process owners "
        "use it to see exactly which obligations sit in their area.")]
s += doc_control("CAN-COMP-RA-001", "Compliance Requirements Analysis")
s += [P("Business process map — patient billing and payment", "h2"),
      P("The swimlane shows where ePHI and card data flow, which roles touch them, and the PCI scope boundary "
        "(dashed). Steps inside the boundary are subject to PCI DSS; every step that touches ePHI is subject to "
        "HIPAA.")]
lanes = ["Patient", "Front desk / Billing (Billing role)", "CAN systems", "Payment processor (PCI-validated)"]
steps = {
    "a": (0, 0, "Visit / portal login", "identity verified", D_GREY),
    "b": (1, 1, "Review balance", "Billing App (ePHI)", D_CREAM),
    "c": (2, 1, "Keycloak RBAC", "billing role only", D_GREY),
    "d": (0, 2, "Enters card", "hosted payment fields", D_CREAM),
    "e": (3, 2, "Authorize", "PAN never at HealthLine", D_GREY),
    "f": (2, 3, "Store token + last 4", "audit log written", D_GREY),
    "g": (1, 4, "Post payment", "receipt to patient", D_CREAM),
}
arrows = [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e"), ("e", "f"), ("f", "g")]
s += fig(swimlane(lanes, steps, arrows, cols=5, zones=[(0, 3, 2, 3, "PCI DSS scope (CDE)")]),
         "Patient billing and card-payment process with data flows and PCI scope boundary.")
s += [P("Requirements by business process", "h2")]
s += table([
    ["Business process", "Data / systems", "Roles", "HIPAA requirements", "PCI DSS requirements", "Owner"],
    ["Patient identity and portal access", "ePHI; Patient Portal, Keycloak", "Patient, Clinician, Nurse",
     "§164.312(d) authentication; §164.524 right of access", "8.3 authentication (if in CDE)",
     "IAM Analyst"],
    ["Clinical documentation", "ePHI; EHR Simulator", "Clinician, Nurse", "§164.312(a)(1) access control; "
     "§164.312(b) audit; minimum necessary §164.502(b)", "Out of scope", "Clinical Ops Mgr"],
    ["Billing and card payment", "ePHI + CHD; Billing App, processor", "Billing", "§164.506 payment use; "
     "§164.312(e)(1) transmission", "3.2/3.3 no SAD storage; 4.2.1 TLS; 6.4.3 payment-page scripts; 10.2",
     "Revenue Cycle Mgr"],
    ["Workforce access lifecycle (JML)", "Workforce PII; HR App, Keycloak, Entra ID", "HR, IT Support",
     "§164.308(a)(3)(ii)(B)–(C) clearance and termination", "7.2.4 6-monthly review; 8.2.6 inactive "
     "accounts", "HR / IAM Analyst"],
    ["Vendor and remote access", "Varies; Keycloak Vendor role", "Vendor, Vendor Mgr", "§164.308(b)(1) BAAs; "
     "§164.314(a)", "8.2.7 vendor remote access enabled only when needed; 12.8 TPSP oversight",
     "Vendor Manager"],
    ["Security monitoring and incidents", "Logs; Azure Monitor, Defender", "Security Analyst",
     "§164.308(a)(1)(ii)(D) activity review; §164.308(a)(6)", "10.4.1 daily review; 12.10 IR plan",
     "Security Officer"],
], [1.1 * inch, 1.05 * inch, 0.8 * inch, 1.35 * inch, 1.35 * inch, 0.85 * inch])

# ------------------------------------------------------------------ 4. program plan
s += [CondPageBreak(3.5 * inch), P("4. Compliance Program Plan", "h1"),
      P("The plan follows the elements of an effective compliance program (written standards, a designated officer "
        "and committee, training, monitoring and auditing, reporting channels, enforcement, and response). HIPAA "
        "itself requires named privacy and security officials, so those roles are explicit.")]
s += doc_control("CAN-COMP-PLN-001", "Compliance Program Plan FY2027")
s += [P("4.1 Organizational roles", "h2")]
s += fig(org_chart(
    [[("Board of Trustees", "audit & compliance committee")],
     [("Program Sponsor", "COO")],
     [("Chief Compliance Officer", "program lead"), ("Internal Audit", "independent assurance")],
     [("Privacy Officer", "HIPAA §164.530(a)"), ("Security Officer", "HIPAA §164.308(a)(2); PCI"),
      ("GRC Analyst", "controls & evidence"), ("Vendor Manager", "BAAs, TPSPs")],
     [("IAM Analyst", "RBAC, reviews"), ("Security Analyst", "monitoring, IR"), ("Dept. compliance liaisons", "dotted line"), ("Training coordinator", "with HR")]],
    [[0], [0, 0], [0, 0, 0, 0], [1, 1, 0, 0]], highlight={(3, 2)}),
    "Compliance program organization chart (highlighted: author's role).")
s += table([["Role", "Responsibilities"]] + [list(r) for r in ROLES], [1.9 * inch, 4.6 * inch])
s += [P("4.2 RACI for core program activities", "h2")]
s += table([
    ["Activity", "CCO", "Priv.", "Sec.", "GRC", "IAM", "Mgrs", "Audit"],
    ["Annual HIPAA risk analysis", "A", "C", "R", "R", "C", "I", "I"],
    ["Policy development and approval", "A", "R", "R", "R", "C", "C", "I"],
    ["Access reviews (AC-01)", "I", "I", "A", "C", "R", "R", "I"],
    ["Log review and alerting (LOG-01)", "I", "I", "A", "C", "I", "—", "I"],
    ["Workforce training", "A", "R", "R", "C", "—", "R", "I"],
    ["PCI DSS SAQ and ASV scans", "A", "—", "R", "R", "C", "I", "C"],
    ["Breach risk assessment and notification", "A", "R", "C", "C", "—", "I", "I"],
    ["Compliance audits", "I", "C", "C", "R", "C", "C", "A"],
], [2.1 * inch, 0.55 * inch, 0.6 * inch, 0.65 * inch, 0.5 * inch, 0.5 * inch, 0.75 * inch, 0.85 * inch])
s += [P("R = responsible, A = accountable, C = consulted, I = informed.", "caption")]
s += [P("4.3 Implementation timeline", "h2")]
g = [("1 Charter, officers, committee", 0, 1, D_NAVY), ("2 Risk analysis (HIPAA + PCI)", 0, 2, D_AMBER),
     ("3 Policy set v1.0 approved", 1, 3, D_AMBER), ("4 Controls AC-01, LOG-01, ENC-01", 2, 4, D_GREEN),
     ("5 Workforce training rollout", 3, 3, D_GREEN), ("6 BAA and vendor inventory", 2, 3, D_AMBER),
     ("7 First access review cycle", 4, 1, D_GREEN), ("8 Internal compliance audit", 6, 2, D_NAVY),
     ("9 Remediation of findings", 7, 3, D_AMBER), ("10 PCI SAQ + ASV scans", 8, 2, D_NAVY),
     ("11 Program effectiveness review", 10, 2, D_NAVY)]
s += fig(gantt(g, MONTHS, milestone=(11, "Board report")), "Compliance program implementation timeline, "
         "November 2026 – October 2027.")
s += table([
    ["Phase", "Window", "Exit criteria"],
    ["Establish", "Nov–Dec 2026", "Charter signed; officers appointed; committee meeting held; risk analysis "
     "started"],
    ["Design", "Dec 2026–Mar 2027", "Policy set approved; control owners assigned; BAA inventory complete"],
    ["Implement", "Jan–May 2027", "Controls operating; 95% of workforce trained; first access review done"],
    ["Assure", "May–Aug 2027", "Internal audit complete; findings in remediation tracker"],
    ["Improve", "Aug–Oct 2027", "SAQ submitted; effectiveness review and Board report delivered"],
], [1.0 * inch, 1.4 * inch, 4.1 * inch])

# ------------------------------------------------------------------ 5. two controls
s += [CondPageBreak(3.5 * inch), P("5. Documented Compliance Controls", "h1"),
      P("Two controls were selected because they address the highest-rated risks in the capstone risk register "
        "(excessive RBAC privileges and logging/monitoring weakness) and satisfy both frameworks at once.")]
for cid, objective, impl, test, evid in [
    ("AC-01",
     "Each workforce member receives only the access their job requires, approved by their manager, and access is "
     "re-certified at least every six months (quarterly for privileged roles).",
     ["Define the role catalogue (7 roles) and the data each role may reach; record in the access control matrix.",
      "Implement roles in Keycloak; restrict each application with client scopes (fullScopeAllowed = false).",
      "Assign roles from the authoritative source: Entra ID app roles map to Keycloak realm roles (Force sync).",
      "Require manager approval (ticket) for every new role; HR events drive joiner/mover/leaver changes.",
      "Every quarter, export role assignments; managers certify or revoke within 10 business days.",
      "IAM Analyst removes revoked access within 2 business days and records the evidence."],
     [("Design — inspection", "Compare the role catalogue with Keycloak role and client-scope configuration."),
      ("Operating — re-performance", "Sign in as a test user per role and confirm the token holds only the "
       "expected role and the application rejects other areas."),
      ("Operating — sampling", "Select 25 (or all, if fewer) role changes; confirm a manager approval exists."),
      ("Review completion", "Confirm the latest access review was signed off and revocations were completed.")],
     "CloudSec1 Criterion 4 addendum (Billing user → billing only; Nurse user → nurse only); "
     "audit evidence E-AC-01 (Task 3)."),
    ("LOG-01",
     "Security-relevant events are logged centrally, high-risk events alert the security team automatically, and "
     "logs are reviewed daily and retained 12 months (3 months immediately available).",
     ["Enable control-plane logging (Azure Activity Log) and application/IdP event logging (Keycloak events).",
      "Forward logs to the central log platform; set retention to 12 months.",
      "Create alert rules for firewall changes, privilege grants, key retrieval, policy removal and threat "
      "detections; route to the security on-call mailbox.",
      "Security Analyst reviews alerts and the daily summary each business day; record the review.",
      "Investigate per the incident-response playbook; tune noisy rules monthly."],
     [("Design — inspection", "Inspect log sources, retention settings and alert-rule definitions."),
      ("Operating — re-performance", "Generate a benign test event (e.g., a firewall rule change in a lab) "
       "and confirm the alert fires and is received."),
      ("Operating — sampling", "Select 10 business days; confirm a documented log review exists for each."),
      ("Retention", "Confirm the oldest log available is at least 12 months old (or since go-live).")],
     "CloudSec1 Criterion 6 (8 alert rules, incident INC-20261008-01 detected); audit evidence E-LOG-01 (Task 3)."),
]:
    name, hipaa, pci = CONTROLS[cid]
    s += step(cid, name, prefix="")
    s += table([["Attribute", "Detail"],
                ["Control objective", objective], ["HIPAA", hipaa], ["PCI DSS", pci],
                ["Type / frequency", "Preventive + detective / continuous with quarterly review" if cid == "AC-01"
                 else "Detective / continuous with daily review"],
                ["Owner", "IAM Analyst (operator); Security Officer (accountable)" if cid == "AC-01"
                 else "Security Analyst (operator); Security Officer (accountable)"],
                ["Existing evidence", evid]], [1.4 * inch, 5.1 * inch])
    s += [P("<b>Implementation procedure</b>")]
    s += [Paragraph(f"{i}. {t}", ss["bullet"]) for i, t in enumerate(impl, 1)]
    s += [Spacer(1, 6), P("<b>Testing methods</b>")]
    s += table([["Test", "Method"]] + [list(t) for t in test], [1.7 * inch, 4.8 * inch])

s += [P("Summary", "h1"),
      P("HIPAA and PCI DSS both apply to Care Access Navigator; GDPR, SOX and 42 CFR Part 2 were assessed and "
        "documented as out of scope. The requirements analysis ties each business process to its obligations and "
        "owner, the program plan establishes accountable roles and a twelve-month timeline, and controls AC-01 and "
        "LOG-01 are documented with procedures and tests that the Task 3 audit executes against real evidence.")]

build(OUT, s, "CAN Compliance 1 - Task 1 Compliance Fundamentals", FOOT)
