"""Single source of truth for the Care Access Navigator compliance documents."""

ORG = "HealthLine Regional Medical Center"
PLATFORM = "Care Access Navigator (CAN)"
AUTHOR = "Akhila Chennamaneni"
AUTHOR_ROLE = "GRC Analyst (author)"
COURSE = "Compliance 1"
DATE = "October 13, 2026"

PROFILE = [
    ("Organization", f"{ORG} — a fictional regional, not-for-profit acute-care hospital and outpatient network "
                     "(assumed to operate in New York State) used as the capstone scenario"),
    ("Platform in scope", f"{PLATFORM}: the identity and access layer and connected applications that let workforce "
                          "members and vendors reach clinical, billing and HR systems"),
    ("Applications", "EHR Simulator (synthetic ePHI), Patient Portal, Billing App (patient balances and co-pay card "
                     "payments), HR App, Keycloak identity provider federated with Microsoft Entra ID"),
    ("Workforce roles (RBAC)", "Clinician, Nurse, Billing, HR, IT Support, Security Analyst, Vendor"),
    ("Hosting", "Containerised apps and Keycloak; Microsoft Azure for identity federation, governance policy, "
                "monitoring and security tooling (CloudSec1 Criteria 3–6)"),
    ("Sensitive data", "Electronic protected health information (ePHI); payment card data at the point of co-pay "
                       "collection; workforce PII"),
]

# frameworks chosen
FRAMEWORKS = [
    ("HIPAA / HITECH", "Federal law (45 CFR Parts 160 and 164)", "Applies", "HealthLine is a HIPAA covered entity "
     "(health-care provider that bills electronically); CAN creates, receives and transmits ePHI."),
    ("PCI DSS v4.0.1", "Contractual standard (card brands via acquiring bank)", "Applies", "The Billing App accepts "
     "patient co-pay and balance payments by card; any merchant that stores, processes or transmits account data "
     "must comply."),
    ("GDPR", "EU regulation", "Not applicable", "No establishment in the EU and no offering of services to, or "
     "monitoring of, people in the EU."),
    ("SOX", "Federal securities law", "Not applicable", "Not-for-profit; no publicly traded securities. Internal-"
     "control practices are borrowed as good practice only."),
    ("42 CFR Part 2", "Federal regulation (SUD records)", "Not in scope", "Assumes no federally assisted substance-use-"
     "disorder program feeds CAN; to be re-checked if one is added."),
]

# compliance roles (also used for org charts / RACI)
ROLES = [
    ("Board of Trustees", "Ultimate oversight; approves compliance program charter and annual plan"),
    ("Program Sponsor (COO)", "Executive owner; funds the program; accepts residual High risk"),
    ("Chief Compliance Officer (CCO)", "Runs the compliance program; chairs the Compliance & Privacy Committee"),
    ("Privacy Officer", "HIPAA privacy official (§164.530(a)); breach risk assessments; patient rights"),
    ("Security Officer (CISO)", "HIPAA security official (§164.308(a)(2)); PCI DSS executive responsibility"),
    ("GRC Analyst", "Control matrix, evidence register, audits, compliance reporting"),
    ("IAM Analyst", "Identity, RBAC, access reviews in Keycloak / Entra ID"),
    ("Security Analyst", "Monitoring, alert triage, incident response"),
    ("Department Managers", "Approve access; complete access reviews; enforce training"),
    ("HR / Workforce Admin", "Joiner-mover-leaver events, sanctions, training records"),
    ("Vendor Manager", "Business associate agreements (BAAs); PCI service-provider oversight"),
    ("Internal Audit", "Independent assurance; reports to the Board audit committee"),
]

# the two documented controls (Task 1) and the three audited controls (Task 3)
CONTROLS = {
    "AC-01": ("Role-based access control and periodic access review",
              "HIPAA §164.308(a)(4)(ii)(B)–(C), §164.312(a)(1)", "PCI DSS 7.2.1, 7.2.2, 7.2.4, 7.2.5"),
    "LOG-01": ("Security event logging, alerting and log review",
               "HIPAA §164.312(b), §164.308(a)(1)(ii)(D)", "PCI DSS 10.2.1, 10.4.1, 10.5.1"),
    "ENC-01": ("Encryption of data in transit (TLS 1.2+)",
               "HIPAA §164.312(e)(1), (e)(2)(ii)", "PCI DSS 4.2.1"),
}

# implementation timeline (months from Nov 2026)
MONTHS = ["Nov 26", "Dec 26", "Jan 27", "Feb 27", "Mar 27", "Apr 27", "May 27", "Jun 27", "Jul 27", "Aug 27",
          "Sep 27", "Oct 27"]


# ---------------------------------------------------------------- monitoring / reporting data (Tasks 3-4)
# (id, finding, rating, requirement, owner, target ISO date, % complete, evidence)
FINDINGS = [
    ("F-01", "MFA not enforced for privileged / CDE access", "High", "HIPAA 164.312(d); PCI 8.4.2", "IAM Analyst",
     "2026-11-06", 0, "E-AC-02"),
    ("F-02", "Account lockout (brute-force protection) disabled", "High", "PCI 8.3.4", "IAM Analyst",
     "2026-10-23", 0, "E-AC-02"),
    ("F-03", "No 12-month central log retention", "High", "HIPAA 164.312(b); PCI 10.5.1", "Security Officer",
     "2026-11-30", 0, "E-LOG-01"),
    ("F-04", "Password length 10 / history 3 below PCI minimum", "Medium", "PCI 8.3.6, 8.3.7", "IAM Analyst",
     "2026-10-23", 0, "E-AC-02"),
    ("F-05", "No completed access review / daily log review records", "Medium", "PCI 7.2.4, 10.4.1",
     "IAM / Security Analyst", "2026-12-15", 10, "Inquiry"),
    ("F-06", "Identity provider over HTTP in lab", "Low", "HIPAA 164.312(e)(1); PCI 4.2.1", "IT Support",
     "2027-01-31", 0, "E-ENC-01"),
]

# (id, KPI, definition / formula, target, amber threshold, current value, unit, source, frequency, owner, measured?)
KPIS = [
    ("K-01", "Asset tagging compliance", "Resources + RGs with all 3 mandatory tags / total", 100, 95, 100.0, "%",
     "Azure Resource Graph", "Daily (Azure Policy)", "GRC Analyst", "Measured 2026-10-13: 19/19"),
    ("K-02", "Guardrail policy compliance", "Compliant evaluations / total for can-guardrails", 100, 95, 100.0, "%",
     "Azure Policy", "Daily", "Security Officer", "Measured 2026-10-08: 31/31"),
    ("K-03", "Least-privilege accounts", "Workforce accounts holding exactly one approved role / total", 100, 95,
     100.0, "%", "Keycloak extract", "Quarterly", "IAM Analyst", "Measured 2026-10-13: 9/9"),
    ("K-04", "MFA coverage (privileged + CDE)", "In-scope accounts forced through MFA / in-scope accounts", 100, 90,
     0.0, "%", "Keycloak flows", "Monthly", "IAM Analyst", "Measured 2026-10-13: flow not bound"),
    ("K-05", "Security alert rules enabled", "Enabled alert rules / defined alert rules", 100, 90, 100.0, "%",
     "Azure Monitor", "Weekly", "Security Analyst", "Measured 2026-10-13: 7/7"),
    ("K-06", "Log retention vs requirement", "Days of centrally retained logs / 365", 100, 50, 24.7, "%",
     "Log platform", "Monthly", "Security Officer", "Measured 2026-10-13: 90/365"),
    ("K-07", "Audit test pass rate", "Passed audit tests / tests performed", 90, 75, 53.3, "%", "Audit CAN-IA-2026-01",
     "Per audit", "GRC Analyst", "Measured 2026-10-13: 8/15"),
    ("K-08", "High findings overdue", "Open High findings past target date", 0, 1, 0, "count", "Remediation tracker",
     "Weekly", "GRC Analyst", "Measured 2026-10-13"),
    ("K-09", "Mean time to detect (MTTD)", "Avg minutes from security event to alert", 15, 30, 7.5, "min",
     "Incident records", "Per incident", "Security Analyst", "INC-20261008-01"),
    ("K-10", "Workforce training completion", "Workforce who completed required modules / workforce", 95, 85, None,
     "%", "LMS", "Monthly", "Privacy Officer", "Starts Mar 2027 (baseline pending)"),
    ("K-11", "Access reviews completed on time", "Reviews certified by deadline / reviews due", 95, 85, None, "%",
     "Review tickets", "Quarterly", "IAM Analyst", "First review due 2026-12-15"),
]

# (record type, regulation / driver, retention, storage, access, owner, disposal)
RETENTION = [
    ("Compliance policies, procedures (all versions)", "HIPAA 164.316(b)(2)(i)", "6 years from last effective date",
     "Policy portal (versioned)", "All staff read; GRC edit", "GRC Analyst", "Secure delete after review"),
    ("Risk analyses and risk register", "HIPAA 164.316(b)(2)(i); 164.308(a)(1)", "6 years", "GRC repository",
     "Compliance team", "GRC Analyst", "Secure delete"),
    ("Audit reports and evidence packs", "HIPAA 164.316; Internal Audit standards", "6 years", "Evidence repository "
     "(WORM)", "Compliance + Internal Audit", "Internal Audit", "Secure delete"),
    ("Security audit logs (CDE)", "PCI DSS 10.5.1", "12 months (3 months online)", "Central log platform",
     "Security team (read-only)", "Security Officer", "Automatic expiry"),
    ("Security audit logs (ePHI systems)", "HIPAA 164.312(b) (policy-set)", "6 years (summaries); 12 months raw",
     "Central log platform + archive", "Security team", "Security Officer", "Automatic expiry"),
    ("Access requests, reviews, certifications", "HIPAA 164.308(a)(4); PCI 7.2.4", "6 years", "Ticketing + evidence "
     "repository", "IAM + managers", "IAM Analyst", "Secure delete"),
    ("Training records and attestations", "HIPAA 164.530(b)(2), 164.530(j)", "6 years", "LMS", "HR + Privacy",
     "Privacy Officer", "LMS purge"),
    ("Incident and breach records, notifications", "HIPAA 164.530(j); 164.414 burden of proof", "6 years",
     "Incident system", "Privacy + Security", "Privacy Officer", "Secure delete"),
    ("Business associate agreements", "HIPAA 164.316, 164.504(e)", "6 years after termination", "Contract system",
     "Legal + Vendor Mgr", "Vendor Manager", "Secure delete"),
    ("Medical records (EHR)", "NY 10 NYCRR 405.10", "6 years after discharge, or 3 years after age 18, whichever is "
     "longer", "EHR system", "Clinical roles (RBAC)", "HIM Director", "NIST SP 800-88 purge"),
    ("PCI SAQ, AOC, ASV scan reports", "PCI DSS 12.4, 11.3.2", "3 years (policy-set)", "Compliance repository",
     "Security + Compliance", "Security Officer", "Secure delete"),
]

# (doc id, title, version, owner, approver, effective, next review, distribution, classification, location)
DOCS = [
    ("CAN-COMP-RA-001", "Compliance Requirements Analysis", "1.0", "GRC Analyst", "CCO", "2026-10-13", "2027-10-13",
     "Committee, control owners", "Internal", "Task 1 PDF"),
    ("CAN-COMP-PLN-001", "Compliance Program Plan FY2027", "1.0", "CCO", "Program Sponsor", "2026-11-01",
     "2027-10-01", "Committee, Board", "Internal", "Task 1 PDF"),
    ("CAN-COMP-GOV-001", "Compliance Governance Charter & Communication Plan", "1.0", "CCO", "Board committee",
     "2026-11-01", "2027-11-01", "Committee, Board", "Internal", "Task 2 PDF"),
    ("CAN-POL-AC-001", "Access Control and Identity Management Policy", "1.0", "Security Officer", "Committee + COO",
     "2026-12-01", "2027-12-01", "All workforce, vendors", "Internal", "Task 2 PDF"),
    ("CAN-PRC-AC-002", "Quarterly User Access Review Procedure", "1.0", "IAM Analyst", "Security Officer",
     "2027-01-01", "2028-01-01", "IAM, managers, GRC", "Internal", "Task 2 PDF"),
    ("CAN-TRN-PLN-001", "Compliance Training Plan", "1.0", "Privacy Officer", "CCO", "2027-01-01", "2028-01-01",
     "HR, managers", "Internal", "Task 2 PDF"),
    ("CAN-AUD-2026-01", "Internal Compliance Audit Report (IAM & monitoring)", "1.0", "GRC Analyst",
     "Internal Audit", "2026-10-20", "Follow-up Jan 2027", "Committee, Board", "Confidential", "Task 3 PDF"),
    ("CAN-RPT-STS-Q4", "Compliance Status Report Q4 2026", "1.0", "CCO", "Program Sponsor", "2026-10-20",
     "Quarterly", "Executives, Board", "Confidential", "Task 4 PDF"),
    ("CAN-REC-RET-001", "Records Retention Schedule", "1.0", "GRC Analyst", "CCO", "2026-11-01", "2027-11-01",
     "All record owners", "Internal", "Task 4 PDF / tracker"),
    ("CAN-PLB-IR-001", "Incident Response Playbook", "1.0", "Security Officer", "CCO", "2026-10-08", "2027-10-08",
     "Security, Privacy, IT", "Confidential", "CloudSec1 can-secops"),
    ("CAN-LGL-OBL-001", "Compliance Obligations Matrix", "1.0", "Privacy Officer", "CCO + counsel", "2026-11-01",
     "2027-11-01", "Compliance team", "Internal", "Task 5 PDF"),
]
