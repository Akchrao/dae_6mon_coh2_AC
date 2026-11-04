"""Shared facts for the Care Access Navigator Weeks 5-12 GRC deliverables.

One source of truth for the registers (authentication baseline, privileged access matrix,
service/vendor identities, control catalog, exceptions, corrective actions, evidence index).
Live results are read from the evidence folders, not typed in: see live().
Builders: build_workbooks.py (xlsx), build_w5_pdf.py, build_e2e_pdf.py, build_tableau.py.
"""
import csv, hashlib, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
CAN = os.path.dirname(os.path.dirname(HERE))                      # Care_Access_Navigator/
REPO = os.path.dirname(CAN)
EV13 = os.path.join(CAN, "06_Evidence", "04_Test_Results", "EV-13_Auth_Hardening_Live_20261103")
EV14 = os.path.join(CAN, "06_Evidence", "04_Test_Results", "EV-14_End_to_End_Tests_20261103")

ORG = "HealthLine Regional Medical Center (HRMC)"
PROJECT = "Care Access Navigator"
AUTHOR = "Akhila Chennamaneni"
DATE = "November 3, 2026"
ISO_DATE = "2026-11-03"


def audit_log(folder):
    with open(os.path.join(folder, "can_iam_audit_log.jsonl")) as f:
        return [json.loads(l) for l in f if l.strip()]


def live():
    """Before/after facts pulled from the EV-13 audit log (Week 5 live run)."""
    log = audit_log(EV13)
    first = lambda act, **m: next(r for r in log if r["action"] == act and all(r.get(k) == v for k, v in m.items()))
    verify = [r for r in log if r["action"] == "VERIFY.login"]
    harden_ts = first("harden.realm_settings")["ts_utc"]
    before = [r for r in verify if r["ts_utc"] < harden_ts]
    after = [r for r in verify if r["ts_utc"] > harden_ts]
    lock = [r for r in log if r["action"] == "VERIFY.lockout"]
    return {
        "realm": first("harden.realm_settings"),
        "mfa": first("harden.mfa"),
        "misplaced": [r for r in log if r["action"] == "harden.mfa_removed_misplaced_condition"],
        "migrated": [r for r in log if r["action"] == "harden.migrate_user"],
        "skipped": [r for r in log if r["action"] == "harden.migrate_skip"],
        "gate": [r for r in log if r["action"] == "APP_GATE.bound"],
        "before": before, "after": after,
        "lock_before": lock[0], "lock_after": lock[-1],
        "pw": [r for r in log if r["action"] == "VERIFY.password_policy"],
        "detect": [r for r in log if r["action"] == "DETECT.run"][-1],
        "harden_ts": harden_ts,
    }


def e2e():
    with open(os.path.join(EV14, "e2e_results.json")) as f:
        return json.load(f)


def review_rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


# ---------------------------------------------------------------- Week 5 Day 1: authentication control baseline
# (id, control, standard set, before 11/03, after 11/03, how verified, requirement refs, status)
AUTH_BASELINE = [
    ("AUTH-01", "MFA for privileged and cardholder-data roles",
     "OTP (TOTP) required for Billing, IT-Support and Security-Analysts at every browser sign-in; users without an "
     "authenticator are forced to enrol",
     "Flow browser-mfa-privileged existed but was bound to nothing; its OTP step only ran for users who had already "
     "set up OTP; realm browser flow = browser (F-01)",
     "Realm browser flow = browser-mfa-privileged; condition = realm role mfa-required (held by the 3 privileged groups)",
     "test.billing2 sign-in to billing-app: LOGGED_IN before, MFA_REQUIRED after",
     "HIPAA 164.312(d); PCI DSS 8.4.1-8.4.2; NIST 800-53 IA-2(1)", "Enforced"),
    ("AUTH-02", "Account lockout (brute-force protection)",
     "Temporary lockout after 10 failures for 30 minutes; failures counted over 12 hours",
     "bruteForceProtected = false (F-02)", "bruteForceProtected = true, failureFactor 10, wait 1800 s",
     "11 wrong passwords on test.vendor1: not locked before; locked after 10 failures after",
     "PCI DSS 8.3.4; NIST 800-53 AC-7", "Enforced"),
    ("AUTH-03", "Password standard",
     "12+ characters, upper, lower, digit, special; cannot reuse last 4",
     "length(10), history 3 (F-04)", "length(12), history 4",
     "Admin reset to an 11-character password rejected; reuse of the current password rejected",
     "PCI DSS 8.3.6-8.3.7; HIPAA 164.308(a)(5)(ii)(D); NIST 800-53 IA-5(1)", "Enforced"),
    ("AUTH-04", "Per-application sign-in gate",
     "Only approved job roles may sign in to each app (Billing -> billing-app; Clinician/Nurse -> EHR and Patient "
     "Portal; HR/IT-Support -> HR app)",
     "Any realm user could sign in to any app (scopes only trimmed the token)",
     "4 gate flows bound (gate-<app>); denied users see 'Access denied'",
     "test.clinician2: EHR and Portal LOGGED_IN, Billing and HR DENIED after (EHR, Billing and HR all LOGGED_IN before)",
     "HIPAA 164.312(a)(1); PCI DSS 7.2.1; NIST 800-53 AC-3", "Enforced"),
    ("AUTH-05", "Group-based role assignment",
     "Access is granted by job-function group, never by a role attached directly to a person",
     "7 local users held a direct role as well as group membership",
     "Direct roles removed from all 7 local users; Entra users keep IdP-mapped roles (by design)",
     "Access review AR-AFTER-HARDEN-20261103: no DIRECT_ROLE_NOT_VIA_GROUP flags on local users",
     "HIPAA 164.308(a)(4)(ii)(B); NIST 800-53 AC-2, AC-6", "Enforced"),
    ("AUTH-06", "Session termination on role change and termination",
     "Mover and leaver sign the person out of every session immediately",
     "Manual (Entra 'revoke sessions' only during the JML cycle)",
     "can_iam.py mover / leaver call logout for the user", "TC-03 / TC-04 (end-to-end run)",
     "HIPAA 164.308(a)(3)(ii)(C); NIST 800-53 AC-2, AC-12", "Enforced"),
    ("AUTH-07", "Authentication and admin event logging",
     "Login and admin events stored with details; 90-day retention in Keycloak",
     "Events on; no expiry set", "eventsExpiration = 7,776,000 s (90 days); admin event details on",
     "Detection run read 146 login and 182 admin events", "HIPAA 164.312(b); PCI DSS 10.2.1; NIST 800-53 AU-2",
     "Enforced (12-month store: exception EX-02)"),
    ("AUTH-08", "Federated (Entra ID) users' MFA",
     "Entra users authenticate at Microsoft; MFA must be enforced there (Security defaults, free tier)",
     "Not evidenced", "Not evidenced (needs the Entra admin; see EX-01)", "Pending: Security defaults screenshot",
     "HIPAA 164.312(d); NIST 800-53 IA-2(1)", "Exception EX-01"),
    ("AUTH-09", "Identity provider transport encryption",
     "TLS 1.2+ for every sign-in", "HTTP (Keycloak start-dev) on localhost (F-06)", "Unchanged",
     "-", "HIPAA 164.312(e)(1); PCI DSS 4.2.1", "Exception EX-05"),
    ("AUTH-10", "Administrator (master realm) account",
     "Single named admin, MFA, lockout, reachable from localhost only",
     "admin without OTP; master realm lockout off; port 8080 published on all interfaces",
     "Unchanged (changing it could lock the only admin out of the lab)", "Keycloak master realm extract 11/03",
     "PCI DSS 8.4.1; NIST 800-53 AC-6(5), IA-2(1)", "Exception EX-03"),
]

# ---------------------------------------------------------------- Week 5 Day 2: privileged access matrix
# (id, account / role, system, privilege, holders 11/03, justification, approval, MFA, safeguards, monitoring,
#  review, status)
PRIVILEGED = [
    ("PA-01", "admin (master realm)", "Keycloak", "Full administrator of every realm, user and flow",
     "1: lab administrator (author)", "Builds and operates the IAM lab", "Security Officer (self-approved in lab)",
     "No (EX-03)", "Strong password kept in local .env (not in git since 11/03); realm export before every change",
     "Admin events (realm care-access-navigator); CAN-ID-005 on role/group changes; port bound to localhost (CA-11)", "Quarterly", "Gap: EX-03"),
    ("PA-02", "it-support (group IT-Support)", "Keycloak / hr-app",
     "User support; may sign in to hr-app", "test.itsupport1", "Workforce account support",
     "IT Manager + IAM Analyst", "Yes (enforced 11/03)", "Group-based; app gate", "CAN-ID-005 High on membership add",
     "Quarterly", "Enforced"),
    ("PA-03", "security-analyst (group Security-Analysts)", "Keycloak / SIEM",
     "Reads security events and detections; no app access", "test.secanalyst1", "Monitoring and investigation",
     "Security Officer", "Yes (enforced 11/03)", "Group-based; no application access", "CAN-ID-005 High on membership add",
     "Quarterly", "Enforced"),
    ("PA-04", "billing (group Billing)", "Keycloak / billing-app (PCI cardholder data)",
     "Card payments and patient billing records", "test.billing1, test.billing2, Tara Jones (Entra)",
     "Patient Financial Services", "Billing Manager", "Yes (local, enforced 11/03); Entra user: EX-01",
     "App gate: billing-app only", "CAN-ID-005 High on membership add; CAN-ID-004 on denied apps", "Quarterly",
     "Enforced"),
    ("PA-05", "Global Administrator", "Microsoft Entra ID tenant", "Full tenant administration",
     "1: tenant owner (author)", "Tenant set-up for OIDC federation", "Security Officer",
     "Verify (Security defaults: EX-01)", "Personal tenant; no other admins", "Entra audit log (JML-15 export)",
     "Quarterly", "Verify"),
    ("PA-06", "Owner (subscription)", "Microsoft Azure", "Full control of the subscription",
     "1: subscription owner (author)", "Cloud Security 1 labs; governance", "Security Officer",
     "Through Entra (EX-01)", "Billable resources deleted 2026-10-13; $1 budget alert can-zero-spend-guard",
     "Azure Activity Log (90 days)", "Quarterly", "Verify"),
    ("PA-07", "keycloak (PostgreSQL role)", "Keycloak database", "Database superuser",
     "Service only (no person)", "Keycloak needs its own database", "IT Support",
     "n/a (service)", "Port not published outside the Docker network; password in local .env",
     "None (lab)", "Annually + on staff change", "Rotate: CA-12"),
    ("PA-08", "it_admin (sudo)", "IR lab VM parrot-vm", "root through sudo", "Lab torn down 2026-11-03",
     "IR 1 exercise", "IT Manager", "n/a", "Unapproved sudo grant to Sathya Hasi removed in IR Task 6",
     "Wazuh rule 100231 (sudo use); IR1-2026-003", "Per exercise", "Retired with lab"),
    ("PA-09", "CISO Assistant superuser", "CISO Assistant (localhost:8443)", "GRC tool administrator",
     "1: author", "GRC tool evaluation", "Security Officer", "No", "localhost only; database not in git",
     "None", "Quarterly", "Low risk (local)"),
    ("PA-10", "bg-admin-01 (break-glass)", "Keycloak master realm", "Emergency full administrator",
     "Not provisioned", "Recover the lab if the admin or OTP fails", "Security Officer (two-person rule)",
     "No by design (sealed 24-character password, rotated after each use)", "Use alerts; single use",
     "Every sign-in is an incident", "After each use", "Designed only: EX-04"),
]

# privileged-access request lifecycle (12-week plan section 8)
PAM_PROCESS = [
    ("Request", "Requester names the privileged role, system, business reason and end date (ticket REQ-)"),
    ("Approve", "Manager approves the need; Security Officer approves the privilege (two approvals)"),
    ("Assign", "IAM Analyst adds the person to the privileged group only (never a direct role); OTP enrolment forced"),
    ("Monitor", "CAN-ID-005 raises High on any membership add to Billing, IT-Support or Security-Analysts"),
    ("Review / expire", "Quarterly access review; privilege removed at end date or on mover/leaver"),
]

# ---------------------------------------------------------------- Week 5 Day 3: service and vendor identities
# (id, identity, type, system, owner, credential, expiry / rotation, controls, review, status)
SERVICE_VENDOR = [
    ("SV-01", "billing-app", "OIDC client (public)", "Keycloak", "Billing application owner",
     "None (public client, browser code flow)", "n/a", "fullScopeAllowed=false; gate-billing-app; MFA flow",
     "Annually", "OK (enable PKCE: CA-15)"),
    ("SV-02", "ehr-simulator", "OIDC client (public)", "Keycloak", "Clinical application owner", "None (public client)",
     "n/a", "fullScopeAllowed=false; gate-ehr-simulator", "Annually", "OK (enable PKCE: CA-15)"),
    ("SV-03", "patient-portal", "OIDC client (public)", "Keycloak", "Clinical application owner", "None (public client)",
     "n/a", "fullScopeAllowed=false; gate-patient-portal", "Annually", "OK (enable PKCE: CA-15)"),
    ("SV-04", "hr-app", "OIDC client (public)", "Keycloak", "HR application owner", "None (public client)", "n/a",
     "fullScopeAllowed=false; gate-hr-app; MFA flow", "Annually", "OK (enable PKCE: CA-15)"),
    ("SV-05", "admin-cli (used by can_iam.py)", "Automation client", "Keycloak master realm", "IAM Analyst",
     "Admin username + password (password grant)", "Rotate with admin password",
     "Runs only from the lab Mac; every action written to the hashed audit log",
     "Quarterly", "Improve: dedicated service account with client credentials (CA-16)"),
    ("SV-06", "care-access-navigator-keycloak-broker", "Entra app registration (OIDC)", "Microsoft Entra ID",
     "IAM Analyst", "Client secret stored in Keycloak identity provider entra-id", "Check expiry in Entra (CA-17)",
     "Assignment required; app roles mapped to realm roles (sync FORCE)", "Before secret expiry", "Verify expiry"),
    ("SV-07", "keycloak (database)", "Database service account", "PostgreSQL 16", "IT Support",
     "Password in local .env", "Rotate (was in public git history: CA-12)", "Not reachable outside Docker network",
     "Annually", "Rotate"),
    ("SV-08", "Wazuh agent key (parrot-vm)", "Agent enrolment key", "Wazuh manager 4.9.2 (IR lab)", "Security Analyst",
     "Agent key", "Retired 2026-11-03", "Lab torn down", "n/a", "Retired"),
    ("VN-01", "test.vendor1 (Krish)", "Vendor workforce account", "Keycloak (group Vendors)", "Sponsor not recorded",
     "Password", "No access_end_date", "No application approved (all 4 apps deny Vendor)", "Quarterly",
     "Gap: set sponsor + end date or remove (CA-08)"),
    ("VN-02", "test.vendor2 (Omar Haddad, MedTech Services)", "Vendor workforce account", "Keycloak (group Vendors)",
     "it.manager1", "Password (temporary)", "access_end_date 2026-11-02", "Flagged ACCESS_PAST_END_DATE; leaver TERM-2026-0603",
     "Quarterly", "Disabled 2026-11-03 (TC-08)"),
]

VENDOR_RULES = [
    "Every vendor account has a named HRMC sponsor, a ticket and an access_end_date no more than 90 days out "
    "(can_iam.py refuses a vendor joiner without an end date).",
    "A signed Business Associate Agreement is on file before any access to systems that hold ePHI (HIPAA 164.308(b)).",
    "No application access by default: every app gate denies the Vendor role; access is granted per request and time-boxed.",
    "Access past the end date is flagged High by the access review (ACCESS_PAST_END_DATE) and alerted by CAN-ID-006 "
    "if used; the account is disabled with the leaver step.",
    "Service accounts have an owner, are never used by a person, and their secrets are rotated at least yearly and "
    "on any exposure.",
]

# ---------------------------------------------------------------- Week 9: control catalog + mappings + gap assessment
# (id, objective, area, HIPAA, CSF 2.0, SP 800-53 r5, ISO 27001:2022, PCI DSS 4.0.1, risks, evidence, test,
#  result 11/03, implementation, gap / follow-up)
CONTROLS = [
    ("AC-01", "Users receive only the access their job requires (RBAC, least privilege)", "IAM / RBAC",
     "164.308(a)(4)(ii)(B); 164.312(a)(1)", "PR.AA-05", "AC-2, AC-3, AC-6", "A.5.15, A.5.18", "7.2.1, 7.2.2",
     "R01", "EV-13 access reviews; TC-01", "TC-01; audit AC-01 tests 1-2", "PASS", "Implemented", "-"),
    ("AC-02", "Terminated users are disabled and all access removed promptly", "IAM / JML",
     "164.308(a)(3)(ii)(C)", "PR.AA-01, PR.AA-05", "AC-2, PS-4", "A.5.18, A.6.5", "8.2.5",
     "R02", "JML evidence (TERM-2026-0301); TC-04; TC-09", "TC-04; TC-09",
     "PASS (after CA-09)", "Implemented", "Leaver left the IdP-mapped role on the Keycloak copy; corrected (CA-09)"),
    ("AC-03", "Role changes remove old access before new access is granted", "IAM / JML",
     "164.308(a)(4)(ii)(C)", "PR.AA-05", "AC-2, PS-5", "A.5.18", "7.2.4",
     "R01", "JML evidence (CHG-2026-0201); TC-03", "TC-03", "PASS", "Implemented", "-"),
    ("AC-04", "Each application admits only approved job roles", "IAM / application access",
     "164.312(a)(1)", "PR.AA-05", "AC-3", "A.8.3", "7.2.1",
     "R01", "EV-13 app-gate verify; TC-02", "TC-02", "PASS", "Implemented", "-"),
    ("AC-05", "Privileged access is approved, limited and monitored", "IAM / PAM",
     "164.308(a)(4)(ii)(B)", "PR.AA-05", "AC-2(7), AC-6(5), AC-6(9)", "A.8.2", "7.2.2, 8.2.2",
     "R04", "Privileged access matrix; TC-07", "TC-07", "PASS",
     "Partially implemented", "Lab admin has no MFA (EX-03); break-glass designed only (EX-04)"),
    ("IA-01", "Privileged and cardholder-data users pass MFA", "Authentication",
     "164.312(d)", "PR.AA-03", "IA-2(1), IA-2(2)", "A.8.5", "8.4.1, 8.4.2",
     "R03", "EV-13 verify (MFA_REQUIRED)", "W5 verify; TC-03", "PASS", "Partially implemented",
     "Entra users' MFA not evidenced (EX-01); privileged users enrol at next sign-in (CA-13)"),
    ("IA-02", "Lockout after repeated failures; strong password standard", "Authentication",
     "164.308(a)(5)(ii)(D)", "PR.AA-03", "AC-7, IA-5(1)", "A.5.17, A.8.5", "8.3.4, 8.3.6, 8.3.7",
     "R03", "EV-13 lockout + password tests", "W5 verify; TC-05", "PASS", "Implemented", "-"),
    ("AR-01", "Access is reviewed periodically and findings are remediated", "IAM / GRC",
     "164.308(a)(4)(ii)(C); 164.308(a)(1)(ii)(D)", "PR.AA-05, ID.IM-01", "AC-2(j)", "A.5.18", "7.2.4, 7.2.5.1",
     "R01, R02", "access_review_*.csv; TC-09", "TC-09", "PASS", "Partially implemented",
     "Reviewer sign-off on AR-AFTER-HARDEN-20261103 pending (CA-05)"),
    ("VM-01", "Vendor access is sponsored, time-boxed and removed at expiry", "Third-party access",
     "164.308(b)(1); 164.314(a)", "GV.SC-07, PR.AA-05", "AC-2(2), PS-7", "A.5.19, A.5.20", "8.2.7",
     "R05", "Service/vendor identity register; TC-08", "TC-08", "PASS", "Partially implemented",
     "test.vendor1 has no end date or sponsor (CA-08)"),
    ("AU-01", "Security-relevant identity events are logged", "Monitoring",
     "164.312(b)", "DE.CM-03, PR.PS-04", "AU-2, AU-3, AU-12", "A.8.15", "10.2.1",
     "R03, R04", "keycloak_login_events.csv; Wazuh (IR lab)", "W5 detect run", "PASS", "Implemented", "-"),
    ("AU-02", "Alerts are raised and investigated", "Monitoring / IR",
     "164.308(a)(1)(ii)(D); 164.308(a)(6)(ii)", "DE.AE-02, DE.AE-06", "AU-6, SI-4", "A.8.16", "10.4.1",
     "R03, R04", "identity_detections.csv; IR1 Tasks 2-3", "TC-05, TC-06, TC-07", "PASS (TC-05 after CA-10)",
     "Implemented", "Brute-force rule suppressed repeat bursts; fixed (CA-10)"),
    ("AU-03", "Security logs are kept 12 months", "Monitoring / retention",
     "164.316(b)(2) (policy); 164.312(b)", "PR.PS-04", "AU-11", "A.8.15", "10.5.1",
     "R03", "Compliance E-LOG-01", "Audit LOG-01 test 3", "FAIL", "Not implemented",
     "Log Analytics removed for cost; exception EX-02, corrective action CA-03"),
    ("IR-01", "Incidents are handled with a tested playbook", "Incident response",
     "164.308(a)(6)(i)-(ii)", "RS.MA-01, RS.AN-03", "IR-4, IR-5, IR-8", "A.5.24-A.5.28", "12.10.1",
     "R03, R04", "IR1 Tasks 1-6; CAN-IR-PB-02", "IR1 Task 6 (34 checks)", "PASS", "Implemented", "-"),
    ("RA-01", "Security risks are identified, scored and treated", "GRC",
     "164.308(a)(1)(ii)(A)-(B)", "ID.RA-05, ID.RA-06", "RA-3, PM-9", "Clause 6.1.2, 6.1.3", "12.3.1",
     "R01-R05", "Risk register R01-R05 (Risk Management 1)", "Register review", "PASS", "Implemented",
     "Residual scores refreshed 11/03 (see risks.csv)"),
    ("CA-01", "Control gaps are tracked to verified remediation", "GRC",
     "164.308(a)(8)", "ID.IM-01, GV.OV-03", "CA-5, CA-7", "Clause 10.2", "12.4.2",
     "R01-R05", "Corrective action tracker; exception register", "TC-10", "PASS", "Implemented", "-"),
    ("SC-01", "ePHI and credentials are encrypted in transit (TLS 1.2+)", "Data protection",
     "164.312(e)(1), (e)(2)(ii)", "PR.DS-02", "SC-8, SC-8(1)", "A.8.24", "4.2.1",
     "R03", "Compliance E-ENC-01", "Audit ENC-01 tests 1-4", "PASS (Azure); EXCEPTION (IdP)",
     "Partially implemented", "Keycloak over HTTP in lab (EX-05, CA-06)"),
]

# ---------------------------------------------------------------- Week 10 Day 3: exception register
# (id, control, exception, business justification, compensating controls, risk, requested by, approved by,
#  approved, expires, status)
EXCEPTIONS = [
    ("EX-01", "IA-01", "Entra-federated users' MFA is enforced in Entra, and that setting is not yet evidenced",
     "Entra users authenticate at Microsoft; Keycloak's OTP step never runs for them",
     "Entra assignment required; app roles mapped with sync FORCE; leaver disables both copies",
     "R03", "IAM Analyst", "Security Officer", ISO_DATE, "2026-12-15", "Open: turn on Security defaults and screenshot"),
    ("EX-02", "AU-03", "Security logs kept 90 days, not 12 months (F-03)",
     "The Log Analytics workspace was removed on 2026-10-13 to stop charges ($0 credit, pay-as-you-go)",
     "Keycloak 90-day event store; detections and login events exported to CSV and SHA-256 indexed in git; "
     "Azure Activity Log 90 days", "R03", "Security Officer", "Security Officer", ISO_DATE, "2027-01-31",
     "Approved"),
    ("EX-03", "AC-05", "Lab administrator (master realm) has no MFA and the master realm has no lockout",
     "Single-person lab; turning on OTP for the only admin risks locking the lab and breaks the automation login",
     "Strong password in a local, untracked .env; realm export before every change; admin events; bind port to "
     "localhost (CA-11)", "R04", "IAM Analyst", "Security Officer", ISO_DATE, "2026-12-31", "Approved"),
    ("EX-04", "AC-05", "Break-glass account designed but not provisioned",
     "The lab has one administrator; a second unmonitored admin adds risk without a second operator",
     "Realm exports allow rebuild; admin password held offline", "R04", "IAM Analyst", "Security Officer", ISO_DATE,
     "2027-01-31", "Approved"),
    ("EX-05", "SC-01", "Keycloak serves sign-in over HTTP (start-dev) (F-06)",
     "Lab runs on localhost with synthetic data only", "No real ePHI; localhost; Azure storage enforces TLS 1.2",
     "R03", "IT Support", "Security Officer", "2026-10-13", "2027-01-31", "Approved"),
    ("EX-06", "IR-01", "IR 1 lab used Debian 12 under QEMU instead of Parrot OS on VirtualBox; no Wazuh dashboard",
     "No admin rights for VirtualBox on Apple silicon; real Wazuh manager and agent 4.9.2 used",
     "Each hypervisor step mapped to its VBoxManage equivalent", "-", "Student", "Instructor (pending)", "-",
     "2026-11-05", "Pending instructor acceptance"),
    ("EX-07", "IA-02", "Lab passwords were committed to the public repository before 2026-11-03",
     "Mistake; the .env file is now untracked and git-ignored",
     "Lab is localhost-only; .env.example holds placeholders", "R03", "IAM Analyst", "Security Officer", ISO_DATE,
     "2026-11-10", "Open: rotate (CA-12)"),
]

# ---------------------------------------------------------------- Week 10 Day 4: corrective actions to verification
# (id, source, issue, action, owner, due, status, verification criterion, verification evidence, verified on)
ACTIONS = [
    ("CA-01", "F-01", "MFA not enforced", "Bind browser-mfa-privileged realm-wide with role condition mfa-required",
     "IAM Analyst", "2026-11-06", "Verified", "Privileged sign-in shows the OTP step",
     "EV-13: test.billing2 billing-app MFA_REQUIRED", ISO_DATE),
    ("CA-02", "F-02", "Lockout disabled", "bruteForceProtected on, 10 failures, 30 minutes", "IAM Analyst",
     "2026-10-23", "Verified (late)", "11 wrong passwords lock the account", "EV-13 VERIFY.lockout PASS", ISO_DATE),
    ("CA-03", "F-03", "No 12-month log retention", "Archive identity and cloud logs to low-cost storage with a 365-day "
     "lifecycle rule (cost approval needed first)", "Security Officer", "2027-01-31", "Open (EX-02)",
     "Logs older than 90 days can be queried", "-", ""),
    ("CA-04", "F-04", "Password standard below PCI", "length(12), history 4", "IAM Analyst", "2026-10-23",
     "Verified (late)", "11-character and reused passwords rejected", "EV-13 VERIFY.password_policy", ISO_DATE),
    ("CA-05", "F-05", "No completed access review", "Run review; reviewer records a decision per account and signs",
     "IAM Analyst + managers", "2026-12-15", "In progress", "Every row has reviewer_decision, reviewer, date",
     "access_review_AR-AFTER-HARDEN-20261103.csv (decisions pending)", ""),
    ("CA-06", "F-06", "IdP over HTTP", "Put Keycloak behind a TLS reverse proxy", "IT Support", "2027-01-31",
     "Open (EX-05)", "Sign-in page served over HTTPS with TLS 1.2+", "-", ""),
    ("CA-07", "TC-07", "Vendor added to Billing without a ticket", "Remove the membership; investigate who made it",
     "IAM Analyst", ISO_DATE, "Verified", "Vendor holds only the vendor role", "EV-14 E2E.remediation TC-07", ISO_DATE),
    ("CA-08", "Access review", "test.vendor1 has no sponsor or end date", "Sponsor sets an end date or the account "
     "is removed with the leaver step", "IT Manager (sponsor)", "2026-11-10", "Open",
     "Review shows no VENDOR_NO_END_DATE", "-", ""),
    ("CA-09", "TC-09", "Leaver (Jeevan Smith) kept the billing role on the disabled Keycloak copy",
     "Remove the role under TERM-2026-0301; add the IdP-role check to the leaver procedure", "IAM Analyst", ISO_DATE,
     "Verified", "Re-review shows no DISABLED_BUT_HAS_ACCESS", "EV-14 AR-E2E-TC09-AFTER", ISO_DATE),
    ("CA-10", "TC-05", "Brute-force rule CAN-ID-001 alerted only once per user, ever",
     "Alert once per 10-minute burst", "Security Analyst", ISO_DATE, "Verified",
     "A new burst on the same user raises a new alert", "EV-14 TC-05 retest", ISO_DATE),
    ("CA-11", "EX-03", "Keycloak port 8080 published on all interfaces", "Publish as 127.0.0.1:8080 in docker-compose "
     "(and pin the compose project name so the existing database volume is kept)", "IT Support", "2026-11-10", "Verified",
     "Port not reachable from another host", "EV-13 audit log CA-11.applied; LAN-IP request refused; app checks still pass",
     "2026-11-04"),
    ("CA-12", "EX-07", "Lab passwords exposed in public git history", "Rotate Keycloak admin and database passwords",
     "IAM Analyst", "2026-11-10", "Open", "Old password rejected", "-", ""),
    ("CA-13", "Access review", "Privileged users not yet enrolled in OTP", "Enrolment forced at next sign-in; "
     "follow up on accounts not enrolled within 7 days", "IAM Analyst", "2026-11-10", "In progress",
     "Review shows mfa_enrolled = True for all privileged users", "-", ""),
    ("CA-14", "Board audit", "Status deck and design doc overstate progress (MVP deck slides 3 and 10; design doc "
     "section 14)", "Update both to the verified status", "Student", "2026-11-04", "Verified",
     "Every claim traces to evidence", "MVP deck v1.1 (slides 3, 10); design doc v1.3 section 14 (PDF export of the deck "
     "still to do)", "2026-11-04"),
    ("CA-15", "SV-01..04", "PKCE not enforced on public clients", "Set pkce.code.challenge.method = S256",
     "IAM Analyst", "2026-12-15", "Open", "Sign-in without code_challenge fails", "-", ""),
    ("CA-16", "SV-05", "Automation signs in as the human admin", "Create a service-account client with only the "
     "realm-management roles can_iam.py needs", "IAM Analyst", "2027-01-31", "Open",
     "can_iam.py runs with client credentials", "-", ""),
    ("CA-18", "LP-01", "IT-Support can sign in to hr-app although its role description excludes HR data",
     "Owner decides: narrow IT-Support to account administration, or document the business reason", "HR Manager + IAM Analyst",
     "2026-12-15", "Open", "Role description and hr-app gate agree", "-", ""),
    ("CA-17", "SV-06", "Entra broker client secret expiry unknown", "Record the expiry and set a reminder 30 days "
     "before", "IAM Analyst", "2026-11-10", "Open", "Expiry recorded in the register", "-", ""),
]

# ---------------------------------------------------------------- Week 10 Day 1: evidence index by control
# (control, evidence id, description, path relative to the repository)
EVIDENCE = [
    ("AC-01", "EV-13a", "Access review after hardening (13 accounts)",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/EV-13_Auth_Hardening_Live_20261103/access_review_AR-AFTER-HARDEN-20261103.csv"),
    ("AC-01", "E-AC-01", "Keycloak users and roles extract (Compliance 1 audit)",
     "Semester_5/Compliance_1/audit-evidence/E-AC-01_keycloak_users_roles.txt"),
    ("AC-02", "JML-LOG", "Joiner/mover/leaver log (Entra + Keycloak)",
     "Care_Access_Navigator/06_Evidence/07_JML_Lifecycle/JML-LOG.csv"),
    ("AC-02", "JML-PDF", "JML lifecycle evidence package",
     "Care_Access_Navigator/06_Evidence/07_JML_Lifecycle/Care_Access_Navigator_JML_Lifecycle_Evidence.pdf"),
    ("AC-02", "EV-14", "End-to-end run results (TC-04, TC-09)",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/EV-14_End_to_End_Tests_20261103/e2e_results.json"),
    ("AC-03", "EV-14", "End-to-end run results (TC-03 mover)",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/EV-14_End_to_End_Tests_20261103/e2e_results.json"),
    ("AC-04", "EV-13b", "Hardening audit log incl. app-gate verification",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/EV-13_Auth_Hardening_Live_20261103/can_iam_audit_log.jsonl"),
    ("AC-05", "PAM", "Privileged access matrix",
     "Care_Access_Navigator/07_GRC/02_Controls/CAN_DOC_Authentication_and_Privileged_Access_v1.0.pdf"),
    ("IA-01", "EV-13b", "MFA before/after verification",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/EV-13_Auth_Hardening_Live_20261103/can_iam_audit_log.jsonl"),
    ("IA-01", "E-AC-02", "Authentication settings before remediation (Compliance 1 audit)",
     "Semester_5/Compliance_1/audit-evidence/E-AC-02_authn_settings_and_entra_assignments.txt"),
    ("IA-02", "EV-13b", "Lockout and password-policy tests",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/EV-13_Auth_Hardening_Live_20261103/can_iam_audit_log.jsonl"),
    ("IA-02", "EXPORT", "Realm export before hardening (rollback point)",
     "Care_Access_Navigator/03_IAM_Lab/01_Keycloak/02_Realm_Exports/CAN_KC_Realm_Export_Before_W5_Hardening_20261103_v1.json"),
    ("AR-01", "EV-14", "Access reviews from the end-to-end run",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/EV-14_End_to_End_Tests_20261103/access_review_AR-E2E-TC09-AFTER-20261103.csv"),
    ("VM-01", "EV-14", "Vendor past end date flagged and removed (TC-08)",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/EV-14_End_to_End_Tests_20261103/access_review_AR-E2E-TC08-20261103.csv"),
    ("AU-01", "EV-14", "Keycloak login events",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/EV-14_End_to_End_Tests_20261103/keycloak_login_events.csv"),
    ("AU-02", "EV-14", "Identity detections (CAN-ID rules)",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/EV-14_End_to_End_Tests_20261103/identity_detections.csv"),
    ("AU-02", "IR1-T2", "IR 1 Task 2 log analysis package",
     "Semester_5/Incident_Response_1/task2_log_analysis/evidence/EVIDENCE-INDEX-SHA256.txt"),
    ("AU-03", "E-LOG-01", "Alerting and log retention (Compliance 1 audit)",
     "Semester_5/Compliance_1/audit-evidence/E-LOG-01_alerting_and_log_retention.txt"),
    ("IR-01", "IR1-T3", "Containment evidence index (IR1-2026-002)",
     "Semester_5/Incident_Response_1/task3_containment/evidence/EVIDENCE-INDEX-SHA256.txt"),
    ("IR-01", "IR1-T4", "Chain of custody and forensics index",
     "Semester_5/Incident_Response_1/task4_evidence_management/evidence/EVIDENCE-INDEX-SHA256.txt"),
    ("IR-01", "IR1-T6", "Recovery validation index",
     "Semester_5/Incident_Response_1/task6_post_incident/evidence/EVIDENCE-INDEX-SHA256.txt"),
    ("RA-01", "RISKS", "Risk register R01-R05 (dashboard extract)",
     "Care_Access_Navigator/08_Reporting/02_Dashboards/Tableau_Dataset/risks.csv"),
    ("CA-01", "CAT", "Exceptions and corrective-action tracker",
     "Care_Access_Navigator/07_GRC/04_Remediation/CAN_DOC_Exceptions_and_Corrective_Actions_v1.0.xlsx"),
    ("AC-01", "W3", "RBAC matrix, least privilege, SoD and access-request register",
     "Care_Access_Navigator/03_IAM_Lab/CAN_DOC_RBAC_SoD_Access_Request_v1.0.xlsx"),
    ("AC-03", "W3-WF", "Access request and approval workflow diagram",
     "Care_Access_Navigator/02_Diagrams/02_Workflows/CAN_DGM_Access_Request_Workflow_v1.0.pdf"),
    ("AU-01", "LOGS", "Exported Keycloak login/admin events, detections, automation audit (05_Logs, hash index)",
     "Care_Access_Navigator/05_Logs/EVIDENCE-INDEX-SHA256.txt"),
    ("RA-01", "ASSETS", "Asset inventory (applications, infrastructure, data types, identities)",
     "Care_Access_Navigator/04_Applications/01_Application_Inventory/CAN_DOC_Asset_Inventory_v1.0.xlsx"),
    ("SC-01", "E-ENC-01", "TLS enforcement re-performance (Compliance 1 audit)",
     "Semester_5/Compliance_1/audit-evidence/E-ENC-01_tls_enforcement.txt"),
]


def sha256(rel):
    p = os.path.join(REPO, rel)
    if not os.path.isfile(p):
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
