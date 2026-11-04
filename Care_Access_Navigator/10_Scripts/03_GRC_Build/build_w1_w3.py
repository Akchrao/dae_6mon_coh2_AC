"""Close the remaining Week 1 and Week 3 board items from live data:
  W1 Tue  asset inventory         04_Applications/01_Application_Inventory/CAN_DOC_Asset_Inventory_v1.0.xlsx
  W3 Mon  RBAC matrix             03_IAM_Lab/CAN_DOC_RBAC_SoD_Access_Request_v1.0.xlsx + .pdf
  W3 Tue  least privilege + SoD   (same workbook / PDF)
  W3 Wed  access request workflow (same) + 02_Diagrams/02_Workflows/CAN_DGM_Access_Request_Workflow_v1.0.pdf
Role descriptions are the ones stored on the Keycloak realm roles (Week 2 build). The access-request register is read
from the JML log and the can_iam.py audit logs, not typed in."""
import csv, json, os
from html import escape as e

from openpyxl import Workbook
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate

import grc_data as g
from build_workbooks import cover, save, sheet
from pdfstyle import P, bullets, note, table, kv, ok, bad, build, Spacer, PageBreak, FULL_W, NAVY, AMBER, GREY_BG, MUTED

ROLES = ["clinician", "nurse", "billing", "hr", "it-support", "security-analyst", "vendor"]
GROUP = {"clinician": "Clinicians", "nurse": "Nurses", "billing": "Billing", "hr": "HR", "it-support": "IT-Support",
         "security-analyst": "Security-Analysts", "vendor": "Vendors"}
# realm role descriptions as stored in Keycloak (read 2026-11-04)
DESC = {
    "clinician": "Front-line care provider access. Represents the role with the broadest ePHI access.",
    "nurse": "Supporting clinical access. Illustrates a least-privilege distinction between two clinical roles with "
             "overlapping but not identical access.",
    "billing": "Access to the Billing App and billing-relevant patient/claims data only (charges, insurance/claims status, "
               "payment records); explicitly no access to clinical notes in the EHR Simulator.",
    "hr": "Access to the HR App and workforce records (employee records, onboarding/offboarding status, role "
          "assignments); no access to any patient-facing application.",
    "it-support": "Administrative/helpdesk access: view user account status and assist with access issues (e.g., password "
                  "resets) but not standing access to clinical, billing, or HR data itself.",
    "security-analyst": "Access to security monitoring and logging tools (SIEM, authentication logs, Keycloak Events) "
                        "for investigation, but not standing operational access to patient, billing, or HR data.",
    "vendor": "External/third-party access, narrowly scoped to a specific system or time-limited engagement, with the "
              "shortest expected access lifespan of all seven roles.",
}
APPS = ["ehr-simulator", "patient-portal", "billing-app", "hr-app"]
# role x app: permission granted (design) ; '-' = denied by the live sign-in gate. Gate = can_iam.APP_ACCESS (live 11/03)
RBAC = {
    "clinician": {"ehr-simulator": "Read/write full chart, orders, notes", "patient-portal": "Read/reply to patient messages"},
    "nurse": {"ehr-simulator": "Read chart; document vitals, meds given (no orders)", "patient-portal": "Read/reply to messages"},
    "billing": {"billing-app": "Charges, claims, payments (cardholder data)"},
    "hr": {"hr-app": "Workforce records, onboarding/offboarding"},
    "it-support": {"hr-app": "Sign-in allowed by the live gate (see finding LP-01)"},
    "security-analyst": {},
    "vendor": {},
}
DATA = {"ehr-simulator": "ePHI (clinical)", "patient-portal": "ePHI (patient-facing)",
        "billing-app": "PHI (demographics, codes) + PCI cardholder data", "hr-app": "Workforce PII"}
PRIV = {"billing", "it-support", "security-analyst"}

# least privilege: needed vs granted vs explicitly excluded
LEAST = [
    ("clinician", "Diagnose, treat, document", "EHR + Portal", "Billing, HR; any admin function", "Matches"),
    ("nurse", "Care delivery under orders", "EHR + Portal (no orders - design)", "Billing, HR; orders", "Matches"),
    ("billing", "Bill and collect", "Billing app only, MFA", "EHR clinical notes, Portal, HR", "Matches"),
    ("hr", "Workforce administration", "HR app only", "All patient-facing apps", "Matches"),
    ("it-support", "Account status, password resets", "HR app sign-in, MFA", "Clinical, billing and HR data (per role "
     "description)", "Gap LP-01: HR app sign-in conflicts with 'no standing access to HR data'"),
    ("security-analyst", "Investigate security events", "No application; logs/SIEM only, MFA", "All application data",
     "Matches"),
    ("vendor", "Defined engagement only", "No application by default; time-boxed per request", "Everything not in the "
     "request", "Matches (test.vendor1 end date open: CA-08)"),
]
# separation of duties: (role A, role B, why the pair is toxic, risk)
SOD = [
    ("billing", "clinician", "Could record a service and bill for it (false claims)", "High"),
    ("billing", "nurse", "Could document care and bill for it", "High"),
    ("billing", "it-support", "Could reset another biller's password and post payments as them", "High"),
    ("hr", "it-support", "Could create a workforce record and grant the account access: joiner without independent "
                         "approval", "High"),
    ("security-analyst", "it-support", "Could change accounts and also review the alerts about those changes", "High"),
    ("security-analyst", "billing", "Could investigate alerts about their own billing activity", "Medium"),
    ("vendor", "*any workforce role", "External party with internal standing access", "High"),
    ("clinician", "nurse", "Not toxic, but redundant: one person holds one clinical role", "Low"),
]
PROCESS_SOD = [
    ("Request", "Requester (person or manager)", "Cannot approve their own request"),
    ("Approve", "Manager; + Security Officer for privileged roles", "Approver is not the requester and not the provisioner"),
    ("Provision", "IAM Analyst (can_iam.py)", "Provisions only approved tickets; cannot approve"),
    ("Verify / review", "Manager / application owner (quarterly)", "Reviewer is not the IAM Analyst who provisioned"),
    ("Monitor", "Security Analyst", "Alerts on membership changes (CAN-ID-005), independent of IAM"),
]


def requests():
    """Access-request register: JML cycle (Entra) + every can_iam.py joiner/mover/leaver/test identity."""
    out = []
    for r in csv.DictReader(open(os.path.join(g.CAN, "06_Evidence/07_JML_Lifecycle/JML-LOG.csv"), newline="")):
        out.append((r["ticket"], r["type"], r["person"], r["login"], "Entra ID + Keycloak", r["before"], r["after"],
                    "Manager (JML-LOG)", "JML-LOG.csv"))
    for folder in ("EV-13_Auth_Hardening_Live_20261103", "EV-14_End_to_End_Tests_20261103"):
        for rec in g.audit_log(os.path.join(g.CAN, "06_Evidence/04_Test_Results", folder)):
            a = rec["action"]
            if a in ("JOINER", "MOVER", "LEAVER"):
                aft = rec.get("after", {})
                before = rec.get("before", {})
                out.append((rec.get("ticket"), a.title(), aft.get("username", ""), aft.get("username", ""),
                            "Keycloak (can_iam.py)",
                            ";".join(before.get("effective_roles", [])) if before else "no account",
                            ("disabled; " if not aft.get("enabled") else "") + ";".join(aft.get("groups", []) or ["no groups"]),
                            rec.get("approved_by", ""), f"{folder} {rec['ts_utc']}"))
            elif a == "TEST_IDENTITY.created":
                out.append((rec["ticket"], "Joiner (test account)", rec["username"], rec["username"],
                            "Keycloak (admin API)", "no account", rec["group"], "IAM Analyst (W5 test plan)",
                            f"{folder} {rec['ts_utc']}"))
    return out


REQ = requests()
LIVE_IDS = g.review_rows(os.path.join(g.CAN, "06_Evidence/05_Access_Reviews/EV-15_Access_Review_AR-2026-Q4_20261103/"
                                              "access_review_AR-2026-Q4.csv"))


# ------------------------------------------------------------------ workflow diagram
def workflow(w=10.0 * inch, h=5.6 * inch):
    d = Drawing(w, h)
    lanes = ["Requester", "Manager", "Security Officer", "IAM Analyst", "Keycloak / Entra", "Security Analyst"]
    lh, lw = (h - 30) / len(lanes), 1.05 * inch
    d.add(String(0, h - 14, "Access request and approval workflow (REQ- joiner / CHG- mover / TERM- leaver)",
                 fontName="Helvetica-Bold", fontSize=10, fillColor=NAVY))
    for i, lab in enumerate(lanes):
        y = h - 30 - (i + 1) * lh
        d.add(Rect(0, y, w, lh, fillColor=GREY_BG if i % 2 == 0 else colors.white, strokeColor=colors.HexColor("#CCCCCC")))
        d.add(Rect(0, y, lw, lh, fillColor=NAVY, strokeColor=None))
        d.add(String(6, y + lh / 2 - 3, lab, fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.white))
    cy = lambda lane: h - 30 - (lane + 0.5) * lh
    bw, bh = 1.15 * inch, 0.42 * inch
    boxes = {  # key: (lane, x, text lines, fill)
        "submit": (0, 1.2, ["1 Submit request", "role, reason, end date"], colors.white),
        "approve": (1, 2.55, ["2 Approve need", "or reject"], colors.white),
        "priv": (2, 3.9, ["3 Approve privilege", "(Billing/IT/SecAn)"], colors.white),
        "prov": (3, 5.25, ["4 Provision group", "can_iam.py joiner/mover"], colors.white),
        "enforce": (4, 6.6, ["5 Group -> role;", "MFA + app gate"], colors.white),
        "verify": (3, 7.95, ["6 Verify + evidence", "snapshot, hashed log"], colors.white),
        "monitor": (5, 6.6, ["CAN-ID-005 alert", "on any group change"], colors.HexColor("#FFF4DE")),
        "review": (1, 7.95, ["7 Quarterly review", "Keep / Modify / Revoke"], colors.white),
        "reject": (0, 2.55, ["Rejected:", "requester notified"], colors.HexColor("#F8D7D3")),
    }
    pos = {}
    for k, (lane, x, lines, fill) in boxes.items():
        X, Y = x * inch, cy(lane) - bh / 2
        pos[k] = (X, Y)
        d.add(Rect(X, Y, bw, bh, rx=5, ry=5, fillColor=fill, strokeColor=AMBER, strokeWidth=1.2))
        for j, t in enumerate(lines):
            d.add(String(X + 5, Y + bh - 12 - j * 10, t, fontName="Helvetica-Bold" if j == 0 else "Helvetica",
                         fontSize=7, fillColor=NAVY if j == 0 else MUTED))

    def arrow(a, b, label=None, dx=0):
        (x1, y1), (x2, y2) = pos[a], pos[b]
        sx, sy = x1 + bw, y1 + bh / 2
        ex, ey = x2, y2 + bh / 2
        if abs(x1 - x2) < 1:            # vertical
            sx, sy = x1 + bw / 2 + dx, (y1 if y2 < y1 else y1 + bh)
            ex, ey = x2 + bw / 2 + dx, (y2 + bh if y2 < y1 else y2)
        d.add(Line(sx, sy, ex, ey, strokeColor=NAVY, strokeWidth=1))
        import math
        ang = math.atan2(ey - sy, ex - sx)
        p1 = (ex - 6 * math.cos(ang - 0.4), ey - 6 * math.sin(ang - 0.4))
        p2 = (ex - 6 * math.cos(ang + 0.4), ey - 6 * math.sin(ang + 0.4))
        d.add(Polygon([ex, ey, p1[0], p1[1], p2[0], p2[1]], fillColor=NAVY, strokeColor=NAVY))
        if label:
            d.add(String((sx + ex) / 2 + 3, (sy + ey) / 2 + 3, label, fontName="Helvetica-Oblique", fontSize=6.5,
                         fillColor=MUTED))
    arrow("submit", "approve")
    arrow("approve", "priv", "privileged")
    arrow("priv", "prov")
    arrow("approve", "reject", "no")
    arrow("prov", "enforce")
    arrow("enforce", "verify")
    arrow("enforce", "monitor")
    arrow("verify", "review")
    d.add(String(2.55 * inch, cy(3) + 2, "non-privileged: Manager approval goes straight to step 4",
                 fontName="Helvetica-Oblique", fontSize=6.5, fillColor=MUTED))
    return d


# ------------------------------------------------------------------ 1 asset inventory (W1 Tue)
wb = Workbook()
cover(wb, "Asset Inventory", "Week 1 Day 2: the systems, data, identities and privileged functions in scope, with owner, "
      "classification and the controls that protect them. Identities are read from the live realm (AR-2026-Q4, 11/03).",
      [("Applications", "4"), ("Identities", str(len(LIVE_IDS)))])
sheet(wb, "Applications",
      ["Asset ID", "Application", "Keycloak client", "Data held", "Classification", "Business owner", "Allowed roles (live gate)",
       "MFA", "Status"],
      [("AST-01", "EHR Simulator", "ehr-simulator", DATA["ehr-simulator"], "Restricted (ePHI)", "Clinical application owner",
        "clinician, nurse", "No (non-privileged roles)", "OIDC client; no front end"),
       ("AST-02", "Patient Portal", "patient-portal", DATA["patient-portal"], "Restricted (ePHI)", "Clinical application owner",
        "clinician, nurse", "No", "OIDC client; no front end"),
       ("AST-03", "Billing App", "billing-app", DATA["billing-app"], "Restricted (PHI + PCI)", "Billing Manager", "billing",
        "Yes", "OIDC client; no front end"),
       ("AST-04", "HR App", "hr-app", DATA["hr-app"], "Confidential (PII)", "HR Manager", "hr, it-support (LP-01)", "Yes for "
        "it-support", "OIDC client; no front end")],
      [9, 16, 16, 34, 18, 22, 22, 18, 22])
sheet(wb, "Infrastructure",
      ["Asset ID", "Asset", "Type", "Location", "Owner", "Holds", "Protection", "Status"],
      [("AST-10", "Keycloak 26.0 (care-access-keycloak)", "Identity provider", "Docker, Mac, 127.0.0.1:8080", "IAM Analyst",
        "Identities, roles, sessions, events (90 days)", "MFA flow, lockout, app gates; localhost only (CA-11)", "Live"),
       ("AST-11", "PostgreSQL 16 (care-access-postgres)", "Database", "Docker network only", "IT Support",
        "Keycloak data", "Not published to the host", "Live"),
       ("AST-12", "Microsoft Entra ID tenant", "Cloud identity provider", "Microsoft cloud", "IAM Analyst",
        "Workforce identities, app roles", "Assignment required; Security defaults pending (EX-01)", "Live"),
       ("AST-13", "EHR Simulator stand-in (can-ehr-simulator)", "Container", "Docker, 127.0.0.1:8081", "IT Support",
        "Health endpoint only (Cloud Security 1 container scan target)", "Localhost only", "Live (not integrated)"),
       ("AST-14", "IR lab (parrot-vm, Wazuh 4.9.2)", "VM + SIEM", "QEMU in Docker (torn down)", "Security Analyst",
        "IR1-2026-001/002/003 evidence", "Isolated networks", "Retired 2026-11-03"),
       ("AST-15", "CISO Assistant", "GRC tool", "Docker, localhost:8443", "GRC Analyst", "GRC records (empty)",
        "Localhost only", "Live"),
       ("AST-16", "Azure subscription (rg-cloudsec1-can)", "Cloud", "Azure", "Security Officer", "Governance only",
        "Policy guardrails; $1 budget alert", "Billable resources deleted 2026-10-13"),
       ("AST-17", "GitHub repository (public)", "Code / evidence store", "github.com", "Student", "Synthetic data, docs",
        "No secrets (.env untracked)", "Live")],
      [9, 34, 18, 26, 16, 34, 36, 22])
sheet(wb, "Data_Types",
      ["Data type", "Examples", "Classification", "Regulation", "Where", "Who may access"],
      [("ePHI (clinical)", "Charts, orders, notes, vitals", "Restricted", "HIPAA Security Rule", "EHR", "clinician, nurse"),
       ("ePHI (patient-facing)", "Messages, appointments", "Restricted", "HIPAA", "Portal", "clinician, nurse"),
       ("Cardholder data", "Card numbers in payments", "Restricted", "PCI DSS v4.0.1", "Billing App", "billing (MFA)"),
       ("Billing PHI", "Demographics, codes, claims", "Restricted", "HIPAA (minimum necessary)", "Billing App", "billing"),
       ("Workforce PII", "Employee records", "Confidential", "State privacy law", "HR App", "hr"),
       ("Security logs", "Login/admin events, detections", "Internal", "HIPAA 164.312(b); PCI 10", "Keycloak, 05_Logs",
        "security-analyst"),
       ("Credentials", "Passwords, OTP secrets, client secrets", "Secret", "PCI 8.3", "Keycloak, .env (local)",
        "Owner only")],
      [20, 30, 14, 26, 20, 22])
sheet(wb, "Identities",
      ["Username", "Enabled", "Source", "Group", "Role", "MFA enrolled", "Last sign-in", "Flags"],
      [(r["username"], r["enabled"], r["source"], r["groups"], r["effective_roles"], r["mfa_enrolled"], r["last_login"],
        r["flags"]) for r in LIVE_IDS], [44, 9, 10, 16, 16, 12, 12, 40])
sheet(wb, "Privileged_Functions",
      ["ID", "Account / role", "System", "Privilege", "MFA", "Status"],
      [(p[0], p[1], p[2], p[3], p[7], p[11]) for p in g.PRIVILEGED], [8, 30, 26, 40, 30, 18])
save(wb, "04_Applications/01_Application_Inventory/CAN_DOC_Asset_Inventory_v1.0.xlsx")

# ------------------------------------------------------------------ 2 RBAC / SoD / requests workbook (W3)
wb = Workbook()
cover(wb, "RBAC Matrix, Least Privilege, Separation of Duties and Access Requests",
      "Week 3: the role-to-application matrix enforced on the live realm (groups + sign-in gates, tested 11/03), the "
      "least-privilege comparison, the separation-of-duties conflict matrix and the access-request register.",
      [("Roles", "7"), ("Applications", "4"), ("Access requests in register", str(len(REQ)))])
sheet(wb, "RBAC_Matrix", ["Role", "Group", "Description (Keycloak)"] + APPS + ["MFA"],
      [(r, GROUP[r], DESC[r]) + tuple(RBAC[r].get(a, "Denied (gate)") for a in APPS) + ("Required" if r in PRIV else "No",)
       for r in ROLES], [16, 16, 50, 26, 22, 26, 26, 10])
sheet(wb, "Least_Privilege", ["Role", "Job needs", "Granted (live)", "Explicitly excluded", "Assessment"], LEAST,
      [16, 28, 32, 40, 50], status_cols=(4,))
ws = sheet(wb, "SoD_Matrix", ["Role"] + ROLES,
           [[a] + ["-" if a == b else next((s[3] for s in SOD if {s[0], s[1]} == {a, b}),
                                            "High" if "vendor" in (a, b) else "Blocked (one role per person)")
                   for b in ROLES] for a in ROLES], [16] + [18] * 7, status_cols=tuple(range(1, 8)),
           note="Week 3 Day 2: conflict level when one person holds both roles. Policy: one role per person, so every pair "
                "is blocked; the level says how serious a breach of that rule is.")
sheet(wb, "SoD_Conflicts", ["Role A", "Role B", "Why the combination is toxic", "Risk"], SOD, [16, 20, 70, 9],
      status_cols=(3,))
sheet(wb, "Process_SoD", ["Step", "Performed by", "Separation rule"], PROCESS_SOD, [16, 40, 60])
sheet(wb, "Access_Requests", ["Ticket", "Type", "Person", "Login", "System", "Before", "After", "Approved by", "Evidence"],
      REQ, [16, 18, 30, 30, 20, 26, 34, 22, 46])
save(wb, "03_IAM_Lab/CAN_DOC_RBAC_SoD_Access_Request_v1.0.xlsx")

# ------------------------------------------------------------------ 3 workflow diagram (standalone)
wf_out = os.path.join(g.CAN, "02_Diagrams/02_Workflows/CAN_DGM_Access_Request_Workflow_v1.0.pdf")
from reportlab.graphics import renderPDF
renderPDF.drawToFile(workflow(), wf_out, "Access Request Workflow")
print("wrote", wf_out)

# ------------------------------------------------------------------ 4 PDF (W3 package)
TITLE = "RBAC, Separation of Duties & Access Requests"
s = [P(TITLE, "title"), Spacer(1, 4), P(f"Week 3 &middot; {g.PROJECT} &middot; {g.ORG}", "subtitle"),
     P("Role-based access model, least privilege, separation of duties and the access-request workflow, "
       "as enforced and tested on the live Keycloak realm", "subsub"), Spacer(1, 10)]
s += kv([("Author", g.AUTHOR), ("Date", "November 4, 2026"), ("Version", "v1.0"),
         ("Enforcement", "7 job-function groups, one realm role each; 4 sign-in gates (live since 11/03/2026)"),
         ("Tested", "EV-13 (before/after) and end-to-end TC-01, TC-02, TC-03, TC-07"),
         ("Workbook", "03_IAM_Lab/CAN_DOC_RBAC_SoD_Access_Request_v1.0.xlsx")])
s += table([["Day", "Board item", "Section", "Status"],
            ["Mon", "Design healthcare RBAC model", "1 RBAC matrix", ok("Done")],
            ["Tue", "Apply least privilege and separation-of-duties rules", "2 and 3", ok("Done")],
            ["Wed", "Design access request and approval workflow", "4 workflow + register", ok("Done")],
            ["Thu", "Implement and test RBAC roles", "EV-13, TC-01/02 (done 11/03)", ok("Done")]],
           [0.5 * inch, 2.9 * inch, 2.1 * inch, 1.0 * inch])
s += [P("1. RBAC matrix", "h1"), P("Rows are the seven job roles; each is granted by exactly one Keycloak group. A cell "
      "shows what the role may do in that application; <b>Denied</b> means the application's sign-in gate refuses the "
      "role (tested). Token contents match: each client's scope mapping carries only its allowed roles.")]
s += table([["Role / group"] + APPS + ["MFA"]] +
           [[f"<b>{r}</b><br/><font size=7.5 color='#555555'>{GROUP[r]}</font>"] +
            [e(RBAC[r][a]) if a in RBAC[r] else "<font color='#A3271F'>Denied</font>" for a in APPS] +
            ["Required" if r in PRIV else "-"] for r in ROLES],
           [1.05 * inch, 1.35 * inch, 1.15 * inch, 1.15 * inch, 1.1 * inch, 0.7 * inch])
s += table([["Application", "Data", "Classification"]] +
           [[a, DATA[a], "Restricted" if a != "hr-app" else "Confidential"] for a in APPS],
           [1.4 * inch, 3.5 * inch, 1.6 * inch])
s += [PageBreak(), P("2. Least privilege", "h1")]
s += table([["Role", "Needs", "Granted", "Excluded", "Assessment"]] +
           [[f"<b>{a}</b>", e(b), e(c), e(d), ok("Matches") if x == "Matches" else e(x)] for a, b, c, d, x in LEAST],
           [0.95 * inch, 1.2 * inch, 1.35 * inch, 1.4 * inch, 1.6 * inch])
s += note("Finding <b>LP-01</b>: the IT-Support role description (stored on the Keycloak role) says no standing access to "
          "HR data, but the hr-app client scope and sign-in gate admit it-support. Either narrow IT-Support to an "
          "account-administration function without HR records, or update the role description with the business reason. "
          "Tracked as corrective action CA-18 (owner: HR Manager + IAM Analyst). Not changed on the live realm without "
          "the owner's decision.", "Finding")
s += [P("3. Separation of duties", "h1"), P("Policy: one job role per person. These pairs are the reason; the access "
      "review flags any account holding two roles (MULTIPLE_ROLES_SOD_CHECK), and CAN-ID-005 alerts on the group change. "
      "TC-07 proved both on 11/03 (vendor added to Billing: alerted High, flagged, removed).")]
s += table([["Role A", "Role B", "Why toxic", "Risk"]] + [[a, b, e(w), x] for a, b, w, x in SOD],
           [1.0 * inch, 1.1 * inch, 3.7 * inch, 0.7 * inch])
s += table([["Step", "Performed by", "Separation rule"]] + [list(r) for r in PROCESS_SOD],
           [0.9 * inch, 2.3 * inch, 3.3 * inch])
s += [PageBreak(), P("4. Access request and approval workflow", "h1")]
from reportlab.graphics.shapes import Group
small = Drawing(FULL_W, 3.7 * inch)
grp = Group(*workflow().contents)
sc = FULL_W / (10.0 * inch)
grp.scale(sc, sc)
small.add(grp)
s += [small, P("Full-size diagram: 02_Diagrams/02_Workflows/CAN_DGM_Access_Request_Workflow_v1.0.pdf", "caption")]
s += bullets(["<b>Every request has a ticket</b>: REQ- (joiner), CHG- (mover), TERM- (leaver). Vendors must give an end "
              "date; can_iam.py refuses a vendor joiner without one.",
              "<b>Two approvals for privileged roles</b> (Billing, IT-Support, Security-Analysts): manager for the need, "
              "Security Officer for the privilege. OTP enrolment is forced at first sign-in.",
              "<b>Provisioning is by group only</b>, through can_iam.py, which writes ticket, approver and before/after state "
              "to a hashed audit log; a mover loses old access before gaining new.",
              "<b>Verification</b>: snapshot of groups/roles/sessions and a sign-in test; the quarterly review re-certifies."])
s += [P("5. Access-request register", "h1"), P(f"{len(REQ)} requests, read from the JML log and the can_iam.py audit logs.")]
s += table([["Ticket", "Type", "Login", "Before &rarr; after", "Approved by"]] +
           [[e(r[0] or ""), e(r[1]), e(r[3][:34]), e((f"{r[5]} -> {r[6]}")[:110] + ("..." if len(f"{r[5]} -> {r[6]}") > 110 else "")), e(r[7])] for r in REQ],
           [1.2 * inch, 0.85 * inch, 1.5 * inch, 2.0 * inch, 0.95 * inch])
build(os.path.join(g.CAN, "03_IAM_Lab/CAN_DOC_RBAC_SoD_Access_Request_v1.0.pdf"), s, TITLE,
      f"{g.PROJECT} | RBAC, SoD & Access Requests | v1.0")
