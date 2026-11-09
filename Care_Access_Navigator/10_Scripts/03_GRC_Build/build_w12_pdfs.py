"""Week 12 Days 2-4: portfolio index + lessons learned + closure, and the 5-minute demo script.
Outputs:
  09_Portfolio/01_Documents/CAN_DOC_Portfolio_Index_and_Lessons_Learned_v1.1.pdf
  09_Portfolio/04_Demo/CAN_DOC_5_Minute_Demo_Script_v1.1.pdf
v1.1 (2026-11-05): GRC registers and dashboard in CISO Assistant; Entra design (W2 Wed); learning folder."""
import csv, os
from html import escape as e

import grc_data as g
from pdfstyle import P, bullets, note, code, table, kv, ok, bad, build, step, Spacer, PageBreak, inch

DS = os.path.join(g.CAN, "08_Reporting/02_Dashboards/Tableau_Dataset")
K = {r["kpi"]: r for r in csv.DictReader(open(os.path.join(DS, "kpi_values.csv"), newline=""))}
E2E = g.e2e()["results"]
passed = sum(r["result"].startswith("PASS") for r in E2E)
verified = sum(a[6].startswith("Verified") for a in g.ACTIONS)
exists = lambda rel: os.path.exists(os.path.join(g.REPO, rel))

# ------------------------------------------------------------------ portfolio index + lessons learned
DELIV = [  # (deliverable from plan section 15, contents, file, status)
    ("Project charter", "Problem, objectives, scope, stakeholders, success criteria",
     "Care_Access_Navigator/01_Docs/01_Project_Planning/CAN_DOC_Week1_Day1_Objective_Scope_Baseline_v1.0.pdf", "Done"),
    ("Project design documentation", "Design, tech stack, timeline, rubric crosswalk",
     "Care_Access_Navigator/01_Docs/01_Project_Planning/CAN_DOC_Project_Design_Documentation_v1.3.docx",
     "Done (v1.3, status verified 11/04)"),
    ("Architecture", "IAM, applications, SIEM, GRC and data flow",
     "Care_Access_Navigator/01_Docs/01_Project_Planning/CAN_DOC_Week1_Day4_High_Level_Architecture_Data_Flow_v1.0.pdf", "Done"),
    ("Asset inventory", "Applications, infrastructure, data types, live identities, privileged functions",
     "Care_Access_Navigator/04_Applications/01_Application_Inventory/CAN_DOC_Asset_Inventory_v1.0.xlsx", "Done"),
    ("RBAC matrix, least privilege, SoD, access requests", "Role x app matrix, SoD conflicts, workflow, 11-request register",
     "Care_Access_Navigator/03_IAM_Lab/CAN_DOC_RBAC_SoD_Access_Request_v1.0.pdf", "Done"),
    ("Logs", "Exported login/admin events, EHR sample, detections, automation audit",
     "Care_Access_Navigator/05_Logs/EVIDENCE-INDEX-SHA256.txt", "Done"),
    ("IAM build log", "Keycloak + Entra ID federation build",
     "Care_Access_Navigator/03_IAM_Lab/CAN_DOC_Keycloak_EntraID_Build_Log_v1.0.docx", "Done"),
    ("Entra ID identity governance design", "Tenant set-up, app role -> realm role -> group design, JML/review/MFA rules, gaps",
     "Care_Access_Navigator/03_IAM_Lab/CAN_DOC_Entra_ID_Identity_Governance_Design_v1.0.pdf", "Done (11/05)"),
    ("JML procedures + evidence", "Joiner, mover, leaver with Entra and Keycloak evidence",
     "Care_Access_Navigator/06_Evidence/07_JML_Lifecycle/Care_Access_Navigator_JML_Lifecycle_Evidence.pdf", "Done"),
    ("Authentication & privileged access", "Baseline, privileged access matrix, service/vendor register, tests",
     "Care_Access_Navigator/07_GRC/02_Controls/CAN_DOC_Authentication_and_Privileged_Access_v1.0.pdf", "Done"),
    ("Access review", "Quarterly review AR-2026-Q4 with flags and sign-off sheet",
     "Care_Access_Navigator/06_Evidence/05_Access_Reviews/CAN_DOC_Access_Review_AR-2026-Q4_v1.0.xlsx",
     "Done (signed 2026-11-09, CA-05 verified)"),
    ("SIEM use cases + incident", "Wazuh rules, CAN-ID identity rules, IR1-2026-002 report",
     "incident_response_1/task5_ir_documentation/README.md", "Done"),
    ("Risk register", "R01-R05 in CISO Assistant: inherent, current and residual levels, treatment, linked controls",
     "Care_Access_Navigator/07_GRC/01_Risks/CAN_DOC_CISO_Risk_Assessment_R01-R05_v2.0.pdf", "Done"),
    ("Control matrix + compliance mapping", "18 controls; HIPAA audit (25 requirements: 17 compliant, 7 partial, 1 "
     "non-compliant) and NIST CSF 2.0 mapping (15 subcategories) in CISO Assistant; SP 800-53/ISO/PCI in the catalog",
     "Care_Access_Navigator/07_GRC/03_Compliance/CAN_DOC_CISO_HIPAA_Audit_v2.0.xlsx", "Done"),
    ("Exceptions + corrective actions", "8 exceptions (EX-01 resolved) and 18 corrective actions + CAN-FIND-001 as "
     "CISO Assistant findings, tracked to verification",
     "Care_Access_Navigator/07_GRC/04_Remediation/CAN_DOC_CISO_Corrective_Action_Tracker_v1.0.pdf", "Done"),
    ("Evidence index", "Evidence by control with SHA-256; 43 evidence items with files in CISO Assistant",
     "Care_Access_Navigator/06_Evidence/CAN_DOC_Evidence_Index_v1.0.xlsx", "Done"),
    ("End-to-end test report", f"TC-01 to TC-10: {passed}/{len(E2E)} passed",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/CAN_DOC_End_to_End_Test_Report_v1.0.pdf", "Done"),
    ("GRC dashboard", "CISO Assistant analytics, risk matrix and compliance progress (replaces Tableau, EX-08); "
     "KPI design PDF kept", "Care_Access_Navigator/08_Reporting/02_Dashboards/EV-16_CISO_Dashboard_Compliance_20261105.png",
     "Done (EX-08 pending instructor)"),
    ("CISO Assistant learning project", "Plan, tutorial, observability notes, exports and proof",
     "learning/evidence/README.md", "Done (reflection to finalise)"),
    ("5-minute demo", "Script with live commands and backup evidence",
     "Care_Access_Navigator/09_Portfolio/04_Demo/CAN_DOC_5_Minute_Demo_Script_v1.1.pdf", "Done (rehearse)"),
    ("Demo deck", "MVP deck, slides 3 and 10 corrected to verified status",
     "Care_Access_Navigator/09_Portfolio/04_Demo/CAN_DOC_MVP_Demo_v1.1.pptx", "Done (export PDF from PowerPoint/Keynote)"),
]
CRITERIA = [  # plan section 17
    ("IAM", "At least one complete JML workflow, RBAC matrix, access request and access-review demonstration",
     "JML cycle (Entra + Keycloak) and automated JML in TC-01/03/04; RBAC app matrix enforced; access review run",
     "Met"),
    ("Monitoring", "At least three useful detection use cases with controlled test events and investigation",
     "CAN-ID-001/002/004/005/007 fired on controlled events; Wazuh rules 100210/100221/100231 in IR 1", "Met"),
    ("Incident response", "One end-to-end simulated access incident from detection through lessons learned",
     "IR1-2026-002 (Tara Jones, ePHI exfiltration): alert to containment in 49 s, forensics, RCA, recovery", "Met"),
    ("GRC", "Risk register, control matrix, evidence index, gap assessment, exceptions/remediation, dashboard",
     "Registers in CISO Assistant since 11/04 (5 risks, 18 controls, 43 evidence items, 8 exceptions, 19 findings); "
     "dashboards in CISO Assistant", "Met (EX-08 pending)"),
    ("Compliance", "Controls mapped to HIPAA Security Rule and NIST concepts without claiming certification",
     "16 controls mapped to HIPAA, CSF 2.0 and SP 800-53 (plus ISO 27001 and PCI DSS); CISO Assistant audits of "
     "HIPAA (25 requirements) and CSF 2.0 (15 subcategories)", "Met"),
    ("Portfolio", "Architecture, evidence, procedures, test cases and 5-minute demo presentation-ready",
     "This index; demo script; corrected deck", "Met (rehearse demo)"),
]
LESSONS = [
    ("Verify status, don't trust it", "The board export and two status decks said items were done that were not. "
     "An evidence-based audit (11/02) found 8 items not started and 3 false claims.",
     "Every status claim now points to an evidence file; the deck was corrected (CA-14)."),
    ("Configuration that exists is not configuration that works", "An MFA flow had been built but was bound to nothing, "
     "its OTP step used 'user configured' (people without OTP skipped MFA), and a role condition sat where Keycloak "
     "ignores it.", "Test the negative path: a privileged user without OTP must be stopped (EV-13)."),
    ("Federation creates a second copy of every identity", "Jeevan Smith was disabled in Entra and Keycloak, but the "
     "Keycloak copy kept the billing role mapped from Entra. Only the access review caught it (TC-09).",
     "Leavers go through can_iam.py leaver, which strips IdP-mapped roles; the review checks DISABLED_BUT_HAS_ACCESS."),
    ("Detection rules need regression tests", "CAN-ID-001 alerted once per user for all time, so a second attack on "
     "the same account was silent. Only the end-to-end test found it (TC-05).",
     "Rule fixed (CA-10) and retested with a fresh burst; rerun e2e_tests.py after every rule change."),
    ("Test design can hide results", "The TC-05 attempts fell inside the 10-minute window of an earlier test.",
     "Space tests beyond the detection window or use fresh test identities."),
    ("Cost limits shape compliance", "Removing the Log Analytics workspace to stop charges created finding F-03 "
     "(no 12-month logs).", "Accepted as exception EX-02 with compensating controls and an expiry; any fix needs a cost "
     "estimate first."),
    ("Secrets hygiene in a public repository", "The lab .env with passwords had been committed to a public repo.",
     ".env untracked and ignored, .env.example added, rotation tracked (CA-12)."),
    ("Write down tool substitutions early", "IR 1 used Debian/QEMU in place of Parrot/VirtualBox.",
     "Substitution note in every deliverable; instructor acceptance requested (EX-06)."),
    ("Hash evidence when you collect it", "SHA-256 indexes let folders be reorganised without losing integrity: "
     "moving folders kept every index valid.", "Index every evidence folder at collection time; never rename files "
     "inside one."),
    ("Stop before you copy", "The CISO Assistant database was copied from Windows while the app was running and "
     "arrived corrupt.", "Recovered with sqlite3 .recover; now always docker compose down before copying or backing up."),
    ("Use dedicated test identities", "Week 5 tests used new accounts (test.billing2, test.clinician2) instead of "
     "resetting existing users' passwords.", "Test accounts are labelled employment_type=test-account and reviewed "
     "quarterly like any other."),
]

s = [P("Portfolio Index & Lessons Learned", "title"), Spacer(1, 4),
     P(f"Week 12 &middot; {g.PROJECT} &middot; {g.ORG}", "subtitle"),
     P("Final documentation set, success criteria, lessons learned, limitations and project closure", "subsub"),
     Spacer(1, 10)]
s += kv([("Author", g.AUTHOR), ("Date", "November 5, 2026"), ("Version", "v1.1"),
         ("Project window", "2026-08-17 to 2026-11-05 (12 weeks)"),
         ("Headline results", f"End-to-end tests {passed}/{len(E2E)} passed; control test pass rate "
                              f"{K['Control test pass rate (10/13 audit)']['value']}% (10/13 audit) &rarr; "
                              f"{K['Control test pass rate (11/03)']['value']}% (11/03); "
                              f"{verified}/{len(g.ACTIONS)} corrective actions verified; 3 of 6 audit findings closed "
                              "with before/after evidence"),
         ("Positioning", "Hands-on cybersecurity lab capstone using synthetic identities and events; no production "
                         "healthcare data and no certification claimed")])
s += [P("1. Documentation set", "h1")]
s += table([["Deliverable", "Contents", "Status"]] +
           [[f"<b>{e(d)}</b><br/><font name='Courier' size=6.8>{e(f)}</font>"
             + ("" if exists(f) else " <font color='#A3271F'>(missing)</font>"), e(c), e(st)] for d, c, f, st in DELIV],
           [3.0 * inch, 2.0 * inch, 1.5 * inch])
s += [PageBreak(), P("2. Success criteria (12-week plan, section 17)", "h1")]
s += table([["Area", "Standard", "Evidence", "Result"]] +
           [[a, e(b), e(c), ok(e(d)) if d == "Met" else e(d)] for a, b, c, d in CRITERIA],
           [0.9 * inch, 2.0 * inch, 2.5 * inch, 1.1 * inch])
s += [P("3. Lessons learned", "h1")]
s += table([["Lesson", "What happened", "What changed"]] + [[f"<b>{e(a)}</b>", e(b), e(c)] for a, b, c in LESSONS],
           [1.4 * inch, 2.8 * inch, 2.3 * inch])
s += [PageBreak(), P("4. Limitations", "h1")]
s += bullets([
    "Applications are OIDC clients without a full front end; access is proven at the identity provider (auth code "
    "issued or denied), which is where the control sits.",
    "Entra ID is a personal free-tier tenant: no Conditional Access, Access Reviews or group-based app assignment "
    "(P1/P2). MFA for Entra users relies on Security defaults, enabled and evidenced 11/05 (EV-17, EX-01 resolved).",
    "Log retention is 90 days (EX-02); there is no running SIEM for the identity layer. Detections run on demand with "
    "can_iam.py detect, and the IR lab used a real Wazuh manager.",
    "The IR lab substitutes Debian 12 under QEMU for Parrot OS on VirtualBox (EX-06).",
    "Keycloak runs in development mode over HTTP on localhost (EX-05).",
])
s += [P("5. Open items at closure", "h1")]
s += table([["ID", "Item", "Owner", "Due"]] +
           [[a[0], e(a[2]), e(a[4]), a[5]] for a in g.ACTIONS if not a[6].startswith("Verified")],
           [0.6 * inch, 3.9 * inch, 1.2 * inch, 0.8 * inch])
s += [P("6. Next steps (future version)", "h1")]
s += bullets(["Self-service access-request portal feeding can_iam.py joiner (design doc section 11).",
              "Stream Keycloak events to Wazuh so CAN-ID rules run continuously, with 12-month archive (closes EX-02).",
              "TLS reverse proxy and production-mode Keycloak (closes EX-05).",
              "Entra ID P2 trial for Conditional Access and Access Reviews, with a cancellation reminder (cost approval first)."])
s += note("Project closure: the Weeks 1-12 board items are delivered, with the open items above carried into the "
          "corrective-action tracker with owners and dates. Sign-off by the project sponsor: "
          "____________________  Date: __________", "Closure")
build(os.path.join(g.CAN, "09_Portfolio/01_Documents/CAN_DOC_Portfolio_Index_and_Lessons_Learned_v1.1.pdf"), s,
      "Portfolio Index & Lessons Learned", f"{g.PROJECT} | Portfolio Index & Lessons Learned | v1.1")

# ------------------------------------------------------------------ 5-minute demo script
SEG = [
    ("0:00-0:30", "Problem", "Deck slides 1-3",
     "HRMC must keep ePHI and card data to the right people. Five access problems: too much access, movers keep old "
     "access, access that never ends, leavers who can still sign in, and no proof.",
     "Healthcare access must be secure and governed."),
    ("0:30-1:30", "IAM", "Keycloak admin console (Groups &rarr; Billing &rarr; Role mapping) then Terminal",
     "Show the seven job-function groups. Run the app check: a clinician gets the EHR but is denied Billing; a billing "
     "user gets an MFA prompt. Mention the mover and leaver results from TC-03 and TC-04.",
     "Least privilege is enforced by identity governance."),
    ("1:30-2:30", "Incident", "Terminal, then deck slide 9",
     "Run the password-guessing test: the account locks after 10 failures and CAN-ID-001 fires. Slide 9: leaver "
     "Jeevan Smith tries to come back (IR1-2026-001). Main case IR1-2026-002: Wazuh rule 100221 fired 1.3 s after "
     "Tara Jones read a patient record after her move to Billing; egress was blocked 49 s after the alert.", "The analyst detects and investigates abnormal activity."),
    ("2:30-3:45", "GRC", "CISO Assistant: risk R02, control IA-01, HIPAA audit, finding CA-01, exception EX-02",
     "R02 (leaver keeps access) stays High: the scripted leaver works, Entra-triggered disable is not built yet. "
     "Finding F-01 (no MFA) became corrective action CA-01, fixed and verified with before/after evidence. Control "
     "IA-01 maps to HIPAA 164.312(d) and CSF PR.AA-03 with evidence EV-13 and EV-17 attached. Exception EX-02 (log "
     "retention): compensating controls and an expiry date.", "IAM findings become measurable governance and risk actions."),
    ("3:45-4:30", "Dashboard", "CISO Assistant Analytics, then the risk matrix and the HIPAA audit donut",
     "25 HIPAA access requirements assessed: 17 compliant, 7 partially compliant, 1 non-compliant (log retention). "
     f"Control test pass rate {K['Control test pass rate (10/13 audit)']['value']}% &rarr; "
     f"{K['Control test pass rate (11/03)']['value']}%. Open items are visible with owners and dates: OTP enrolment "
     "(CA-13) and vendor end date (CA-08); the access review was signed off on 2026-11-09 (CA-05).", "Security posture is communicated to management."),
    ("4:30-5:00", "Outcome", "Deck closing slide",
     f"{passed} of {len(E2E)} end-to-end tests passed; the one failure exposed a real detection bug that was fixed and "
     "retested. One lesson: configuration that exists is not configuration that works; test the negative path.",
     "The project demonstrates an end-to-end analyst workflow."),
]
s = [P("5-Minute Capstone Demo Script", "title"), Spacer(1, 4),
     P(f"Week 12 &middot; {g.PROJECT} &middot; {g.ORG}", "subtitle"),
     P("Storyboard from the 12-week plan (section 14) with the exact screens, commands and numbers", "subsub"),
     Spacer(1, 10)]
s += table([["Time", "Segment", "Show", "Say", "Key message"]] +
           [[a, f"<b>{b}</b>", c, d, f"<i>{m}</i>"] for a, b, c, d, m in SEG],
           [0.75 * inch, 0.85 * inch, 1.25 * inch, 2.45 * inch, 1.2 * inch])
s += [PageBreak(), P("Before the demo (10 minutes)", "h1")]
s += code("""cd ~/Desktop/dae_6mon_coh2_AC/Care_Access_Navigator
docker start care-access-postgres care-access-keycloak     # wait ~20 s, then open http://localhost:8080
(cd ../ciso-assistant-community && docker compose up -d)   # CISO Assistant: wait for healthy, https://localhost:8443
set -a; . 03_IAM_Lab/01_Keycloak/01_Config/.env; set +a
export KC_ADMIN=$KC_ADMIN_USERNAME KC_ADMIN_PW=$KC_ADMIN_PASSWORD CAN_EVIDENCE=/tmp/can-demo
cd 10_Scripts/02_IAM_Automation""", title="Terminal set-up (keeps demo output out of the evidence folders)")
s += bullets(["Browser tabs: Keycloak admin console (realm care-access-navigator, Groups), the deck, CISO Assistant "
              "(Analytics; risk assessment CAN-RA-001; HIPAA audit; findings assessment CAN-FA-001).",
              "Font size up in Terminal (Cmd +) so the room can read the results.",
              "Wait at least 10 minutes after any rehearsal lockout so CAN-ID-001 raises a fresh alert."])
s += [P("Live commands", "h1")]
s += code("""# IAM (0:30): clinician allowed in the EHR, denied in Billing; billing user must pass MFA
python3 can_iam.py verify --username test.clinician2 --password "$CAN_TEST_PW" --clients ehr-simulator billing-app
python3 can_iam.py verify --username test.billing2  --password "$CAN_TEST_PW" --clients billing-app

# Incident (1:30): password guessing locks the account, then the detection fires
python3 can_iam.py verify --username test.billing2 --password "$CAN_TEST_PW" --clients billing-app \\
        --lockout-user test.vendor1 --unlock
python3 can_iam.py detect && grep "CAN-ID-001" /tmp/can-demo/identity_detections.csv | tail -1""",
          title="Expected: LOGGED_IN / DENIED; MFA_REQUIRED; PASS (locked after 10 failures); a new CAN-ID-001 High line")
s += [P("If something fails on the day", "h1")]
s += table([["Problem", "Fallback"],
            ["Keycloak not up", "Show EV-13 results in the Week 5 PDF, section 2 (same before/after table)"],
            ["Lockout already active", "Run the unlock: the --unlock flag clears it; or show TC-05 in the end-to-end report"],
            ["CISO Assistant not up", "Show the EV-16 dashboard screenshots and the CAN_DOC_CISO_* PDFs in 07_GRC"],
            ["Over time", "Skip the CISO Assistant tour; say the one-line F-01 &rarr; CA-01 story"]],
           [1.8 * inch, 4.7 * inch])
build(os.path.join(g.CAN, "09_Portfolio/04_Demo/CAN_DOC_5_Minute_Demo_Script_v1.1.pdf"), s,
      "5-Minute Capstone Demo Script", f"{g.PROJECT} | 5-Minute Demo Script | v1.1")
