"""Week 12 Days 2-4: portfolio index + lessons learned + closure, and the 5-minute demo script.
Outputs:
  09_Portfolio/01_Documents/CAN_DOC_Portfolio_Index_and_Lessons_Learned_v1.0.pdf
  09_Portfolio/04_Demo/CAN_DOC_5_Minute_Demo_Script_v1.0.pdf"""
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
    ("IAM build log", "Keycloak + Entra ID federation build",
     "Care_Access_Navigator/03_IAM_Lab/CAN_DOC_Keycloak_EntraID_Build_Log_v1.0.docx", "Done"),
    ("JML procedures + evidence", "Joiner, mover, leaver with Entra and Keycloak evidence",
     "Care_Access_Navigator/06_Evidence/07_JML_Lifecycle/Care_Access_Navigator_JML_Lifecycle_Evidence.pdf", "Done"),
    ("Authentication & privileged access", "Baseline, privileged access matrix, service/vendor register, tests",
     "Care_Access_Navigator/07_GRC/02_Controls/CAN_DOC_Authentication_and_Privileged_Access_v1.0.pdf", "Done"),
    ("Access review", "Quarterly review AR-2026-Q4 with flags and sign-off sheet",
     "Care_Access_Navigator/06_Evidence/05_Access_Reviews/CAN_DOC_Access_Review_AR-2026-Q4_v1.0.xlsx",
     "Reviewer sign-off pending (CA-05)"),
    ("SIEM use cases + incident", "Wazuh rules, CAN-ID identity rules, IR1-2026-002 report",
     "Semester_5/Incident_Response_1/task5_ir_documentation/README.md", "Done"),
    ("Risk register", "R01-R05 with inherent/residual scores and treatment status",
     "Care_Access_Navigator/08_Reporting/02_Dashboards/Tableau_Dataset/risks.csv", "Done"),
    ("Control matrix + compliance mapping", "16 controls mapped to HIPAA, CSF 2.0, SP 800-53, ISO 27001, PCI DSS; gap assessment",
     "Care_Access_Navigator/07_GRC/02_Controls/CAN_DOC_Control_Catalog_and_Mapping_v1.0.xlsx", "Done"),
    ("Exceptions + corrective actions", "7 exceptions, 17 corrective actions with verification",
     "Care_Access_Navigator/07_GRC/04_Remediation/CAN_DOC_Exceptions_and_Corrective_Actions_v1.0.xlsx", "Done"),
    ("Evidence index", "Evidence by control with SHA-256",
     "Care_Access_Navigator/06_Evidence/CAN_DOC_Evidence_Index_v1.0.xlsx", "Done"),
    ("End-to-end test report", f"TC-01 to TC-10: {passed}/{len(E2E)} passed",
     "Care_Access_Navigator/06_Evidence/04_Test_Results/CAN_DOC_End_to_End_Test_Report_v1.0.pdf", "Done"),
    ("GRC dashboard", "KPIs, wireframe, Tableau steps, validation values; live dataset",
     "Care_Access_Navigator/08_Reporting/02_Dashboards/CAN_DOC_GRC_Dashboard_Design_v1.0.pdf",
     "Design + data done; Tableau build in the app"),
    ("5-minute demo", "Script with live commands and backup evidence",
     "Care_Access_Navigator/09_Portfolio/04_Demo/CAN_DOC_5_Minute_Demo_Script_v1.0.pdf", "Done (rehearse)"),
    ("Demo deck", "MVP deck, slides 3 and 10 corrected to verified status",
     "Care_Access_Navigator/09_Portfolio/04_Demo/CAN_DOC_MVP_Demo_v1.1.pptx", "Done (export PDF from PowerPoint/Keynote)"),
]
CRITERIA = [  # plan section 17
    ("IAM", "At least one complete JML workflow, RBAC matrix, access request and access-review demonstration",
     "JML cycle (Entra + Keycloak) and automated JML in TC-01/03/04; RBAC app matrix enforced; access review run",
     "Met (review sign-off pending)"),
    ("Monitoring", "At least three useful detection use cases with controlled test events and investigation",
     "CAN-ID-001/002/004/005/007 fired on controlled events; Wazuh rules 100210/100221/100231 in IR 1", "Met"),
    ("Incident response", "One end-to-end simulated access incident from detection through lessons learned",
     "IR1-2026-002 (Tara Jones, ePHI exfiltration): alert to containment in 49 s, forensics, RCA, recovery", "Met"),
    ("GRC", "Risk register, control matrix, evidence index, gap assessment, exceptions/remediation, dashboard",
     "All registers built 11/03; dashboard data and design ready", "Met (Tableau build in the app)"),
    ("Compliance", "Controls mapped to HIPAA Security Rule and NIST concepts without claiming certification",
     "16 controls mapped to HIPAA, CSF 2.0 and SP 800-53 (plus ISO 27001 and PCI DSS)", "Met"),
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
    ("Use dedicated test identities", "Week 5 tests used new accounts (test.billing2, test.clinician2) instead of "
     "resetting existing users' passwords.", "Test accounts are labelled employment_type=test-account and reviewed "
     "quarterly like any other."),
]

s = [P("Portfolio Index & Lessons Learned", "title"), Spacer(1, 4),
     P(f"Week 12 &middot; {g.PROJECT} &middot; {g.ORG}", "subtitle"),
     P("Final documentation set, success criteria, lessons learned, limitations and project closure", "subsub"),
     Spacer(1, 10)]
s += kv([("Author", g.AUTHOR), ("Date", g.DATE), ("Version", "v1.0"),
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
    "(P1/P2). MFA for Entra users relies on Security defaults (EX-01).",
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
build(os.path.join(g.CAN, "09_Portfolio/01_Documents/CAN_DOC_Portfolio_Index_and_Lessons_Learned_v1.0.pdf"), s,
      "Portfolio Index & Lessons Learned", f"{g.PROJECT} | Portfolio Index & Lessons Learned | v1.0")

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
    ("2:30-3:45", "GRC", "Excel: Control_Catalog, Exceptions, Corrective_Actions; deck slide 10",
     "Finding F-01 (no MFA) became corrective action CA-01, fixed and verified with before/after evidence. Show one "
     "control mapped to HIPAA 164.312(d), CSF PR.AA-03 and SP 800-53 IA-2(1), and exception EX-02 (log retention, "
     "compensating controls, expiry).", "IAM findings become measurable governance and risk actions."),
    ("3:45-4:30", "Dashboard", "Tableau dashboard (or the wireframe page + kpi_values.csv)",
     f"Control pass rate {K['Control test pass rate (10/13 audit)']['value']}% &rarr; "
     f"{K['Control test pass rate (11/03)']['value']}%. Open High findings {K['Open High audit findings']['value']}. "
     "Two red tiles on purpose: OTP enrolment and review sign-off are still open, with owners and dates.",
     "Security posture is communicated to management."),
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
set -a; . 03_IAM_Lab/01_Keycloak/01_Config/.env; set +a
export KC_ADMIN=$KC_ADMIN_USERNAME KC_ADMIN_PW=$KC_ADMIN_PASSWORD CAN_EVIDENCE=/tmp/can-demo
cd 10_Scripts/02_IAM_Automation""", title="Terminal set-up (keeps demo output out of the evidence folders)")
s += bullets(["Browser tabs: Keycloak admin console (realm care-access-navigator, Groups), the deck, the Excel "
              "control catalog, the Tableau dashboard.",
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
            ["Tableau not ready", "Show the wireframe page of the dashboard design PDF and kpi_values.csv"],
            ["Over time", "Skip the GRC Excel tour; say the one-line F-01 &rarr; CA-01 story"]],
           [1.8 * inch, 4.7 * inch])
build(os.path.join(g.CAN, "09_Portfolio/04_Demo/CAN_DOC_5_Minute_Demo_Script_v1.0.pdf"), s,
      "5-Minute Capstone Demo Script", f"{g.PROJECT} | 5-Minute Demo Script | v1.0")
