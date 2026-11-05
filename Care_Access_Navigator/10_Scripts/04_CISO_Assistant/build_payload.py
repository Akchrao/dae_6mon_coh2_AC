"""Build the CISO Assistant import payload from the project registers (grc_data.py).

Run on the Mac (no extra packages):  python3 build_payload.py
Writes <ciso>/db/import_tmp/payload.json and copies every evidence file next to it, so the
backend container (which mounts <ciso>/db at /code/db) can read them. Then run load_ciso.py.

CISO Assistant becomes the system of record for the GRC registers (W8-W11). grc_data.py stays as
the source the registers were first written in; this script translates it, it does not retype it.
"""
import csv, json, os, shutil, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "03_GRC_Build"))
import grc_data as g  # noqa: E402

REPO = g.REPO
CISO = os.path.join(REPO, "ciso-assistant-community")
OUT = os.path.join(CISO, "db", "import_tmp")
CAN = "Care_Access_Navigator/"

# ------------------------------------------------------------------ assets (W1 Tue asset inventory)
ASSETS = [
    # ref, name, type, description
    ("CAN-AST-000", "Patient ePHI and billing data (synthetic)", "PR",
     "Primary asset: electronic protected health information and patient billing / cardholder data handled by the "
     "HRMC applications. All records in the lab are synthetic."),
    ("CAN-AST-001", "Mock EHR Application", "SP", None),  # exists; description kept
    ("CAN-AST-002", "Keycloak Identity Provider (realm care-access-navigator)", "SP",
     "Identity broker and authorization layer: realm roles, job-function groups, MFA flow, lockout, per-app sign-in "
     "gates, event logging. Bound to 127.0.0.1:8080 (CA-11)."),
    ("CAN-AST-003", "Microsoft Entra ID (workforce identity source)", "SP",
     "Workforce identity source federated to Keycloak over OIDC (broker app care-access-navigator-keycloak-broker)."),
    ("CAN-AST-004", "Patient Portal", "SP", "OIDC client patient-portal; admits Clinician and Nurse roles only."),
    ("CAN-AST-005", "Billing Application", "SP",
     "OIDC client billing-app; cardholder data (PCI DSS scope); admits Billing role only; MFA required."),
    ("CAN-AST-006", "HR Application", "SP", "OIDC client hr-app; admits HR and IT-Support roles; MFA required."),
]
ALL_SP = [a[0] for a in ASSETS if a[2] == "SP"]

# ------------------------------------------------------------------ risks (risks.csv = Risk Management 1 register)
RISK_ASSETS = {
    "R01": ALL_SP, "R02": ["CAN-AST-001", "CAN-AST-002", "CAN-AST-003"],
    "R03": ["CAN-AST-002", "CAN-AST-003"], "R04": ["CAN-AST-002", "CAN-AST-003"],
    "R05": ["CAN-AST-002"],
}


def residual_li(score, impact):
    """risks.csv keeps residual as a score only; treatment lowers likelihood, impact stays."""
    return score // impact, impact


def risks():
    rows = list(csv.DictReader(open(os.path.join(REPO, CAN, "08_Reporting/02_Dashboards/Tableau_Dataset/risks.csv"))))
    out = []
    for r in rows:
        li, im = int(r["inherent_likelihood"]), int(r["inherent_impact"])
        rl, ri = residual_li(int(r["residual_score"]), im)
        out.append(dict(ref=r["risk_id"], name=r["risk"], inherent=(li, im), residual=(rl, ri),
                        treatment=r["treatment"], status=r["treatment_status"], evidence=r["treatment_evidence"],
                        framework=r["framework_ref"], owner=r["owner"], source=r["source"],
                        residual_rating=r["residual_rating"], residual_score=r["residual_score"],
                        assets=RISK_ASSETS[r["risk_id"]]))
    return out


# ------------------------------------------------------------------ evidence (Evidence Index + W1-W5 screenshots)
SHOT = CAN + "06_Evidence/01_Screenshots/"
EV13 = CAN + "06_Evidence/04_Test_Results/EV-13_Auth_Hardening_Live_20261103/"
EV14 = CAN + "06_Evidence/04_Test_Results/EV-14_End_to_End_Tests_20261103/"
EV15 = CAN + "06_Evidence/05_Access_Reviews/"
EXTRA_EVIDENCE = [
    # id, description, path, controls
    ("EV-02", "Entra ID tenant overview p1 (baseline 2026-09-21)", SHOT + "EV-02_Entra_ID_Overview_Page1_20260921.png", ["IA-01"]),
    ("EV-03", "Entra ID tenant overview p2 (baseline 2026-09-21)", SHOT + "EV-03_Entra_ID_Overview_Page2_20260921.png", ["IA-01"]),
    ("EV-04", "Entra ID to Keycloak connection point (baseline 2026-09-21)", SHOT + "EV-04_Entra_ID_Keycloak_Connect_Point_20260921.png", ["IA-01", "AC-02"]),
    ("EV-05", "Federated user confirmation (baseline 2026-09-21)", SHOT + "EV-05_Federated_User_Confirmation_20260921.png", ["AC-02"]),
    ("EV-06", "Entra ID application page (baseline 2026-09-22)", SHOT + "EV-06_Entra_ID_Application_Page_20260922.png", ["AC-04"]),
    ("EV-07", "Keycloak sign-in before authentication changes (baseline 2026-09-22)", SHOT + "EV-07_Keycloak_Before_Authentication_20260922.png", ["IA-01"]),
    ("EV-08", "Keycloak password policy (baseline 2026-09-22, before W5 hardening)", SHOT + "EV-08_Keycloak_Password_Policies_20260922.png", ["IA-02"]),
    ("EV-09", "Keycloak brute-force detection (baseline 2026-09-22, before W5 hardening)", SHOT + "EV-09_Keycloak_Brute_Force_Detection_20260922.png", ["IA-02"]),
    ("EV-10", "Keycloak MFA authentication flow (baseline 2026-09-22, before W5 hardening)", SHOT + "EV-10_Keycloak_MFA_Authentication_Flow_20260922.png", ["IA-01"]),
    ("EV-11", "Azure VNet address space", SHOT + "EV-11_Azure_VNet_Address_Space_20260923.png", ["SC-01"]),
    ("EV-12", "Azure network security groups", SHOT + "EV-12_Azure_Network_Security_Groups_20260923.png", ["SC-01"]),
    ("EV-14", "End-to-end test report TC-01..TC-10 (10/10 PASS, 2026-11-03)", CAN + "06_Evidence/04_Test_Results/CAN_DOC_End_to_End_Test_Report_v1.0.pdf",
     ["AC-01", "AC-02", "AC-03", "AC-04", "AC-05", "AR-01", "VM-01", "AU-02", "CA-01"]),
    ("EV-15", "Access review AR-2026-Q4 (reviewer sign-off pending, CA-05)", EV15 + "EV-15_Access_Review_AR-2026-Q4_20261103/access_review_AR-2026-Q4.csv", ["AR-01"]),
    ("EV-15", "Access review AR-2026-Q4 sign-off workbook", EV15 + "CAN_DOC_Access_Review_AR-2026-Q4_v1.0.xlsx", ["AR-01"]),
    ("W2-ENTRA", "Entra ID identity governance design (W2 Wed, 2026-11-05)", CAN + "03_IAM_Lab/CAN_DOC_Entra_ID_Identity_Governance_Design_v1.0.pdf", ["AC-01", "AC-02", "IA-01"]),
    ("EV-17", "Entra ID Security defaults enabled (2026-11-05)", SHOT + "EV-17_Entra_Security_Defaults_20261105.png", ["IA-01"]),
    ("JML-15", "Entra ID audit log export for the JML cycle", CAN + "06_Evidence/07_JML_Lifecycle/JML-15-entra-audit-log.txt", ["AC-02"]),
    ("CTL-CAT", "Control catalog and HIPAA/NIST/ISO/PCI mapping (W9)", CAN + "07_GRC/02_Controls/CAN_DOC_Control_Catalog_and_Mapping_v1.0.xlsx", ["CA-01", "RA-01"]),
]
# JML-PDF is already in CISO Assistant as "Jeevan Smith -Leaver Access Revocation Evidence"
EXISTING_JML_EVIDENCE = "Jeevan Smith -Leaver Access Revocation Evidence"


def evidence():
    by_path = {}
    for ctl, eid, desc, path in g.EVIDENCE:
        by_path.setdefault(path, dict(id=eid, desc=desc, path=path, controls=[]))["controls"].append(ctl)
    for eid, desc, path, ctls in EXTRA_EVIDENCE:
        e = by_path.setdefault(path, dict(id=eid, desc=desc, path=path, controls=[]))
        e["controls"] += [c for c in ctls if c not in e["controls"]]
    out = []
    for e in by_path.values():
        src = os.path.join(REPO, e["path"])
        if not os.path.isfile(src):
            sys.exit(f"missing evidence file: {e['path']}")
        if e["path"].endswith("Care_Access_Navigator_JML_Lifecycle_Evidence.pdf"):
            e.update(existing=EXISTING_JML_EVIDENCE)
        else:
            e.update(file=f"{e['id']}_{os.path.basename(src)}", sha256=g.sha256(e["path"]))
        e["name"] = f"{e['id']} - {e['desc']}"
        out.append(e)
    return out


# ------------------------------------------------------------------ HIPAA (NIST SP 800-66r2) requirements assessed
# node -> controls. Result = weakest implementation of the mapped controls unless overridden.
HIPAA = [
    ("node6", "164.308(a)(1)(ii)(A) risk analysis", ["RA-01"]),
    ("node10", "164.308(a)(1)(ii)(B) risk management", ["RA-01", "CA-01"]),
    ("node22", "164.308(a)(1)(ii)(D) information system activity review process", ["AU-02", "AR-01"]),
    ("node28", "164.308(a)(1)(ii)(D) activity review and audit in operation", ["AU-01", "AU-02"]),
    ("node48", "164.308(a)(3)(ii)(C) termination procedures", ["AC-02", "CAN-CTRL-JML-001", "CAN-CTRL-JML-002"]),
    ("node57", "164.308(a)(4)(ii)(B) access authorization", ["AC-01", "AC-05"]),
    ("node61", "164.308(a)(4)(ii)(C) access establishment and modification", ["AC-03", "AC-01"]),
    ("node65", "164.308(a)(4) evaluate access-control measures", ["AR-01"]),
    ("node76", "164.308(a)(5)(ii)(C) log-in monitoring", ["AU-02", "IA-02"]),
    ("node78", "164.308(a)(5)(ii)(D) password management", ["IA-02"]),
    ("node95", "164.308(a)(6)(ii) incident response and reporting", ["IR-01"]),
    ("node99", "164.308(a)(6) post-incident analysis", ["IR-01"]),
    ("node131", "164.308(a)(8) evaluation", ["CA-01"]),
    ("node138", "164.308(b)(1) business associates identified", ["VM-01"]),
    ("node201", "164.312(a)(1) access needs analysed", ["AC-01"]),
    ("node205", "164.312(a)(2)(i) unique user identification", ["AC-01"]),
    ("node211", "164.312(a)(1) access control implemented", ["AC-04", "AC-01"]),
    ("node213", "164.312(a)(1) access reviewed and updated", ["AR-01"]),
    ("node215", "164.312(a)(2)(ii) emergency access procedure", ["AC-05"]),
    ("node225", "164.312(a)(1) access terminated when no longer required", ["AC-02"]),
    ("node228", "164.312(b) activities to be audited", ["AU-01"]),
    ("node236", "164.312(b) audit / activity review process", ["AU-02"]),
    ("node258", "164.312(d) person or entity authentication", ["IA-01", "IA-02"]),
    ("node269", "164.312(e)(2)(ii) encryption in transit", ["SC-01"]),
    ("node321", "164.316(b)(2) retention (security log retention policy)", ["AU-03"]),
]
HIPAA_OVERRIDE = {
    "node48": ("partially_compliant",
               "Termination procedure exists and the scripted Keycloak leaver step passed TC-04 and TC-09 (after CA-09) on "
               "2026-11-03. Still open: an Entra ID termination does not disable the Keycloak copy automatically "
               "(CAN-FIND-001, CAN-CTRL-JML-002), so the federated path depends on the operator running the leaver step."),
    "node78": ("partially_compliant",
               "Password standard enforced (length 12, history 4; EV-13). Lab passwords that were committed to the "
               "public repository before 2026-11-03 are not yet rotated (EX-07, CA-12)."),
    "node215": ("partially_compliant", "Break-glass procedure designed, account not provisioned (EX-04)."),
    "node138": ("partially_compliant",
                "Vendor rules require a sponsor, end date and BAA; test.vendor1 has no sponsor or end date (CA-08). "
                "No signed BAA is evidenced in the lab."),
}
HIPAA_EXCEPTIONS = {"node258": ["EX-01"], "node321": ["EX-02"], "node215": ["EX-04"], "node269": ["EX-05"],
                    "node95": ["EX-06"], "node78": ["EX-07"]}

# ------------------------------------------------------------------ exceptions (W10 Wed) + new EX-08
EX_STATUS = {"Approved": "approved", "Pending instructor acceptance": "in_review"}
EX_SEVERITY = {"EX-01": 2, "EX-02": 3, "EX-03": 2, "EX-04": 1, "EX-05": 1, "EX-06": 0, "EX-07": 3, "EX-08": 0}
EX_08 = ("EX-08", "-", "W11 Thu deliverable: the integrated GRC dashboard is delivered in CISO Assistant (analytics, "
         "risk and audit dashboards and exports) instead of a Tableau workbook",
         "Tableau is not installed and the GRC registers now live in CISO Assistant, which reports on them directly; "
         "a separate Tableau copy would duplicate the data",
         "Tableau dataset CSVs and dashboard design PDF kept in 08_Reporting/02_Dashboards for reference",
         "-", "Student", "Instructor (pending)", "-", "2026-11-05", "Pending instructor acceptance")
# severities from the Compliance 1 remediation tracker (F-01..F-06); others are left unrated
F_SEVERITY = {"F-01": 3, "F-02": 3, "F-03": 3, "F-04": 2, "F-05": 2, "F-06": 1}
CA_CONTROL = {"F-01": "IA-01", "F-02": "IA-02", "F-03": "AU-03", "F-04": "IA-02", "F-05": "AR-01", "F-06": "SC-01",
              "TC-07": "AC-05", "Access review": None, "TC-09": "AC-02", "TC-05": "AU-02", "EX-03": "AC-05",
              "EX-07": "IA-02", "Board audit": "CA-01", "SV-01..04": "AC-04", "SV-05": "AC-05", "LP-01": "AC-01",
              "SV-06": "AC-05"}
CA_CONTROL_BY_ID = {"CA-08": "VM-01", "CA-13": "IA-01"}
CA_STATUS = {"Verified": "resolved", "Verified (late)": "resolved", "Open": "assigned", "In progress": "in_progress"}


def main():
    os.makedirs(OUT, exist_ok=True)
    ev = evidence()
    for e in ev:
        if "file" in e:
            shutil.copy2(os.path.join(REPO, e["path"]), os.path.join(OUT, e["file"]))
    names = [e["file"] for e in ev if "file" in e]
    if len(names) != len(set(names)):
        sys.exit("duplicate evidence file names")
    payload = dict(
        assets=ASSETS, risks=risks(), controls=g.CONTROLS, evidence=ev,
        hipaa=HIPAA, hipaa_override=HIPAA_OVERRIDE, hipaa_exceptions=HIPAA_EXCEPTIONS,
        exceptions=list(g.EXCEPTIONS) + [EX_08], ex_status=EX_STATUS, ex_severity=EX_SEVERITY,
        actions=g.ACTIONS, f_severity=F_SEVERITY, ca_control=CA_CONTROL, ca_control_by_id=CA_CONTROL_BY_ID,
        ca_status=CA_STATUS, iso_date=g.ISO_DATE,
        ex_evidence={"EX-01": "EV-17"},
    )
    json.dump(payload, open(os.path.join(OUT, "payload.json"), "w"), indent=1)
    print(f"payload: {len(ASSETS)} assets, {len(payload['risks'])} risks, {len(g.CONTROLS)} controls, "
          f"{len(ev)} evidence, {len(HIPAA)} HIPAA requirements, {len(payload['exceptions'])} exceptions, "
          f"{len(g.ACTIONS)} corrective actions -> {OUT}")


if __name__ == "__main__":
    main()
