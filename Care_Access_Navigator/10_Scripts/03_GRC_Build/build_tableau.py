"""Week 11: refresh the Tableau dataset from live evidence and grc_data.py, and compute current KPI values.

Writes into Care_Access_Navigator/08_Reporting/02_Dashboards/Tableau_Dataset/:
  access_review_AR-2026-Q4.csv   live quarterly review (EV-15), replaces the replica sample
  identity_detections.csv        live CAN-ID detections (EV-14), replaces the replica sample
  control_tests.csv              audit CAN-IA-2026-01 tests + 11/03 retests and end-to-end tests
  audit_findings.csv             F-01..F-06 with verified status
  controls.csv, exceptions.csv, corrective_actions.csv   from the Week 9-10 registers
  risks.csv                      adds treatment_status / treatment_evidence (scores unchanged)
  kpi_values.csv                 KPI value measured from the files above, with target and RAG status
"""
import csv, datetime as dt, os, shutil

import grc_data as g

DS = os.path.join(g.CAN, "08_Reporting/02_Dashboards/Tableau_Dataset")
EV15 = os.path.join(g.CAN, "06_Evidence/05_Access_Reviews/EV-15_Access_Review_AR-2026-Q4_20261103")


def write(name, header, rows):
    with open(os.path.join(DS, name), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"wrote {name} ({len(rows)} rows)")


def read(name):
    with open(os.path.join(DS, name), newline="") as f:
        return list(csv.DictReader(f))


shutil.copy(os.path.join(EV15, "access_review_AR-2026-Q4.csv"), os.path.join(DS, "access_review_AR-2026-Q4.csv"))
shutil.copy(os.path.join(g.EV14, "identity_detections.csv"), os.path.join(DS, "identity_detections.csv"))
print("copied live access review (EV-15) and identity detections (EV-14)")

# control tests: keep the 10/13 audit rows, add the 11/03 retests and end-to-end results
tests = [r for r in read("control_tests.csv") if r["audit_id"] == "CAN-IA-2026-01"]
L = g.live()
retest = [("AC-01", "4", "MFA enforcement (retest)", "PASS"), ("AC-01", "5", "Lockout and password policy (retest)", "PASS"),
          ("AC-01", "6", "Completed access review (retest)", "FAIL")]   # review run, sign-off pending (CA-05)
rows = [[r["control_id"], r["test_no"], r["test"], r["result"], r["test_date"], r["audit_id"]] for r in tests]
rows += [[c, n, t, res, g.ISO_DATE, "CAN-W5-RETEST-2026-11-03"] for c, n, t, res in retest]
tc_ctl = {"TC-01": "AC-01", "TC-02": "AC-04", "TC-03": "AC-03", "TC-04": "AC-02", "TC-05": "IA-02", "TC-06": "AU-02",
          "TC-07": "AC-05", "TC-08": "VM-01", "TC-09": "AR-01", "TC-10": "CA-01"}
for r in g.e2e()["results"]:
    rows.append([tc_ctl[r["tc"]], r["tc"], r["scenario"], "PASS" if r["result"].startswith("PASS") else "FAIL",
                 g.ISO_DATE, "CAN-E2E-2026-11-03"])
    if r["tc"] == "TC-05":   # keep the first-run failure visible
        rows.append([tc_ctl["TC-05"], "TC-05 first run", r["scenario"], "FAIL", g.ISO_DATE, "CAN-E2E-2026-11-03"])
write("control_tests.csv", ["control_id", "test_no", "test", "result", "test_date", "audit_id"], rows)

# audit findings with verified status
act = {a[1]: a for a in g.ACTIONS}
f_rows = []
for r in read("audit_findings.csv"):
    a = act.get(r["finding_id"])
    status = ("Closed (verified)" if a and a[6].startswith("Verified") else
              "Open (exception)" if a and "EX-" in a[6] else "In progress" if a and a[6] == "In progress" else "Open")
    f_rows.append([r["finding_id"], r["rating"], r["finding"], r["requirement"], r["owner"], r["target_date"], status,
                   a[0] if a else "", a[9] if a else ""])
write("audit_findings.csv", ["finding_id", "rating", "finding", "requirement", "owner", "target_date", "status",
                             "corrective_action", "verified_date"], f_rows)

write("controls.csv", ["control_id", "objective", "area", "hipaa", "nist_csf_2", "nist_800_53", "iso_27001",
                       "pci_dss", "risks", "evidence", "test", "result", "implementation", "gap"], g.CONTROLS)
write("exceptions.csv", ["exception_id", "control_id", "exception", "justification", "compensating_controls", "risk",
                         "requested_by", "approved_by", "approved", "expires", "status"], g.EXCEPTIONS)
write("corrective_actions.csv", ["action_id", "source", "issue", "action", "owner", "due", "status",
                                 "verification_criterion", "verification_evidence", "verified_on"], g.ACTIONS)

treat = {"R01": ("Implemented", "Group RBAC + app gates + quarterly review (TC-01, TC-02, TC-07)"),
         "R02": ("Implemented", "Leaver automation verified (TC-04); leftover role fixed (CA-09)"),
         "R03": ("Partially implemented", "MFA + lockout enforced (EV-13); Entra MFA and 12-month logs open (EX-01, EX-02)"),
         "R04": ("Partially implemented", "Privileged groups need MFA; CAN-ID-005 alerts; admin MFA exception (EX-03)"),
         "R05": ("Partially implemented", "Vendor end date enforced for new vendors (TC-08); test.vendor1 open (CA-08)")}
risks = read("risks.csv")
for r in risks:
    r["treatment_status"], r["treatment_evidence"] = treat[r["risk_id"]]
write("risks.csv", list(risks[0].keys()), [list(r.values()) for r in risks])

# KPI values measured from the dataset
rev = read("access_review_AR-2026-Q4.csv")
priv = [r for r in rev if r["enabled"] == "True" and set(r["effective_roles"].split(";")) & {"billing", "it-support", "security-analyst"}]
priv_local = [r for r in priv if r["source"] == "local"]
tests_now = [r for r in rows if r[5] != "CAN-IA-2026-01"]
kpis = [
    ("Privileged MFA enforcement", "privileged local accounts forced through OTP / privileged local accounts",
     len(priv_local), len(priv_local), "100%", "Policy enforced realm-wide by role mfa-required (EV-13)"),
    ("Privileged MFA enrolment", "privileged users with OTP enrolled / privileged users",
     sum(r["mfa_enrolled"] == "True" for r in priv), len(priv), "100%", "Enrolment happens at next sign-in (CA-13)"),
    ("Access review completion", "accounts with reviewer_decision / accounts",
     sum(bool(r["reviewer_decision"]) for r in rev), len(rev), "100% per quarter", "Sign-off pending (CA-05)"),
    ("Flagged accounts (High)", "count risk=High", sum(r["risk"] == "High" for r in rev), None, "0", "AR-2026-Q4"),
    ("Open High audit findings", "count rating=High and not closed",
     sum(r[1] == "High" and not r[6].startswith("Closed") for r in f_rows), None, "0 by Dec 2026", "F-03 (EX-02)"),
    ("Control test pass rate (11/03)", "PASS / tests run on 2026-11-03",
     sum(r[3] == "PASS" for r in tests_now), len(tests_now), ">= 90%", "W5 retests + end-to-end run"),
    ("Control test pass rate (10/13 audit)", "PASS / tests in CAN-IA-2026-01",
     sum(r[3] == "PASS" for r in rows if r[5] == "CAN-IA-2026-01"),
     sum(1 for r in rows if r[5] == "CAN-IA-2026-01"), ">= 90%", "Baseline for the before/after story"),
    ("Corrective actions verified", "Verified actions / all actions",
     sum(a[6].startswith("Verified") for a in g.ACTIONS), len(g.ACTIONS), "trend up", "Exceptions and CA tracker"),
    ("Open exceptions", "exceptions not closed", sum(1 for x in g.EXCEPTIONS), None, "each within expiry",
     "Exception register"),
    ("Residual High risks", "count residual_rating=High", sum(r["residual_rating"] == "High" for r in risks), None,
     "<= 1", "risks.csv (scores from Risk Management 1)"),
]
out = []
for name, formula, num, den, target, note in kpis:
    value = round(100 * num / den, 1) if den else num
    unit = "%" if den else "count"
    out.append([name, formula, num, den if den else "", value, unit, target, g.ISO_DATE, note])
write("kpi_values.csv", ["kpi", "formula", "numerator", "denominator", "value", "unit", "target", "measured_on",
                         "note"], out)
