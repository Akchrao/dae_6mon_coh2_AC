"""Week 12 Day 1: end-to-end test report built from EV-14 e2e_results.json.
Output: Care_Access_Navigator/06_Evidence/04_Test_Results/CAN_DOC_End_to_End_Test_Report_v1.0.pdf"""
import json, os
from html import escape as e

import grc_data as g
from pdfstyle import P, bullets, note, code, table, kv, ok, bad, build, Spacer, PageBreak, inch

D = g.e2e()
R = D["results"]
OUT = os.path.join(g.CAN, "06_Evidence/04_Test_Results/CAN_DOC_End_to_End_Test_Report_v1.0.pdf")
TITLE = "End-to-End Test Report"
passed = sum(r["result"].startswith("PASS") for r in R)


def verdict(r):
    return ok(e(r["result"])) if r["result"].startswith("PASS") else bad(e(r["result"]))


def show(v):
    if isinstance(v, dict):
        return "<br/>".join(f"<b>{e(str(k))}</b>: {show(x)}" for k, x in v.items())
    if isinstance(v, list):
        if v and isinstance(v[0], dict) and "rule_id" in v[0]:
            return "<br/>".join(e(f"{a['rule_id']} ({a['severity']}) {a['time_utc'][11:19]}Z {a['subject']}: {a['detail']}")
                                for a in v)
        return e(", ".join(map(str, v))) or "none"
    return e(str(v)) if v not in ("", None) else "none"


s = [P(TITLE, "title"), Spacer(1, 4), P(f"Week 12 &middot; {g.PROJECT} &middot; {g.ORG}", "subtitle"),
     P("Test case catalog TC-01 to TC-10 (12-week plan, section 13) executed against the live lab", "subsub"),
     Spacer(1, 10)]
s += kv([("Author", g.AUTHOR), ("Date", g.DATE), ("Version", "v1.0"),
         ("Run", f"{D['run_start_utc'][:19]}Z to {D['run_end_utc']} (UTC); TC-05 retest 21:31Z"),
         ("System", f"Keycloak realm {D['realm']} after Week 5 hardening; can_iam.py + e2e_tests.py"),
         ("Evidence", "06_Evidence/04_Test_Results/EV-14_End_to_End_Tests_20261103/ (results, audit log, access "
                      "reviews, login events, detections; SHA-256 indexed)"),
         ("Result", f"{passed} of {len(R)} passed (TC-05 failed on the first run and passed after corrective action CA-10)")])
s += table([["TC", "Scenario", "Expected result", "Result"]] +
           [[r["tc"], e(r["scenario"]), e(r["expected"]), verdict(r)] for r in R],
           [0.55 * inch, 2.2 * inch, 2.6 * inch, 1.15 * inch])
s += note("Test identities were created by the run itself: test.clinician3 (Priya Natarajan, joiner), test.nurse2 "
          "(Maya Rivera, joiner &rarr; mover &rarr; leaver) and test.vendor2 (Omar Haddad, vendor past end date). "
          "Passwords were random per run and never written to disk. test.nurse2 and test.vendor2 are left disabled "
          "and kept for audit. TC-07 used a simulated insider change on test.vendor1, reversed in the same run.",
          "Test data")

s += [PageBreak(), P("Test case details", "h1")]
for r in R:
    rows = [["Steps", "<br/>".join(f"{i}. {e(x)}" for i, x in enumerate(r["steps"], 1))],
            ["Actual", show(r["actual"]) if r["tc"] != "TC-05" else show({k: v for k, v in r["retest"].items() if k != "note"})],
            ["Evidence", e(r["evidence"])], ["Result", verdict(r)]]
    if r["tc"] == "TC-05":
        rows.insert(1, ["First run", bad("FAIL") + " &mdash; " + e(r["root_cause"])])
        rows.insert(2, ["Corrective action", e(r["corrective_action"]) + ". Retest: " + e(r["retest"]["note"]) + "."])
    s += [P(f"{r['tc']} &middot; {e(r['scenario'])}", "h2")]
    s += table([[k, v] for k, v in rows], [1.2 * inch, 5.3 * inch], header=False, zebra=False)

s += [PageBreak(), P("Findings from the test run", "h1")]
s += table([["Finding", "Found by", "Action", "Status"],
            ["The brute-force rule CAN-ID-001 raised one alert per user for all history, so a second attack on the same "
             "account was never alerted", "TC-05", "CA-10: alert once per 10-minute burst; retested with a fresh burst",
             ok("Verified")],
            ["The approved leaver for Jeevan Smith (TERM-2026-0301) disabled the Keycloak copy but left the "
             "Entra-mapped billing role on it", "TC-09 (access review)",
             "CA-09: role removed. Federated leavers must go through can_iam.py leaver (strips IdP-mapped roles), not only Disable in the console", ok("Verified")],
            ["test.vendor1 has no sponsor or access end date", "TC-07 review flags", "CA-08: sponsor decision",
             "Open"],
            ["Privileged accounts not yet enrolled in OTP", "Access reviews", "CA-13: enrolment forced at next sign-in",
             "In progress"]],
           [2.7 * inch, 1.1 * inch, 1.9 * inch, 0.8 * inch])
s += [P("Proof of detection and proof of prevention (identity layer)", "h2")]
s += table([["Attack (simulated)", "Prevention", "Detection"],
            ["Password guessing on test.vendor1", "Locked after 10 failures (TC-05)", "CAN-ID-001 High"],
            ["Billing user opens the EHR (ePHI)", "Denied by the EHR gate (TC-02)", "CAN-ID-004 Medium"],
            ["Terminated nurse signs in", "Denied: account disabled (TC-04)", "CAN-ID-002 High (TC-06)"],
            ["Insider adds a vendor to Billing", "Access review flag + removal (TC-07)", "CAN-ID-005 High"],
            ["Vendor past end date", "Flagged High + leaver (TC-08)", "ACCESS_PAST_END_DATE; CAN-ID-006 if used"]],
           [2.3 * inch, 2.3 * inch, 1.9 * inch])
s += [P("Not covered by this run", "h2")]
s += bullets(["Entra-federated sign-in with Entra MFA (needs the Entra admin: exception EX-01).",
              "Excessive ePHI access (CAN-ID-007) was tested with the synthetic EHR access log in Week 5, not with a "
              "running EHR application.",
              "Host-level incident response was tested separately in Incident Response 1 (IR1-2026-001/002/003)."])
build(OUT, s, TITLE, f"{g.PROJECT} | End-to-End Test Report | v1.0")
