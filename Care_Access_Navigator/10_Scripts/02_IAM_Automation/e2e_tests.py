#!/usr/bin/env python3
"""
e2e_tests.py — Week 12 Day 1 end-to-end test run (test case catalog TC-01..TC-10, 12-week plan §13)
====================================================================================================
Runs every test case against the live Keycloak realm with can_iam.py, then writes
e2e_results.json (one record per test case: steps, expected, actual, result) next to the
can_iam audit log in $CAN_EVIDENCE.

Test identities are synthetic and created by the run itself (test.clinician3, test.nurse2,
test.vendor2). Their passwords are random per run and never written to disk.
TC-10 (high-risk control gap -> risk register -> dashboard) is a document trace, recorded
here with its references; it has no Keycloak step.
"""
import csv, datetime as dt, json, os, secrets, sys, time
from types import SimpleNamespace as NS

import can_iam as c

kc = c.KC()
START = dt.datetime.now(dt.timezone.utc)
RESULTS = []


def pw():
    return "E2e!" + secrets.token_urlsafe(12) + "7x"


def activate(username):
    """Simulate the person finishing first sign-in (sets a permanent password the run knows)."""
    p = pw()
    u = kc.user(username)
    kc.put(f"/users/{u['id']}/reset-password", {"type": "password", "value": p, "temporary": False})
    ra = [r for r in kc.user(username).get("requiredActions", []) if r != "UPDATE_PASSWORD"]
    kc.put(f"/users/{u['id']}", {"requiredActions": ra})
    return p


def login(client, username, password):
    time.sleep(1.5)   # stay clear of Keycloak's quick-login check
    res = c.browser_login(client, username, password, kc)
    c.log("E2E.login", client=client, user=username, result=res)
    return res


def review(rid):
    c.cmd_review(kc, NS(review_id=rid))
    with open(os.path.join(c.EVID, f"access_review_{rid}.csv"), newline="") as f:
        return {r["username"]: r for r in csv.DictReader(f)}


def record(tc, scenario, expected, steps, actual, passed, evidence):
    RESULTS.append({"tc": tc, "scenario": scenario, "expected": expected, "steps": steps, "actual": actual,
                    "result": "PASS" if passed else "FAIL", "evidence": evidence})
    c.log("E2E.result", tc=tc, result="PASS" if passed else "FAIL", actual=actual)


def detections():
    c.cmd_detect(kc, NS(max=5000, ehr_log=None, ehr_threshold=15))
    with open(os.path.join(c.EVID, "identity_detections.csv"), newline="") as f:
        return [r for r in csv.DictReader(f) if dt.datetime.fromisoformat(r["time_utc"]) >= START]


for name in ("test.clinician3", "test.nurse2", "test.vendor2"):
    if kc.get(f"/users?exact=true&username={name}"):
        sys.exit(f"{name} already exists: this run creates it. Pick new usernames or remove the old test account.")

# ---------------------------------------------------------------- TC-01 joiner
c.cmd_joiner(kc, NS(username="test.clinician3", first="Priya", last="Natarajan", email="test.clinician3@hrmc.example",
                    role="clinician", department="Cardiology", manager="clinical.manager1", ticket="REQ-2026-0601",
                    temp_password=pw(), end_date=None))
p_cl = activate("test.clinician3")
r = {app: login(app, "test.clinician3", p_cl) for app in ("ehr-simulator", "patient-portal", "billing-app", "hr-app")}
snap = kc.snapshot("test.clinician3")
ok = (snap["groups"] == ["Clinicians"] and snap["effective_roles"] == ["clinician"]
      and all(r[a].startswith("LOGGED_IN") for a in ("ehr-simulator", "patient-portal"))
      and all(r[a].startswith("DENIED") for a in ("billing-app", "hr-app")))
record("TC-01", "New clinician receives approved role", "Only clinician-approved application access is granted",
       ["can_iam.py joiner (REQ-2026-0601, group Clinicians)", "first sign-in completed", "sign in to all 4 apps"],
       {"groups": snap["groups"], "roles": snap["effective_roles"], "logins": r}, ok,
       "can_iam_audit_log.jsonl: JOINER, E2E.login")

# ---------------------------------------------------------------- TC-02 billing user tries clinical app
p_b = os.environ["CAN_TEST_PW"]
r = {app: login(app, "test.billing2", p_b) for app in ("ehr-simulator", "patient-portal", "hr-app")}
ok = all(v.startswith("DENIED") for v in r.values())
record("TC-02", "Billing user attempts clinical / admin function", "Access denied",
       ["sign in as test.billing2 to ehr-simulator, patient-portal, hr-app"], {"logins": r}, ok,
       "E2E.login; keycloak_login_events.csv (LOGIN_ERROR access_denied); CAN-ID-004")

# ---------------------------------------------------------------- TC-03 mover nurse -> billing
c.cmd_joiner(kc, NS(username="test.nurse2", first="Maya", last="Rivera", email="test.nurse2@hrmc.example", role="nurse",
                    department="Med-Surg 4W", manager="nurse.manager1", ticket="REQ-2026-0602",
                    temp_password=pw(), end_date=None))
p_n = activate("test.nurse2")
before = {"snapshot": kc.snapshot("test.nurse2"), "ehr": login("ehr-simulator", "test.nurse2", p_n)}
c.cmd_mover(kc, NS(username="test.nurse2", new_role="billing", department="Patient Financial Services",
                   manager="billing.manager1", ticket="CHG-2026-0602"))
after = {"snapshot": kc.snapshot("test.nurse2"), "ehr": login("ehr-simulator", "test.nurse2", p_n),
         "billing": login("billing-app", "test.nurse2", p_n)}
ok = (before["ehr"].startswith("LOGGED_IN") and after["snapshot"]["effective_roles"] == ["billing"]
      and after["ehr"].startswith("DENIED") and after["billing"].startswith("MFA_REQUIRED"))
record("TC-03", "Employee changes from Nurse to Billing", "Old access removed; new billing access granted",
       ["joiner nurse (REQ-2026-0602)", "EHR sign-in before", "can_iam.py mover (CHG-2026-0602)",
        "EHR + Billing sign-in after"], {"before": before, "after": after}, ok,
       "can_iam_audit_log.jsonl: MOVER removed/added")

# ---------------------------------------------------------------- TC-04 leaver
c.cmd_leaver(kc, NS(username="test.nurse2", manager="billing.manager1", ticket="TERM-2026-0602", password=None))
snap = kc.snapshot("test.nurse2")
res = login("ehr-simulator", "test.nurse2", p_n)
ok = not snap["enabled"] and not snap["groups"] and not snap["effective_roles"] and res.startswith("DENIED (account disabled")
record("TC-04", "Employee termination simulated", "Identity disabled and access revoked/removed",
       ["can_iam.py leaver (TERM-2026-0602)", "old password tried on ehr-simulator"],
       {"after": snap, "login": res}, ok, "can_iam_audit_log.jsonl: LEAVER verification")

# ---------------------------------------------------------------- TC-07 unexpected privileged-role assignment
v = kc.user("test.vendor1"); billing = kc.group("Billing")
kc.put(f"/users/{v['id']}/groups/{billing['id']}", {})          # simulated insider change, no ticket
c.log("E2E.simulated_attack", tc="TC-07", change="add test.vendor1 to Billing (no ticket)")
flag_rev = review("AR-E2E-TC07-20261103")["test.vendor1"]
kc.delete(f"/users/{v['id']}/groups/{billing['id']}")            # remediation: remove unapproved privilege
c.log("E2E.remediation", tc="TC-07", change="removed test.vendor1 from Billing", ticket="CA-07")
after_v = kc.snapshot("test.vendor1")

# ---------------------------------------------------------------- TC-08 vendor past end date
yesterday = (dt.date.today() - dt.timedelta(days=1)).isoformat()
c.cmd_joiner(kc, NS(username="test.vendor2", first="Omar", last="Haddad", email="test.vendor2@hrmc.example",
                    role="vendor", department="Imaging vendor (MedTech Services)", manager="it.manager1",
                    ticket="REQ-2026-0603", temp_password=pw(), end_date=yesterday))
rev8 = review("AR-E2E-TC08-20261103")["test.vendor2"]
c.cmd_leaver(kc, NS(username="test.vendor2", manager="it.manager1", ticket="TERM-2026-0603", password=None))
after_v2 = kc.snapshot("test.vendor2")
ok = "ACCESS_PAST_END_DATE" in rev8["flags"] and rev8["risk"] == "High" and not after_v2["enabled"]
record("TC-08", "Vendor account reaches expiry", "Access is disabled or flagged for review",
       [f"vendor joiner with access_end_date={yesterday} (REQ-2026-0603)", "access review", "leaver (TERM-2026-0603)"],
       {"review_flags": rev8["flags"], "risk": rev8["risk"], "after": after_v2}, ok,
       "access_review_AR-E2E-TC08-20261103.csv; LEAVER")

# ---------------------------------------------------------------- TC-09 access review finds excess access
j = "entra-id.test.billing@chakhilaraogmail.onmicrosoft.com"
rev9 = review("AR-E2E-TC09-BEFORE-20261103")[j]
ju = kc.user(j)
dr = kc.direct_roles(ju["id"])
if dr:   # corrective action CA-09: leaver TERM-2026-0301 left the IdP-mapped role on the disabled Keycloak copy
    kc.delete(f"/users/{ju['id']}/role-mappings/realm", [kc.role(x) for x in dr])
c.log("E2E.remediation", tc="TC-09", user=j, removed_roles=dr, ticket="CA-09",
      authority="TERM-2026-0301 (approved leaver: all access removed)")
rev9b = review("AR-E2E-TC09-AFTER-20261103")[j]
ok = "DISABLED_BUT_HAS_ACCESS" in rev9["flags"] and "DISABLED_BUT_HAS_ACCESS" not in rev9b["flags"] \
     and not rev9b["effective_roles"]
record("TC-09", "Quarterly access review identifies excess access", "Finding becomes remediation task",
       ["access review", "flag DISABLED_BUT_HAS_ACCESS on Jeevan Smith (leaver)", "corrective action CA-09: remove role",
        "re-review"], {"before_flags": rev9["flags"], "removed": dr, "after_flags": rev9b["flags"],
                       "after_roles": rev9b["effective_roles"]}, ok,
       "access_review_AR-E2E-TC09-BEFORE/AFTER-20261103.csv; E2E.remediation")

# ---------------------------------------------------------------- TC-05 / TC-06 / TC-07 detections
lock_u = kc.user("test.vendor1")
for i in range(11):
    c.browser_login("ehr-simulator", "test.vendor1", "Wrong-Password-%d!" % i, kc)
    time.sleep(1.5)
st = kc.get(f"/attack-detection/brute-force/users/{lock_u['id']}")
kc.delete(f"/attack-detection/brute-force/users/{lock_u['id']}")
c.log("E2E.lockout", user="test.vendor1", keycloak_status=st)
alerts = detections()
by = lambda rule, who: [a for a in alerts if a["rule_id"].startswith(rule) and a["subject"] == who]
d5 = by("CAN-ID-001", "test.vendor1")
record("TC-05", "Repeated failed authentication", "SIEM detects/alerts based on configured threshold",
       ["11 wrong passwords for test.vendor1", "can_iam.py detect"],
       {"locked": st.get("disabled"), "numFailures": st.get("numFailures"), "alerts": d5},
       bool(d5) and st.get("disabled"), "identity_detections.csv CAN-ID-001; E2E.lockout")
d6 = by("CAN-ID-002", "test.nurse2")
record("TC-06", "Disabled user attempts login", "Event is visible and investigated",
       ["terminated test.nurse2 signs in (TC-04)", "can_iam.py detect"], {"alerts": d6}, bool(d6),
       "identity_detections.csv CAN-ID-002; keycloak_login_events.csv user_disabled")
d7 = [a for a in by("CAN-ID-005", "test.vendor1") if "Billing" in a["detail"]]
ok = (any(a["severity"] == "High" and a["detail"].startswith("CREATE") for a in d7)
      and "MULTIPLE_ROLES_SOD_CHECK" in flag_rev["flags"] and after_v["effective_roles"] == ["vendor"])
record("TC-07", "Unexpected privileged-role assignment", "Change is detected/reviewed and unauthorized privilege removed",
       ["insider adds test.vendor1 to Billing (no ticket)", "access review", "remove from Billing (CA-07)",
        "can_iam.py detect"], {"alerts": d7, "review_flags": flag_rev["flags"], "after_roles": after_v["effective_roles"]},
       ok, "identity_detections.csv CAN-ID-005; access_review_AR-E2E-TC07-20261103.csv")

# ---------------------------------------------------------------- TC-10 control gap -> risk -> dashboard (document trace)
record("TC-10", "High-risk control gap identified", "Risk is recorded, assigned and tracked",
       ["audit finding F-03 (no 12-month log retention, High)", "risk R03 credential compromise / monitoring gap",
        "exception EX-02 with compensating controls", "corrective action CA-03", "dashboard tile Open High findings"],
       {"trace": "F-03 -> R03 -> EX-02 -> CA-03 -> audit_findings.csv / exceptions.csv (Tableau)"}, True,
       "CAN_DOC_Exceptions_and_Corrective_Actions_v1.0.xlsx; Tableau_Dataset")

RESULTS.sort(key=lambda x: x["tc"])
out = os.path.join(c.EVID, "e2e_results.json")
json.dump({"run_start_utc": START.isoformat(), "run_end_utc": c.now(), "realm": c.REALM, "results": RESULTS},
          open(out, "w"), indent=1)
c.log("E2E.summary", passed=sum(r["result"] == "PASS" for r in RESULTS), total=len(RESULTS), file=out)
c.hash_index()
for r in RESULTS:
    print(f"{r['tc']}  {r['result']}  {r['scenario']}")
