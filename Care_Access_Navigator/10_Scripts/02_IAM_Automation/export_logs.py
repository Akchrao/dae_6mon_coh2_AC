#!/usr/bin/env python3
"""
export_logs.py — export the live Keycloak logs into Care_Access_Navigator/05_Logs (Week 2 Day 4 logging foundation)
=================================================================================================================
  05_Logs/01_Authentication/CAN_LOG_Keycloak_Login_Events_<YYYYMMDD>.csv   every LOGIN / LOGIN_ERROR / LOGOUT ... event
  05_Logs/02_Access/CAN_LOG_Keycloak_Admin_Events_<YYYYMMDD>.csv          user, group, role and realm changes (who/what)
  05_Logs/02_Access/CAN_LOG_EHR_Access_Sample_<YYYYMMDD>.csv              synthetic EHR record-access log (CAN-ID-007 input)
  05_Logs/03_Test_Logs/CAN_LOG_Identity_Detections_<YYYYMMDD>.csv         CAN-ID-001..007 over the exported events
  05_Logs/03_Test_Logs/CAN_LOG_IAM_Automation_Audit_<YYYYMMDD>.jsonl      can_iam.py audit logs (EV-13 + EV-14)
  05_Logs/EVIDENCE-INDEX-SHA256.txt                                      `shasum -a 256 -c` format
Keycloak keeps events for 90 days (eventsExpiration); exporting is how they are kept longer (exception EX-02).
Same environment variables as can_iam.py.
"""
import csv, datetime as dt, hashlib, json, os, shutil
from types import SimpleNamespace as NS

import can_iam as c

HERE = os.path.dirname(os.path.abspath(__file__))
CAN = os.path.dirname(os.path.dirname(HERE))
LOGS = os.path.join(CAN, "05_Logs")
DAY = dt.date.today().strftime("%Y%m%d")
kc = c.KC()
ts = lambda ms: dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).isoformat()
users = {u["id"]: u["username"] for u in kc.get("/users?max=2000")}
written = []


def out(sub, name):
    p = os.path.join(LOGS, sub, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    written.append(p)
    return p


ev = sorted(kc.get("/events?max=10000") or [], key=lambda e: e["time"])
with open(out("01_Authentication", f"CAN_LOG_Keycloak_Login_Events_{DAY}.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["time_utc", "type", "error", "username", "client", "ip", "auth_method", "identity_provider"])
    for e in ev:
        d = e.get("details") or {}
        w.writerow([ts(e["time"]), e["type"], e.get("error", ""), users.get(e.get("userId"), d.get("username", "")),
                    e.get("clientId", ""), e.get("ipAddress", ""), d.get("auth_method", ""), d.get("identity_provider", "")])

adm = sorted(kc.get("/admin-events?max=10000") or [], key=lambda e: e["time"])
with open(out("02_Access", f"CAN_LOG_Keycloak_Admin_Events_{DAY}.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["time_utc", "operation", "resource_type", "resource_path", "target_user", "detail", "admin_user", "ip"])
    for e in adm:
        rp = e.get("resourcePath", "")
        parts = rp.split("/")
        target = users.get(parts[1], "") if parts[0] == "users" and len(parts) > 1 else ""
        try:
            rep = json.loads(e.get("representation") or "null")
        except ValueError:
            rep = None
        detail = (",".join(r.get("name", "") for r in rep if isinstance(r, dict)) if isinstance(rep, list)
                  else (rep or {}).get("name", "") if isinstance(rep, dict) else "")
        a = e.get("authDetails") or {}
        w.writerow([ts(e["time"]), e.get("operationType"), e.get("resourceType"), rp, target, detail,
                    users.get(a.get("userId"), "admin (master realm)"), a.get("ipAddress", "")])

shutil.copy(os.path.join(HERE, "sample_ehr_access_log.csv"), out("02_Access", f"CAN_LOG_EHR_Access_Sample_{DAY}.csv"))

det_dir = os.path.join(LOGS, "03_Test_Logs")
os.makedirs(det_dir, exist_ok=True)
c.EVID = det_dir   # detect writes identity_detections.csv + keycloak_login_events.csv into EVID
c.cmd_detect(kc, NS(max=10000, ehr_log=os.path.join(HERE, "sample_ehr_access_log.csv"), ehr_threshold=15))
os.replace(os.path.join(det_dir, "identity_detections.csv"), out("03_Test_Logs", f"CAN_LOG_Identity_Detections_{DAY}.csv"))
for tmp in ("keycloak_login_events.csv", "can_iam_audit_log.jsonl", "EVIDENCE-INDEX-SHA256.txt"):
    if os.path.exists(os.path.join(det_dir, tmp)):
        os.remove(os.path.join(det_dir, tmp))   # duplicates of the files above / this run's own log

with open(out("03_Test_Logs", f"CAN_LOG_IAM_Automation_Audit_{DAY}.jsonl"), "w") as f:
    for ev_dir in ("EV-13_Auth_Hardening_Live_20261103", "EV-14_End_to_End_Tests_20261103"):
        with open(os.path.join(CAN, "06_Evidence", "04_Test_Results", ev_dir, "can_iam_audit_log.jsonl")) as src:
            for line in src:
                rec = json.loads(line)
                rec["evidence_folder"] = ev_dir
                f.write(json.dumps(rec) + "\n")

with open(os.path.join(LOGS, "EVIDENCE-INDEX-SHA256.txt"), "w") as f:
    for p in sorted(written):
        f.write(f"{hashlib.sha256(open(p, 'rb').read()).hexdigest()}  {os.path.relpath(p, LOGS)}\n")
for p in written:
    n = sum(1 for _ in open(p)) - (0 if p.endswith(".jsonl") else 1)
    print(f"{n:6} records  {os.path.relpath(p, CAN)}")
