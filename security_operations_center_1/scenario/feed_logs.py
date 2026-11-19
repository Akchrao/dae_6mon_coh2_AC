#!/usr/bin/env python3
"""SOC 1 log feeder.

Replays the Care Access Navigator capstone logs into the files Wazuh monitors
(~/soc1-lab/soc1/logs, mounted at /var/log/soc1 in the manager), one JSON object per line.
Each record keeps its original fields and timestamp (field "event_time") and gets a "src" tag
that the SOC 1 rules use to tell the log sources apart.

  python3 feed_logs.py history     # replay the real capstone logs (4 sources)
  python3 feed_logs.py scenario    # run the SOC 1 investigation scenario (synthetic, labelled)
"""
import csv, json, sys, time, pathlib, datetime

REPO = pathlib.Path.home() / "Desktop/dae_6mon_coh2_AC"
LOGS = pathlib.Path(__file__).resolve().parent / "logs"
LOGS.mkdir(exist_ok=True)

SOURCES = [
    ("keycloak_login", REPO / "Care_Access_Navigator/05_Logs/01_Authentication/CAN_LOG_Keycloak_Login_Events_20261104.csv"),
    ("keycloak_admin", REPO / "Care_Access_Navigator/05_Logs/02_Access/CAN_LOG_Keycloak_Admin_Events_20261104.csv"),
    ("ehr_access", REPO / "Care_Access_Navigator/05_Logs/02_Access/CAN_LOG_EHR_Access_Sample_20261104.csv"),
]
AUTH_LOG = REPO / "incident_response_1/task2_log_analysis/evidence/parrot/auth.log"


def write(src, rec):
    rec = {"src": src, **rec}
    with open(LOGS / f"{src}.json", "a") as f:
        f.write(json.dumps(rec) + "\n")


def history(delay=0.4):
    """Interleave the three CSV sources by time, then the Linux auth.log."""
    rows = []
    for src, path in SOURCES:
        for r in csv.DictReader(open(path)):
            r = {k: v for k, v in r.items() if v != ""}
            r["event_time"] = r.pop("time_utc")
            rows.append((r["event_time"], src, r))
    rows.sort(key=lambda x: x[0])
    for _, src, r in rows:
        write(src, r)
        time.sleep(delay)
    with open(LOGS / "auth.log", "a") as out:
        for line in open(AUTH_LOG):
            out.write(line)
            out.flush()
            time.sleep(0.05)
    print(f"history: {len(rows)} capstone events + auth.log replayed")


def scenario():
    """SOC 1 investigation scenario (synthetic, clearly labelled).

    Shift: Night, 2026-11-18. A password-guessing burst against test.nurse2 from an outside IP,
    followed by a successful sign-in from the same IP and bulk chart access by the same account.
    """
    now = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    ip = "203.0.113.45"  # documentation range (RFC 5737), not a real host
    for _ in range(6):
        write("keycloak_login", {"event_time": now(), "type": "LOGIN_ERROR", "error": "invalid_user_credentials",
                                 "username": "test.nurse2", "client": "ehr-simulator", "ip": ip,
                                 "auth_method": "openid-connect", "scenario": "SOC1-SCN-01"})
        time.sleep(2)
    write("keycloak_login", {"event_time": now(), "type": "LOGIN", "username": "test.nurse2", "client": "ehr-simulator",
                             "ip": ip, "auth_method": "openid-connect", "scenario": "SOC1-SCN-01"})
    time.sleep(3)
    for i in range(18):
        write("ehr_access", {"event_time": now(), "username": "test.nurse2", "role": "nurse",
                             "patient_id": f"SYN-PT-{20100 + i}", "action": "view_chart",
                             "workstation": "REMOTE-VPN", "scenario": "SOC1-SCN-01"})
        time.sleep(1.5)
    print("scenario SOC1-SCN-01 written")


if __name__ == "__main__":
    {"history": history, "scenario": scenario}[sys.argv[1]]()
