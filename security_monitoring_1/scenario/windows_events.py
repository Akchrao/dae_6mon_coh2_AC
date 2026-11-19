#!/usr/bin/env python3
"""Imported Windows Security event samples for Security Monitoring 1 (option B: no live Windows host).

The events follow the Microsoft Security log schema (event IDs 4624, 4625, 4634, 4663, 4732, 4740, 5156) in the
flattened JSON a log shipper produces. Each event carries "sample": "imported-synthetic" so nobody mistakes it for
live telemetry, and a normalised "username" (the IAM username behind the AD account) so it can be correlated with
Keycloak / EHR events.

  python3 windows_events.py history   > 7-day normal baseline (2026-11-09 .. 11-15), written for Wazuh
  python3 windows_events.py scenario  > SM1-SCN-01 attack, written in real time
Writes to ~/soc1-lab/soc1/logs/windows_security.json (monitored by the Wazuh manager).
"""
import json, random, sys, time, pathlib, datetime as dt

LOG = pathlib.Path.home() / "soc1-lab/soc1/logs/windows_security.json"
HIST = pathlib.Path(__file__).resolve().parent.parent / "evidence/windows_history_sample.jsonl"
rnd = random.Random(2026)
USERS = {  # username: (workstation, shift start hour, share)
    "test.nurse1": ("HRMC-WS-4W-01", 7, r"\\HRMC-FS01\Clinical\Protocols"),
    "test.nurse2": ("HRMC-WS-4W-02", 7, r"\\HRMC-FS01\Clinical\Protocols"),
    "test.clinician1": ("HRMC-WS-ICU-01", 8, r"\\HRMC-FS01\Clinical\Guidelines"),
    "test.billing1": ("HRMC-WS-PFS-02", 9, r"\\HRMC-FS01\Billing\Statements"),
    "test.hr1": ("HRMC-WS-HR-01", 9, r"\\HRMC-FS01\HR\Policies"),
    "it_admin": ("HRMC-WS-IT-01", 8, r"\\HRMC-FS01\IT\Runbooks"),
}


def ev(t, event_id, user, computer, **kw):
    return {"src": "windows_security", "event_time": t.isoformat(timespec="seconds"), "event_id": str(event_id),
            "channel": "Security", "computer": f"{computer}.hrmc.local", "target_user": f"HRMC\\{user}",
            "username": user, "sample": "imported-synthetic", **kw}


def history():
    out = []
    for day in range(7):
        d0 = dt.datetime(2026, 11, 9, tzinfo=dt.timezone.utc) + dt.timedelta(days=day)
        weekend = d0.weekday() >= 5
        for u, (ws, h, share) in USERS.items():
            if weekend and u in ("test.billing1", "test.hr1"):
                continue
            t = d0 + dt.timedelta(hours=h, minutes=rnd.randint(0, 25))
            for _ in range(rnd.choice([0, 0, 0, 1, 1, 2])):          # typos at sign-in
                out.append(ev(t, 4625, u, ws, logon_type="2", ip="-", status="0xC000006A", failure="bad password"))
                t += dt.timedelta(seconds=rnd.randint(5, 40))
            out.append(ev(t, 4624, u, ws, logon_type="2", ip="-", logon_process="User32"))
            for _ in range(rnd.randint(4, 14)):                       # normal file reads during the shift
                t += dt.timedelta(minutes=rnd.randint(5, 40))
                out.append(ev(t, 4663, u, "HRMC-FS01", object_name=f"{share}\\doc_{rnd.randint(1, 60):02d}.pdf",
                              access_mask="0x1", access="ReadData", process_name="C:\\Windows\\explorer.exe"))
            for _ in range(rnd.randint(3, 8)):                        # normal outbound web traffic
                t += dt.timedelta(minutes=rnd.randint(3, 30))
                out.append(ev(t, 5156, u, ws, direction="Outbound", application="chrome.exe", protocol="6",
                              dest_ip=rnd.choice(["10.20.0.15", "10.20.0.16", "13.107.42.14"]), dest_port="443"))
            out.append(ev(d0 + dt.timedelta(hours=h + 8, minutes=rnd.randint(0, 30)), 4634, u, ws, logon_type="2"))
        if day == 2:                                                  # approved change: helpdesk added to local admins
            out.append(ev(d0 + dt.timedelta(hours=14), 4732, "it_admin", "HRMC-WS-IT-01", member="HRMC\\helpdesk2",
                          group="Administrators", change_ticket="CHG-2026-0315"))
    out.sort(key=lambda e: e["event_time"])
    HIST.parent.mkdir(exist_ok=True)
    HIST.write_text("".join(json.dumps(e) + "\n" for e in out))
    with open(LOG, "a") as f:
        for e in out:
            f.write(json.dumps(e) + "\n"); f.flush(); time.sleep(0.35)
    print(f"history: {len(out)} Windows events")


def scenario():
    """SM1-SCN-01: billing account compromised over RDP, EHR exports read in bulk, data sent out."""
    now = lambda: dt.datetime.now(dt.timezone.utc)
    bad, u, ws = "203.0.113.77", "test.billing1", "HRMC-WS-PFS-02"
    tag = {"scenario": "SM1-SCN-01"}
    with open(LOG, "a") as f:
        w = lambda e: (f.write(json.dumps({**e, **tag}) + "\n"), f.flush())
        for _ in range(7):
            w(ev(now(), 4625, u, ws, logon_type="10", ip=bad, status="0xC000006A", failure="bad password")); time.sleep(3)
        w(ev(now(), 4624, u, ws, logon_type="10", ip=bad, logon_process="User32")); time.sleep(10)
        for i in range(30):
            w(ev(now(), 4663, u, "HRMC-FS01", object_name=f"\\\\HRMC-FS01\\EHR_Exports\\patients_2026_{i:02d}.csv",
                 access_mask="0x1", access="ReadData", process_name="C:\\Users\\test.billing1\\AppData\\Local\\Temp\\rclone.exe"))
            time.sleep(1)
        time.sleep(5)
        w(ev(now(), 5156, u, ws, direction="Outbound", application="rclone.exe", protocol="6", dest_ip=bad, dest_port="443"))
    print("scenario SM1-SCN-01 (Windows part) written")


if __name__ == "__main__":
    {"history": history, "scenario": scenario}[sys.argv[1]]()
