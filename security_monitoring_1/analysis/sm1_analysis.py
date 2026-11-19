#!/usr/bin/env python3
"""Security Monitoring 1 analysis: baselines + thresholds, detection metrics, trends and the summary data.

Inputs: evidence/windows_history_sample.jsonl (7-day normal week), capstone Keycloak sign-in CSV,
evidence/sm1_scenario_alerts.json (alerts exported from the Wazuh indexer), live analysisd counters, MailHog.
Outputs: outputs/baselines.csv, outputs/sm1_metrics.json, outputs/trend_week.png, outputs/scenario_timeline.png
"""
import csv, json, statistics, pathlib, collections, subprocess, urllib.request, datetime as dt
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = pathlib.Path(__file__).resolve().parents[1]
REPO = R.parent
OUT = R / "outputs"; EV = R / "evidence"
hist = [json.loads(l) for l in open(EV / "windows_history_sample.jsonl")]
alerts = json.load(open(EV / "sm1_scenario_alerts.json"))
T = lambda s: dt.datetime.fromisoformat(s.replace("Z", "+00:00").replace("+0000", "+00:00"))

# ---------------- baselines (normal week) ----------------
by = collections.defaultdict(lambda: collections.Counter())
for e in hist:
    t = T(e["event_time"]); key = (t.date(), t.hour)
    by[e["event_id"]][key] += 1
hours = [(dt.date(2026, 11, 9) + dt.timedelta(days=d), h) for d in range(7) for h in range(24)]
work = [k for k in hours if 7 <= k[1] < 19 and k[0].weekday() < 5]


def stats(counter, keys):
    v = [counter.get(k, 0) for k in keys]
    m, s = statistics.mean(v), statistics.pstdev(v)
    p95 = sorted(v)[int(.95 * (len(v) - 1))]
    return round(m, 2), round(s, 2), max(v), p95


per_user_day = collections.Counter((e["username"], e["event_time"][:10]) for e in hist if e["event_id"] == "4625")
fail_ud = list(per_user_day.values()) + [0] * (7 * 6 - len(per_user_day))
reads_um = collections.Counter((e["username"], e["event_time"][:16]) for e in hist if e["event_id"] == "4663")
kc = list(csv.DictReader(open(REPO / "Care_Access_Navigator/05_Logs/01_Authentication/CAN_LOG_Keycloak_Login_Events_20261104.csv")))
kc_fail_day = collections.Counter(r["time_utc"][:10] for r in kc if r["type"] == "LOGIN_ERROR")
rows = []
for eid, name in [("4624", "Windows logons per working hour"), ("4625", "Windows failed logons per working hour"),
                  ("4663", "File reads per working hour"), ("5156", "Outbound connections per working hour")]:
    m, s, mx, p95 = stats(by[eid], work)
    rows.append([name, "7-day sample, 60 working hours", m, s, p95, mx, round(max(m + 3 * s, mx + 1), 1)])
m, s = statistics.mean(fail_ud), statistics.pstdev(fail_ud)
rows.append(["Failed logons per user per day", "7 days x 6 users", round(m, 2), round(s, 2), sorted(fail_ud)[int(.95 * (len(fail_ud) - 1))], max(fail_ud), 6])
rv = list(reads_um.values())
rows.append(["File reads per user per active minute", f"7 days, {len(rv)} user-minutes with reads", round(statistics.mean(rv), 2), round(statistics.pstdev(rv), 2),
             sorted(rv)[int(.95 * (len(rv) - 1))], max(rv), "20 in 60 s (rule 100612)"])
kv = list(kc_fail_day.values())
rows.append(["Keycloak failed sign-ins per active day", f"capstone log, {len(kv)} active days", round(statistics.mean(kv), 1), round(statistics.pstdev(kv), 1),
             "n/a (too few days)" if len(kv) < 10 else sorted(kv)[int(.95 * (len(kv) - 1))], max(kv), "5 per user in 2 min (rule 100502)"])
with open(OUT / "baselines.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["metric", "basis", "mean", "std_dev", "p95", "max", "alert_threshold"]); w.writerows(rows)

# ---------------- detection metrics ----------------
def lvl(a): return a["rule"]["level"]
scn = [a for a in alerts if str(a.get("data", {}).get("scenario", "")).startswith("SM1") or a["agent"]["name"] == "hrmc-linux-srv01"]
lat = []
for a in alerts:
    et = a.get("data", {}).get("event_time")
    if et and str(a.get("data", {}).get("scenario", "")).startswith("SM1"):
        lat.append((T(a["timestamp"]) - T(et)).total_seconds())
steps = [("Linux SSH password guessing", ["5763", "5551", "5712"]), ("Linux success after failures", ["40112"]),
         ("Linux file staging in EHR export share (FIM)", ["550", "553", "554"]), ("Linux outbound to known-bad IP", ["100630"]),
         ("Windows RDP password guessing", ["100602"]), ("Windows RDP logon from outside", ["100604"]),
         ("Windows mass EHR export reads", ["100612"]), ("Windows exfiltration connection (correlated)", ["100651"]),
         ("EHR access by same user after RDP (cross-source)", ["100650", "100521"])]
ids = collections.Counter(a["rule"]["id"] for a in alerts)
detected = [(s, any(ids.get(i) for i in r), [i for i in r if ids.get(i)]) for s, r in steps]
hist_high = 0  # the normal week produced no alerts at level >= 10 (checked in the indexer: rule counts in section 1.5)
mail = json.load(open(EV / "mailhog_messages.json"))          # exported from MailHog
since = min(T(a["timestamp"]) for a in alerts)
sm1_mail = [m for m in mail if T(m["created"][:19] + "+00:00") >= since - dt.timedelta(seconds=5)]
mail_n = len(sm1_mail); mail_to = collections.Counter(",".join(m["to"]) for m in sm1_mail)
st = dict(l.split("=", 1) for l in open(EV / "analysisd_state.txt").read().splitlines() if "=" in l and not l.startswith("#"))
metrics = {
    "operational": {"events_decoded_since_manager_start": int(float(st.get("total_events_decoded", "0").strip("'"))),
                    "events_dropped": int(float(st.get("events_dropped", "0").strip("'"))),
                    "scenario_alerts_total": len(alerts), "scenario_alerts_level10plus": sum(lvl(a) >= 10 for a in alerts),
                    "mttd_seconds_median": round(statistics.median(lat), 1) if lat else None, "mttd_seconds_max": round(max(lat), 1) if lat else None,
                    "notification_emails_sent": mail_n, "notification_recipients": dict(mail_to)},
    "coverage": {"log_sources_reporting": "5 configured; 4 active in the scenario window (Windows samples, Linux agent, Keycloak sign-in, EHR access); Keycloak admin idle (no admin activity, replays on demand)",
                 "scenario_types_covered": "3/3 (authentication, file access, network activity)",
                 "linux_servers_with_agent": "1/1 (hrmc-linux-srv01)",
                 "attack_techniques_with_rules": sorted({t for a in alerts for t in a["rule"].get("mitre", {}).get("id", [])})},
    "effectiveness": {"scenario_steps": len(steps), "steps_detected": sum(1 for _, d, _ in detected if d), "detection_rate_pct": round(100 * sum(1 for _, d, _ in detected if d) / len(steps)),
                      "normal_week_high_alerts": hist_high, "false_positive_rate_high_alerts_pct": 0.0,
                      "rule_defect_found": "100650 ignored on first run (rule load order); fixed and re-validated"},
    "steps": [{"step": s, "detected": d, "rules": r} for s, d, r in detected],
}
json.dump(metrics, open(OUT / "sm1_metrics.json", "w"), indent=1)

# ---------------- trend chart: the normal week + scenario day ----------------
days = [dt.date(2026, 11, 9) + dt.timedelta(days=d) for d in range(7)]
c = {k: collections.Counter(T(e["event_time"]).date() for e in hist if e["event_id"] == k) for k in ("4624", "4625", "4663", "5156")}
fig, ax = plt.subplots(1, 2, figsize=(9.5, 3.3), dpi=150, gridspec_kw={"width_ratios": [3, 2]})
for k, lab, col in [("4663", "File reads (4663)", "#2B6F8E"), ("5156", "Outbound connections (5156)", "#8FB8CC"),
                    ("4624", "Logons (4624)", "#2E8B57"), ("4625", "Failed logons (4625)", "#C8553D")]:
    ax[0].plot([d.strftime("%a %d") for d in days], [c[k].get(d, 0) for d in days], marker="o", label=lab, color=col)
ax[0].set_title("Normal week: Windows events per day (baseline)", fontsize=9); ax[0].legend(fontsize=7); ax[0].grid(alpha=.3); ax[0].tick_params(labelsize=7)
lv = collections.Counter(("10+" if lvl(a) >= 10 else "7-9" if lvl(a) >= 7 else "3-6") for a in alerts)
ax[1].bar(["3-6", "7-9", "10+"], [lv.get(k, 0) for k in ["3-6", "7-9", "10+"]], color=["#8FB8CC", "#E5A14B", "#C8553D"])
ax[1].set_title("Scenario day: alerts by level", fontsize=9); ax[1].grid(axis="y", alpha=.3)
fig.tight_layout(); fig.savefig(OUT / "trend_week.png")

hi = [a for a in alerts if lvl(a) >= 10]
first = {}
for a in hi:
    first.setdefault(a["rule"]["id"], a)
fig, ax = plt.subplots(figsize=(9.5, 3.2), dpi=150)
t0 = T(alerts[0]["timestamp"])
for i, (rid, a) in enumerate(sorted(first.items(), key=lambda x: x[1]["timestamp"])):
    x = (T(a["timestamp"]) - t0).total_seconds() / 60
    col = "#C8553D" if lvl(a) >= 14 else "#E5A14B" if lvl(a) >= 12 else "#2B6F8E"
    ax.scatter(x, i, s=40 + 8 * lvl(a), color=col, zorder=3)
    ax.text(x + .08, i, f"{rid} (L{lvl(a)}) {a['rule']['description'][:62]}", fontsize=6.3, va="center")
ax.set_yticks([]); ax.set_xlabel("Minutes from first scenario alert"); ax.set_title("SM1-SCN-01: first alert of each high rule (level 10+)", fontsize=9)
ax.set_xlim(-.2, max((T(a["timestamp"]) - t0).total_seconds() / 60 for a in hi) + 4); ax.grid(axis="x", alpha=.3)
fig.tight_layout(); fig.savefig(OUT / "scenario_timeline.png")
print(json.dumps(metrics, indent=1)); [print(r) for r in rows]
