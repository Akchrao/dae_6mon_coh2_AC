#!/usr/bin/env python3
"""Process integration and optimization (Compliance 2, criterion 3).

Baseline = the MANUAL joiner / mover / leaver run on 2026-10-19 (JML-LOG.csv, JML evidence PDF).
Optimized = the AUTOMATED run with can_iam.py on 2026-11-03 (EV-14 can_iam_audit_log.jsonl).
Touch times are measured from the evidence timestamps; queue/wait steps (request intake, approval, evidence filing)
are planning assumptions and are labelled as such.
Outputs: process_baseline.csv, process_summary.json, process_before_after.png
"""
import csv, json, pathlib, datetime as dt
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "compliance_2/outputs"
AUD = ROOT / "Care_Access_Navigator/06_Evidence/04_Test_Results/EV-14_End_to_End_Tests_20261103/can_iam_audit_log.jsonl"


def mins(a, b):
    f = "%H:%M"
    return (dt.datetime.strptime(b, f) - dt.datetime.strptime(a, f)).seconds / 60


# measured manual provisioning (Entra first action -> Keycloak state confirmed), JML-LOG.csv 2026-10-19
manual = {"Joiner": mins("16:23", "17:10"), "Mover": mins("17:21", "17:41"), "Leaver": mins("18:13", "18:28")}
manual_errors = {"Joiner": 0, "Mover": 0, "Leaver": 1}   # leaver left the billing role on the Keycloak copy (CA-09)

# measured automated provisioning + verification, can_iam_audit_log.jsonl 2026-11-03
log = [json.loads(l) for l in open(AUD)]
t = lambda i: dt.datetime.fromisoformat(log[i]["ts_utc"].replace("Z", "+00:00"))
idx = {a: [i for i, x in enumerate(log) if x["action"] == a] for a in ("JOINER", "MOVER", "LEAVER", "E2E.result")}
def secs_to_next_result(i):
    nxt = next(j for j in idx["E2E.result"] if j > i)
    return (t(nxt) - t(i)).total_seconds()
auto = {"Joiner": secs_to_next_result(idx["JOINER"][0]) / 60,          # TC-01 verified
        "Mover": secs_to_next_result(idx["MOVER"][0]) / 60,            # TC-03 verified
        "Leaver": secs_to_next_result(idx["LEAVER"][0]) / 60}          # TC-04 verified
auto_errors = {"Joiner": 0, "Mover": 0, "Leaver": 0}

# end-to-end lead time per request (hours). 'measured' rows come from evidence; others are planning assumptions.
steps = [  # step, baseline_h, optimized_h, basis
    ("Request intake (email / form)", 4.0, 0.5, "assumption: email triage vs. structured form"),
    ("Manager approval", 16.0, 8.0, "assumption: approval inside the workflow with reminder"),
    ("Provisioning in Entra + Keycloak (avg of J/M/L)", sum(manual.values()) / 3 / 60, sum(auto.values()) / 3 / 60, "MEASURED"),
    ("Verification of access", 0.25, 0.0, "baseline: manual check (measured part of JML evidence); optimized: automatic in can_iam"),
    ("Evidence filing for audit", 0.5, 0.0, "assumption: screenshots + register vs. automatic JSONL audit log"),
]
base_h = sum(s[1] for s in steps); opt_h = sum(s[2] for s in steps)
base_touch = sum(s[1] for s in steps if s[0].startswith(("Provisioning", "Verification", "Evidence")))
opt_touch = sum(s[2] for s in steps if s[0].startswith(("Provisioning", "Verification", "Evidence")))

with open(OUT / "process_baseline.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["step", "baseline_hours", "optimized_hours", "basis"])
    for s in steps: w.writerow([s[0], round(s[1], 3), round(s[2], 4), s[3]])

summary = {
    "measured_provisioning_minutes": {"manual_2026-10-19": {k: round(v, 1) for k, v in manual.items()},
                                      "automated_2026-11-03": {k: round(v, 2) for k, v in auto.items()}},
    "provisioning_time_reduction_pct": round((1 - sum(auto.values()) / sum(manual.values())) * 100, 1),
    "error_rate": {"manual": f"{sum(manual_errors.values())}/3", "automated": f"{sum(auto_errors.values())}/3 (plus 6 more JML checks in TC-01..TC-09, all PASS)"},
    "leaver_exposure_window_minutes": {"manual": 12, "automated": 0},
    "touch_time_hours": {"baseline": round(base_touch, 2), "optimized": round(opt_touch, 3),
                         "reduction_pct": round((1 - opt_touch / base_touch) * 100, 1)},
    "lead_time_hours": {"baseline": round(base_h, 2), "optimized": round(opt_h, 2), "reduction_pct": round((1 - opt_h / base_h) * 100, 1)},
    "target": "30% efficiency improvement",
    "validation": ["TC-01 joiner, TC-02 least privilege, TC-03 mover, TC-04 leaver all PASS on 2026-11-03 (EV-14)",
                   "KPI 'leaver deprovisioned and verified within 24 h' = 100% for automated leavers",
                   "Re-run of can_iam.py verify on 2026-11-17: clinician DENIED on billing-app, billing MFA_REQUIRED"]}
json.dump(summary, open(OUT / "process_summary.json", "w"), indent=1)

fig, ax = plt.subplots(1, 2, figsize=(9, 3.4), dpi=150)
k = list(manual)
ax[0].bar([x + "\nmanual" for x in k], [manual[x] for x in k], color="#C8553D")
ax[0].bar([x + "\nautomated" for x in k], [auto[x] for x in k], color="#2B6F8E")
ax[0].set_ylabel("Minutes"); ax[0].set_title("Provisioning time (measured)", fontsize=9); ax[0].tick_params(axis="x", labelsize=7)
ax[1].barh(["Lead time", "Touch time"], [base_h, base_touch], color="#C8553D", label="Baseline")
ax[1].barh(["Lead time", "Touch time"], [opt_h, opt_touch], color="#2B6F8E", label="Optimized", height=.45)
ax[1].set_xlabel("Hours per request"); ax[1].set_title("End-to-end per JML request", fontsize=9); ax[1].legend(fontsize=7)
fig.tight_layout(); fig.savefig(OUT / "process_before_after.png")
print(json.dumps(summary, indent=1))
