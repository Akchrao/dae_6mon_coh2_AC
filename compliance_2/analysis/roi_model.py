#!/usr/bin/env python3
"""ROI, cost-benefit and payback for the HRMC compliance automation program (Compliance 2, criterion 2).

Volumes are for the expanded HRMC (10,800 staff). Unit times come from measured evidence where available
(process_summary.json); hourly rates and volumes are planning assumptions, listed in ASSUMPTIONS.
Outputs: roi_model.csv, roi_summary.json, roi_cumulative.png
"""
import csv, json, pathlib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "compliance_2/outputs"
proc = json.load(open(OUT / "process_summary.json"))
mc = json.load(open(OUT / "risk_mc_summary.json"))

ASSUMPTIONS = {
    "staff": 10_800, "annual_turnover": 0.18, "internal_moves": 0.10,
    "iam_rate": 55, "grc_rate": 65, "manager_rate": 70, "audit_rate": 75,  # loaded USD per hour (blended US/EU/India)
    "unified_controls": 48, "regions": 3, "manual_hours_per_control_test": 2.5, "test_automation_share": 0.70,
    "review_managers": 120, "manual_review_prep_hours": 1.5,
    "audit_prep_hours_per_framework": 400, "frameworks": 3, "audit_prep_reduction": 0.40,
    "risk_benefit_share_credited": 0.25,   # share of the modelled R02 + R05 risk reduction credited to automation
    "discount_rate": 0.08,
}
A = ASSUMPTIONS
events = round(A["staff"] * A["annual_turnover"]) * 2 + round(A["staff"] * A["internal_moves"])   # joiners + leavers + movers
manual_min = sum(proc["measured_provisioning_minutes"]["manual_2026-10-19"].values()) / 3 + 15 + 30   # + verification + evidence filing
auto_min = sum(proc["measured_provisioning_minutes"]["automated_2026-11-03"].values()) / 3 + 2.5      # + approval click / spot check

savings = {
    "JML touch time": events * (manual_min - auto_min) / 60 * A["iam_rate"],
    "Control testing and evidence collection": A["unified_controls"] * A["regions"] * 4 * A["manual_hours_per_control_test"] * A["test_automation_share"] * A["grc_rate"],
    "Access review preparation": A["review_managers"] * 4 * A["manual_review_prep_hours"] * A["manager_rate"],
    "External audit preparation": A["audit_prep_hours_per_framework"] * A["frameworks"] * A["audit_prep_reduction"] * A["audit_rate"],
}
risk_r = {r: 0 for r in ("R02", "R05")}
for row in csv.DictReader(open(OUT / "risk_mc_results.csv")):
    if row["risk_id"] in risk_r:
        risk_r[row["risk_id"]] = float(row["risk_reduction"])
risk_benefit = sum(risk_r.values()) * A["risk_benefit_share_credited"]

one_time = {"Workflow engine + AI triage build (320 h)": 320 * 85, "CISO Assistant deployment + data sync (160 h)": 160 * 85,
            "SIEM (Wazuh) integration (120 h)": 120 * 85, "JML automation hardening for 3 regions (200 h)": 200 * 85,
            "Training: 200 staff x 1 h": 200 * 60,
            "Program + change management (300 h)": 300 * 95,
            "Privacy review of the AI step: GDPR Art. 22 / DPIA (60 h)": 60 * 150,
            "Validation testing of the automation (120 h)": 120 * 85, "Open-source licences (CISO Assistant CE, Wazuh, Keycloak)": 0}
annual = {"Hosting: 3 VMs / containers": 3 * 250 * 12, "Platform administration (0.5 FTE)": 55_000,
          "Model retraining and rule tuning (80 h)": 80 * 85}
C0, Cy = sum(one_time.values()), sum(annual.values())
S_hard = sum(savings.values())

def npv(cash, r):
    return sum(c / (1 + r) ** i for i, c in enumerate(cash))

rows, cum, cum_r = [], -C0, -C0
for y in range(0, 4):
    if y == 0:
        rows.append({"year": 0, "costs": C0, "hard_savings": 0, "risk_benefit": 0, "net": -C0, "cumulative_hard": cum, "cumulative_with_risk": cum_r})
        continue
    ramp = {1: 0.6, 2: 1.0, 3: 1.0}[y]          # year 1 = 60% adoption while the EU / India sites onboard
    net = S_hard * ramp - Cy; net_r = net + risk_benefit * ramp
    cum += net; cum_r += net_r
    rows.append({"year": y, "costs": Cy, "hard_savings": round(S_hard * ramp), "risk_benefit": round(risk_benefit * ramp),
                 "net": round(net), "cumulative_hard": round(cum), "cumulative_with_risk": round(cum_r)})

monthly_y1 = (S_hard * 0.6 - Cy) / 12
payback_months = round(C0 / monthly_y1, 1) if monthly_y1 > 0 else None
cash_hard = [-C0] + [r["net"] for r in rows[1:]]
cash_risk = [-C0] + [r["net"] + r["risk_benefit"] for r in rows[1:]]
summary = {"assumptions": A, "jml_events_per_year": events, "minutes_per_jml_event": {"manual": round(manual_min, 1), "automated": round(auto_min, 1)},
           "annual_hard_savings_full_adoption": {k: round(v) for k, v in savings.items()}, "annual_hard_savings_total": round(S_hard),
           "annual_risk_benefit_credited": round(risk_benefit), "one_time_costs": one_time, "one_time_total": C0,
           "annual_costs": annual, "annual_cost_total": Cy, "payback_months_hard_savings": payback_months,
           "three_year_npv_hard": round(npv(cash_hard, A["discount_rate"])), "three_year_npv_with_risk": round(npv(cash_risk, A["discount_rate"])),
           "three_year_roi_pct_hard": round((sum(r["hard_savings"] for r in rows) - (C0 + 3 * Cy)) / (C0 + 3 * Cy) * 100),
           "operational_savings_hours_per_year": round(events * (manual_min - auto_min) / 60 + A["unified_controls"] * A["regions"] * 4 * A["manual_hours_per_control_test"] * A["test_automation_share"]
                                                       + A["review_managers"] * 4 * A["manual_review_prep_hours"] + A["audit_prep_hours_per_framework"] * A["frameworks"] * A["audit_prep_reduction"])}
with open(OUT / "roi_model.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
json.dump(summary, open(OUT / "roi_summary.json", "w"), indent=1)

fig, ax = plt.subplots(figsize=(7, 3.2), dpi=150)
ax.plot([r["year"] for r in rows], [r["cumulative_hard"] / 1e3 for r in rows], marker="o", label="Hard savings only", color="#2B6F8E")
ax.plot([r["year"] for r in rows], [r["cumulative_with_risk"] / 1e3 for r in rows], marker="s", label="Including credited risk reduction", color="#2E8B57")
ax.axhline(0, color="#888", lw=1); ax.set_xticks([0, 1, 2, 3]); ax.set_xlabel("Year"); ax.set_ylabel("Cumulative net (US$ thousands)")
ax.set_title("Compliance automation: cumulative cash position", fontsize=10); ax.grid(alpha=.3); ax.legend(fontsize=8)
fig.tight_layout(); fig.savefig(OUT / "roi_cumulative.png")
print(json.dumps(summary, indent=1)); print(rows)
