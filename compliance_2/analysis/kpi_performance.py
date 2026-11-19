#!/usr/bin/env python3
"""Performance management and continuous improvement (Compliance 2, criterion 6).

KPI framework (current values from live evidence), reference benchmarks, predictive alerts
(items predicted to miss their date), and the measured results of PDCA cycle 1.
Outputs: kpi_framework.csv, kpi_summary.json, pdca_cycle1.png
"""
import csv, json, pathlib, datetime as dt
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "compliance_2/outputs"
snap = json.load(open(ROOT / "compliance_2/data/ciso_snapshot.json"))
wf = json.load(open(OUT / "workflow_summary.json"))
aa = json.load(open(OUT / "audit_analytics.json"))
proc = json.load(open(OUT / "process_summary.json"))
mc = json.load(open(OUT / "risk_mc_summary.json"))
today = dt.date.fromisoformat(snap["exported_utc"][:10])

hipaa = next(c for c in snap["compliance_assessments"] if "HIPAA" in c["ref_id"])["results"]
csf = next(c for c in snap["compliance_assessments"] if "CSF" in c["ref_id"])["results"]
pct = lambda r: round(100 * r.get("compliant", 0) / sum(r.values()), 1)
exc = snap["exceptions"]
expired = [x["ref_id"] for x in exc if x["status"] not in ("resolved",) and x["expiration_date"] and dt.date.fromisoformat(x["expiration_date"]) < today]
cas = [f for f in snap["findings"] if f["ref_id"].startswith("CA-")]
overdue = [f["ref_id"] for f in cas if f["status"] != "resolved" and f["due_date"] and dt.date.fromisoformat(f["due_date"]) < today]
ct = aa["control_tests"]

aud = list(csv.DictReader(open(ROOT / "Care_Access_Navigator/08_Reporting/02_Dashboards/Tableau_Dataset/audit_findings.csv")))
# live status: finding F-0n is closed when its corrective action CA-0n is resolved in CISO Assistant
live = {f["ref_id"]: f["status"] for f in snap["findings"]}
for a in aud:
    if live.get("CA-" + a["finding_id"][2:]) == "resolved":
        a["status"] = "Closed (CISO Assistant: resolved)"
HIGH_BEFORE = sum(a["rating"] == "High" for a in aud)
HIGH_AFTER = sum(a["rating"] == "High" and not a["status"].startswith("Closed") for a in aud)
CLOSED_AFTER = sum(a["status"].startswith("Closed") for a in aud)
KPIS = [  # category, kpi, formula, current, target, benchmark / reference
    ("Compliance", "HIPAA requirements fully compliant", "compliant / assessed (CISO Assistant CAN-AUD-HIPAA-001)", f"{pct(hipaa)}% ({hipaa.get('compliant')}/{sum(hipaa.values())})", ">= 90% by Q4 2027", "HHS OCR audit protocol: every addressable spec documented"),
    ("Compliance", "NIST CSF 2.0 subcategories met", "compliant / assessed (CAN-AUD-CSF-001)", f"{pct(csf)}% ({csf.get('compliant')}/{sum(csf.values())})", "Tier 3 'Repeatable' by 2028", "NIST CSF implementation tiers 1-4"),
    ("Control", "Control test pass rate", "PASS / tests run", f"{ct[-1]['rate_pct']}% ({ct[-1]['pass']}/{ct[-1]['total']}, {ct[-1]['date']})", ">= 95%", "Internal target; first audit was " + f"{ct[0]['rate_pct']}%"),
    ("Remediation", "Corrective actions closed", "resolved / total", f"{aa['ca_closure']['closed_pct']}% ({aa['ca_closure']['closed']}/{aa['ca_closure']['total']})", ">= 90%", "Forecast to reach 90% on " + aa["ca_closure"]["forecast_90pct_date"]),
    ("Remediation", "Corrective actions overdue", "open CAs past due date", str(len(overdue)), "0", "Zero tolerance for overdue Highs"),
    ("Governance", "Exceptions past expiry", "open exceptions with expiry < today", f"{len(expired)} ({', '.join(expired) or '-'})", "0", "Every exception renewed or closed before expiry"),
    ("Operational", "Leaver exposure window", "minutes between HR leave date action and last access removed", f"{proc['leaver_exposure_window_minutes']['automated']} min automated (manual was {proc['leaver_exposure_window_minutes']['manual']} min)", "0 min; <= 24 h at worst", "PCI DSS 8.2.5: revoke immediately; HIPAA 164.308(a)(3)(ii)(C)"),
    ("Operational", "JML provisioning time", "minutes from approved request to verified access", f"{round(sum(proc['measured_provisioning_minutes']['automated_2026-11-03'].values())/3*60)} s automated", "< 5 min", f"Manual baseline {round(sum(proc['measured_provisioning_minutes']['manual_2026-10-19'].values())/3,1)} min"),
    ("Operational", "Compliance workflow run time", "end-to-end run of S1-S6", f"{wf['runtime_ms']} ms for {wf['issues']} issues", "< 60 s", "Replaces a weekly manual register review (about 4 h)"),
    ("Risk", "Residual annual IAM loss, P95", "Monte Carlo 95th percentile", f"${mc['residual']['p95']/1e6:.1f}M (with FIDO2 + insurance ${mc['option_fido2_plus_insurance']['p95_total']/1e6:.1f}M)", "<= $5M (appetite)", "IBM Cost of a Data Breach 2025: healthcare average US$7.42M per breach"),
    ("Risk", "AI triage model quality", "AUC on held-out history", f"{wf['model']['auc']} (accuracy {wf['model']['accuracy']})", ">= 0.85", "Retrain quarterly; human approval on every escalation"),
    ("Incident", "First response to SEV-1", "minutes from alert to triage", "4.2 min (SOC1-2026-001)", "<= 15 min", "IR playbook CAN-IR-PB-02; GDPR 72 h / HIPAA 60-day notice clocks"),
]
with open(OUT / "kpi_framework.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["category", "kpi", "formula", "current", "target", "benchmark_or_reference"]); w.writerows(KPIS)

predictive = {"at_risk_next_14_days": aa["ca_closure"]["at_risk_next_14_days"], "expired_exceptions": expired,
              "workflow_escalations": wf["routes"]}
pdca1 = {"plan": "Compliance 1 internal audit CAN-IA-2026-01 (2026-10-13): 6 findings (F-01..F-06), 3 High",
         "do": "Week 5 hardening: MFA for privileged roles, lockout, 12-char passwords, app gates (EV-13)",
         "check": f"Re-test 2026-11-03 and access review signed 2026-11-09: control pass rate {ct[0]['rate_pct']}% -> {ct[-1]['rate_pct']}%; High findings {HIGH_BEFORE} -> {HIGH_AFTER}; {CLOSED_AFTER} of {len(aud)} findings closed with evidence; E2E 9/10 then 10/10 after CA-10",
         "act": "Remaining gaps governed as exceptions (EX-02, EX-05) with expiry dates; corrective actions tracked in CISO Assistant",
         "measured_improvement_points": round(ct[-1]["rate_pct"] - ct[0]["rate_pct"], 1)}
json.dump({"kpis": [dict(zip(["category", "kpi", "formula", "current", "target", "reference"], k)) for k in KPIS],
           "predictive": predictive, "pdca_cycle_1": pdca1}, open(OUT / "kpi_summary.json", "w"), indent=1)

fig, ax = plt.subplots(figsize=(6.5, 3), dpi=150)
labels = ["Control pass rate %", "High findings open", "Audit findings closed"]
before = [ct[0]["rate_pct"], HIGH_BEFORE, 0]; after = [ct[-1]["rate_pct"], HIGH_AFTER, CLOSED_AFTER]
x = range(3)
ax.bar([i - .2 for i in x], before, .4, label="Before (2026-10-13 audit)", color="#C8553D")
ax.bar([i + .2 for i in x], after, .4, label="After (2026-11-03 re-test)", color="#2E8B57")
for i in x:
    ax.text(i - .2, before[i] + 1, str(before[i]), ha="center", fontsize=7); ax.text(i + .2, after[i] + 1, str(after[i]), ha="center", fontsize=7)
ax.set_xticks(list(x), labels, fontsize=8); ax.set_title("PDCA cycle 1: measured results", fontsize=10); ax.legend(fontsize=7); ax.grid(axis="y", alpha=.3)
fig.tight_layout(); fig.savefig(OUT / "pdca_cycle1.png")
print(json.dumps({"kpis": KPIS, "predictive": predictive, "pdca": pdca1}, indent=1))
