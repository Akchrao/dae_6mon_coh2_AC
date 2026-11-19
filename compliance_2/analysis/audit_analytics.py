#!/usr/bin/env python3
"""Advanced auditing analytics (Compliance 2, criterion 4).

1. Statistical attribute sampling sizes for the multi-site audit (binomial, exact).
2. Evidence analytics on real capstone logs: EHR access by role, Keycloak sign-in failures per user (z-scores),
   control-test pass rates with Wilson 95% confidence intervals.
3. Predictive analytics: forecast of findings per site (Poisson, from the capstone audit rate) and the
   corrective-action closure trend (linear fit on the CISO Assistant snapshot).
4. Automated reporting: writes audit_analytics_report.md.
"""
import csv, json, math, pathlib, statistics, datetime as dt, collections
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "compliance_2/outputs"
CAN = ROOT / "Care_Access_Navigator"
TD = CAN / "08_Reporting/02_Dashboards/Tableau_Dataset"


def binom_cdf(k, n, p):
    return sum(math.comb(n, i) * p**i * (1 - p)**(n - i) for i in range(k + 1))


def sample_size(conf, tolerable, allowed_dev):
    n = allowed_dev + 1
    while binom_cdf(allowed_dev, n, tolerable) > 1 - conf:
        n += 1
    return n


def wilson(k, n, z=1.96):
    if n == 0:
        return (0, 0)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(100 * (c - h), 1), round(100 * (c + h), 1))


R = {}
# 1. sampling
R["sampling"] = [{"confidence": c, "tolerable_deviation": t, "deviations_allowed": k, "sample_size": sample_size(c, t, k)}
                 for c, t, k in [(.95, .05, 0), (.95, .05, 1), (.95, .05, 2), (.90, .05, 1), (.95, .10, 1)]]

# 2a. EHR access by role
ehr = list(csv.DictReader(open(CAN / "05_Logs/02_Access/CAN_LOG_EHR_Access_Sample_20261104.csv")))
by_role = collections.Counter(r["role"] for r in ehr)
bill = by_role["billing"]
R["ehr_access"] = {"events": len(ehr), "by_role": dict(by_role), "billing_role_clinical_views": bill,
                   "billing_share_pct": round(100 * bill / len(ehr), 1), "billing_share_ci95": wilson(bill, len(ehr)),
                   "finding": "Billing role should have zero clinical views (least privilege); every one is an exception to test"}
per_user = collections.Counter(r["username"] for r in ehr)
mu, sd = statistics.mean(per_user.values()), statistics.pstdev(per_user.values())
R["ehr_access"]["per_user"] = {u: {"views": c, "z": round((c - mu) / sd, 2) if sd else 0} for u, c in per_user.items()}

# 2b. sign-in failures per user (z-score outliers)
kc = list(csv.DictReader(open(CAN / "05_Logs/01_Authentication/CAN_LOG_Keycloak_Login_Events_20261104.csv")))
fails = collections.Counter(r["username"] or "(unknown)" for r in kc if r["type"] == "LOGIN_ERROR")
mu, sd = statistics.mean(fails.values()), statistics.pstdev(fails.values())
R["signin_failures"] = sorted([{"user": u, "failures": c, "z": round((c - mu) / sd, 2)} for u, c in fails.items()], key=lambda x: -x["failures"])
R["signin_outliers_z_gt_2"] = [x for x in R["signin_failures"] if x["z"] > 2]

# 2c. control test pass rates with CIs
tests = list(csv.DictReader(open(TD / "control_tests.csv")))
by_date = collections.defaultdict(lambda: [0, 0])
for t in tests:
    by_date[t["test_date"]][1] += 1
    by_date[t["test_date"]][0] += t["result"].upper().startswith("PASS")
R["control_tests"] = [{"date": d, "pass": p, "total": n, "rate_pct": round(100 * p / n, 1), "ci95": wilson(p, n)} for d, (p, n) in sorted(by_date.items())]

# 3a. predictive: findings per site
aud = list(csv.DictReader(open(TD / "audit_findings.csv")))
controls_audited = 13                        # capstone internal audit CAN-IA-2026-01 (Compliance 1, 2026-10-13)
rate = len(aud) / controls_audited
def poisson_pi(lam, lo=.05, hi=.95):
    cdf, k, a, b = 0, 0, None, None
    while b is None:
        cdf += math.exp(-lam) * lam**k / math.factorial(k)
        if a is None and cdf >= lo: a = k
        if cdf >= hi: b = k
        k += 1
    return a, b
sites = [("US - HRMC flagship (Albany, NY)", 48, 0.6), ("US - community campuses (2)", 48, 0.8),
         ("EU - Dublin + Cork clinics", 48, 1.3), ("EU - Munich diagnostics", 48, 1.3), ("India - Hyderabad shared services", 48, 1.2)]
R["findings_forecast"] = {"capstone_rate_per_control": round(rate, 3), "sites": []}
for s, n_ctrl, maturity in sites:
    lam = rate * n_ctrl * maturity
    lo, hi = poisson_pi(lam)
    R["findings_forecast"]["sites"].append({"site": s, "controls_in_scope": n_ctrl, "maturity_factor": maturity,
                                             "expected_findings": round(lam, 1), "pi90": f"{lo}-{hi}"})

# 3b. predictive: corrective action closure trend from the live CISO Assistant snapshot
snap = json.load(open(ROOT / "compliance_2/data/ciso_snapshot.json"))
cas = [f for f in snap["findings"] if f["ref_id"].startswith("CA-")]
closed = sum(f["status"] == "resolved" for f in cas)
open_due = sorted([(f["due_date"], f["ref_id"]) for f in cas if f["status"] != "resolved"])
first = dt.date(2026, 10, 13); today = dt.date.fromisoformat(snap["exported_utc"][:10])
days = (today - first).days
rate_per_day = closed / days
need = math.ceil(0.9 * len(cas)) - closed
R["ca_closure"] = {"total": len(cas), "closed": closed, "closed_pct": round(100 * closed / len(cas), 1),
                   "closure_rate_per_week": round(rate_per_day * 7, 2), "needed_for_90pct": need,
                   "forecast_90pct_date": (today + dt.timedelta(days=math.ceil(need / rate_per_day))).isoformat(),
                   "open_by_due_date": open_due,
                   "at_risk_next_14_days": [r for d, r in open_due if d and dt.date.fromisoformat(d) <= today + dt.timedelta(days=14)]}

json.dump(R, open(OUT / "audit_analytics.json", "w"), indent=1)

# chart: control-test pass rate with CI + findings forecast
fig, ax = plt.subplots(1, 2, figsize=(9, 3.3), dpi=150)
ct = R["control_tests"]
ax[0].errorbar(range(len(ct)), [c["rate_pct"] for c in ct], yerr=[[c["rate_pct"] - c["ci95"][0] for c in ct], [c["ci95"][1] - c["rate_pct"] for c in ct]],
               fmt="o", capsize=4, color="#2B6F8E")
ax[0].set_xticks(range(len(ct)), [f"{c['date']}\n{c['pass']}/{c['total']}" for c in ct], fontsize=7)
ax[0].set_ylim(0, 105); ax[0].set_ylabel("Pass rate % (95% CI)"); ax[0].set_title("Control tests by date", fontsize=9); ax[0].grid(alpha=.3)
fs = R["findings_forecast"]["sites"]
ax[1].barh([s["site"].split(" (")[0] for s in fs], [s["expected_findings"] for s in fs], color="#C8553D")
ax[1].set_xlabel("Expected findings (Poisson)"); ax[1].set_title("Predicted audit findings per site", fontsize=9); ax[1].tick_params(axis="y", labelsize=7)
fig.tight_layout(); fig.savefig(OUT / "audit_analytics.png")

# automated report
md = [f"# Automated audit analytics report\n\nGenerated from live data (CISO Assistant snapshot {snap['exported_utc']}) and the capstone logs.\n",
      "## Sampling plan\n", "| Confidence | Tolerable deviation | Deviations allowed | Sample size |", "|---|---|---|---|"]
md += [f"| {int(s['confidence']*100)}% | {int(s['tolerable_deviation']*100)}% | {s['deviations_allowed']} | {s['sample_size']} |" for s in R["sampling"]]
md += ["\n## Evidence analytics\n", f"- EHR: {bill} of {len(ehr)} views ({R['ehr_access']['billing_share_pct']}%, 95% CI {R['ehr_access']['billing_share_ci95']}) were by the billing role: least-privilege exceptions.",
       f"- Sign-in failure outliers (z > 2): " + ", ".join(f"{x['user']} ({x['failures']}, z={x['z']})" for x in R["signin_outliers_z_gt_2"]),
       "- Control tests: " + "; ".join(f"{c['date']} {c['pass']}/{c['total']} = {c['rate_pct']}% (CI {c['ci95'][0]}-{c['ci95'][1]})" for c in ct),
       "\n## Predictions\n", f"- Corrective actions: {closed}/{len(cas)} closed; at {R['ca_closure']['closure_rate_per_week']}/week, 90% closure is forecast for {R['ca_closure']['forecast_90pct_date']}.",
       f"- At risk in the next 14 days: {', '.join(R['ca_closure']['at_risk_next_14_days']) or 'none'}"]
md += [f"- {s['site']}: expected {s['expected_findings']} findings (90% interval {s['pi90']})" for s in fs]
open(OUT / "audit_analytics_report.md", "w").write("\n".join(md) + "\n")
print(json.dumps(R, indent=1, default=str)[:3000])
