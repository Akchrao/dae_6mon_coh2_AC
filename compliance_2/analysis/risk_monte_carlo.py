#!/usr/bin/env python3
"""Quantitative risk assessment for HRMC (Compliance 2, criterion 5).

FAIR-style Monte Carlo on the five capstone IAM risks (R01-R05, Risk Management 1 register):
  annual loss = sum over a Poisson number of loss events of a PERT-distributed loss per event.
Frequency comes from the register's 1-5 likelihood score; inherent -> residual reduction comes from the
register's inherent and residual scores; loss-per-event ranges are planning assumptions anchored to the
Risk Management 1 business impact analysis (Keycloak IAM outage = $25,000 for the flagship) and scaled to the
expanded HRMC (about 10,800 staff, 3 regions, HIPAA + GDPR + PCI DSS exposure).

Outputs (compliance_2/outputs): risk_mc_results.csv, risk_mc_scenarios.csv, risk_mc_summary.json,
loss_exceedance_curve.png, ale_by_risk.png
"""
import csv, json, pathlib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "compliance_2/outputs"
OUT.mkdir(exist_ok=True)
RISKS = ROOT / "Care_Access_Navigator/08_Reporting/02_Dashboards/Tableau_Dataset/risks.csv"
N = 100_000
rng = np.random.default_rng(42)

# likelihood score (1-5) -> most-likely annual frequency of a loss event for the enterprise
FREQ_MODE = {1: 0.05, 2: 0.15, 3: 0.40, 4: 0.80, 5: 1.50}
# loss per event, USD (min, most likely, max): planning assumptions, see the document section 5.2
LOSS = {"R01": (50_000, 400_000, 4_000_000), "R02": (30_000, 250_000, 3_000_000),
        "R03": (150_000, 1_200_000, 12_000_000), "R04": (100_000, 900_000, 9_000_000),
        "R05": (40_000, 300_000, 3_500_000)}
# annual cost of the treatment that moves each risk from inherent to residual (enterprise scale, USD)
TREAT_COST = {"R01": 180_000, "R02": 120_000, "R03": 260_000, "R04": 220_000, "R05": 60_000}
# detective controls also cut the size of a loss (faster detection); preventive ones only cut frequency
MAG_FACTOR = {"R01": 1.0, "R02": 1.0, "R03": 0.8, "R04": 0.8, "R05": 1.0}


def pert(a, m, b, size):
    alpha = 1 + 4 * (m - a) / (b - a)
    beta = 1 + 4 * (b - m) / (b - a)
    return a + rng.beta(alpha, beta, size) * (b - a)


def simulate(rid, f_mode, loss, mag=1.0, freq_mult=1.0):
    lam = rng.triangular(f_mode * 0.25, f_mode, f_mode * 3, N) * freq_mult
    n = rng.poisson(lam)
    total = np.zeros(N)
    idx = np.repeat(np.arange(N), n)
    if idx.size:
        np.add.at(total, idx, pert(*loss, idx.size) * mag)
    return total, n


def insured(rid, f_mode, loss, mag, freq_mult, retention=1_000_000, limit=10_000_000):
    """Per-event retention and limit; returns retained (uninsured) annual loss."""
    lam = rng.triangular(f_mode * 0.25, f_mode, f_mode * 3, N) * freq_mult
    n = rng.poisson(lam)
    idx = np.repeat(np.arange(N), n)
    kept = np.zeros(N)
    if idx.size:
        ev = pert(*loss, idx.size) * mag
        retained = np.minimum(ev, retention) + np.maximum(ev - retention - limit, 0)
        np.add.at(kept, idx, retained)
    return kept


risks = list(csv.DictReader(open(RISKS)))
rows, inh_tot, res_tot, ins_tot = [], np.zeros(N), np.zeros(N), np.zeros(N)
for r in risks:
    rid = r["risk_id"]
    fm = FREQ_MODE[int(r["inherent_likelihood"])]
    red = int(r["residual_score"]) / int(r["inherent_score"])            # register's own reduction ratio
    inh, _ = simulate(rid, fm, LOSS[rid])
    res, _ = simulate(rid, fm, LOSS[rid], MAG_FACTOR[rid], red)
    ins = insured(rid, fm, LOSS[rid], MAG_FACTOR[rid], red)
    inh_tot += inh; res_tot += res; ins_tot += ins
    benefit = inh.mean() - res.mean()
    rows.append({"risk_id": rid, "risk": r["risk"], "register_inherent": r["inherent_score"], "register_residual": r["residual_score"],
                 "freq_mode_per_year": fm, "loss_min": LOSS[rid][0], "loss_mode": LOSS[rid][1], "loss_max": LOSS[rid][2],
                 "inherent_ALE_mean": round(inh.mean()), "inherent_ALE_p90": round(np.percentile(inh, 90)),
                 "residual_ALE_mean": round(res.mean()), "residual_ALE_p90": round(np.percentile(res, 90)),
                 "residual_ALE_p95": round(np.percentile(res, 95)),
                 "ci95_residual_mean": f"{res.mean() - 1.96 * res.std() / N**.5:,.0f} - {res.mean() + 1.96 * res.std() / N**.5:,.0f}",
                 "annual_treatment_cost": TREAT_COST[rid], "risk_reduction": round(benefit),
                 "ROSI_pct": round((benefit - TREAT_COST[rid]) / TREAT_COST[rid] * 100)})

# premium priced like an insurer: expected covered loss x 1.35 loading (expenses + profit)
premium = int(round(1.35 * (res_tot.mean() - ins_tot.mean()), -3))
summary = {"iterations": N, "seed": 42,
           "inherent": {"mean": round(inh_tot.mean()), "p50": round(np.median(inh_tot)), "p90": round(np.percentile(inh_tot, 90)),
                        "p95": round(np.percentile(inh_tot, 95)), "p99": round(np.percentile(inh_tot, 99))},
           "residual": {"mean": round(res_tot.mean()), "p50": round(np.median(res_tot)), "p90": round(np.percentile(res_tot, 90)),
                        "p95": round(np.percentile(res_tot, 95)), "p99": round(np.percentile(res_tot, 99))},
           "residual_with_insurance": {"premium": premium, "premium_basis": "expected covered loss x 1.35", "retention_per_event": 1_000_000, "limit_per_event": 10_000_000,
                                       "mean": round(ins_tot.mean() + premium), "p95": round(np.percentile(ins_tot, 95) + premium),
                                       "p99": round(np.percentile(ins_tot, 99) + premium)},
           "treatment_cost_total": sum(TREAT_COST.values())}
summary["appetite"] = {"statement": "Annual IAM-related loss above $5M should be no more than 5% likely (P95 <= $5M)",
                       "inherent_p95_within": bool(summary["inherent"]["p95"] <= 5e6), "residual_p95_within": bool(summary["residual"]["p95"] <= 5e6),
                       "with_insurance_p95_within": bool(summary["residual_with_insurance"]["p95"] <= 5e6)}
summary["portfolio_ROSI_pct"] = round((summary["inherent"]["mean"] - summary["residual"]["mean"] - summary["treatment_cost_total"])
                                      / summary["treatment_cost_total"] * 100)

# residual risk treatment option: phishing-resistant MFA (FIDO2) + conditional access for R03, then insure
EXTRA = {"R03": 0.5}            # halves the remaining credential-compromise frequency
extra_cost = 150_000
opt_res, opt_ins = np.zeros(N), np.zeros(N)
for r in risks:
    rid = r["risk_id"]
    fm = FREQ_MODE[int(r["inherent_likelihood"])]
    red = int(r["residual_score"]) / int(r["inherent_score"]) * EXTRA.get(rid, 1)
    t, _ = simulate(rid, fm, LOSS[rid], MAG_FACTOR[rid], red)
    opt_res += t
    opt_ins += insured(rid, fm, LOSS[rid], MAG_FACTOR[rid], red)
opt_prem = int(round(1.35 * (opt_res.mean() - opt_ins.mean()), -3))
summary["option_fido2_plus_insurance"] = {
    "extra_control": "Phishing-resistant MFA (FIDO2) + conditional access for all ePHI roles (R03)", "extra_annual_cost": extra_cost,
    "residual_mean_before_insurance": round(opt_res.mean()), "residual_p95_before_insurance": round(np.percentile(opt_res, 95)),
    "premium": opt_prem, "mean_total_cost": round(opt_ins.mean() + opt_prem + extra_cost),
    "p95_total": round(np.percentile(opt_ins, 95) + opt_prem + extra_cost),
    "within_appetite": bool(np.percentile(opt_ins, 95) + opt_prem + extra_cost <= 5e6)}

# scenario analysis on the residual position
scen = []
for name, fmult, mmult, note in [
        ("S0 Baseline (residual, controls as tested)", {}, {}, "Register residual scores"),
        ("S1 Expansion year 1 (EU + India sites not yet at HRMC control level)", {"R01": 1.5, "R03": 1.5, "R05": 1.5}, {}, "Frequency x1.5 for privilege, credential and vendor risks"),
        ("S2 Major breach stress (GDPR + HIPAA penalties, class action)", {}, {"R03": 2.0, "R04": 2.0}, "Loss per event x2 for credential compromise and privileged misuse"),
        ("S3 Controls fail (MFA / JML automation outage for a year)", {"R02": 3.0, "R03": 2.0}, {}, "Residual reduction lost for R02, R03")]:
    tot = np.zeros(N)
    for r in risks:
        rid = r["risk_id"]
        fm = FREQ_MODE[int(r["inherent_likelihood"])]
        red = int(r["residual_score"]) / int(r["inherent_score"])
        t, _ = simulate(rid, fm, LOSS[rid], MAG_FACTOR[rid] * mmult.get(rid, 1), red * fmult.get(rid, 1))
        tot += t
    scen.append({"scenario": name, "assumption": note, "mean": round(tot.mean()), "p90": round(np.percentile(tot, 90)),
                 "p95": round(np.percentile(tot, 95)), "p99": round(np.percentile(tot, 99))})

with open(OUT / "risk_mc_results.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
with open(OUT / "risk_mc_scenarios.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(scen[0])); w.writeheader(); w.writerows(scen)
summary["scenarios"] = scen
json.dump(summary, open(OUT / "risk_mc_summary.json", "w"), indent=1)

# loss exceedance curve
fig, ax = plt.subplots(figsize=(8, 4.2), dpi=150)
for data, lab, col in [(inh_tot, "Inherent (no controls)", "#C8553D"), (res_tot, "Residual (controls as tested)", "#2B6F8E"),
                       (ins_tot + premium, "Residual + cyber insurance (incl. premium)", "#2E8B57")]:
    xs = np.sort(data); ys = 1 - np.arange(1, N + 1) / N
    ax.plot(xs / 1e6, ys * 100, label=lab, color=col, lw=2)
ax.axvline(5, color="#888", ls="--", lw=1); ax.text(5.1, 60, "Risk appetite:\n$5M annual loss\nat most 5% likely", fontsize=8, color="#555")
ax.set_xlim(0, 25); ax.set_xlabel("Annual loss (US$ millions)"); ax.set_ylabel("Probability of exceeding (%)")
ax.set_title("HRMC IAM risk portfolio: loss exceedance curve (100,000 simulated years)", fontsize=10)
ax.grid(alpha=.3); ax.legend(fontsize=8); fig.tight_layout(); fig.savefig(OUT / "loss_exceedance_curve.png")

fig, ax = plt.subplots(figsize=(8, 3.6), dpi=150)
x = np.arange(len(rows)); wd = .38
ax.bar(x - wd / 2, [r["inherent_ALE_mean"] / 1e3 for r in rows], wd, label="Inherent ALE", color="#C8553D")
ax.bar(x + wd / 2, [r["residual_ALE_mean"] / 1e3 for r in rows], wd, label="Residual ALE", color="#2B6F8E")
ax.set_xticks(x, [f"{r['risk_id']}\n{r['risk'][:22]}" for r in rows], fontsize=7)
ax.set_ylabel("Mean annual loss (US$ thousands)"); ax.set_title("Annualized loss expectancy by risk (Monte Carlo mean)", fontsize=10)
ax.legend(fontsize=8); ax.grid(axis="y", alpha=.3); fig.tight_layout(); fig.savefig(OUT / "ale_by_risk.png")

print(json.dumps(summary, indent=1))
for r in rows:
    print(r["risk_id"], r["inherent_ALE_mean"], r["residual_ALE_mean"], r["risk_reduction"], r["annual_treatment_cost"], r["ROSI_pct"])
