#!/usr/bin/env python3
"""HRMC automated compliance workflow (Compliance 2, criterion 2).

Multi-stage workflow with automated decision points, an AI (machine-learning) triage step, exception handling
and escalation. Input is the LIVE register snapshot exported from CISO Assistant (ciso_sync_export.py) plus the
capstone control catalogue. Output: a work queue, an escalation log and a run summary.

  python3 compliance_workflow.py --today 2026-11-18

Stages
  S1 Ingest      read the CISO Assistant snapshot + control catalogue; bad records go to a data-quality queue
  S2 Evaluate    find open issues: controls not fully implemented, open findings, exceptions
  S3 AI triage   logistic-regression model scores each issue: P(material compliance exposure)
  S4 Decide      D1 overdue? D2 AI score band? D3 exception expired / expiring? D4 human approval needed?
                 D5 is the gap already covered by a valid, approved exception (compensating controls)?
  S5 Route       ESCALATE-CCO / ESCALATE-COMMITTEE / ASSIGN-OWNER / REMIND / MONITOR, with SLA dates
  S6 Report      work_queue.csv, escalations.jsonl, workflow_summary.json
"""
import argparse, csv, json, math, pathlib, random, time, datetime as dt

ROOT = pathlib.Path(__file__).resolve().parents[2]          # dae_6mon_coh2_AC
C2 = ROOT / "compliance_2"
DATA = C2 / "data"
OUT = C2 / "outputs"
OUT.mkdir(exist_ok=True)
CATALOG = ROOT / "Care_Access_Navigator/08_Reporting/02_Dashboards/Tableau_Dataset/controls.csv"
RISKS = ROOT / "Care_Access_Navigator/08_Reporting/02_Dashboards/Tableau_Dataset/risks.csv"

# corrective action -> (control, risk, touches ePHI) ; from grc_data.py descriptions
CA_LINK = {"CA-03": ("AU-03", "R03", 1), "CA-05": ("AR-01", "R01", 1), "CA-06": ("SC-01", "R03", 1),
           "CA-08": ("VM-01", "R05", 1), "CA-12": ("IA-02", "R03", 1), "CA-13": ("IA-01", "R03", 1),
           "CA-15": ("IA-01", "R03", 1), "CA-16": ("AC-05", "R04", 0), "CA-17": ("AC-04", "R03", 0),
           "CA-18": ("AC-01", "R01", 0), "CAN-FIND-001": ("AC-02", "R02", 1)}
EX_LINK = {"EX-01": ("IA-01", "R03"), "EX-02": ("AU-03", "R03"), "EX-03": ("AC-05", "R04"), "EX-04": ("AC-05", "R04"),
           "EX-05": ("SC-01", "R03"), "EX-06": ("IR-01", None), "EX-07": ("IA-02", "R03"), "EX-08": ("CA-01", None)}
SLA_DAYS = {"ESCALATE-CCO": 2, "ESCALATE-COMMITTEE": 5, "ASSIGN-OWNER": 30, "REMIND": 7, "MONITOR": 90}


# ------------------------------------------------------------------ S3: the AI model (logistic regression, no libs)
FEATURES = ["inherent_risk", "frameworks", "ephi", "days_overdue", "prior_fail", "impl_gap"]


def _sig(z):
    return 1 / (1 + math.exp(-max(-30, min(30, z))))


def synth_history(n=800, seed=7):
    """Labelled history of past compliance issues (synthetic, for training).

    Ground truth used to label them (what the compliance committee historically escalated): high inherent risk,
    many frameworks affected, ePHI involved, long overdue, repeat failures and big implementation gaps raise the
    chance an issue became a material exposure. Noise makes the labels imperfect, as in real life."""
    rnd = random.Random(seed)
    rows = []
    for _ in range(n):
        x = {"inherent_risk": rnd.choice([0.48, 0.6, 0.8, 1.0]), "frameworks": rnd.randint(1, 5) / 5,
             "ephi": rnd.random() < 0.6, "days_overdue": min(rnd.expovariate(1 / 20), 120) / 90,
             "prior_fail": rnd.random() < 0.3, "impl_gap": rnd.choice([0, 0.5, 1])}
        z = (-5.2 + 3.0 * x["inherent_risk"] + 1.6 * x["frameworks"] + 1.1 * x["ephi"] + 2.4 * x["days_overdue"]
             + 1.2 * x["prior_fail"] + 1.8 * x["impl_gap"] + rnd.gauss(0, 0.8))
        rows.append(([float(x[f]) for f in FEATURES], 1 if z > 0 else 0))
    return rows


def train(rows, epochs=600, lr=0.5):
    w = [0.0] * (len(FEATURES) + 1)
    for _ in range(epochs):
        g = [0.0] * len(w)
        for x, y in rows:
            p = _sig(w[0] + sum(wi * xi for wi, xi in zip(w[1:], x)))
            g[0] += p - y
            for i, xi in enumerate(x):
                g[i + 1] += (p - y) * xi
        w = [wi - lr * gi / len(rows) for wi, gi in zip(w, g)]
    return w


def predict(w, x):
    return _sig(w[0] + sum(wi * xi for wi, xi in zip(w[1:], x)))


def evaluate(w, rows):
    ps = [(predict(w, x), y) for x, y in rows]
    tp = sum(1 for p, y in ps if p >= .5 and y); fp = sum(1 for p, y in ps if p >= .5 and not y)
    fn = sum(1 for p, y in ps if p < .5 and y); tn = sum(1 for p, y in ps if p < .5 and not y)
    pos = [p for p, y in ps if y]; neg = [p for p, y in ps if not y]
    auc = sum((a > b) + 0.5 * (a == b) for a in pos for b in neg) / (len(pos) * len(neg))
    return {"n_test": len(rows), "accuracy": round((tp + tn) / len(rows), 3), "precision": round(tp / max(tp + fp, 1), 3),
            "recall": round(tp / max(tp + fn, 1), 3), "auc": round(auc, 3)}


# ------------------------------------------------------------------ helpers
def d(s):
    return dt.date.fromisoformat(s[:10]) if s and s not in ("None", "-") else None


def add_business_days(day, n):
    while n:
        day += dt.timedelta(days=1)
        if day.weekday() < 5:
            n -= 1
    return day


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--today", default=dt.date.today().isoformat())
    a = ap.parse_args()
    today = dt.date.fromisoformat(a.today)
    t0 = time.perf_counter()

    # ---------------- S1 ingest
    snap = json.load(open(DATA / "ciso_snapshot.json"))
    catalog = {r["control_id"]: r for r in csv.DictReader(open(CATALOG))}
    risk = {r["risk_id"]: int(r["inherent_score"]) for r in csv.DictReader(open(RISKS))}
    dq = []

    def nfw(c):
        r = catalog.get(c, {})
        return sum(1 for k in ("hipaa", "nist_csf_2", "nist_800_53", "iso_27001", "pci_dss") if r.get(k, "-") not in ("", "-"))

    # ---------------- S3 model
    hist = synth_history()
    random.Random(1).shuffle(hist)
    cut = int(len(hist) * .7)
    w = train(hist[:cut])
    metrics = evaluate(w, hist[cut:])

    # ---------------- S2 evaluate -> issues
    issues = []
    for c, r in catalog.items():                         # controls not fully implemented
        if r["implementation"] != "Implemented" or r["result"].startswith("FAIL"):
            rk = [x.strip() for x in r["risks"].replace("R01-R05", "R01,R02,R03,R04,R05").split(",")]
            issues.append({"id": c, "kind": "control", "title": r["objective"], "control": c,
                           "risk": ",".join(rk), "status": r["implementation"], "due": None,
                           "x": {"inherent_risk": max(risk.get(k, 12) for k in rk) / 25, "frameworks": nfw(c) / 5,
                                 "ephi": 1, "days_overdue": 0, "prior_fail": 1 if "FAIL" in r["result"] or "after" in r["result"] else 0,
                                 "impl_gap": 1 if r["implementation"] == "Not implemented" else .5}})
    for f in snap["findings"]:                           # open findings / corrective actions
        try:
            if f["status"] in ("resolved", "closed", "dismissed"):
                continue
            c, rk, ephi = CA_LINK[f["ref_id"]]
            due = d(f.get("due_date")) or d(f.get("eta"))
            over = max((today - due).days, 0) if due else 30
            issues.append({"id": f["ref_id"], "kind": "finding", "title": f["name"], "control": c, "risk": rk,
                           "status": f["status"], "due": due.isoformat() if due else None,
                           "x": {"inherent_risk": risk.get(rk, 12) / 25, "frameworks": nfw(c) / 5, "ephi": ephi,
                                 "days_overdue": min(over, 120) / 90, "prior_fail": 0,
                                 "impl_gap": 1 if f["status"] == "assigned" else .5}})
        except (KeyError, ValueError) as e:              # exception handling: never crash on one bad record
            dq.append({"record": f.get("ref_id"), "error": f"{type(e).__name__}: {e}"})
    for x in snap["exceptions"]:
        try:
            if x["status"] in ("resolved", "expired", "deprecated"):
                continue
            c, rk = EX_LINK[x["ref_id"]]
            exp = d(x["expiration_date"])
            issues.append({"id": x["ref_id"], "kind": "exception", "title": x["name"], "control": c, "risk": rk or "-",
                           "status": x["status"], "due": exp.isoformat() if exp else None,
                           "x": {"inherent_risk": risk.get(rk, 12) / 25, "frameworks": nfw(c) / 5, "ephi": 1,
                                 "days_overdue": max((today - exp).days, 0) / 90 if exp else 0, "prior_fail": 0, "impl_gap": .5}})
        except (KeyError, ValueError) as e:
            dq.append({"record": x.get("ref_id"), "error": f"{type(e).__name__}: {e}"})

    # D5 support: controls covered by an approved exception that has not expired
    covered = {}
    for x in snap["exceptions"]:
        exp = d(x["expiration_date"])
        if x["status"] == "approved" and exp and exp >= today and x["ref_id"] in EX_LINK:
            covered.setdefault(EX_LINK[x["ref_id"]][0], []).append((x["ref_id"], exp))

    # ---------------- S3 + S4 decide + S5 route
    queue, esc = [], []
    for i in issues:
        p = predict(w, [float(i["x"][k]) for k in FEATURES])
        due = d(i["due"])
        overdue = due is not None and due < today
        days_left = (due - today).days if due else None
        path = []
        if i["kind"] == "exception":                                       # D3
            if overdue:
                route, why = "ESCALATE-COMMITTEE", f"exception expired {-days_left} days ago: renew with new evidence or close"
            elif days_left is not None and days_left <= 14:
                route, why = "REMIND", f"exception expires in {days_left} days"
            else:
                route, why = "MONITOR", f"approved exception, valid until {due}; re-check at expiry"
            path.append("D3")
        elif i["control"] in covered:                                      # D5
            ex, exp = min(covered[i["control"]], key=lambda t: t[1])
            route, why = "MONITOR", f"covered by approved exception {ex} until {exp}; compensating controls in place"
            path.append("D5")
        elif overdue:                                                      # D1
            route, why = ("ESCALATE-CCO", f"overdue {-days_left} days and AI score {p:.2f}") if p >= .5 else \
                         ("ASSIGN-OWNER", f"overdue {-days_left} days; re-plan with owner")
            path.append("D1")
        elif p >= .85:                                                     # D2
            route, why = "ESCALATE-CCO", f"AI score {p:.2f} >= 0.85"
            path.append("D2")
        elif p >= .5:
            route, why = "ASSIGN-OWNER", f"AI score {p:.2f} in 0.50-0.85"
            path.append("D2")
        else:
            route, why = "MONITOR", f"AI score {p:.2f} < 0.50"
            path.append("D2")
        approval = route.startswith("ESCALATE")                            # D4 human in the loop
        sla = add_business_days(today, SLA_DAYS[route]) if route.startswith("ESCALATE") else today + dt.timedelta(days=SLA_DAYS[route])
        row = {"id": i["id"], "kind": i["kind"], "control": i["control"], "risk": i["risk"], "status": i["status"],
               "due": i["due"] or "", "ai_score": round(p, 2), "decision_path": "S2>S3>" + ">".join(path) + (">D4" if approval else ""),
               "route": route, "reason": why, "needs_human_approval": approval, "sla_due": sla.isoformat(), "title": i["title"]}
        queue.append(row)
        if approval:
            esc.append({"at": f"{today}T00:00:00Z", **{k: row[k] for k in ("id", "route", "reason", "ai_score", "sla_due")}})

    order = {"ESCALATE-COMMITTEE": 0, "ESCALATE-CCO": 1, "REMIND": 2, "ASSIGN-OWNER": 3, "MONITOR": 4}
    queue.sort(key=lambda r: (order[r["route"]], -r["ai_score"]))
    with open(OUT / "work_queue.csv", "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(queue[0].keys()))
        wr.writeheader(); wr.writerows(queue)
    with open(OUT / "escalations.jsonl", "w") as f:
        f.writelines(json.dumps(e) + "\n" for e in esc)
    ms = round((time.perf_counter() - t0) * 1000)
    summary = {"run_date": today.isoformat(), "snapshot_exported_utc": snap["exported_utc"], "runtime_ms": ms,
               "issues": len(queue), "routes": {r: sum(1 for q in queue if q["route"] == r) for r in order},
               "needs_human_approval": len(esc), "data_quality_queue": dq,
               "model": {"type": "logistic regression (6 features)", "features": FEATURES,
                         "weights": [round(x, 2) for x in w], "trained_on": cut, **metrics}}
    json.dump(summary, open(OUT / "workflow_summary.json", "w"), indent=1)
    print(json.dumps(summary, indent=1))
    for q in queue:
        print(f"{q['route']:19} {q['id']:13} p={q['ai_score']:.2f} {q['decision_path']:14} {q['reason']}")


if __name__ == "__main__":
    main()
