"""Builds compliance_2/build/compliance2.html (then rendered to PDF) from content.py and the analysis outputs."""
import csv, json, pathlib, sys, html
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import content as C

ROOT = HERE.parents[1]
OUT = ROOT / "compliance_2/outputs"
J = lambda f: json.load(open(OUT / f))
wf, mc, roi, proc, aa, kpi = J("workflow_summary.json"), J("risk_mc_summary.json"), J("roi_summary.json"), J("process_summary.json"), J("audit_analytics.json"), J("kpi_summary.json")
snap = json.load(open(ROOT / "compliance_2/data/ciso_snapshot.json"))
mcr = list(csv.DictReader(open(OUT / "risk_mc_results.csv")))
queue = list(csv.DictReader(open(OUT / "work_queue.csv")))
cat = list(csv.DictReader(open(ROOT / "Care_Access_Navigator/08_Reporting/02_Dashboards/Tableau_Dataset/controls.csv")))
e = html.escape
M = lambda v: f"${float(v)/1e6:,.2f}M"
K = lambda v: f"${float(v)/1e3:,.0f}k"
D = lambda v: f"${float(v):,.0f}"


def table(head, rows, widths=None):
    h = "".join(f'<th{f" style=width:{w}" if widths and w else ""}>{e(str(x))}</th>' for x, w in zip(head, widths or [None] * len(head)))
    b = "".join("<tr>" + "".join(f"<td>{x}</td>" for x in r) + "</tr>" for r in rows)
    return f"<table><tr>{h}</tr>{b}</table>"


def img(f, cap, h=None):
    st = f' style="max-height:{h}px"' if h else ""
    return f'<div class="fig"><img src="{f}"{st}><div class="cap">{cap}</div></div>'


hip = next(c for c in snap["compliance_assessments"] if "HIPAA" in c["ref_id"])["results"]
staff = sum(s[2] for s in C.SITES)
opt = mc["option_fido2_plus_insurance"]
P = []
P.append(f"""
<h1>Compliance 2: Project Submission</h1>
<div class="meta">{C.AUTHOR} &middot; DAE 6-Month Cybersecurity Cohort 2 &middot; November 2026<br>
Organization: {C.ORG}. Live data: CISO Assistant snapshot {snap['exported_utc'][:16].replace('T',' ')} UTC.</div>

<div class="note"><b>Scenario.</b> HRMC is the fictional hospital used throughout my capstone (Care Access Navigator). For Compliance 2 it
expands into a multinational group: the US hospital network, clinics in Ireland and Germany, and a shared-services centre in
Hyderabad, India ({staff:,} staff). Everything measured (controls, audits, timings, logs, risks) comes from my capstone evidence
and live systems; the expansion figures (sites, volumes, budgets, loss ranges) are planning assumptions and are labelled as such.</div>

<h3>Executive summary</h3>
{table(["Area", "Result"], [
 ["Strategy", f"6 regulatory conflicts resolved; 3 major frameworks (HIPAA, GDPR, PCI DSS v4.0.1) integrated on an ISO 27001 control backbone; 3-year roadmap, {K(sum(r[5] for r in C.ROADMAP))} total"],
 ["Automation", f"Live CISO Assistant sync + 6-stage workflow with AI triage (AUC {wf['model']['auc']}); {wf['issues']} open issues routed in {wf['runtime_ms']} ms; caught 2 expired exceptions (EX-06, EX-08)"],
 ["ROI", f"One-time {K(roi['one_time_total'])}, payback {roi['payback_months_hard_savings']} months, 3-year NPV {K(roi['three_year_npv_hard'])} (hard savings), ROI {roi['three_year_roi_pct_hard']}%"],
 ["Process", f"JML provisioning {proc['provisioning_time_reduction_pct']}% faster (measured); lead time per request down {proc['lead_time_hours']['reduction_pct']}% (target 30%); leaver exposure 12 &rarr; 0 min"],
 ["Auditing", "6-week, 5-site audit (virtual + on-site), cross-functional team, binomial sampling, log analytics, predicted findings per site"],
 ["Quantitative risk", f"Monte Carlo (100,000 years): residual ALE {M(mc['residual']['mean'])}, P95 {M(mc['residual']['p95'])}; FIDO2 + insurance brings P95 to {M(opt['p95_total'])}, inside the $5M appetite"],
 ["Performance", f"12 KPIs with benchmarks, predictive alerts; PDCA cycle 1 measured: control pass rate 57.1% &rarr; 85.7%"]], ["18%", None])}

<h3>Rubric map</h3>
{table(["Rubric criterion", "Section"], [["Advanced Compliance Strategy", "1"], ["Compliance Automation Implementation", "2"], ["Process Integration &amp; Optimization", "3"],
 ["Advanced Auditing Techniques", "4"], ["Quantitative Risk Assessment", "5"], ["Performance Management &amp; Continuous Improvement", "6"]], ["45%", None])}
""")

# ---------------------------------------------------------------- 1 strategy
P.append(f"""<h2 class="pb">1. Advanced Compliance Strategy</h2>
<h3>1.1 Organization and scope</h3>
{table(["Region", "Entity", "Staff", "Services", "Regulation"], [[s[0], e(s[1]), f"{s[2]:,}", e(s[3]), e(s[4])] for s in C.SITES] + [["", "<b>Total</b>", f"<b>{staff:,}</b>", "", ""]], ["7%", "30%", "8%", "27%", None])}
<p>In Compliance 1 GDPR was <i>not applicable</i> to HRMC (no EU establishment). The expansion changes that: the Irish and German clinics are EU
establishments, and EU data reaching the US and India becomes an international transfer.</p>
<h3>1.2 Regulatory landscape</h3>
{table(["Framework", "Type", "Scope at HRMC"], [[e(a), e(b), e(c)] for a, b, c in C.FRAMEWORKS], ["30%", "14%", None])}
<p>The integrated program covers <b>three major frameworks, HIPAA, GDPR and PCI DSS v4.0.1</b>, and uses <b>ISO/IEC 27001:2022 Annex A</b> as the
common control language, so one control is tested once and its evidence satisfies every framework it maps to. India's DPDP Act is handled as a local overlay.</p>
<h3 class="pb">1.3 Conflicting requirements and how they are resolved</h3>
{table(["Topic", "Conflicting requirements", "Resolution"], [[f"<b>{e(a)}</b>", e(b), e(c)] for a, b, c in C.CONFLICTS], ["14%", "43%", None])}
<p><b>Principle:</b> where rules conflict on <i>time</i>, use the strictest (72 hours, 30 days); where they conflict on <i>data</i>, apply the law
of the record's jurisdiction, never a global maximum; where they conflict on <i>location</i>, keep data in its region and move access, not data.</p>
<h3 class="pb">1.4 Integrated compliance program: unified control mapping</h3>
<p>The 16 controls already built and tested in the capstone (CISO Assistant, Week 9 catalogue) are the core. GDPR and DPDP references are added,
and 6 new controls cover what the expansion introduces. The full group set grows to 48 controls by Q1 2027 (workbook sheet <code>Unified_Controls</code>).</p>
{table(["Ctrl", "Objective", "HIPAA", "GDPR", "PCI DSS", "ISO 27001", "DPDP", "Status"],
 [[r["control_id"], e(r["objective"]), e(r["hipaa"]), e(C.GDPR_DPDP[r["control_id"]][0]), e(r["pci_dss"]), e(r["iso_27001"]), e(C.GDPR_DPDP[r["control_id"]][1]), e(r["implementation"])] for r in cat] +
 [[c[0], e(c[1]), e(c[2]), e(c[3]), e(c[5]), e(c[4]), e(c[6]), "Planned 2027"] for c in C.NEW_ENTERPRISE_CONTROLS],
 ["6%", "26%", "15%", "13%", "10%", "10%", "8%", None])}
<h3 class="pb">1.5 Enterprise compliance architecture (10,000+ staff, multiple locations)</h3>
{img("../diagrams/compliance_architecture.png", "Source: diagrams/compliance_architecture.mmd", 560)}
{table(["Layer", "Design for scale"], [
 ["Governance", "Board committee &rarr; CCO &rarr; regional leads (US HIPAA officers, EU DPO, India lead) + CISO for PCI DSS. 43 compliance champions (1 per 250 staff) in departments."],
 ["Process", "One global process per topic (risk, testing, audit, breach, DSAR, vendors) with regional rule tables, so a new site plugs into existing processes."],
 ["Platform", "Federated identity (Entra ID + Keycloak) so 10,800 joiners/movers/leavers are automated; Wazuh for log evidence; CISO Assistant with one domain per region as the system of record; the workflow engine reads it continuously."],
 ["Data", "Regional residency: US data in the US, EU data in the EU; Hyderabad has no patient data at rest and works through VDI on pseudonymised billing data."]], ["14%", None])}
<h3 class="pb">1.6 Three-year strategic roadmap</h3>
{table(["Phase", "When", "Milestones", "Owner", "FTE", "Budget"], [[e(a), b, e(c), e(d), str(f), K(g)] for a, b, c, d, f, g in C.ROADMAP] +
 [["<b>Total 2027-2029</b>", "", "", "", "", f"<b>{K(sum(r[5] for r in C.ROADMAP))}</b>"]], ["16%", "9%", "45%", "13%", "5%", None])}
<p>Budgets cover people, audits, certification, tooling and training (planning assumptions). The compliance automation in section 2 is part of the
Q2 2027 line. Milestones are gated: Year 2 starts only when the Year 1 multi-site audit shows no open High findings older than 90 days.</p>
""")

# ---------------------------------------------------------------- 2 automation
routes = wf["routes"]
top = [q for q in queue if q["route"] in ("ESCALATE-COMMITTEE", "ESCALATE-CCO", "REMIND")] + [q for q in queue if q["route"] == "ASSIGN-OWNER"][:3] + [q for q in queue if q["route"] == "MONITOR"][:2]
P.append(f"""<h2 class="pb">2. Compliance Automation Implementation</h2>
<h3>2.1 Tools implemented</h3>
{table(["Tool", "What it automates", "Status"], [
 ["CISO Assistant (live sync)", "<code>automation/ciso_sync_export.py</code> exports controls, exceptions, findings, risks and audit results read-only from the GRC system of record", f"Implemented; snapshot {snap['exported_utc'][:10]}: {len(snap['applied_controls'])} controls, {len(snap['exceptions'])} exceptions, {len(snap['findings'])} findings"],
 ["Compliance workflow engine", "<code>automation/compliance_workflow.py</code>: 6 stages, 5 decision points, AI triage, exception handling, escalation with SLAs", f"Implemented; {wf['issues']} issues in {wf['runtime_ms']} ms"],
 ["JML automation", "<code>can_iam.py</code> joiner / mover / leaver with verification and JSONL audit log (capstone)", "Implemented (EV-14)"],
 ["Wazuh SIEM", "Log evidence and alerting for monitoring controls (SOC 1 lab)", "Implemented"]], ["20%", "52%", None])}
<h3>2.2 Multi-stage workflow with automated decision points</h3>
{img("../diagrams/compliance_workflow.png", "Source: diagrams/compliance_workflow.mmd")}
{table(["Stage / decision", "Logic"], [
 ["S1 Ingest", "Live CISO Assistant snapshot + capstone control catalogue. A malformed record goes to a data-quality queue instead of stopping the run."],
 ["S2 Evaluate", "Open issues = controls not fully implemented or failing, unresolved findings, open exceptions"],
 ["S3 AI triage", "Probability that the issue is a material compliance exposure (section 2.4)"],
 ["D3 Exception status", "Expired &rarr; ESCALATE-COMMITTEE (5 business days); expires within 14 days &rarr; REMIND; valid &rarr; MONITOR"],
 ["D5 Covered by exception?", "If an approved, unexpired exception with compensating controls covers the control &rarr; MONITOR (prevents escalation overload)"],
 ["D1 Overdue?", "Past due and AI &ge; 0.50 &rarr; ESCALATE-CCO (2 business days); else ASSIGN-OWNER"],
 ["D2 AI score band", "&ge; 0.85 ESCALATE-CCO; 0.50-0.85 ASSIGN-OWNER (30 days); &lt; 0.50 MONITOR"],
 ["D4 Human approval", "Every escalation needs a named approver before it is sent: the AI recommends, people decide"],
 ["S6 Report", "<code>work_queue.csv</code>, <code>escalations.jsonl</code>, <code>workflow_summary.json</code>"]], ["22%", None])}
<h3 class="pb">2.3 Run on live data ({wf['run_date']})</h3>
{table(["Route", "Count"], [[k, v] for k, v in routes.items()], ["40%", None])}
{table(["ID", "Type", "Control", "AI score", "Path", "Route", "Reason"], [[q["id"], q["kind"], q["control"], q["ai_score"], q["decision_path"], q["route"], e(q["reason"])] for q in top], ["10%", "8%", "7%", "7%", "13%", "15%", None])}
<div class="ok"><b>What the automation caught:</b> exceptions <b>EX-06 and EX-08 expired on 2026-11-05</b> while still "in review". A manual weekly register check had not
flagged them; the workflow escalated both to the compliance committee on its first run. Before the D5 rule was added, the first version escalated 13 issues to the CCO;
tuning it to respect approved exceptions cut that to 1, which is the kind of alert-fatigue control an enterprise program needs.</div>
<h3>2.4 AI integration</h3>
{table(["Item", "Detail"], [
 ["Model", f"Logistic regression, 6 features: {', '.join(wf['model']['features'])}; implemented without external libraries"],
 ["Training data", f"{wf['model']['trained_on']} labelled historical issues (synthetic history representing past committee decisions); {wf['model']['n_test']} held out"],
 ["Quality", f"Accuracy {wf['model']['accuracy']}, precision {wf['model']['precision']}, recall {wf['model']['recall']}, AUC {wf['model']['auc']}"],
 ["Weights", ", ".join(f"{f} {w}" for f, w in zip(["bias"] + wf["model"]["features"], wf["model"]["weights"])) + " (overdue days and inherent risk weigh most)"],
 ["Governance", "Human approval on every escalation (D4); decisions concern compliance issues, not individuals, so GDPR Art. 22 automated-decision rules are not triggered, which the DPIA records; quarterly retraining on real committee outcomes; drift check = AUC below 0.85 triggers review"]], ["16%", None])}
<h3>2.5 Exception handling and escalation procedures</h3>
{table(["Situation", "Automated handling", "Escalation"], [
 ["Bad or missing data in a record", "Logged to the data-quality queue; the run continues", "GRC analyst fixes the source record in CISO Assistant"],
 ["Exception expiring in 14 days or less", "REMIND owner", "If not renewed by expiry &rarr; committee"],
 ["Exception expired", "ESCALATE-COMMITTEE, 5 business days", "Committee renews with new evidence or closes it"],
 ["Finding overdue, AI &ge; 0.50", "ESCALATE-CCO, 2 business days", "CCO re-plans or accepts risk formally"],
 ["Escalation not acted on within SLA", "Re-raised on the next run with SLA breached", "Board audit and compliance committee report"]], ["26%", "34%", None])}
<h3 class="pb">2.6 Costs, savings, ROI and payback</h3>
{table(["One-time cost", "USD"], [[e(k), D(v)] for k, v in roi["one_time_costs"].items()] + [["<b>Total one-time</b>", f"<b>{D(roi['one_time_total'])}</b>"]], ["70%", None])}
{table(["Annual cost", "USD"], [[e(k), D(v)] for k, v in roi["annual_costs"].items()] + [["<b>Total annual</b>", f"<b>{D(roi['annual_cost_total'])}</b>"]], ["70%", None])}
{table(["Annual operational saving (full adoption)", "USD"], [[e(k), D(v)] for k, v in roi["annual_hard_savings_full_adoption"].items()] + [["<b>Total</b>", f"<b>{D(roi['annual_hard_savings_total'])}</b>"]], ["70%", None])}
<p>JML saving: {roi['jml_events_per_year']:,} joiner/mover/leaver events a year &times; ({roi['minutes_per_jml_event']['manual']} &minus; {roi['minutes_per_jml_event']['automated']}) minutes,
using the provisioning times measured in section 3. About <b>{roi['operational_savings_hours_per_year']:,} staff hours</b> are freed each year. Year 1 assumes 60% adoption while the EU and India sites onboard.</p>
{table(["Measure", "Hard savings only", "Including credited risk reduction"], [
 ["Payback", f"{roi['payback_months_hard_savings']} months", "-"],
 ["3-year NPV (8%)", D(roi['three_year_npv_hard']), D(roi['three_year_npv_with_risk'])],
 ["3-year ROI", f"{roi['three_year_roi_pct_hard']}%", "-"]], ["30%", "30%", None])}
{img("../outputs/roi_cumulative.png", "Cumulative cash position (roi_model.py). Risk credit = 25% of the modelled R02 + R05 loss reduction (section 5).", 300)}
""")

# ---------------------------------------------------------------- 3 process
mm, am = proc["measured_provisioning_minutes"]["manual_2026-10-19"], proc["measured_provisioning_minutes"]["automated_2026-11-03"]
base = list(csv.DictReader(open(OUT / "process_baseline.csv")))
P.append(f"""<h2 class="pb">3. Process Integration &amp; Optimization</h2>
<h3>3.1 Integrated compliance platform with data synchronization</h3>
{table(["Flow", "From &rarr; To", "Sync method", "Frequency"], [
 ["Identity events", "Keycloak / Entra &rarr; Wazuh", "Event export + log collection (SOC 1 lab)", "Real time"],
 ["JML actions", "can_iam.py &rarr; audit log &rarr; evidence store", "Append-only JSONL, SHA-256 indexed", "Per action"],
 ["GRC registers", "CISO Assistant &rarr; workflow engine", "Read-only export (ciso_sync_export.py)", "On demand / hourly schedule"],
 ["Decisions", "Workflow engine &rarr; owners, CCO, committee", "Work queue + escalation log", "Every run"],
 ["Evidence + results", "Evidence store &rarr; CISO Assistant", "Loader (load_ciso.py, upsert by ref_id: no duplicates)", "After each test cycle"]], ["16%", "28%", "34%", None])}
<h3>3.2 Method (DMAIC)</h3>
<ol><li><b>Define:</b> the access-request (joiner / mover / leaver) process, the most frequent compliance-relevant process (about {roi['jml_events_per_year']:,} events a year at group scale).</li>
<li><b>Measure:</b> baseline from the manual run on 2026-10-19 (JML evidence timestamps).</li>
<li><b>Analyze:</b> waste = re-keying in two systems, manual verification, screenshots for evidence; defect = the leaver's Keycloak copy kept the billing role (CA-09).</li>
<li><b>Improve:</b> automate provisioning + verification + evidence in one step (can_iam.py); approvals in the workflow.</li>
<li><b>Control:</b> end-to-end tests TC-01 to TC-10, KPI on leaver timeliness, workflow monitoring.</li></ol>
<h3 class="pb">3.3 Baseline measurements and results</h3>
{table(["Event", "Manual 2026-10-19 (measured)", "Automated 2026-11-03 (measured)"], [[k, f"{mm[k]} min", f"{am[k]*60:.0f} s"] for k in mm], ["30%", "35%", None])}
{table(["Step per request", "Baseline h", "Optimized h", "Basis"], [[e(b["step"]), b["baseline_hours"], b["optimized_hours"], e(b["basis"])] for b in base], ["32%", "11%", "11%", None])}
{table(["Measure", "Baseline", "Optimized", "Change"], [
 ["Provisioning time (measured)", f"{sum(mm.values())/3:.1f} min avg", f"{sum(am.values())/3*60:.0f} s avg", f"&minus;{proc['provisioning_time_reduction_pct']}%"],
 ["Touch time per request", f"{proc['touch_time_hours']['baseline']} h", f"{proc['touch_time_hours']['optimized']} h", f"&minus;{proc['touch_time_hours']['reduction_pct']}%"],
 ["Lead time per request", f"{proc['lead_time_hours']['baseline']} h", f"{proc['lead_time_hours']['optimized']} h", f"<b>&minus;{proc['lead_time_hours']['reduction_pct']}%</b> (target 30%)"],
 ["Errors", proc["error_rate"]["manual"], proc["error_rate"]["automated"], "defect removed"],
 ["Leaver exposure window", f"{proc['leaver_exposure_window_minutes']['manual']} min", f"{proc['leaver_exposure_window_minutes']['automated']} min", "eliminated"]], ["30%", "20%", "25%", None])}
{img("../outputs/process_before_after.png", "Measured provisioning time and modelled lead/touch time (process_optimization.py)", 300)}
<p>The 30% target is met on the most conservative measure (lead time, which still contains assumed approval waiting time). The efficiency
claim does not depend on the assumptions: provisioning alone is measured.</p>
<h3>3.4 Validation procedures</h3>
<ul>{"".join(f"<li>{e(v)}</li>" for v in proc["validation"])}<li>Repeat the measurement at every quarterly access review; publish the KPI in the board pack (section 6).</li></ul>
""")

# ---------------------------------------------------------------- 4 audit
ca = aa["ca_closure"]
P.append(f"""<h2 class="pb">4. Advanced Auditing Techniques</h2>
<h3>4.1 Multi-site audit plan (Q4 2027, 6 weeks)</h3>
{table(["Site", "Mode", "When", "Focus", "Sample"], [[e(x) for x in r] for r in C.AUDIT_PLAN], ["24%", "16%", "8%", "32%", None])}
<p><b>Virtual techniques:</b> screen-share walkthroughs, evidence requests through CISO Assistant, VDI observation in Hyderabad, live queries on Wazuh.
<b>On-site techniques:</b> workstation and badge checks, observation of clinical access, interviews, re-performance of a leaver.
<b>Common basis:</b> one audit program, the unified controls (1.4), one evidence standard (hashed files linked to the control).</p>
<h3>4.2 Cross-functional audit team</h3>
{table(["Role", "Who", "Responsibility"], [[e(x) for x in r] for r in C.AUDIT_TEAM], ["28%", "30%", None])}
<p>IT, operational and financial compliance are each covered by a team member who owns that part of the report; the lead auditor consolidates.</p>
<h3 class="pb">4.3 Statistical sampling</h3>
{table(["Confidence", "Tolerable deviation", "Deviations allowed", "Sample size"], [[f"{int(s['confidence']*100)}%", f"{int(s['tolerable_deviation']*100)}%", s["deviations_allowed"], f"<b>{s['sample_size']}</b>"] for s in aa["sampling"]], ["25%", "25%", "25%", None])}
<p>Exact binomial attribute sampling: the smallest n where the chance of seeing no more than the allowed deviations, if the true rate were the tolerable rate, is below 5%.
Example: 59 items with zero deviations give 95% confidence the deviation rate is under 5%.</p>
<h3>4.4 Evidence analysis with data analytics</h3>
{table(["Analysis (real capstone data)", "Result"], [
 ["EHR access by role (90 events)", f"Billing role: {aa['ehr_access']['billing_role_clinical_views']} clinical views = {aa['ehr_access']['billing_share_pct']}% (95% CI {aa['ehr_access']['billing_share_ci95'][0]}-{aa['ehr_access']['billing_share_ci95'][1]}%). Expected 0: each is a least-privilege exception to test."],
 ["Sign-in failures per user (z-score)", "Outliers z &gt; 2: " + ", ".join(f"{x['user']} ({x['failures']} failures, z = {x['z']})" for x in aa["signin_outliers_z_gt_2"]) + ". Explained: the lockout test account."],
 ["Control test pass rate with confidence intervals", "; ".join(f"{c['date']}: {c['pass']}/{c['total']} = {c['rate_pct']}% (95% CI {c['ci95'][0]}-{c['ci95'][1]}%)" for c in aa["control_tests"]) + ". The intervals overlap because the sample is small: retest with more items before claiming the improvement statistically."]], ["30%", None])}
{img("../outputs/audit_analytics.png", "audit_analytics.py: control-test pass rate with 95% CI, and predicted findings per site", 300)}
<h3 class="pb">4.5 Predictive analytics and automated reporting</h3>
{table(["Site", "Controls", "Maturity factor", "Expected findings", "90% interval"], [[e(s["site"]), s["controls_in_scope"], s["maturity_factor"], s["expected_findings"], s["pi90"]] for s in aa["findings_forecast"]["sites"]], ["36%", "12%", "14%", "16%", None])}
<p>Findings are modelled as Poisson: the capstone audit found {aa['findings_forecast']['capstone_rate_per_control']} findings per control tested, scaled by site maturity
(EU and India sites are newer to HRMC controls). The forecast sets audit staffing: the EU weeks get two auditors.</p>
<p><b>Corrective-action forecast (live CISO Assistant data):</b> {ca['closed']} of {ca['total']} closed ({ca['closed_pct']}%), {ca['closure_rate_per_week']} per week since the 2026-10-13 audit;
at that rate 90% closure is reached around <b>{ca['forecast_90pct_date']}</b>. Predicted at risk in the next 14 days: {', '.join(ca['at_risk_next_14_days'])}.</p>
<p><b>Automated reporting:</b> <code>audit_analytics.py</code> writes <code>outputs/audit_analytics_report.md</code> on every run (sampling plan, analytics, predictions), so the audit pack is regenerated from data, not retyped.</p>
""")

# ---------------------------------------------------------------- 5 risk
P.append(f"""<h2 class="pb">5. Quantitative Risk Assessment</h2>
<h3>5.1 Method</h3>
<p>FAIR-style Monte Carlo simulation (<code>analysis/risk_monte_carlo.py</code>, 100,000 simulated years, seed 42). For each capstone risk:
<b>annual loss = sum of N loss events</b>, where N is Poisson with a rate drawn from a triangular distribution, and each event's loss is drawn from a PERT distribution.
This builds on Risk Management 1, which used single-point ALE (e.g. asset $100,000 &times; EF 0.30 = SLE $30,000; ARO 0.5 &rarr; ALE $15,000) and a business impact analysis
(Keycloak IAM outage $25,000 for the flagship). Simulation replaces single points with ranges and gives percentiles, not just an average.</p>
<h3>5.2 Inputs (from the capstone register + planning assumptions)</h3>
{table(["Risk", "Register inherent &rarr; residual", "Events/yr (mode)", "Loss per event: min / likely / max", "Annual treatment cost"],
 [[f"{r['risk_id']} {e(r['risk'])}", f"{r['register_inherent']} &rarr; {r['register_residual']}", r["freq_mode_per_year"], f"{K(r['loss_min'])} / {K(r['loss_mode'])} / {M(r['loss_max'])}", K(r["annual_treatment_cost"])] for r in mcr],
 ["30%", "16%", "12%", "26%", None])}
<p>Frequency mode comes from the register likelihood (3 &rarr; 0.4/yr, 4 &rarr; 0.8/yr), with the range 0.25&times; to 3&times; the mode. Residual frequency = inherent &times; (residual score &divide; inherent score),
taken straight from the CISO Assistant register; detective controls (R03, R04) also cut loss size by 20%. Loss ranges include response, notification, regulatory penalties
(HIPAA civil penalty tiers; GDPR fines up to &euro;20M or 4% of worldwide turnover) and litigation. They are calibrated estimates for planning, not actuarial data.</p>
<h3 class="pb">5.3 Results by risk</h3>
{table(["Risk", "Inherent ALE (mean)", "Inherent P90", "Residual ALE (mean)", "Residual P90", "Reduction", "Cost", "ROSI"],
 [[f"{r['risk_id']} {e(r['risk'])}", K(r["inherent_ALE_mean"]), K(r["inherent_ALE_p90"]), K(r["residual_ALE_mean"]), K(r["residual_ALE_p90"]), K(r["risk_reduction"]), K(r["annual_treatment_cost"]), f"{r['ROSI_pct']}%"] for r in mcr],
 ["24%", "11%", "10%", "11%", "10%", "11%", "9%", None])}
{img("../outputs/ale_by_risk.png", "Mean annualized loss by risk, inherent vs residual", 280)}
<p>ROSI = (risk reduction &minus; treatment cost) &divide; treatment cost. Every treatment pays for itself; credential compromise (R03) is both the largest risk and the best investment.
The 95% confidence interval on each mean is narrow (e.g. R03 residual {e(next(r['ci95_residual_mean'] for r in mcr if r['risk_id']=='R03'))}), so 100,000 iterations are enough.</p>
<h3 class="pb">5.4 Portfolio view and risk appetite</h3>
{table(["Position", "Mean", "P50", "P90", "P95", "P99"], [
 ["Inherent", M(mc["inherent"]["mean"]), M(mc["inherent"]["p50"]), M(mc["inherent"]["p90"]), M(mc["inherent"]["p95"]), M(mc["inherent"]["p99"])],
 ["Residual (controls as tested)", M(mc["residual"]["mean"]), M(mc["residual"]["p50"]), M(mc["residual"]["p90"]), M(mc["residual"]["p95"]), M(mc["residual"]["p99"])]], ["30%", "14%", "14%", "14%", "14%", None])}
{img("../outputs/loss_exceedance_curve.png", "Loss exceedance curve: chance that the annual IAM-related loss exceeds a given amount", 320)}
<p><b>Risk appetite (proposed to the board):</b> {e(mc['appetite']['statement'])}. Inherent and residual positions are both outside appetite.</p>
<h3>5.5 Scenario analysis</h3>
{table(["Scenario", "Assumption", "Mean", "P90", "P95", "P99"], [[e(s["scenario"]), e(s["assumption"]), M(s["mean"]), M(s["p90"]), M(s["p95"]), M(s["p99"])] for s in mc["scenarios"]], ["30%", "28%", "10%", "10%", "10%", None])}
<p>The expansion itself (S1) raises expected loss by about {M(mc['scenarios'][1]['mean']-mc['scenarios'][0]['mean'])} a year until the new sites reach HRMC's control level: the reason the roadmap
extends JML automation to the EU and India in Q3 2027, before anything else.</p>
<h3 class="pb">5.6 Risk treatment strategy, transfer and residual risk plan</h3>
{table(["Option", "Added annual cost", "Expected annual loss + added cost", "P95 annual loss + added cost", "Within appetite?"], [
 ["A. Accept residual (current controls)", "none (existing controls " + K(mc["treatment_cost_total"]) + " already in place for all options)", M(mc["residual"]["mean"]), M(mc["residual"]["p95"]), "No"],
 ["B. Transfer: cyber insurance ($1M retention, $10M limit per event)", f"premium {M(mc['residual_with_insurance']['premium'])}", M(mc["residual_with_insurance"]["mean"]), M(mc["residual_with_insurance"]["p95"]), "Yes" if mc["appetite"]["with_insurance_p95_within"] else "No (just above)"],
 ["<b>C. Mitigate + transfer: FIDO2 MFA for ePHI roles, then insure (recommended)</b>", f"+{K(opt['extra_annual_cost'])} control, premium {M(opt['premium'])}", f"<b>{M(opt['mean_total_cost'])}</b>", f"<b>{M(opt['p95_total'])}</b>", "<b>Yes</b>"]], ["38%", "18%", "15%", "15%", None])}
<p>Insurance premiums are priced at expected covered loss &times; 1.35 (insurer expenses and profit), so insurance alone costs more than it saves on average; its value is cutting the tail.
Option C lowers both the average and the tail, because the extra control shrinks what the insurer has to cover.</p>
<p><b>Residual risk management plan:</b> (1) Board accepts option C and the appetite statement; (2) FIDO2 rollout in the 2028 roadmap, insurance bound for 2027;
(3) R02 stays residual Moderate through JML automation (CAN-FIND-001 automatic deprovisioning closes the last gap); (4) triggers for re-assessment: scenario S1 or S3 conditions,
a SEV-1 incident, or the model's P95 moving above $5M; (5) the model is re-run each quarter with updated register scores from CISO Assistant.</p>
""")

# ---------------------------------------------------------------- 6 performance
P.append(f"""<h2 class="pb">6. Performance Management &amp; Continuous Improvement</h2>
<h3>6.1 KPI framework with benchmarks</h3>
{table(["Category", "KPI", "Current (live)", "Target", "Benchmark / reference"], [[k["category"], e(k["kpi"]), e(k["current"]), e(k["target"]), e(k["reference"])] for k in kpi["kpis"]], ["11%", "22%", "24%", "14%", None])}
<p>Formulas for every KPI are in the workbook (<code>KPI_Framework</code>). Industry reference points: IBM <i>Cost of a Data Breach Report 2025</i> (healthcare remains the costliest industry,
about US$7.4M per breach); regulatory clocks (GDPR 72 h, HIPAA 60 days); NIST CSF 2.0 implementation tiers for maturity.</p>
<h3 class="pb">6.2 Advanced monitoring with predictive capabilities and automated review</h3>
{table(["Monitor", "Predictive / automated element", "Current output"], [
 ["Compliance workflow (daily)", "AI score predicts which issues become material exposures", f"{routes['ESCALATE-COMMITTEE']} committee, {routes['ESCALATE-CCO']} CCO, {routes['ASSIGN-OWNER']} owner, {routes['MONITOR']} monitor"],
 ["Corrective-action burn-down (weekly)", "Closure-rate forecast; items due within 14 days flagged before they slip", f"90% closure forecast {ca['forecast_90pct_date']}; at risk: {', '.join(ca['at_risk_next_14_days'])}"],
 ["Exception expiry (daily)", "Reminder 14 days ahead; automatic committee escalation at expiry", f"Expired now: {', '.join(kpi['predictive']['expired_exceptions'])}"],
 ["Risk model (quarterly)", "Monte Carlo P95 vs appetite; scenario stress", f"Residual P95 {M(mc['residual']['p95'])}"],
 ["Audit forecast (annual)", "Poisson findings forecast per site sets audit staffing", "EU sites highest"],
 ["Security operations (real time)", "Wazuh correlation rules, email escalation (SOC 1)", "33 alert emails routed in the SOC 1 lab"]], ["24%", "40%", None])}
<p><b>Automated review process:</b> each Monday the workflow and analytics scripts run, the work queue and audit report regenerate, and the CCO reviews only the escalations;
monthly, the KPI table goes to the compliance committee; quarterly, the board sees KPIs, the loss exceedance curve and roadmap status.</p>
<h3>6.3 Continuous improvement program (PDCA) with measured results</h3>
{table(["PDCA", "Cycle 1 (Oct-Nov 2026, measured)"], [["Plan", e(kpi["pdca_cycle_1"]["plan"])], ["Do", e(kpi["pdca_cycle_1"]["do"])], ["Check", e(kpi["pdca_cycle_1"]["check"])], ["Act", e(kpi["pdca_cycle_1"]["act"])]], ["12%", None])}
{img("../outputs/pdca_cycle1.png", f"Measured improvement: +{kpi['pdca_cycle_1']['measured_improvement_points']} percentage points in control pass rate in one cycle", 260)}
{table(["Cycle 2 (2027)", "Plan"], [
 ["Plan", "Targets from section 6.1; close EX-06 / EX-08 decisions; automatic Keycloak deprovisioning (CAN-FIND-001)"],
 ["Do", "Extend automation to EU + India; FIDO2 pilot; works-council agreement"],
 ["Check", "First multi-site audit (section 4); compare actual findings with the Poisson forecast to calibrate it"],
 ["Act", "Re-weight the AI triage model on real committee outcomes; update the unified control set; feed lessons into the 2028 roadmap"]], ["12%", None])}

<h2 class="pb">Files and reproduction</h2>
{table(["Path (repository folder compliance_2/)", "Content"], [
 ["automation/ciso_sync_export.py", "Read-only live export from CISO Assistant"], ["automation/compliance_workflow.py", "Workflow, AI triage, exception handling, escalation"],
 ["analysis/risk_monte_carlo.py", "Monte Carlo, scenarios, insurance, ROSI"], ["analysis/process_optimization.py", "Measured baseline vs automated JML"],
 ["analysis/roi_model.py", "Costs, savings, payback, NPV"], ["analysis/audit_analytics.py", "Sampling, analytics, predictions, automated report"],
 ["analysis/kpi_performance.py", "KPI framework, predictive alerts, PDCA results"], ["build/content.py", "Sites, conflicts, control map, roadmap, audit plan"],
 ["HRMC_Compliance2_Workbook.xlsx", "17 sheets: every table in this document"], ["outputs/", "CSV, JSON and charts produced by the scripts"],
 ["diagrams/*.mmd", "Mermaid sources of the architecture and workflow diagrams"]], ["40%", None])}
<p>Re-run: <code>docker exec -i backend sh -c 'cd /code &amp;&amp; uv run python manage.py shell' &lt; automation/ciso_sync_export.py</code> (extract the JSON), then
<code>python3 automation/compliance_workflow.py</code> and the analysis scripts (Python 3.11 + numpy, matplotlib, openpyxl).</p>
""")

CSS = """body{font-family:"DejaVu Sans",Arial,sans-serif;color:#1F2D33;font-size:10pt;line-height:1.42;margin:0}
h1{font-family:"DejaVu Serif",Georgia,serif;color:#16324F;font-size:22pt;margin:0 0 4px}
h2{font-family:"DejaVu Serif",Georgia,serif;color:#16324F;font-size:15pt;margin:20px 0 8px;border-bottom:2px solid #C8553D;padding-bottom:3px}
h3{color:#2B6F8E;font-size:11.5pt;margin:14px 0 5px}
.meta{color:#5B6B70;font-size:9.5pt;margin-bottom:10px}
table{border-collapse:collapse;width:100%;margin:5px 0 10px;page-break-inside:auto}
tr{page-break-inside:avoid}
th,td{border:1px solid #D3DEE6;padding:4px 6px;vertical-align:top;text-align:left;font-size:8.8pt}
th{background:#E6EFF5;color:#16324F}
code{font-family:"DejaVu Sans Mono",monospace;font-size:8.3pt}
.note{background:#FBF1E6;border-left:4px solid #C8553D;padding:7px 10px;font-size:9.5pt;margin:8px 0}
.ok{background:#EAF5EE;border-left:4px solid #2E8B57;padding:7px 10px;font-size:9.5pt;margin:8px 0}
.fig{text-align:center;margin:6px 0 10px;page-break-inside:avoid}.fig img{max-width:100%}
.cap{color:#5B6B70;font-size:8.5pt;text-align:center}
.pb{page-break-before:always} ul,ol{margin:4px 0 6px 20px;padding:0} li{margin:2px 0}"""
open(HERE / "compliance2.html", "w").write(f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{''.join(P)}</body></html>")
print("ok")
