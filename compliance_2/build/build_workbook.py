"""Builds compliance_2/HRMC_Compliance2_Workbook.xlsx from content.py and the analysis outputs."""
import csv, json, pathlib, sys
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import content as C

ROOT = HERE.parents[1]
OUT = ROOT / "compliance_2/outputs"
CAT = ROOT / "Care_Access_Navigator/08_Reporting/02_Dashboards/Tableau_Dataset/controls.csv"
wb = Workbook(); wb.remove(wb.active)
HDR = PatternFill("solid", fgColor="16324F")


def sheet(name, header, rows, widths=None):
    ws = wb.create_sheet(name)
    ws.append(header)
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF"); c.fill = HDR; c.alignment = Alignment(wrap_text=True, vertical="top")
    for r in rows:
        ws.append(list(r))
    for i, w in enumerate(widths or [22] * len(header), 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "A2"
    return ws


sheet("README", ["Item", "Value"], [
    ("Organization", C.ORG + " - expansion scenario (fictional) for Compliance 2"),
    ("Author", C.AUTHOR), ("Built from", "content.py + compliance_2/outputs (workflow, Monte Carlo, ROI, process, audit, KPI scripts)"),
    ("Live data", "CISO Assistant snapshot " + json.load(open(ROOT / "compliance_2/data/ciso_snapshot.json"))["exported_utc"]),
    ("Note", "Every dollar figure marked 'assumption' is a planning estimate, not actual spend")], [24, 110])
sheet("Sites", ["Region", "Entity", "Staff", "Services", "Regulation"], C.SITES + [("TOTAL", "", sum(s[2] for s in C.SITES), "", "")], [8, 48, 9, 40, 44])
sheet("Frameworks", ["Framework", "Type", "Scope at HRMC"], C.FRAMEWORKS, [44, 20, 90])
sheet("Conflicts", ["Topic", "Conflicting requirements", "Resolution in the integrated program"], C.CONFLICTS, [24, 80, 80])
rows = []
for r in csv.DictReader(open(CAT)):
    g, d = C.GDPR_DPDP[r["control_id"]]
    rows.append((r["control_id"], r["objective"], r["hipaa"], g, r["pci_dss"], r["iso_27001"], d, r["implementation"], "capstone"))
rows += [(c[0], c[1], c[2], c[3], c[5], c[4], c[6], "Planned 2027", "new for expansion") for c in C.NEW_ENTERPRISE_CONTROLS]
sheet("Unified_Controls", ["Control", "Objective", "HIPAA", "GDPR", "PCI DSS v4.0.1", "ISO 27001:2022", "India DPDP", "Status", "Source"], rows, [8, 48, 26, 24, 16, 16, 14, 18, 16])
sheet("Roadmap_3yr", ["Phase", "When", "Milestones", "Owner", "FTE", "Budget USD (assumption)"],
      C.ROADMAP + [("TOTAL", "", "", "", "", sum(r[5] for r in C.ROADMAP))], [26, 12, 80, 22, 6, 16])
for name, f in [("Risk_MonteCarlo", "risk_mc_results.csv"), ("Risk_Scenarios", "risk_mc_scenarios.csv"), ("ROI_Cashflow", "roi_model.csv"),
                ("Process_Baseline", "process_baseline.csv"), ("KPI_Framework", "kpi_framework.csv"), ("Workflow_Queue", "work_queue.csv")]:
    data = list(csv.reader(open(OUT / f)))
    sheet(name, data[0], data[1:], [18] * len(data[0]))
roi = json.load(open(OUT / "roi_summary.json"))
sheet("ROI_Assumptions", ["Item", "Value"], [(k, v) for k, v in roi["assumptions"].items()] +
      [("One-time: " + k, v) for k, v in roi["one_time_costs"].items()] + [("Annual: " + k, v) for k, v in roi["annual_costs"].items()] +
      [("Annual saving: " + k, v) for k, v in roi["annual_hard_savings_full_adoption"].items()] +
      [("Payback (months)", roi["payback_months_hard_savings"]), ("3-year NPV, hard savings", roi["three_year_npv_hard"]),
       ("3-year NPV incl. credited risk reduction", roi["three_year_npv_with_risk"]), ("3-year ROI % (hard)", roi["three_year_roi_pct_hard"])], [50, 20])
sheet("Audit_Plan", ["Site", "Mode", "When", "Focus", "Sample"], C.AUDIT_PLAN, [32, 22, 10, 50, 26])
sheet("Audit_Team", ["Role", "Who", "Responsibility"], C.AUDIT_TEAM, [30, 30, 44])
aa = json.load(open(OUT / "audit_analytics.json"))
sheet("Audit_Sampling", ["Confidence", "Tolerable deviation", "Deviations allowed", "Sample size"],
      [(s["confidence"], s["tolerable_deviation"], s["deviations_allowed"], s["sample_size"]) for s in aa["sampling"]], [14, 18, 18, 14])
sheet("Findings_Forecast", ["Site", "Controls in scope", "Maturity factor", "Expected findings", "90% interval"],
      [(s["site"], s["controls_in_scope"], s["maturity_factor"], s["expected_findings"], s["pi90"]) for s in aa["findings_forecast"]["sites"]], [36, 16, 14, 16, 12])
wb.save(ROOT / "compliance_2/HRMC_Compliance2_Workbook.xlsx")
print("workbook sheets:", wb.sheetnames)
