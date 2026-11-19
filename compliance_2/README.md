# Compliance 2

Final project submission: [`Compliance_2_Submission.pdf`](Compliance_2_Submission.pdf) (21 pages) and
[`HRMC_Compliance2_Workbook.xlsx`](HRMC_Compliance2_Workbook.xlsx) (17 sheets).

Scenario: HealthLine Regional Medical Center (HRMC), the capstone hospital, expands into a multinational group
(US, Ireland, Germany, India; 10,800 staff). Measured inputs come from the capstone evidence and the live CISO Assistant
instance; expansion figures are labelled planning assumptions.

| Rubric criterion | Section | Built with |
|---|---|---|
| Advanced Compliance Strategy | 1 | `build/content.py` (conflicts, unified control map, roadmap), `diagrams/compliance_architecture.mmd` |
| Compliance Automation Implementation | 2 | `automation/ciso_sync_export.py`, `automation/compliance_workflow.py` (AI triage), `analysis/roi_model.py` |
| Process Integration & Optimization | 3 | `analysis/process_optimization.py` (measured JML baseline vs automation) |
| Advanced Auditing Techniques | 4 | `analysis/audit_analytics.py` (sampling, analytics, predictions, automated report) |
| Quantitative Risk Assessment | 5 | `analysis/risk_monte_carlo.py` (100,000-run Monte Carlo, scenarios, insurance, ROSI) |
| Performance Management & Continuous Improvement | 6 | `analysis/kpi_performance.py` (KPIs, predictive alerts, PDCA results) |

Run order: `ciso_sync_export.py` (inside the CISO Assistant backend) → `compliance_workflow.py` → `risk_monte_carlo.py` →
`process_optimization.py` → `roi_model.py` → `audit_analytics.py` → `kpi_performance.py` → `build/build_workbook.py` → `build/build_doc.py`.
Python 3.11 with numpy, matplotlib and openpyxl. Everything runs locally at no cost.
