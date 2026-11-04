# 02_Dashboards

**W11 Thu integrated GRC dashboard = CISO Assistant** (`https://localhost:8443`), replacing the planned Tableau
workbook (Tableau is not installed). This substitution is exception **EX-08**, pending instructor acceptance.

Where to look in CISO Assistant (domain *Care Access Navigator - IAM & GRC*):

| Dashboard view | Shows |
|---|---|
| Analytics (home) | Applied-control status, compliance progress, risk level counts, exceptions and findings |
| Risk assessment CAN-RA-001 v2.0 | 5x5 heat maps of inherent, current and residual risk for R01-R05 |
| Audit CAN-AUD-HIPAA-001 v2.0 | HIPAA donut and progress: 14 compliant, 10 partial, 1 non-compliant of 25 assessed |
| Audit CAN-AUD-CSF-001 | NIST CSF 2.0: 9 compliant, 5 partial, 1 non-compliant of 15 assessed |
| Findings assessment CAN-FA-001 | Corrective actions by status and severity (8 resolved, 3 in progress, 8 open) |

Screenshots of these views go in this folder as `EV-16_CISO_Dashboard_<view>_<YYYYMMDD>.png`.

Kept for reference: `CAN_DOC_GRC_Dashboard_Design_v1.0.pdf` (KPI definitions) and `Tableau_Dataset/`
(CSV extracts from `grc_data.py` and the evidence folders; superseded as a reporting source by CISO Assistant).
