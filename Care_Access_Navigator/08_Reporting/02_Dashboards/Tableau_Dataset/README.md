# Tableau dataset: Care Access Navigator GRC dashboard (Week 11)

Refreshed on 2026-11-03 from live evidence by `10_Scripts/03_GRC_Build/build_tableau.py`. Every row is synthetic.
Build steps, the wireframe and the values the finished dashboard must show are in
`../CAN_DOC_GRC_Dashboard_Design_v1.0.pdf`.

| File | What it holds | Source |
|---|---|---|
| `kpi_values.csv` | 10 KPIs with numerator, denominator, value, target | computed from the files below |
| `access_review_AR-2026-Q4.csv` | Quarterly access review, 16 accounts, flags and risk | live realm (EV-15) |
| `identity_detections.csv` | CAN-ID-001..007 detections | live Keycloak events (EV-14) |
| `control_tests.csv` | Audit CAN-IA-2026-01 (10/13) + Week 5 retests + end-to-end tests (11/03) | audit + EV-13/EV-14 |
| `audit_findings.csv` | F-01..F-06 with status, corrective action, verified date | Compliance 1 + CA tracker |
| `controls.csv` | 16 controls with HIPAA, CSF 2.0, SP 800-53, ISO 27001, PCI DSS mappings | Week 9 catalog |
| `exceptions.csv`, `corrective_actions.csv` | Week 10 registers | `grc_data.py` |
| `risks.csv` | R01..R05 scores (Risk Management 1) + treatment status | register |
| `incidents.csv` | Cloud INC-20261008-01 + IR1-2026-001/002/003 | IR register |
| `azure_alerts_30d.csv` | Azure alert rules that fired (Cloud Security 1) | E-LOG-01 |

**Tableau Public publishes workbooks publicly.** That is acceptable only because the data is synthetic; never load real data.
