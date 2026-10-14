# Tableau dataset: Care Access Navigator GRC dashboard (Week 11 starter)

The CSVs below come from evidence that already exists: the RiskMgmt1 register, Compliance 1 audit CAN-IA-2026-01, E-LOG-01 alert history, the incident records and KPI definitions. `access_review_AR-2026-Q4.csv` and `identity_detections.csv` are **samples from the replica test run**. Replace them with the files `can_iam.py review` and `can_iam.py detect` produce on your own lab.

**Tableau Public (free) publishes workbooks publicly.** That's fine here because everything is synthetic, but never load real data.

Suggested views: (1) Risk heat map: inherent vs residual (risks.csv). (2) Audit findings by rating/status with a target-date Gantt. (3) Control test pass rate (control_tests.csv). (4) Identity detections by rule over time. (5) Access review: flagged accounts by flag and department. (6) KPI tiles from kpi_definitions.csv.
