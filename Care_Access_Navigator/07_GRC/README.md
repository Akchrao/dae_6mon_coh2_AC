# 07_GRC - Governance, Risk and Compliance

**System of record (from 2026-11-04): CISO Assistant Community Edition v4.2.1**, self-hosted at
`https://localhost:8443` (`ciso-assistant-community`, domain *Care Access Navigator - IAM & GRC*).
The registers were loaded from `10_Scripts/03_GRC_Build/grc_data.py` by `10_Scripts/04_CISO_Assistant/` and every file
named `CAN_DOC_CISO_*` here is an export from CISO Assistant. The database itself is local and not in git.

| Folder | CISO Assistant record | Exports |
|---|---|---|
| `01_Risks` | Risk assessment CAN-RA-001 v2.0, risks R01-R05 (5x5 ISO 27005 matrix; inherent, current, residual) | `CAN_DOC_CISO_Risk_Assessment_R01-R05_v2.0` (pdf, xlsx), `CAN_DOC_CISO_Risk_Register_v2.0.xlsx`, `CAN_DOC_CISO_Risk_Treatment_Plan_v2.0` (pdf, xlsx) |
| `02_Controls` | 18 applied controls (16 from the catalog + CAN-CTRL-JML-001/002), 7 assets | `CAN_DOC_CISO_Applied_Controls_v1.0.xlsx`, `CAN_DOC_CISO_Assets_v1.0.xlsx` |
| `03_Compliance` | Audit CAN-AUD-HIPAA-001 v2.0 (NIST SP 800-66r2, 25 access-related requirements assessed); audit CAN-AUD-CSF-001 (NIST CSF 2.0, 15 subcategories) | `CAN_DOC_CISO_HIPAA_Audit_v2.0.xlsx`, `CAN_DOC_CISO_HIPAA_Audit_Report_v2.0.docx`, `CAN_DOC_CISO_NIST_CSF2_Mapping_v1.0` (xlsx, docx) |
| `04_Remediation` | Security exceptions EX-01..EX-08; findings assessment CAN-FA-001 (CA-01..CA-18 + CAN-FIND-001) | `CAN_DOC_CISO_Exception_Register_v1.0.xlsx`, `CAN_DOC_CISO_Corrective_Action_Tracker_v1.0` (pdf, xlsx), `CAN_DOC_CISO_HIPAA_Action_Plan_v2.0` (pdf, xlsx) |

Evidence (41 items, EV-02..EV-15, JML, Compliance 1 and IR 1 indexes) is attached in CISO Assistant to the controls,
requirements and resolved findings; the files stay in `06_Evidence` and their SHA-256 is in each evidence description.

## Superseded (kept for history, do not edit)

- `02_Controls/CAN_DOC_Control_Catalog_and_Mapping_v1.0.xlsx` -> CISO applied controls + HIPAA / CSF audits
- `04_Remediation/CAN_DOC_Exceptions_and_Corrective_Actions_v1.0.xlsx` -> CISO exceptions + corrective action tracker
- `06_Evidence/CAN_DOC_Evidence_Index_v1.0.xlsx` -> CISO evidence library
- `08_Reporting/02_Dashboards/Tableau_Dataset/risks.csv` (risk register extract) -> CISO risk assessment

`02_Controls/CAN_DOC_Authentication_and_Privileged_Access_v1.0.pdf` (W5) is still current; it is also attached in CISO as evidence.

## Scoring notes

- `risks.csv` stores residual as a score only. It was entered as likelihood = score / impact (impact unchanged): R01, R03,
  R04 = 2 x 5; R02 = 1 x 5; R05 = 1 x 4.
- R02 current level stays 3 x 5 (High): the scripted Keycloak leaver step passed TC-04/TC-09, but an Entra ID termination
  still does not disable the Keycloak copy automatically (CAN-CTRL-JML-002 test 1, CAN-FIND-001). The register's
  residual 1 x 5 is the target.
- Requirement results are the weakest implementation of the mapped controls, with documented overrides (termination
  procedures, password management, emergency access, business associates).
- Educational simulation with synthetic data; "mapped to HIPAA/NIST concepts", not a compliance certification.
