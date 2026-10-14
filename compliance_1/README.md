# Compliance 1 — Care Access Navigator

| Task | Deliverable |
|---|---|
| 1 Compliance Fundamentals | `Care_Access_Navigator_Compliance1_Task1_Compliance_Fundamentals.pdf` |
| 2 Compliance Program Development | `Care_Access_Navigator_Compliance1_Task2_Compliance_Program_Development.pdf` |
| 3 Compliance Auditing Basics | `Care_Access_Navigator_Compliance1_Task3_Compliance_Auditing.pdf` + `audit-evidence/` |
| 4 Documentation & Reporting | `Care_Access_Navigator_Compliance1_Task4_Documentation_Reporting.pdf` + `Care_Access_Navigator_Compliance1_Tracker.xlsx` |
| 5 Legal & Ethical Implementation | `Care_Access_Navigator_Compliance1_Task5_Legal_Ethical_Implementation.pdf` |

Frameworks: **HIPAA** (Privacy, Security, Breach Notification Rules) and **PCI DSS v4.0.1** (Billing App card payments).

- `audit-evidence/` — real evidence collected 2026-10-13 (read-only / validate-only, no Azure cost) with a SHA-256 index.
- `pdf-build/` — generators. Rebuild with the venv in `cloud_security_1/pdf-build/.venv`:
  `cd pdf-build && ../../cloud_security_1/pdf-build/.venv/bin/python build_task1.py` (… `build_task5.py`, `build_tracker.py`).
  Shared facts live in `org.py`; diagrams in `diagrams.py`; style in `style.py`.
