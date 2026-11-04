# GRC build scripts (Weeks 5-12)

`grc_data.py` holds the registers (authentication baseline, privileged access matrix, service/vendor identities,
control catalog, exceptions, corrective actions, evidence index). Live results are read from the evidence folders
(EV-13, EV-14, EV-15), never typed in. Each builder writes one deliverable:

| Script | Output |
|---|---|
| `build_w1_w3.py` | asset inventory (xlsx), RBAC/SoD/access-request workbook + PDF, access-request workflow diagram |
| `update_design_doc.py` | design documentation v1.2 -> v1.3 (section 14 status) |
| `build_w5_pdf.py` | `07_GRC/02_Controls/CAN_DOC_Authentication_and_Privileged_Access_v1.0.pdf` |
| `build_workbooks.py` | control catalog, exceptions + corrective actions, evidence index, access review sign-off (xlsx) |
| `build_tableau.py` | refreshes `08_Reporting/02_Dashboards/Tableau_Dataset/` and `kpi_values.csv` |
| `build_dashboard_design.py` | `08_Reporting/02_Dashboards/CAN_DOC_GRC_Dashboard_Design_v1.0.pdf` |
| `build_e2e_pdf.py` | `06_Evidence/04_Test_Results/CAN_DOC_End_to_End_Test_Report_v1.0.pdf` |
| `build_w12_pdfs.py` | portfolio index + lessons learned, 5-minute demo script |

Run order (needs reportlab and openpyxl, e.g. the venv in `Semester_4/Cloud_Security_1/pdf-build/.venv`):

```bash
python build_w1_w3.py && python build_tableau.py && python build_workbooks.py && python build_w5_pdf.py \
  && python build_e2e_pdf.py && python build_dashboard_design.py && python build_w12_pdfs.py
```

`pdfstyle.py` is the same house style as the Incident Response 1 packages.
