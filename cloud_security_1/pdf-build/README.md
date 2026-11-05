# PDF build scripts

Regenerate the CloudSec1 evidence PDFs from the screenshots and evidence files in `cloud_security_1/`.

```bash
python3 -m venv .venv && .venv/bin/pip install reportlab pypdf pillow openpyxl
.venv/bin/python build_pdf.py            # Criterion 3 Infrastructure & Container Security PDF
.venv/bin/python build_c4_addendum.py    # Criterion 4 IAM PDF = original 11 pages + Oct 6 addendum
.venv/bin/python build_c5.py             # Criterion 5 Compliance & Governance PDF + HIPAA checklist .xlsx
.venv/bin/python build_c6.py             # Criterion 6 Security Operations & Incident Response PDF
```

Optional screenshots are embedded automatically when saved in `cloud_security_1/` under these names:
`Container - Dockerfile.png`, `Container - Compose.png`, `Container - Runtime tests.png`,
`Serverless - Storage IAM.png`, `Governance - Management groups.png`, `Governance - Policy compliance.png`,
`Governance - Deny message.png`, `Cloud_Security_1:SecOps_Dashboard.png`, `Cloud_Security_1:SecOps_Defender_alert.png`, `Alert_email.png`.

- `data/` – captured CLI output used in the PDFs, and the original Sept 30 Criterion 4 PDF.
- `c5_data.py` – the HIPAA checklist, remediation plan, guardrails and tag standard (single source for PDF + Excel).
- `.cache/` – downscaled screenshots; safe to delete.
