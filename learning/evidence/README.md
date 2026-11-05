# Learning: CISO Assistant (GRC platform) for Care Access Navigator

All my tool documents and evidence are in this folder (`learning/evidence/`); the general templates are in `learning/templates/`.

Semester 5 new-technology learning project. Chosen tool: **CISO Assistant Community Edition** (intuitem), v4.2.1,
self-hosted with Docker at `https://localhost:8443` from [`../../ciso-assistant-community/`](../../ciso-assistant-community/).

| File | What it is |
|---|---|
| [`PLAN.md`](PLAN.md) | My learning plan (2026-10-28) with a status update (2026-11-05) |
| [`TUTORIAL.md`](TUTORIAL.md) | Mini-tutorial: tracing an IAM risk from evidence to a HIPAA finding in CISO Assistant |
| [`NOTES.md`](NOTES.md) | Observability notes: health check, logs, dashboards |
| [`REFLECTION.md`](REFLECTION.md) | Reflection (draft for me to finish) |
| [`risk_register_export.csv`](risk_register_export.csv), [`assessment_export.csv`](assessment_export.csv) | CSV exports of the risk register and the HIPAA audit (`;`-separated) |
| [`docker_compose_ps.txt`](docker_compose_ps.txt), [`health_check.txt`](health_check.txt) | Running containers and the `/api/health/` response |
| `EV-16_CISO_Dashboard_*.png` | Dashboard screenshots: [analytics](EV-16_CISO_Dashboard_Analytics_20261104.png), [risk matrix](EV-16_CISO_Dashboard_Risk_Heatmap_20261104.png), [compliance](EV-16_CISO_Dashboard_Compliance_20261105.png) |
| [`../templates/`](../templates/) | The general blank templates (plan, tutorial, notes) |

---

## Task 1 - Install steps and issues

Steps (Mac, Docker Desktop):

1. `git clone https://github.com/intuitem/ciso-assistant-community.git` into the repository root.
2. `./docker-compose.sh` on the first run (pulls the images, starts backend, frontend, huey, caddy, qdrant, creates the
   superuser); afterwards `docker compose up -d` from `ciso-assistant-community/`.
3. Log in at `https://localhost:8443`, load the libraries NIST SP-800-66 rev2 (HIPAA), NIST CSF 2.0 and the 5x5 ISO 27005
   risk matrix.
4. Create the domain *Care Access Navigator - IAM & GRC*, the perimeter *Mock EHR - Workforce Access Governance* and the
   7 assets (1 primary: synthetic ePHI and billing data; 6 supporting: Mock EHR, Keycloak, Entra ID, Patient Portal,
   Billing, HR app), each with an owner and a type.

Issues met:

| Issue | What happened | Fix |
|---|---|---|
| Two machines | Work started on the Windows laptop (v4.1.5, WSL 2) and moved to the Mac (v4.2.1) on 2026-11-04 | Database copied over; the Mac migrated it on start-up |
| Corrupt database copy | The SQLite file was copied while the app was running; integrity check failed | Recovered with `sqlite3 ... ".recover"`; one user row was lost and rebuilt with its original ID. Rule: `docker compose down` before copying |
| Secrets in the db folder | `db/` holds the database, the Django secret key and the OIDC private key | `db/` is git-ignored; backups kept outside the repository |
| Self-signed certificate | Browser shows "Not Secure" on `https://localhost:8443` | Expected for localhost; the port is bound to 127.0.0.1 only |
| Read-only containers | `docker cp` into the backend fails (read-only root filesystem) | Scripts are piped in with `docker exec -i backend ... manage.py shell < script.py`; files staged in the mounted `db/` folder |

Proof: [`docker_compose_ps.txt`](docker_compose_ps.txt), [`health_check.txt`](health_check.txt),
dashboard screenshot `EV-16_CISO_Dashboard_Analytics_20261104.png`.
Asset list: export `../../Care_Access_Navigator/07_GRC/02_Controls/CAN_DOC_CISO_Assets_v1.0.xlsx` (no separate screenshot yet).

---

## Task 2 - Risks and the controls that treat them

Levels on the 5x5 ISO 27005 matrix (very low / low / medium / high / very high). Existing = controls in place; additional =
controls still being implemented.

| Risk | Name | Inherent | Current | Residual | Existing controls | Additional controls | Exceptions |
|---|---|---|---|---|---|---|---|
| R01 | Excessive RBAC privileges | very high | medium | medium | AC-01, AC-03, AC-04, CA-01, RA-01 | AR-01 | - |
| R02 | Incomplete leaver deprovisioning across Entra ID and Keycloak | high | high | low | AC-02, CA-01, CAN-CTRL-JML-001, RA-01 | AR-01, CAN-CTRL-JML-002 | - |
| R03 | Credential compromise | very high | medium | medium | AU-01, AU-02, CA-01, IA-02, IR-01, RA-01 | AU-03, IA-01, SC-01 | EX-01 (resolved), EX-02, EX-05, EX-07 |
| R04 | Privileged account misuse | high | medium | medium | AU-01, AU-02, CA-01, IR-01, RA-01 | AC-05 | EX-03, EX-04 |
| R05 | Expired vendor access | high | low | low | CA-01, RA-01 | VM-01 | - |

Every risk is linked to at least one asset and one control; all 18 controls have an owner and a status. **Shortfall:**
the plan asked for at least 8 risks; 5 are entered.

Proof: [`risk_register_export.csv`](risk_register_export.csv) (CISO risk assessment CSV export, `;`-separated),
risk matrix screenshot `EV-16_CISO_Dashboard_Risk_Heatmap_20261104.png`.

---

## Task 3 - HIPAA assessment and gaps

Audit *Healthcare IAM - HIPAA Security Rule Access Controls Audit* (NIST SP 800-66 rev2): **25 access-related requirements
assessed - 14 compliant, 10 partially compliant, 1 non-compliant**; all 25 have evidence attached (43 evidence items in
total). A second audit maps the controls to 15 NIST CSF 2.0 subcategories.

**Gap summary.** The one non-compliant requirement is log retention: security logs are kept 90 days, not 12 months,
because the Azure Log Analytics workspace was removed to stop charges (exception EX-02, corrective action CA-03, due
2027-01-31). The main partial gaps are leaver deprovisioning, where an Entra ID termination still does not disable the
Keycloak account automatically (CAN-FIND-001, control CAN-CTRL-JML-002, so R02 stays High); access review sign-off
not yet recorded (CA-05, due 2026-12-15); privileged users not yet enrolled in OTP (CA-13, due 2026-11-10); lab passwords
exposed in git history and not yet rotated (EX-07, CA-12, due 2026-11-10); the identity provider served over HTTP in the
lab (EX-05, CA-06); and a vendor account without sponsor or end date (CA-08, due 2026-11-10). In total 10 open gaps have
an owner and a due date and 8 exceptions are recorded (EX-01 resolved on 2026-11-05 with the Entra Security defaults
screenshot EV-17).

Proof: [`assessment_export.csv`](assessment_export.csv) (CISO audit CSV export, `;`-separated),
compliance screenshot `EV-16_CISO_Dashboard_Compliance_20261105.png`,
full exports in `../../Care_Access_Navigator/07_GRC/` (`CAN_DOC_CISO_*`). Still to capture: a screenshot of one evidence
item linked to a requirement.

---

Scope note: CISO Assistant covers governance, risk and compliance; Keycloak stays the identity lab. All data is synthetic,
and results are "mapped to HIPAA/NIST concepts", not a compliance certification.
