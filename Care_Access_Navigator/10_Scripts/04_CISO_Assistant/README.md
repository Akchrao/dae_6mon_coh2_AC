# Load the GRC registers into CISO Assistant

Translates `../03_GRC_Build/grc_data.py` (plus `risks.csv` and the W1-W5 screenshots) into CISO Assistant records.
Matching is by ref_id / evidence name, so a rerun updates the records instead of duplicating them.

```bash
cd Care_Access_Navigator/10_Scripts/04_CISO_Assistant
python3 build_payload.py            # writes <ciso>/db/import_tmp/payload.json and copies the evidence files
touch ../../../ciso-assistant-community/db/import_tmp/DRY_RUN   # optional: roll back
docker exec -i backend sh -c 'cd /code && uv run python manage.py shell' < load_ciso.py
rm -rf ../../../ciso-assistant-community/db/import_tmp
```

Back up `db/ciso-assistant.sqlite3` first (`sqlite3 db/ciso-assistant.sqlite3 ".backup <file>"`), and stop the
stack with `docker compose down` before copying the database to another machine (a copy taken while running is
corrupt; the 2026-11-04 Windows-to-Mac transfer had to be recovered).

What it creates or updates: 7 assets, 16 applied controls (and JML-002 progress), 41 evidence items with files,
8 security exceptions (EX-08 = Tableau replaced by CISO dashboards), risks R01-R05, 25 HIPAA (NIST SP 800-66r2)
requirement results, the NIST CSF 2.0 library and a 15-subcategory CSF audit, and the corrective action tracker
(CA-01..CA-18 as findings). Exports in `07_GRC` were pulled from the CISO API afterwards.
