# Incident Response 1 — Task 5: IR Documentation & Reporting

**Deliverable:** `Care_Access_Navigator_IR1_Task5_Documentation_Reporting.pdf` (23 pages)

| Rubric item | Artifact |
|---|---|
| IR playbook: procedures for common incidents, Parrot OS commands, evidence steps | `playbook/CAN-IR-PB-02_Host_Incident_Response_Playbook.md`. Runbooks RB-01 to RB-06, a first-15-minutes checklist, the evidence procedure, VirtualBox isolation, recovery, and HIPAA notification |
| Incident tracking system (implemented) | `tracker/irtrack.py`: SQLite and a CLI (standard library only). It enforces a forward-only status workflow, measures response times against severity targets, and stores actions, timeline and evidence. `tracker/load_cases.py` rebuilds `incidents.db` from the Task 1–6 evidence. Outputs: `incidents_register.csv` and `IR1-2026-002_record.md` |
| Complete incident report, standard format | PDF §4: the IR1-2026-002 report in NIST SP 800-61r2 layout, including the HIPAA four-factor breach risk assessment |
| IR tools and procedures in Parrot OS | `tools/PARROT_IR_TOOLS.md`. Every tool used in Tasks 1–6, each with its exact command and cautions |

The playbook and tools guide are written in Markdown, and the PDF is rendered from those files (`pdf-build/mdpdf.py`).

## Tracker quick start

```
cd tracker
python3 irtrack.py list
python3 irtrack.py report IR1-2026-002
python3 irtrack.py export incidents_register.csv
python3 load_cases.py      # rebuild the database from the evidence
```

`incidents_register.csv` keeps the columns of `Care_Access_Navigator/08_Reporting/02_Dashboards/Tableau_Dataset/incidents.csv` and adds response metrics. It is ready to replace that file. The old file lists IR1 incidents as resolved before any response had been run.

## Rebuild the PDF

Run from `incident_response_1/`:

```
docker run --rm -v "$PWD":/ir -w /ir/task5_ir_documentation/pdf-build python:3.11-slim-bookworm \
  sh -c "pip install -q reportlab==4.2.5 && python build_task5.py"
```
