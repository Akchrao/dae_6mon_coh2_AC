# Incident Response 1 — Task 2: Incident Detection and Analysis

**Deliverable:** `Care_Access_Navigator_IR1_Task2_Log_Analysis.pdf`

The JML people act from the Mac, and Wazuh analyses the Parrot OS (agent) and macOS logs.

- **Alerts:** 1,683 in total: 268 from Parrot and 1,225 from macOS.
- **Suspicious login, IR1-2026-001 (Jeevan Smith, leaver):** both attempts correlated across the Mac SSH client, the packet capture, sshd and Wazuh.
- **Classification with the severity matrix:**
  - IR1-2026-002 (Tara Jones): SEV-1
  - IR1-2026-003 (Sathya Hasi): SEV-2
  - IR1-2026-001 (Jeevan Smith): SEV-3
- **Containment trigger:** Wazuh rule 100221 for IR1-2026-002 fired 1.3 s after the record was read, and its alert started Task 3.

`run_task2.sh scenario` runs before Task 3. `run_task2.sh analysis` runs after it. The analysis code is `analysis/analyze.py`.

## Reproduce

This task runs as part of the shared IR1 exercise (see `../lab/README.md`):

```
bash lab/run_all.sh        # from incident_response_1/
```

Rebuild the PDF from `incident_response_1/`:

```
docker run --rm -v "$PWD":/ir -w /ir/task2_log_analysis/pdf-build python:3.11-slim-bookworm \
  sh -c "pip install -q reportlab==4.2.5 && python build_task2.py"
```
