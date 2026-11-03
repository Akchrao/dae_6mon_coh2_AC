# Incident Response 1 — Task 3: Incident Response and Containment

**Deliverable:** `Care_Access_Navigator_IR1_Task3_Containment.pdf`

Containment of IR1-2026-002 started at the live Wazuh alert. Playbook CAN-IR-PB-02 RB-02, steps C1–C8:

- **Egress block:** 49 s after the alert. 10 uploads got out, and none after the block.
- **Evidence:** the uploader's process memory, a full RAM image, and 13 file artifacts, all hash-verified.
- **Isolation:** clinical cable out, quarantine adapter in. The Wazuh agent kept reporting through a single forwarded port.
- **Probes:** every production path went REACHABLE → BLOCKED; only the forensic path opened.
- **Other incidents:** IR1-2026-001 (leaver key) and IR1-2026-003 (sudo grant) were contained in C7.

## Reproduce

This task runs as part of the shared IR1 exercise (see `../lab/README.md`):

```
bash lab/run_all.sh        # from Semester_5/Incident_Response_1/
```

Rebuild the PDF from `Semester_5/Incident_Response_1/`:

```
docker run --rm -v "$PWD":/ir -w /ir/task3_containment/pdf-build python:3.11-slim-bookworm \
  sh -c "pip install -q reportlab==4.2.5 && python build_task3.py"
```
