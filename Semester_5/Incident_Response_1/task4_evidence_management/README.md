# Incident Response 1 — Task 4: Digital Evidence Management

**Deliverable:** `Care_Access_Navigator_IR1_Task4_Evidence_Management.pdf`

- **Live response:** 24 commands, output to RAM only, each output hashed.
- **Volatility 3:** the uploader (PID 1534) found with its SSH session origin, a SYN_SENT socket to the drop site, and the record in its heap. No rootkit indicators.
- **Disk acquisition:** seized at the hypervisor, imaged with dc3dd from a read-only source; hashes equal. Sleuth Kit recovered the planted files byte-identical.
- **Chain of custody:** 13 items, 54 custody events.
- **Super-timeline:** macOS and Parrot sources merged; 18/18 key events; 7/7 Mac SSH sessions matched by key fingerprint.

The analysis scripts are in `analysis/`. The disk images are outside git, in `~/ir1-vm-lab/evidence/IR1-2026-002/`.

## Reproduce

This task runs as part of the shared IR1 exercise (see `../lab/README.md`):

```
bash lab/run_all.sh        # from Semester_5/Incident_Response_1/
```

Rebuild the PDF from `Semester_5/Incident_Response_1/`:

```
docker run --rm -v "$PWD":/ir -w /ir/task4_evidence_management/pdf-build python:3.11-slim-bookworm \
  sh -c "pip install -q reportlab==4.2.5 && python build_task4.py"
```
