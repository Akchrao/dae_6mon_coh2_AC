# Incident Response 1 — Task 1: Environment Setup (simulated lab)

**Deliverable:** `Care_Access_Navigator_IR1_Task1_Environment_Setup.pdf`

A reproducible SOC/SIEM lab built with Docker Desktop only (no admin rights). A Debian 12
container (`parrot-sim`) stands in for Parrot OS on an isolated network, with centralized
logging, 3 custom Wazuh-format detection rules, Wireshark capture filters, and Volatility 3.

## Layout
- `lab/` — `Dockerfile.parrot-sim`, `run_lab.sh` (builds the host, configures tools, writes evidence)
- `wazuh-sim/` — `local_rules.xml` (3 custom rules), `detect_engine.py` (rule engine), `sample_auth.log`, `cfilters`
- `evidence/` — `transcripts/` (real command output), `pcap/`, `alerts.csv/.json`, `macos/`, `EVIDENCE-INDEX-SHA256.txt`
- `pdf-build/` — `build_task1.py`, `pdfstyle.py` (run in a container with reportlab)

## Reproduce
```
cd lab && bash run_lab.sh
docker rm -f parrot-sim && docker network rm ir1-labnet   # teardown
```

## Rebuild the PDF
```
docker run --rm -v "$PWD":/w -w /w/pdf-build python:3.11-slim-bookworm \
  sh -c "pip install -q reportlab==4.2.5 && python build_task1.py"
```

**Scope note:** this is the capstone design doc's "equivalent lightweight SIEM simulation".
See `../../docs/adr/ADR-SIEM-choice.md`. Confirm the Wazuh/Parrot/VirtualBox substitution with
the instructor in writing before final grading.
