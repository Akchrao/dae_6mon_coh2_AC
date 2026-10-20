# Incident Response 1 — Task 2: Log Analysis and Incident Classification with Wazuh

**Deliverable:** `Care_Access_Navigator_IR1_Task2_Log_Analysis.pdf`

This task uses a real Wazuh 4.9.2 manager, run in Docker with no admin rights. Two hosts feed it:

- **Parrot OS:** `parrot-sim`, a Debian 12 stand-in. It sends its logs to the manager live over syslog.
- **macOS:** DAEDMAC1009. Its real `/var/log/install.log` and an SSH-client trail captured on the Mac are shipped as `localfile` inputs.

The scenario uses the people from the Entra ID / Keycloak JML cycle (`capstone_next_steps/jml-evidence/JML-LOG.csv`).

| Incident | Person | What happened | Severity |
|---|---|---|---|
| IR1-2026-004 (investigated) | Jeevan Smith, `test.billing`, leaver | 2 SSH attempts from the Mac. Blocked by DenyGroups, but the leaver's key was still authorized | SEV-3 Medium |
| IR1-2026-005 | Tara Jones, `test.nurse`, mover Nurse→Billing | Viewed synthetic record PT-1003 through a clinical group that was never removed; then tried sudo | SEV-1 Critical |
| IR1-2026-006 | Sathya Hasi, `test.clinician`, joiner | Added to `sudo` by it_admin with no change record; then used root | SEV-2 High |

## Layout
- `lab/`: `run_lab.sh` runs everything. `host_ssh_logged.py` is the macOS SSH-client logger. `ehr-view` is the EHR audit stub. `Dockerfile.parrot-sim` builds the Parrot stand-in. `.keys/` holds the lab-only SSH key (git-ignored).
- `wazuh/`: the manager configuration.
  - `local_decoder.xml` and `local_rules.xml`: the custom decoders and rules.
  - `lists/`: CDB lists that mirror the JML register.
  - `ossec-task2.conf` and `configure_manager.sh`: install the above on the manager.
- `analysis/`: `normalize_macos_log.py` converts install.log timestamps to ISO 8601. `analyze.py` builds the correlation, timeline and summary tables.
- `evidence/`:
  - `wazuh/`: `alerts.json` and `ossec.conf` from the manager.
  - `parrot/`: `auth.log` and `ehr-audit.log`.
  - `macos/`: the raw and normalised install.log, plus `ssh_client.log`.
  - `pcap/`: the packet capture and client banners.
  - `analysis/`: the CSV and JSON output of `analyze.py`.
  - `transcripts/`: steps 01–11 of the run.
  - `EVIDENCE-INDEX-SHA256.txt`: hashes of all of the above.
- `pdf-build/`: `build_task2.py` and `pdfstyle.py`, the same house style as Task 1.

## Reproduce
```
cd lab && bash run_lab.sh          # ~8 min. Leaves the containers running for extra checks.
docker rm -f parrot-sim wazuh-manager && docker network rm ir2-labnet   # teardown
```
Transcripts 10 and 11 (validation checks) were captured from the live lab after `run_lab.sh` finished.

## Rebuild the PDF
```
docker run --rm -v "$PWD":/w -w /w/pdf-build python:3.11-slim-bookworm \
  sh -c "pip install -q reportlab==4.2.5 && python build_task2.py"
```

**Scope note:** the Wazuh manager is real. The substitutions are:
- Parrot OS is replaced by a Docker Debian container.
- There is no dashboard or indexer.
- The macOS logs are shipped as files, because a macOS agent needs admin rights.

Confirm these substitutions with the instructor, as for Task 1 (`../../docs/adr/ADR-SIEM-choice.md`).

The severity matrix (Impact × Urgency → SEV-1–4) follows the CAN IR playbook §0. If the course taught a different matrix, re-map the scores in §7.
