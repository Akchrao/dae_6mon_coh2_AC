# Incident Response 1 — Task 1: IR Environment Setup

**Deliverable:** `Care_Access_Navigator_IR1_Task1_Environment_Setup.pdf`

Builds the shared lab used by all six tasks (`../lab/`). The JML people (Sathya Hasi, Tara Jones, Jeevan Smith) are set up on parrot-vm.

| Rubric item | Result |
|---|---|
| Wazuh installed and configured | Wazuh manager 4.9.2 running; the Parrot OS host is a VM under a hypervisor (VirtualBox stand-in) |
| Agent deployment | Wazuh agent 4.9.2 installed on parrot-vm, enrolled as agent 001, status Active |
| Log collection from Parrot OS | auth, kernel, EHR-audit and auditd logs collected, plus real-time FIM |
| 3 custom alert rules | 100210 (leaver), 100221 (mover viewing ePHI), 100231 (root without entitlement); 6/6 positive and negative tests pass |
| Wireshark capture filters | 7 saved filters, all compiled with `dumpcap -d`; one live capture |
| Volatility | Symbol table for the exact kernel; baseline RAM image walked (82 processes) |
| Parrot OS and macOS logs ingested | Agent test line received; macOS sample 500 lines sent, 500 received |

Evidence is in `evidence/`, with hashes in `EVIDENCE-INDEX-SHA256.txt`. The baseline RAM image is outside git, in `~/ir1-vm-lab/evidence/baseline/`.

## Reproduce

This task runs as part of the shared IR1 exercise (see `../lab/README.md`):

```
bash lab/run_all.sh        # from incident_response_1/
```

Rebuild the PDF from `incident_response_1/`:

```
docker run --rm -v "$PWD":/ir -w /ir/task1_environment_setup/pdf-build python:3.11-slim-bookworm \
  sh -c "pip install -q reportlab==4.2.5 && python build_task1.py"
```
