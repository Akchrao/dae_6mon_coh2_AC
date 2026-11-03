# Incident Response 1: the shared lab

All six IR tasks run on **one lab**, with **one cast** and **one incident register**, as a single continuous exercise.
Task 1 builds the lab. The people act on it, Wazuh detects them, and the analyst responds through Tasks 2–6.

## Cast

These are the JML people from `capstone_next_steps/jml-evidence/JML-LOG.csv`:

| Person | Account | JML event | Incident |
|---|---|---|---|
| Sathya Hasi | `test.clinician` | Joiner REQ-2026-0101 → Clinician | **IR1-2026-003**: given sudo with no change record, used root (SEV-2) |
| Tara Jones | `test.nurse` | Mover CHG-2026-0201, Nurse → Billing | **IR1-2026-002**: read patient record PT-1003 through her old clinical group and sent it off the host (SEV-1) |
| Jeevan Smith | `test.billing` | Leaver TERM-2026-0301 | **IR1-2026-001**: two SSH attempts; blocked, but his key was still on the host (SEV-3) |
| IT administrator | `it_admin` | — | made the unrecorded sudo grant |

Patient records are synthetic. The "outside" drop site is a lab container.

## Topology

The VirtualBox equivalent of each component is in brackets.

- **`ir-hv`**: the hypervisor container. It runs QEMU [VirtualBox host].
  - **`parrot-vm`** is the Debian 12 VM standing in for Parrot OS. It is built from the golden image and runs Wazuh agent 4.9.2.
  - **nic0** is the clinical NAT adapter [Adapter 1: NAT + port forwarding].
  - **nic1** is the quarantine adapter. Its cable is out until Task 3 [Adapter 2: internal network].
- **`ir-clinical`** 10.78.10.0/24: the clinical LAN, with `nurse-ws`.
- **`ir-internet`** 10.78.99.0/24: the lab "outside", with `exfil-sink`, the drop site.
- **`ir-mgmt`** 10.78.50.0/24, internal: the management network, with `wazuh-manager` (4.9.2) and `ir-forensics` (Parrot forensic workstation: Volatility 3, dc3dd, Sleuth Kit, tshark).
- **macOS host** DAEDMAC1009: user SSH sessions reach the VM on 127.0.0.1:2223. Its logs are shipped to Wazuh.

## Files

| File | Role |
|---|---|
| `build_golden.sh` | One-time. Builds the golden VM disk from the checksum-verified Debian cloud image, with the IR toolset, tshark and the Wazuh agent |
| `lab_common.sh` | Shared settings and helpers: hypervisor and guest control, hash-verified evidence pull, probes, clock skew, `ship_file` |
| `vmctl.py` | Hypervisor control over QMP and the guest agent; the lab's VBoxManage |
| `provision_vm.sh` | Sets up the JML people, the synthetic EHR, the EHR portal and the audit rules on the VM |
| `wazuh/` | Agent and manager config, decoders, `can_ir1_core_rules.xml` (Task 1's 3 rules), `can_ir1_task2_rules.xml`, and CDB lists |
| `syncd.py`, `drop_server.py`, `host_ssh_logged.py` | The scenario's uploader, the drop site, and the macOS SSH logger |
| `ir_live_response.sh`, `recover_harden.sh`, `validate_recovery.sh` | Task 4 collector, Task 6 fixes, Task 6 checklist |
| `Dockerfile.hypervisor`, `Dockerfile.forensics`, `symbols/` | Container images and the Volatility symbol table |
| `run_all.sh` | Runs the whole exercise in order |

## Run

```
bash build_golden.sh        # once (about 7 min)
bash run_all.sh             # Tasks 1 -> 2 (scenario) -> 3 -> 2 (analysis) -> 4 -> 6, then the Task 5 tracker (about 45 min)
```

Then build the PDFs. Each task's README gives the command.

Big files stay outside git, in `~/ir1-vm-lab/`: the golden image, the VM overlay with its snapshots, and the RAM and disk images. Their SHA-256 hashes are in each task's evidence index.
