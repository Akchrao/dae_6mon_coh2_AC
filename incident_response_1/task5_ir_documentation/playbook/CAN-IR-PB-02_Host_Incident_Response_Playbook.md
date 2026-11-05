# Care Access Navigator: Host Incident Response Playbook (Parrot OS / Linux)

| Field | Value |
|---|---|
| Document ID | CAN-IR-PB-02, version 2.0 |
| Owner | Akhila Chennamaneni, IR analyst |
| Date | 2026-11-02 (tested end to end on IR1-2026-002) |
| Applies to | Linux hosts at HealthLine Regional Medical Center (HRMC) (lab): the parrot-vm EHR host, the Parrot OS analyst workstation, and any Debian-family server, virtualised under VirtualBox (lab: QEMU) |
| Companion | CAN-IR-PB-01, the Cloud IR Playbook (`cloud_security_1/can-secops/IR-Playbook.md`), which covers Azure |
| Basis | NIST SP 800-61r2 (lifecycle), NIST SP 800-86 and RFC 3227 (evidence), HIPAA Security Rule §164.308(a)(6) and the Breach Notification Rule §164.400-414 |

## 0. Severity, roles and records

Severity is **Impact x Urgency** (each 1-3), as used in IR1 Task 2:

| Score | Severity | Start response | Escalate to | Examples |
|---|---|---|---|---|
| 9 | **SEV-1 Critical** | 15 min | Incident Commander + Privacy Officer (HIPAA breach risk assessment; 60-day notice clock) | ePHI leaving a host; ePHI read through a role the user should not have |
| 6 | **SEV-2 High** | 1 hour | Security lead, IAM owner | Unapproved root/sudo grant; confirmed account takeover without data access |
| 3-4 | **SEV-3 Medium** | 1 business day | SecOps on-call | Blocked attempts by a leaver; blocked brute force |
| 1-2 | **SEV-4 Low** | Next review | (none) | Single failed login; informational alert |

| Role | Responsibility |
|---|---|
| Incident Commander (IC) | Declares severity, authorises containment that affects service, owns communications |
| IR analyst (responder) | Runs this playbook, records every command, owns evidence and chain of custody |
| System owner (it_admin) | Is told before isolation or service shutdown; leads recovery |
| IAM owner | Applies identity changes (JML corrections, disables, key removal) in Entra ID, Keycloak and on hosts |
| Privacy Officer | Runs the HIPAA four-factor breach risk assessment and notifications |

Every incident gets an ID `IR1-YYYY-NNN` and a record in the tracker (`tracker/irtrack.py new ...`). Record status changes,
actions and evidence there as you go, not afterwards.

## 1. Lifecycle at a glance

| Phase | Goal | Key actions | Main tools |
|---|---|---|---|
| Detect | Know something is wrong | Wazuh alert, user report, audit finding | Wazuh, ehr-audit.log, auditd |
| Triage | Real? How bad? | Validate the alert on the host; set severity; open the tracker record | ausearch, ss, ps, tcpdump |
| Contain | Stop the harm, keep the evidence | Snapshot, preserve volatile data, block, isolate, shut down | VBoxManage, iptables, ip, systemctl |
| Preserve | Evidence that holds up | Order of volatility, hash at both ends, chain of custody | tcpdump, gcore, dc3dd, sha256sum |
| Analyse | What happened, how, who | Memory, disk, logs, timeline | Volatility 3, Sleuth Kit, mactime, timeline script |
| Eradicate | Remove the cause and the artifacts | Restore clean state; fix the root cause | VBoxManage snapshot, usermod, gpasswd |
| Recover | Service back, proven safe | Network and services back; validation checklist, twice | validate_recovery.sh |
| Learn | Do better next time | RCA, report, playbook update | tracker report, this playbook |

## 2. First 15 minutes (any incident)

1. Open the tracker record: `irtrack.py new IR1-2026-NNN --title ... --severity SEV-n --detected <UTC> --source <alert> ...`
2. Note the time on the suspect host against a trusted clock (`date -u` on both) before reading any timestamp.
3. Validate the alert on the host: read the raw log line that fired it. Do not trust the alert text alone.
4. Set severity with the matrix in section 0. For SEV-1 or SEV-2, page the IC now.
5. Decide whether data is leaving or harm is ongoing. If yes, go straight to RB-02 steps C1-C3.
6. Do **not** reboot, shut down, or run cleanup on the suspect host: memory and live connections are evidence.

## 3. Runbooks for common incidents

### RB-01 Unauthorized ePHI access (stale or excessive privilege)

| Item | Detail |
|---|---|
| Trigger | Wazuh 100221 (mover views ePHI), ehr-audit `decision=ALLOW` by a user whose JML role no longer allows it, auditd key `ehr-read` |
| Default severity | SEV-1 if a record was read; SEV-2 if only attempted |
| Contain | Remove the stale group (`gpasswd -d <user> clinical`); lock the account if intent is unclear (`usermod -L -e 1 <user>`); revoke IdP sessions in Keycloak/Entra |
| Collect | `ehr-audit.log`, `ausearch -k ehr-read -i`, `id <user>`, `/etc/group`, the JML ticket (JML-LOG.csv), all with SHA-256 |
| Check | Was the record copied or sent anywhere? Look for new files (`find /home -newermt`), outbound connections (`ss -tnp`), a running process. If yes, go to RB-02 |
| Eradicate / recover | Fix the JML step that left the group behind; re-run the access review for all movers |
| Notify | Privacy Officer: four-factor breach risk assessment |

### RB-02 Data exfiltration in progress (tested on IR1-2026-002)

Run steps C1-C8 in this order. Each step is reversible until C7.

| Step | Action | Commands (Parrot OS / VirtualBox) |
|---|---|---|
| C1 | Live snapshot, the undo point | `VBoxManage snapshot <vm> take ir-pre-containment --live` |
| C2 | Preserve volatile data: packets, processes, connections, persistence | `timeout 25 tcpdump -i <if> -w /dev/shm/live.pcap host <IOC>`; `ps -eo pid,ppid,user,lstart,cmd --forest`; `ss -tunap`; `lsof -nP -i`; `cat /proc/<pid>/{cmdline,environ}`; `crontab -l -u <user>` |
| C3 | **Block the traffic** and keep the process alive | `iptables -N IR-EGRESS-BLOCK`; `iptables -A IR-EGRESS-BLOCK -j LOG --log-prefix "IR-BLOCK " --log-uid`; `iptables -A IR-EGRESS-BLOCK -j DROP`; `iptables -I OUTPUT 1 -d <IOC> -j IR-EGRESS-BLOCK` |
| C4 | Preserve memory: process core and full RAM | `gcore -o /dev/shm/proc <pid>`; `VBoxManage debugvm <vm> dumpvmcore --filename=<case>.elf` |
| C5 | Preserve file-system artifacts | `stat` first, then `cp -a --parents <files> /dev/shm/art`, `sha256sum`, `tar -C /dev/shm/art -cf - . \| ssh forensic 'cat > art.tar'` |
| C6 | **Isolate the host**: cable out, quarantine adapter in, default-deny firewall | `VBoxManage controlvm <vm> setlinkstate1 off`; `VBoxManage controlvm <vm> setlinkstate2 on` (adapter 2 on internal network `quarantine`); `ip link set <if0> down`; `ip addr add <q-ip>/24 dev <if1>`; `iptables -P INPUT DROP; iptables -P OUTPUT DROP; iptables -A INPUT -i <if1> -s <forensic-ws> -p tcp --dport 22 -j ACCEPT` |
| C7 | **Shut down** the process, persistence, exposed services; lock the account | `pkill -KILL -f <proc>`; `systemctl stop cron && systemctl mask cron`; `systemctl stop <svc> && systemctl disable <svc>`; `usermod -L -e 1 <user>`; `gpasswd -d <user> clinical`; move `authorized_keys` to `/root/ir-quarantine/` |
| C8 | Verify with the same probes as before; snapshot | re-run the reachability probes; `VBoxManage snapshot <vm> take ir-contained --live` |

If the transfer is large or ongoing, the IC may order **C3 before C2**: block first, capture after.

### RB-03 Brute force and credential compromise

| Item | Detail |
|---|---|
| Trigger | Wazuh 5710/5712/5760 (sshd failures), 100101 (brute force), 100102 (success after failures), 100110 (privilege escalation after login) |
| Default severity | SEV-3 if all attempts failed; **SEV-1/2 if a login succeeded** after failures |
| Contain | Block the source IP (`iptables -I INPUT -s <ip> -j DROP`); if a login succeeded: lock the account, kill its sessions (`pkill -KILL -u <user>`), rotate its credentials and keys |
| Collect | `auth.log`, `last -F`, `lastb -F`, `journalctl -u ssh`, sshd `LogLevel VERBOSE` key fingerprints, Wazuh alerts.json |
| Check | What did the session do? `ausearch -ua <uid> -i`, bash history, new files, cron, keys |
| Eradicate / recover | Enforce key-only SSH, MFA at the IdP, lockout (Keycloak `bruteForceProtected=true`, finding F-02) |

### RB-04 Leaver or disabled account activity

| Item | Detail |
|---|---|
| Trigger | Wazuh 100210/100211 (CDB list `jml-leavers`), IdP sign-in by a disabled user |
| Default severity | SEV-3 if blocked; SEV-2 if any access succeeded |
| Contain | Confirm the account is disabled everywhere: Entra ID, Keycloak and **local hosts** (`passwd -S`, `chage -l`, DenyGroups) |
| Collect | Correlate the client log with the server log by time and SSH key fingerprint (IR1 Task 2 §6, Task 4 §7.2) |
| Eradicate | Remove standing credentials on every host: `authorized_keys`, local passwords, sudoers entries |
| Lesson (IR1-2026-001) | Disabling at the IdP does not remove host SSH keys. The leaver step must include host keys |

### RB-05 Unauthorized privilege escalation

| Item | Detail |
|---|---|
| Trigger | Wazuh 100230 (added to sudo/adm), 100231 (root by a role with no root entitlement), auditd key `sudoers` |
| Default severity | SEV-2 |
| Contain | `gpasswd -d <user> sudo`; remove any `/etc/sudoers.d/` file not backed by a change record |
| Collect | `auth.log` (usermod, sudo COMMAND=), `getent group sudo`, `/etc/sudoers.d/*`, the change ticket (or its absence) |
| Rule (IR1-2026-003) | Every sudo grant needs a change record and an expiry. Grants without one are removed first and justified after |

### RB-06 Malware or persistence on a host

| Item | Detail |
|---|---|
| Trigger | auditd `cron-persist`/`user-exec`, unknown process with network activity, new systemd unit, new SSH key |
| Default severity | SEV-2; SEV-1 if ePHI is reachable from the account |
| Contain | RB-02 C1-C4 first (memory before kill); then C6 |
| Collect | Process core, RAM image, `crontab -l` for every user, `systemctl list-unit-files`, `find / -newermt`, SUID list, `/proc/<pid>/exe` hash |
| Analyse | Volatility 3: `linux.pslist`, `linux.psaux`, `linux.malfind`, `linux.check_modules`, `linux.check_syscall`, `linux.sockstat` |
| Eradicate | Restore from a known-good snapshot or golden image; do not "clean" a compromised host in place |

## 4. Evidence collection procedure (all incidents)

1. **Clock first.** Record host UTC against a trusted clock.
2. **Order of volatility.** Memory and network state, then processes, then logs, then disk.
3. **Do not write to the suspect disk.** Use `/dev/shm` or stream over SSH to the forensic workstation.
4. **Hash at both ends.** `sha256sum` on the source, then on the copy; record both.
5. **Freeze live logs** before hashing them (`cp -a` to RAM), or the hash will not match the copy.
6. **Write-block disks.** Seize the virtual disk from a snapshot at the hypervisor (`VBoxManage clonemedium disk <vdi> case.raw --format RAW`), attach it read-only, image it with `dc3dd hash=sha256 log=...`.
7. **Chain of custody.** Give each item an ID (E01, E02, ...) and log every acquire, transfer, store, verify and examine event with a hash check (`chain_of_custody.py`).
8. **Store and restrict.** Keep the case folder on an encrypted volume and set images read-only. Never put real ePHI in a code repository.

## 5. Host isolation in VirtualBox

| Need | VirtualBox | Inside Parrot OS |
|---|---|---|
| Undo point before changes | `VBoxManage snapshot <vm> take <name> --live` | (none) |
| Pull the network cable | `VBoxManage controlvm <vm> setlinkstate1 off` | `ip link set <if> down` |
| Move to a quarantine segment | `VBoxManage controlvm <vm> nic2 intnet quarantine` then `setlinkstate2 on` | `ip addr add`, `ip route replace default via` |
| Capture traffic outside the guest | `VBoxManage modifyvm <vm> --nictrace1 on --nictracefile1 nic1.pcap` (VM off) | `tcpdump -i <if> -w file.pcap` |
| Memory without guest tools | `VBoxManage debugvm <vm> dumpvmcore --filename=<case>.elf` | `gcore <pid>` for one process |
| Run commands with the network cut | `VBoxManage guestcontrol <vm> run --exe /bin/sh -- -c '<cmd>'` | (none) |

## 6. Recovery and validation

Restore, do not clean. Revert to the last known-good snapshot (`VBoxManage snapshot <vm> restore baseline-clean`) or rebuild
from the golden image (verify its hash first). Then **fix the root cause on the restored system**, because the baseline usually still contains it.
Validate with the checklist (`validate_recovery.sh`, 31 checks), reboot, and validate again. Take a new snapshot
`recovered-validated`. Full procedure: IR1 Task 6.

## 7. Communication and notification

| When | Who | What |
|---|---|---|
| SEV-1 declared | IC, Privacy Officer, system owner | Short facts: what, when, systems, data at risk, actions under way |
| Every 30 min during SEV-1 | IC to leadership | Status, next step, decisions needed |
| ePHI involved | Privacy Officer | Four-factor risk assessment (§164.402): nature/extent of PHI, who received it, whether it was actually acquired or viewed, mitigation. Notify individuals within 60 days of discovery unless low probability of compromise is shown. Under 500 individuals: HHS log within 60 days of year end |
| Closed | IC | Incident report (tracker record plus report), lessons learned, playbook changes |

## 8. Tracking and reporting

```
irtrack.py new IR1-2026-007 --title "..." --type "..." --severity SEV-2 --detected 2026-11-03T10:00:00Z --source "Wazuh 100231" --handler "..." --summary "..."
irtrack.py status IR1-2026-007 Triage --at 2026-11-03T10:04:00Z --note "validated on host"
irtrack.py action IR1-2026-007 --at ... --phase Containment --by "..." --what "gpasswd -d user sudo" --result "removed"
irtrack.py event  IR1-2026-007 --at ... --host parrot-vm --source auth.log --what "usermod -aG sudo by it_admin"
irtrack.py evidence IR1-2026-007 --item E01 --desc "auth.log" --sha256 ... --location ...
irtrack.py list ; irtrack.py report IR1-2026-007 ; irtrack.py export incidents_register.csv
```

## 9. Maintenance

Review this playbook after every SEV-1 or SEV-2 and at least every 6 months. Change log:

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-10-08 | Cloud playbook CAN-IR-PB-01 (Azure) |
| 2.0 | 2026-11-02 | Host playbook: RB-01..06, evidence procedure, VirtualBox isolation, recovery; tested on IR1-2026-002; lessons from IR1-2026-001/005/006 added |
