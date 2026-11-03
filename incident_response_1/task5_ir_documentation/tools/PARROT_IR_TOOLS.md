# Parrot OS Incident Response Tools: Usage Guide

Document CAN-IR-TOOLS-01, version 1.0, 2026-11-02. Every command below was run during IR1 Tasks 1-6 on case IR1-2026-002
(transcripts are cited). All tools are in Parrot OS Security, or in Debian 12 for the lab stand-in, unless marked otherwise.
**Run as root only where stated.** Where a command changes the system, the caution column says so.

## 1. Live response: system state, processes, network

| Tool | Package | What it answers | Command used in this case | Cautions |
|---|---|---|---|---|
| `date`, `timedatectl` | coreutils, systemd | Is the host clock right? Every other timestamp depends on it | `date -u; timedatectl` (Task 4 live response 01) | Compare with a trusted clock: the contained VM was 75 min slow |
| `uptime`, `who`, `w`, `last` | procps, util-linux | Who is or was logged in, since when | `who -a; w; last -F -n 30` | `last` reads `/var/log/wtmp`; an attacker can edit it, so cross-check with auth.log |
| `ps` | procps | Running processes and their parents | `ps -eo pid,ppid,user,uid,lstart,etime,stat,args --forest` | A rootkit can hide from ps; confirm with Volatility `linux.pslist` |
| `/proc/<pid>/*` | kernel | Exact command line, environment, binary, open files of one process | `tr '\0' ' ' < /proc/1534/cmdline`; `tr '\0' '\n' < /proc/1534/environ`; `ls -l /proc/1534/fd` | `environ` showed `SSH_CONNECTION`, which tied the uploader to the SSH session |
| `lsof` | lsof | Which process has which file or socket open | `lsof -nP -i`; `lsof -nP` | `-n -P`: no DNS or port-name lookups (faster, no network noise) |
| `ss` | iproute2 | Open and listening sockets, with the owning process | `ss -tunap`; `ss -ltnp` | Short-lived connections can be missed; sample in a loop or use tcpdump |
| `ip` | iproute2 | Interfaces, addresses, routes, ARP | `ip -br link; ip -br addr; ip route; ip neigh` | Also used to change config in containment (`ip link set <if> down`) |
| `iptables` | iptables | Firewall rules and hit counters | `iptables-save`; `iptables -vnL` | Counters prove a rule is matching traffic |
| `systemctl` | systemd | Services, timers, persistence | `systemctl list-units --type=service --all`; `systemctl list-timers --all` | |
| `crontab`, `/var/spool/cron` | cron | Scheduled persistence | `crontab -l -u test.nurse`; `ls -la /var/spool/cron/crontabs` | Found the attacker's `*/5` restart job |
| `find` | findutils | Recently changed, hidden or SUID files | `find /home /tmp /etc /var/spool -xdev -newermt "-3 hours" -type f -printf ...` | Reading files changes atime; collect `stat` first |
| `ir_live_response.sh` | this project | All of the above, in order of volatility, output to RAM, each output hashed | `ssh ir-analyst@host 'sudo sh -s' < ir_live_response.sh` | Writes only to `/dev/shm`; pull with `sudo tar -C /dev/shm/lr -cf - .` |

## 2. Network capture and analysis

| Tool | Package | What it answers | Command used in this case | Cautions |
|---|---|---|---|---|
| `tcpdump` | tcpdump | Packets on one interface, with a BPF filter | `timeout 25 tcpdump -i enp0s1 -nn -s0 -U -w /dev/shm/IR1-2026-002_live.pcap host 10.78.99.66` | Capture to RAM or a remote host, never to the suspect disk |
| `tshark` / Wireshark | tshark, wireshark | Protocol decode, filters, statistics | `tshark -r nic0.pcap -Y 'http.request.method==POST && ip.dst==10.78.99.66' -T fields -e frame.time_epoch` ; `tshark -q -z conv,tcp` | Wireshark capture filters (Task 1): `tcp port 22`, `host <ip>` |
| `dumpcap` + saved capture filters | wireshark-common | Which capture filters the analyst uses; are they valid BPF? | `~/.config/wireshark/cfilters` (7 named filters, Task 1); `dumpcap -i enp0s1 -f '<filter>' -d` compiles each | Wireshark GUI and tshark both read this file; a filter that does not compile fails here, not mid-incident |
| `capinfos` | wireshark-common | Packet count, first and last time of a capture | `capinfos -c -a -e file.pcap` | Use it to state the capture window in the report |
| NIC trace (hypervisor) | VirtualBox / QEMU | Traffic seen by the virtual NIC, outside the guest's control | VirtualBox `--nictrace1 on`; lab: QEMU `-object filter-dump,netdev=n0,file=nic0.pcap` | Cannot be tampered with from inside the guest |

## 3. Memory

| Tool | Package | What it answers | Command used in this case | Cautions |
|---|---|---|---|---|
| `gcore` | gdb | Memory image of one process | `gcore -o /dev/shm/syncd 1534` | Briefly pauses the process; run before killing it |
| VM memory dump | VirtualBox / QEMU | Full RAM of the guest, no guest tools needed | VirtualBox `debugvm <vm> dumpvmcore`; lab: QMP `dump-guest-memory` | 1 GiB per 1 GiB RAM; keep outside git |
| Volatility 3 | pip `volatility3` (2.7.0) | Processes, sockets, files, kernel integrity from a RAM image | `vol -s /opt/symbols -f mem.elf linux.pslist.PsList` (also `pstree`, `psaux`, `envars --pid`, `lsof --pid`, `sockstat`, `proc.Maps --pid --dump`, `bash`, `lsmod`, `check_modules`, `check_syscall`, `malfind`, `kmsg`) | Needs a symbol table for the **exact** kernel. Fails on 5-level paging (use `-cpu max,la57=off` / normal VirtualBox CPU) |
| `dwarf2json` | Volatility Foundation (Go) | Builds that symbol table (ISF) from a debug kernel | `dwarf2json linux --elf vmlinux-6.1.0-54-cloud-amd64 > isf.json; xz isf.json` | Debug kernel from `linux-image-<ver>-dbg` |

## 4. Disk acquisition and file-system analysis

| Tool | Package | What it answers | Command used in this case | Cautions |
|---|---|---|---|---|
| Disk seizure (hypervisor) | VirtualBox / qemu-utils | Exact disk content at a snapshot | VirtualBox `clonemedium disk <vdi> case.raw --format RAW`; lab: `qemu-img convert -U -l snapshot.name=ir-contained -O raw` | Seize from a snapshot, not the live disk |
| `dc3dd` | dc3dd | Forensic image with built-in hashing and a log | `dc3dd if=/seized/case.raw of=/bigev/case_vda.dd hash=sha256 log=dc3dd_acquisition.log` | Needs a real output file; it will not write to a pipe or FIFO. Attach the source read-only |
| `dcfldd`, `ewfacquire` | dcfldd, ewf-tools | Alternatives: stream to stdout (dcfldd), compressed E01 with case metadata (ewfacquire) | `ewfacquire -t case -f encase6 /dev/sdX` | E01 is the court-standard container; raw was used here for simplicity |
| `mmls` | sleuthkit | Partition layout and offsets | `mmls case_vda.dd` (root fs at sector 262144) | |
| `fsstat` | sleuthkit | File-system type, last mount, journal | `fsstat -o 262144 case_vda.dd` | |
| `fls` | sleuthkit | File listing, including deleted entries; body file for timelines | `fls -r -p -o 262144 case_vda.dd`; `fls -r -m / -o 262144 case_vda.dd > body` | Deleted entries are marked `*` |
| `ifind`, `icat`, `istat` | sleuthkit | Path to inode, file content, inode metadata (MAC + birth times) | `ifind -n /var/log/auth.log -o 262144 img`; `icat -o 262144 img 32027 \| sha256sum`; `istat -o 262144 img 32027` | Read-only on the image |
| `mactime` | sleuthkit | Body file to a sorted MAC timeline | `mactime -b body -z UTC -d -y 2026-11-02` | `-y` = ISO dates; blank date means "same as row above" |
| `sha256sum` | coreutils | Integrity of every item, at every hand-off | `sha256sum file`; `shasum -a 256 -c index.txt` (macOS) | Hash at the source and at the destination |

## 5. Logs and auditing

| Tool | Package | What it answers | Command used in this case | Cautions |
|---|---|---|---|---|
| `auditd` / `auditctl` | auditd | Kernel-level record of file reads, identity changes, every command a user runs | `auditctl -w /srv/ehr/clinical -p r -k ehr-read`; `-a always,exit -F arch=b64 -S execve -F auid>=1000 -k user-exec` | Serial numbers restart each boot: join records on time + serial |
| `ausearch` | auditd | Query the audit log | `ausearch -k ehr-read -i`; `ausearch -ua 1003 -i` | `-i` turns uids and syscalls into names |
| rsyslog / `journalctl` | rsyslog, systemd | auth.log, kern.log, application logs | `journalctl -u ssh`; `grep IR-BLOCK /var/log/kern.log` | sshd `LogLevel VERBOSE` logs key fingerprints for cross-host correlation |
| Wazuh manager + agent | wazuh-manager 4.9.2, wazuh-agent 4.9.2 | Central collection, detection (custom rules 100210-100253), FIM, alerting (Tasks 1-6) | `agent_control -l` / `-i 001`; `wazuh-logtest -v`; `grep '"id":"100221"' alerts.json` | The agent on parrot-vm kept reporting during quarantine through one forwarded port (Task 3 C6e). A macOS agent needs admin rights, so Mac logs were shipped as files (`ship_file`, which restarts logcollector if it dies under emulation) |
| `build_timeline.py` | this project | Super-timeline from macOS and Parrot sources, in UTC | `python3 analysis/build_timeline.py` | Normalise every source to UTC first |

## 6. Containment and recovery

| Tool | Package | What it does | Command used in this case | Cautions |
|---|---|---|---|---|
| `iptables` | iptables | Block, log and isolate | `iptables -I OUTPUT 1 -d 10.78.99.66 -j IR-EGRESS-BLOCK`; `iptables -P INPUT DROP` | Apply over an out-of-band channel (console or guestcontrol) so a mistake cannot lock you out |
| `usermod`, `gpasswd`, `passwd`, `chage` | passwd | Lock accounts, remove groups, check status | `usermod -L -e 1 test.nurse`; `gpasswd -d test.nurse clinical`; `passwd -S`; `chage -l` | `passwd -S` shows `L` for an account with no password, but **SSH keys still work**. Expire the account (`-e 1`) and remove its keys |
| `pkill`, `systemctl` | procps, systemd | Kill processes; stop, mask or disable services | `pkill -KILL -u test.nurse`; `systemctl stop cron && systemctl mask cron` | Kill only after memory is preserved |
| `dpkg -V` | dpkg | Were packaged binaries modified? | `dpkg -V \| awk '$2 != "c"'` | Built into Debian and Parrot; no extra install |
| VBoxManage | VirtualBox | Snapshots, link state, NIC network, guest control | `snapshot take/restore`, `controlvm setlinkstate1 off`, `guestcontrol run` (lab: `vmctl.py`) | Snapshot before every irreversible step |
| `irtrack.py` | this project | Incident records, status, actions, timeline, evidence | `irtrack.py list`; `irtrack.py report IR1-2026-002` | Status only moves forward; every change is time-stamped |

## 7. Which procedure uses which tools

| Procedure (playbook) | Tools |
|---|---|
| Triage (section 2) | date, ausearch, ss, ps, tcpdump |
| RB-02 C2 preserve volatile data | tcpdump, ps, ss, lsof, /proc, crontab |
| RB-02 C3 / C6 block and isolate | iptables, ip, VBoxManage setlinkstate |
| RB-02 C4 memory | gcore, VBoxManage debugvm dumpvmcore |
| RB-02 C5 files / section 4 evidence | stat, cp -a, sha256sum, tar, ssh |
| Disk acquisition | VBoxManage clonemedium, dc3dd, sha256sum |
| Analysis | Volatility 3, Sleuth Kit, mactime, tshark, build_timeline.py |
| Recovery | VBoxManage snapshot restore, usermod, gpasswd, iptables-restore, systemctl, dpkg -V, validate_recovery.sh |
