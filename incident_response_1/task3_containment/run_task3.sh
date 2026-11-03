#!/usr/bin/env bash
# =============================================================================
# Care Access Navigator - Incident Response 1, Task 3: Incident Response and Containment
# -----------------------------------------------------------------------------
# Starts the moment Task 2's scenario phase sees Wazuh rule 100221 fire (IR1-2026-002, SEV-1: Tara Jones, mover, is
# sending synthetic record PT-1003 off the host). Runs containment playbook CAN-IR-PB-02 RB-02, steps C1-C8:
#   triage -> C1 snapshot -> C2 volatile data -> C3 block -> C4 memory -> C5 file artifacts -> C6 isolate (SIEM channel
#   kept) -> C7 shut down (also contains IR1-2026-001 and -003 on the same host) -> C8 verify + snapshot.
# Leaves the lab running and contained for Task 2's analysis phase and Task 4.
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lab/lab_common.sh"
TASK="$IR/task3_containment"; EV="$TASK/evidence"; T="$EV/transcripts"; MK="$EV/markers.csv"
for d in transcripts volatile network memory filesystem containment exfil-sink; do rm -rf "$EV/$d"; mkdir -p "$EV/$d"; done
rm -f "$MK" "$EV/EVIDENCE-INDEX-SHA256.txt"; mkdir -p "$BIG"
C="/ir/task3_containment/evidence"                                   # the same folder, as the forensic workstation sees it
nup() { cat "$RUN/drop/uploads.jsonl" 2>/dev/null | wc -l | tr -d ' '; }
DET=$(awk -F, '$1=="detection"{print $2}' "$IR/task2_log_analysis/evidence/markers.csv")
echo "phase,utc" > "$MK"; echo "detection,$DET" >> "$MK"

# ---------------------------------------------------------------- 1. triage on the host
: > "$T/01_triage.txt"
{
  echo "# Wazuh rule 100221 fired at $DET (Task 2, transcripts/03). Uploads received by the drop site so far: $(nup)"
  mark triage "$MK"
  echo "\$ tail -2 /var/log/ehr-audit.log"; gx "tail -2 /var/log/ehr-audit.log"
  echo; echo "\$ ausearch -k ehr-read -i | grep -m2 PT-1003"; gx "ausearch -k ehr-read -i 2>/dev/null | grep -m2 'PT-1003'" | cut -c1-200
  echo; echo "\$ timeout 12 tcpdump -nn -i enp0s1 -c 3 'dst host 10.78.99.66 and tcp[tcpflags] & tcp-syn != 0'"
  gx "timeout 12 tcpdump -nn -i enp0s1 -c 3 'dst host 10.78.99.66 and tcp[tcpflags] & tcp-syn != 0' 2>&1" 30
  echo; echo "\$ ps -o pid,user,lstart,cmd -u test.nurse"; gx "ps -o pid,user,lstart,cmd -u test.nurse"
  echo; echo "# Finding: PT-1003 is being sent off-host to 10.78.99.66:8080 by a process owned by test.nurse."
  echo "# IR1-2026-002 confirmed SEV-1 (Critical): ePHI disclosure in progress -> containment authorised."
  echo "# Queue: IR1-2026-003 (SEV-2, unapproved sudo) and IR1-2026-001 (SEV-3, leaver attempts) are contained on the same host in C7."
} 2>&1 | cap "$T/01_triage.txt"

# ---------------------------------------------------------------- C1 snapshot
: > "$T/02_c1_snapshot.txt"
{
  mark c1_snapshot "$MK"
  echo "# C1 live snapshot of the compromised state (RAM + disk)   [VBoxManage snapshot parrot-vm take ir-pre-containment --live]"
  vm hmp "savevm ir-pre-containment"; vm hmp 'info snapshots'
} 2>&1 | cap "$T/02_c1_snapshot.txt"

# ---------------------------------------------------------------- C2 volatile data
: > "$T/03_c2_volatile.txt"
{
  mark c2_volatile "$MK"
  echo "# C2a packet capture on the host itself (tcpdump, saved filter 'IR1 traffic to a suspect host'), 25 s"
  gx "timeout 25 tcpdump -i enp0s1 -nn -s0 -U -w /dev/shm/${CASE}_live.pcap host 10.78.99.66 2>&1 | tail -2" 60
  pull 22 /dev/shm/${CASE}_live.pcap $C/network/${CASE}_live_tcpdump.pcap
  echo; echo "# C2b system state, processes, connections, persistence - over the guest agent, straight to the case folder"
  gx 'echo "== collected $(date -u +%FT%TZ) by guest-agent"; date; uptime; hostname; uname -a; echo; echo "== who / w"; who; w; echo; echo "== last -n 15"; last -n 15 -F' > "$EV/volatile/system_state.txt"
  gx 'ps -eo pid,ppid,user,lstart,etime,stat,cmd --forest' > "$EV/volatile/processes.txt"
  gx 'echo "== ss -tunap"; ss -tunap; echo; echo "== ip -br addr"; ip -br addr; echo; echo "== ip route"; ip route; echo; echo "== lsof -nP -i"; lsof -nP -i' 60 > "$EV/volatile/network_connections.txt"
  gx 'P=$(pgrep -f "^python3 .*[s]yncd" | head -1); echo "PID=$P"; echo "== cmdline"; tr "\0" " " < /proc/$P/cmdline; echo; echo "== exe / cwd"; ls -l /proc/$P/exe /proc/$P/cwd; echo "== status"; grep -E "^(Name|State|PPid|Uid|Gid|VmRSS)" /proc/$P/status; echo "== fds"; ls -l /proc/$P/fd; echo "== environ"; tr "\0" "\n" < /proc/$P/environ | grep -E "^(USER|HOME|SSH_CLIENT|SSH_CONNECTION|PWD)="' > "$EV/volatile/suspect_process.txt"
  gx 'echo "== crontab -l -u test.nurse"; crontab -l -u test.nurse; echo; echo "== sudo group"; getent group sudo; echo; echo "== running services"; systemctl list-units --type=service --state=running --no-pager --no-legend; echo; echo "== listening"; ss -ltnp' > "$EV/volatile/persistence_services.txt"
  for f in system_state processes network_connections suspect_process persistence_services; do echo "wrote volatile/$f.txt ($(wc -l < "$EV/volatile/$f.txt") lines)"; done
  echo; grep -E 'syncd|PID' "$EV/volatile/processes.txt"; grep -E 'PID=|SSH_CONNECTION' "$EV/volatile/suspect_process.txt"
} 2>&1 | cap "$T/03_c2_volatile.txt"

# ---------------------------------------------------------------- C3 block
: > "$T/04_c3_block.txt"
{
  mark c3_block "$MK"
  echo "# C3 drop + log everything to the IOC 10.78.99.66 (applied over the guest agent: a mistake cannot lock responders out)"
  gx "iptables-save > /root/iptables.pre-containment; iptables -N IR-EGRESS-BLOCK; \
      iptables -A IR-EGRESS-BLOCK -m limit --limit 20/min -j LOG --log-prefix 'IR-BLOCK $CASE ' --log-uid; \
      iptables -A IR-EGRESS-BLOCK -j DROP; iptables -I OUTPUT 1 -d 10.78.99.66 -j IR-EGRESS-BLOCK; iptables -S"
  echo; echo "# 30 s later: the uploader still runs, every attempt is dropped"; sleep 30
  gx "iptables -vnL IR-EGRESS-BLOCK"; echo; gx "grep 'IR-BLOCK' /var/log/kern.log | tail -2 | cut -c1-200"
  echo; echo "last upload received by the drop site: $(tail -1 "$RUN/drop/uploads.jsonl" 2>/dev/null | cut -c1-60)"
} 2>&1 | cap "$T/04_c3_block.txt"

# ---------------------------------------------------------------- C4 memory
: > "$T/05_c4_memory.txt"
{
  mark c4_memory "$MK"
  echo "# C4a process memory of the uploader - gdb gcore in the guest"
  gx 'P=$(pgrep -f "^python3 .*[s]yncd" | head -1); gcore -o /dev/shm/syncd $P 2>&1 | tail -2; ls -l /dev/shm/syncd.*' 120
  CORE=$(gx 'ls /dev/shm/syncd.* | head -1')
  pull 22 "$CORE" "$CBIG/${CASE}_syncd.core"
  fx sh -c "grep -aoE '[[:print:]]*(PT-1003|SYN-0003|10\.78\.99\.66|syncd|pt1003)[[:print:]]*' $CBIG/${CASE}_syncd.core | cut -c1-110 | sort | uniq -c | sort -rn | head -12" | tee "$EV/memory/syncd_core_strings.txt"
  gx "rm -f $CORE"
  echo; echo "# C4b full RAM image from the hypervisor   [VBoxManage debugvm parrot-vm dumpvmcore]"
  vm qmp dump-guest-memory "{\"paging\":false,\"protocol\":\"file:$CBIG/${CASE}_parrot-vm.mem.elf\"}"
  for i in $(seq 1 90); do vm qmp query-dump | has '"completed"' && break; sleep 2; done; vm qmp query-dump
  echo "sha256 $(shasum -a 256 "$BIG/${CASE}_parrot-vm.mem.elf" | cut -d' ' -f1)  ${CASE}_parrot-vm.mem.elf"
} 2>&1 | cap "$T/05_c4_memory.txt"

# ---------------------------------------------------------------- C5 file-system artifacts
: > "$T/06_c5_filesystem.txt"
ART="/home/test.nurse/.cache/.sync/pt1003.txt /home/test.nurse/.cache/.sync/syncd.py /var/spool/cron/crontabs/test.nurse \
/home/test.nurse/.ssh/authorized_keys /home/test.billing/.ssh/authorized_keys /var/log/auth.log /var/log/ehr-audit.log \
/var/log/kern.log /var/log/audit/audit.log /etc/group /etc/passwd /etc/sudoers.d/it_admin /var/ossec/logs/ossec.log"
{
  mark c5_filesystem "$MK"
  echo "# C5 stat first (reading changes atime), freeze a copy in RAM, hash, tar to ir-forensics, re-hash the copy"
  fx sh -c "$FS ir-analyst@10.78.50.2 \"sudo stat -c '%n|%s|%U:%G|%a|atime=%x|mtime=%y|ctime=%z' $ART\"" | tee "$EV/filesystem/artifact_stat.txt" | cut -c1-150
  printf '%s\n' "rm -rf /dev/shm/art && mkdir /dev/shm/art && tar --numeric-owner -cpf - $ART 2>/dev/null | tar -xpf - -C /dev/shm/art" 'cd /dev/shm/art && find . -type f | sort | sed "s#^\./#/#" | while read f; do printf "%s  %s\n" "$(sha256sum ".$f" | cut -d" " -f1)" "$f"; done' \
    | docker exec -i ir-forensics sh -c "$FS ir-analyst@10.78.50.2 'sudo sh -s'" > "$EV/filesystem/artifact_sha256_source.txt"
  fx sh -c "$FS ir-analyst@10.78.50.2 'cd /dev/shm/art && sudo tar --numeric-owner -cpf - .' > $C/filesystem/${CASE}_artifacts.tar"
  fx sh -c "$FS ir-analyst@10.78.50.2 'sudo rm -rf /dev/shm/art'"
  fx sh -c "rm -rf /tmp/v && mkdir /tmp/v && tar -xpf $C/filesystem/${CASE}_artifacts.tar -C /tmp/v && cd /tmp/v && find . -type f | sort | sed s#^./## | xargs sha256sum" \
     | sed 's#  #  /#' > "$EV/filesystem/artifact_sha256_copy.txt"
  diff -q "$EV/filesystem/artifact_sha256_source.txt" "$EV/filesystem/artifact_sha256_copy.txt" >/dev/null \
    && echo "all $(wc -l < "$EV/filesystem/artifact_sha256_copy.txt") artifacts: source hash == copy hash (MATCH)" || echo "HASH MISMATCH"
  fx sha256sum $C/filesystem/${CASE}_artifacts.tar
} 2>&1 | cap "$T/06_c5_filesystem.txt"

# ---------------------------------------------------------------- C6 isolate, keep the SIEM channel
: > "$T/07_c6_isolate.txt"
{
  mark c6_isolate "$MK"
  echo "# C6a pull the clinical cable   [setlinkstate1 off] ; C6b quarantine adapter in   [setlinkstate2 on]"
  vm qmp set_link '{"name":"nic0","up":false}'; vm qmp set_link '{"name":"nic1","up":true}'; vm hmp 'info network' | grep -E '^nic|q0|n0'
  echo; echo "# C6c guest interface configuration"
  gx 'ip link set enp0s1 down; ip link set enp0s2 up; ip addr add 10.0.3.15/24 dev enp0s2; ip route replace default via 10.0.3.2 dev enp0s2; ip -br link; ip -br addr; ip route'
  echo; echo "# C6d default-DROP firewall: in = forensic SSH from 10.78.50.5 only; out = Wazuh agent via the quarantine SIEM forward only"
  gx "iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT DROP; \
      iptables -A INPUT -i lo -j ACCEPT; iptables -A OUTPUT -o lo -j ACCEPT; \
      iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; \
      iptables -A INPUT -i enp0s2 -s 10.78.50.5 -p tcp --dport 22 -j ACCEPT; \
      iptables -A OUTPUT -o enp0s2 -d 10.0.3.20 -p tcp --dport 1514 -j ACCEPT; \
      iptables -A INPUT -m limit --limit 20/min -j LOG --log-prefix 'IR-DENY-IN $CASE '; iptables-save | tee /root/iptables.containment"
  echo; echo "# C6e keep monitoring: the Wazuh agent reports through the hypervisor's single forward 10.0.3.20:1514 -> wazuh-manager"
  gx "sed -i 's#<address>10.78.50.20</address>#<address>10.0.3.20</address>#' /var/ossec/etc/ossec.conf; systemctl restart wazuh-agent; \
      for i in \$(seq 1 60); do grep -q 'Connected to the server (\[10.0.3.20\]' /var/ossec/logs/ossec.log && break; sleep 3; done; \
      grep -E 'Connected to the server \(\[10.0.3.20\]' /var/ossec/logs/ossec.log | tail -1" 240
  mgr /var/ossec/bin/agent_control -i 001 | grep -E 'Status|Last keep'
} 2>&1 | cap "$T/07_c6_isolate.txt"

# ---------------------------------------------------------------- C7 shut down + contain the other two incidents
: > "$T/08_c7_shutdown.txt"
{
  mark c7_shutdown "$MK"
  echo "# C7 over the quarantine path (ir-forensics -> 10.78.50.2:2222 -> parrot-vm)"
  R() { echo "\$ $1"; echo "$1" | docker exec -i ir-forensics sh -c "$FS -p 2222 ir-analyst@10.78.50.2 'sudo sh -s'"; }
  echo "## IR1-2026-002 (Tara Jones, mover)"
  R 'pkill -KILL -f "^python3 .*[s]yncd"; pkill -KILL -u test.nurse; sleep 1; pgrep -u test.nurse || echo no test.nurse processes'
  R 'systemctl stop cron && systemctl mask cron && systemctl is-active cron'
  R 'systemctl stop ehr-portal; systemctl disable ehr-portal 2>&1; echo "active=$(systemctl is-active ehr-portal) enabled=$(systemctl is-enabled ehr-portal)"'
  R 'usermod -L -e 1 test.nurse && gpasswd -d test.nurse clinical && usermod -aG disabled-users test.nurse && id test.nurse'
  R 'install -d -m 700 /root/ir-quarantine && mv /home/test.nurse/.ssh/authorized_keys /root/ir-quarantine/test.nurse.authorized_keys && ls /root/ir-quarantine'
  echo; echo "## IR1-2026-003 (Sathya Hasi, unapproved sudo grant)"
  R 'gpasswd -d test.clinician sudo && getent group sudo'
  echo; echo "## IR1-2026-001 (Jeevan Smith, leaver: blocked by DenyGroups, but the SSH key was still on the host)"
  R 'mv /home/test.billing/.ssh/authorized_keys /root/ir-quarantine/test.billing.authorized_keys && ls /root/ir-quarantine'
  echo; echo "## sshd: listen on the quarantine address only, responder only"
  R 'printf "ListenAddress 10.0.3.15\nAllowUsers ir-analyst\n" > /etc/ssh/sshd_config.d/00-ir-containment.conf && sshd -t && systemctl reload ssh && sshd -T | grep -E "^(listenaddress|allowusers)"'
  R 'su -s /bin/sh test.nurse -c true 2>&1; echo "login as test.nurse: exit=$?"; setpriv --reuid=test.nurse --regid=test.nurse --init-groups cat /srv/ehr/clinical/PT-1003.txt 2>&1; echo "read PT-1003 with test.nurse current groups: exit=$?"'
} 2>&1 | cap "$T/08_c7_shutdown.txt"

# ---------------------------------------------------------------- C8 verify + snapshot
: > "$T/09_c8_verification.txt"
{
  mark c8_verify "$MK"
  echo "# reachability AFTER containment (before = Task 1 transcripts/07)"
  probe_matrix
  echo; echo "\$ systemctl is-active ssh cron ehr-portal wazuh-agent"; gx "systemctl is-active ssh cron ehr-portal wazuh-agent | paste -sd' '"
  echo "uploads received by the drop site: $(nup) ; last: $(tail -1 "$RUN/drop/uploads.jsonl" 2>/dev/null | cut -c1-60)"
  echo; echo "# post-containment snapshot   [VBoxManage snapshot parrot-vm take ir-contained --live]"
  vm hmp "savevm ir-contained"; vm hmp 'info snapshots'
  mark contained "$MK"
} 2>&1 | cap "$T/09_c8_verification.txt"

# ---------------------------------------------------------------- export + index
: > "$T/10_export.txt"
{
  cp "$RUN/drop/uploads.jsonl" "$EV/exfil-sink/uploads.jsonl"
  cp "$RUN/nic0-clinical.pcap" "$EV/network/hypervisor_nic0_clinical.pcap"; cp "$RUN/nic1-quarantine.pcap" "$EV/network/hypervisor_nic1_quarantine.pcap"
  for p in ${CASE}_live_tcpdump.pcap hypervisor_nic0_clinical.pcap hypervisor_nic1_quarantine.pcap; do echo "\$ capinfos $p"; fx capinfos -c -a -e $C/network/$p | tail -3; done
  fx sh -c "tshark -r $C/network/hypervisor_nic0_clinical.pcap -Y 'http.request.method==POST && ip.dst==10.78.99.66' -T fields -e frame.time_epoch -e http.user_agent 2>/dev/null" > "$EV/network/ioc_posts_nic0.tsv"
  echo "POSTs to the IOC on the wire: $(grep -c . "$EV/network/ioc_posts_nic0.tsv"); uploads logged by the drop site: $(grep -c . "$EV/exfil-sink/uploads.jsonl")"
  fx sh -c "$FS -p 2222 ir-analyst@10.78.50.2 'sudo cat /root/iptables.containment'" > "$EV/containment/iptables.containment.rules"
  fx sh -c "$FS -p 2222 ir-analyst@10.78.50.2 'sudo cat /root/iptables.pre-containment'" > "$EV/containment/iptables.pre-containment.rules"
  ( cd "$EV" && find . -type f ! -name EVIDENCE-INDEX-SHA256.txt ! -path './transcripts/10_export.txt' | sort | xargs shasum -a 256 ) > "$EV/EVIDENCE-INDEX-SHA256.txt"
  echo "# outside git: $BIG" >> "$EV/EVIDENCE-INDEX-SHA256.txt"
  ( cd "$BIG" && shasum -a 256 ${CASE}_parrot-vm.mem.elf ${CASE}_syncd.core ) >> "$EV/EVIDENCE-INDEX-SHA256.txt"
  echo "evidence index: $(grep -cE '^[0-9a-f]{64} ' "$EV/EVIDENCE-INDEX-SHA256.txt") files"
} 2>&1 | cap "$T/10_export.txt"
echo "done $(now)"
