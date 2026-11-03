#!/usr/bin/env bash
# lab_common.sh - shared settings and helpers for the IR1 lab (sourced by every task's run script).
#
# One lab for Tasks 1-6. Topology (VirtualBox equivalents in brackets):
#   ir-hv          hypervisor container running QEMU                       [VirtualBox host]
#     parrot-vm    Debian 12 VM (Parrot OS stand-in) from the golden image; Wazuh agent 4.9.2
#                  nic0 -> NAT 10.0.2.0/24, port-forwards 22, 8080         [Adapter 1: NAT + port forwarding]
#                  nic1 -> restricted 10.0.3.0/24, forensic SSH only, cable OUT until containment
#                                                                          [Adapter 2: internal network "quarantine"]
#   ir-clinical    10.78.10.0/24  clinical LAN: ir-hv .5, nurse-ws .20
#   ir-internet    10.78.99.0/24  "outside": exfil-sink .66 (lab drop site), ir-hv .5
#   ir-mgmt        10.78.50.0/24  --internal SOC/management: wazuh-manager .20, ir-forensics .5, ir-hv .2
#   macOS host     DAEDMAC1009 -> 127.0.0.1:2223 -> parrot-vm:22 (user sessions, logged by host_ssh_logged.py)
# People (JML register, capstone_next_steps/jml-evidence/JML-LOG.csv):
#   Sathya Hasi  test.clinician  joiner (REQ-2026-0101)  -> Clinician
#   Tara Jones   test.nurse      mover  (CHG-2026-0201)  Nurse -> Billing
#   Jeevan Smith test.billing    leaver (TERM-2026-0301)
#   it_admin     IT administrator (sudo)
# Incidents: IR1-2026-001 leaver login (Jeevan), IR1-2026-002 mover ePHI + exfiltration (Tara), IR1-2026-003 unapproved sudo (Sathya)
IR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; LAB="$IR/lab"
VMLAB="$HOME/ir1-vm-lab"; RUN="$VMLAB/run"; GOLD="$VMLAB/golden"
CASE=IR1-2026-002; EVID="$VMLAB/evidence"; BIG="$EVID/$CASE"   # large evidence (outside git); mounted as /evid in containers
CBIG="/evid/$CASE"
KEYS="$LAB/.keys"; MACKEY="$KEYS/mac_host_ed25519"; IRKEY="$KEYS/ir_analyst_ed25519"
MACLOG="$IR/task2_log_analysis/evidence/macos/ssh_client.log"     # the Mac's SSH client trail (all tasks append)
WAZUH_IMG=wazuh/wazuh-manager:4.9.2

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
# has <grep args>: like grep -q, but reads all of stdin, so a pipe + pipefail never reports a false 'not found'
has() { grep "$@" >/dev/null; }
cap() { tee -a "$1"; }
vm()  { docker exec ir-hv python3 /lab/vmctl.py "$@"; }                     # hypervisor control (= VBoxManage)
gx()  { docker exec ir-hv python3 /lab/vmctl.py exec "$1" "${2:-120}"; }   # root shell in the guest via the agent channel
fx()  { docker exec ir-forensics "$@"; }                                     # Parrot forensic workstation
mgr() { docker exec wazuh-manager "$@"; }                                    # Wazuh manager
FS="ssh -i /root/.ssh/ir_analyst -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"
SSH() { python3 "$LAB/host_ssh_logged.py" "$MACLOG" -i "$MACKEY" -p 2223 -o IdentitiesOnly=yes \
          -o StrictHostKeyChecking=no -o UserKnownHostsFile="$KEYS/known_hosts" -o ConnectTimeout=10 "$@"; }
mark() { echo "$1,$(now)" >> "$2"; echo "[$(now)] >>> $1"; }                # mark <phase> <markers.csv>

# pull <port> <guest path> <workstation path>: copy a file off the guest over SSH and prove it is bit-identical
pull() {
  local src dst
  src=$(fx sh -c "$FS -p $1 ir-analyst@10.78.50.2 'sudo sha256sum $2' | cut -d' ' -f1")
  fx sh -c "$FS -p $1 ir-analyst@10.78.50.2 'sudo cat $2' > $3"
  dst=$(fx sha256sum "$3" | cut -d' ' -f1)
  echo "acquired $2 -> $3  bytes=$(fx stat -c %s "$3")"
  echo "  sha256 source(parrot-vm)=$src"
  echo "  sha256 copy(ir-forensics)=$dst  $([ "$src" = "$dst" ] && echo MATCH || echo MISMATCH)"
}

# reachability probes: same paths every time (Task 1 baseline, Task 3 before/after, Task 6 after recovery)
probe_matrix() {
  local r
  r=$(for i in 1 2 3; do ssh-keyscan -T 10 -p 2223 127.0.0.1 2>/dev/null | has ssh-ed25519 && { echo 1; break; }; done)
  echo "P1 macOS host -> parrot-vm SSH (127.0.0.1:2223)           : $([ "${r:-0}" = 1 ] && echo REACHABLE || echo BLOCKED)"
  r=$(docker exec nurse-ws sh -c 'for i in 1 2 3; do ssh-keyscan -T 10 10.78.10.5 2>/dev/null | grep -q ssh-ed25519 && { echo 1; break; }; done')
  echo "P2 clinical LAN nurse-ws -> parrot-vm SSH (10.78.10.5:22)  : $([ "${r:-0}" = 1 ] && echo REACHABLE || echo BLOCKED)"
  r=$(docker exec nurse-ws sh -c 'curl -s -m 8 http://10.78.10.5:8080/ | grep -c "EHR portal"')
  echo "P3 clinical LAN nurse-ws -> EHR portal (10.78.10.5:8080)   : $([ "${r:-0}" -gt 0 ] && echo REACHABLE || echo BLOCKED)"
  r=$(gx "curl -s -m 6 http://10.78.99.66:8080/ | grep -c drop-site" 30 2>/dev/null)
  echo "P4 parrot-vm -> exfil-sink (10.78.99.66:8080)              : $([ "${r:-0}" -gt 0 ] && echo REACHABLE || echo BLOCKED)"
  r=$(gx "curl -s -m 8 -o /dev/null -w '%{http_code}' http://deb.debian.org/debian/" 30 2>/dev/null)
  echo "P5 parrot-vm -> internet (deb.debian.org:80)               : $([ "${r:-000}" != "000" ] && echo "REACHABLE (HTTP $r)" || echo BLOCKED)"
  r=$(fx sh -c "$FS -p 2222 ir-analyst@10.78.50.2 hostname 2>/dev/null")
  echo "P6 ir-forensics -> parrot-vm quarantine SSH (10.78.50.2:2222): $([ "$r" = parrot-vm ] && echo REACHABLE || echo BLOCKED)"
}

# guest clock vs host clock through the guest agent (works with every network path cut)
skew() {
  docker exec ir-hv python3 -c 'import sys, time; sys.path.insert(0, "/lab"); import vmctl
g = vmctl.qga("guest-get-time")["return"] / 1e9; h = time.time()
f = lambda t: time.strftime("%H:%M:%S", time.gmtime(t))
print("guest %s UTC  host %s UTC  skew %+.1f s" % (f(g), f(h), g - h))'
}

# Wazuh alerts helpers (manager side)
alerts_for() { mgr sh -c "grep -h '\"id\":\"$1\"' /var/ossec/logs/alerts/alerts.json" 2>/dev/null; }
wait_alert() {  # wait_alert <rule id> <timeout s>  -> prints the first alert's timestamp
  local i
  for i in $(seq 1 "$2"); do
    a=$(alerts_for "$1" | head -1)
    [ -n "$a" ] && { echo "$a" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["timestamp"])'; return 0; }
    sleep 1
  done
  return 1
}

# ship_file <local file> <manager file>: append a macOS log to a manager localfile input in 500-line batches.
# Under emulation the manager's logcollector can crash (EINTR in select); it then skips lines written while it was
# down. So after every batch: if logcollector died, restart it and resend that batch. Ends with a sent-vs-received count.
ship_file() {
  local src="$1" dst="$2" tmpd p sent recv0 recv restarts=0
  recv0=$(mgr sh -c "grep -c '$dst' /var/ossec/logs/archives/archives.json" 2>/dev/null | head -1); recv0=${recv0:-0}
  tmpd=$(mktemp -d); split -l 500 "$src" "$tmpd"/part_
  for p in "$tmpd"/part_*; do
    docker exec -i wazuh-manager sh -c "cat >> $dst" < "$p"; sleep 3
    st=$(mgr /var/ossec/bin/wazuh-control status 2>/dev/null)          # capture first: grep -q in a pipe + pipefail misreports
    if [[ "$st" != *"wazuh-logcollector is running"* ]]; then
      restarts=$((restarts + 1)); echo "  logcollector stopped - restarting and resending $(basename "$p")"
      mgr /var/ossec/bin/wazuh-control restart >/dev/null 2>&1; sleep 30
      docker exec -i wazuh-manager sh -c "cat >> $dst" < "$p"; sleep 3
    fi
  done
  rm -rf "$tmpd"; sent=$(grep -c . "$src")
  for i in $(seq 1 30); do
    recv=$(( $(mgr sh -c "grep -c '$dst' /var/ossec/logs/archives/archives.json") - recv0 ))
    [ "$recv" -ge "$sent" ] && break; sleep 5
  done
  echo "$(basename "$src") -> $dst  sent=$sent  received=$recv  logcollector restarts=$restarts  $([ "$recv" -ge "$sent" ] && echo COMPLETE || echo INCOMPLETE)"
}
