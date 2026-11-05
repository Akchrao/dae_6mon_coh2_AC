#!/usr/bin/env bash
# =============================================================================
# Care Access Navigator - Incident Response 1, Task 6: Post-Incident Procedures (recovery + validation)
# -----------------------------------------------------------------------------
# Runs against the contained lab after Task 4. Recovery strategy: restore the known-good snapshot, then remove the
# root cause and harden, then prove it - twice (before and after a reboot).
#   R0 evidence gate      every Task 3/4 evidence hash re-verified before anything is destroyed
#   R1 record + source    snapshot the contained state; verify the golden image (recovery source of last resort)
#   R2 environment        restore snapshot baseline-clean          [VBoxManage snapshot parrot-vm restore baseline-clean]
#                         adapter 1 cable in, adapter 2 cable out  [VBoxManage controlvm parrot-vm setlinkstate1 on / 2 off]
#   R3 system recovery    recover_harden.sh: JML fix, keys, cron.allow, persistent firewall, services, audit
#   R4 network recovery   interfaces, routes, DNS, NTP resync; clock checked against the host
#   R5 validation         validate_recovery.sh (in-guest checklist) + network probes from the other hosts
#   R6 persistence        reboot, run the whole validation again
#   R7 snapshot           recovered-validated (the new known-good baseline)
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lab/lab_common.sh"
TASK="$IR/task6_post_incident"; EV="$TASK/evidence"; T="$EV/transcripts"
for d in transcripts gate validation; do rm -rf "$EV/$d"; mkdir -p "$EV/$d"; done; rm -f "$EV/steps.csv" "$EV/EVIDENCE-INDEX-SHA256.txt"
echo "step,utc" > "$EV/steps.csv"; step() { echo "$1,$(now)" >> "$EV/steps.csv"; echo "[$(now)] >>> $1"; }
probes() {  # probes <run label>  - same paths as Task 3, with the post-recovery expectation
  local r out="$EV/validation/network_probes_$1.tsv"
  printf 'id\tpath\texpected\tactual\tresult\n' > "$out"
  p() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$([ "$3" = "$4" ] && echo PASS || echo FAIL)" >> "$out"; }
  r=$(for i in 1 2 3; do ssh-keyscan -T 10 -p 2223 127.0.0.1 2>/dev/null | has ssh-ed25519 && { echo REACHABLE; break; }; done); p V-P1 "macOS host -> parrot-vm SSH (user network)" BLOCKED "${r:-BLOCKED}"
  r=$(docker exec nurse-ws sh -c 'for i in 1 2 3; do ssh-keyscan -T 10 10.78.10.5 2>/dev/null | grep -q ssh-ed25519 && { echo REACHABLE; break; }; done'); p V-P2 "clinical LAN -> parrot-vm SSH" BLOCKED "${r:-BLOCKED}"
  r=$(docker exec nurse-ws sh -c 'curl -s -m 8 http://10.78.10.5:8080/ | grep -q "EHR portal" && echo REACHABLE'); p V-P3 "clinical LAN -> EHR portal :8080 (service restored)" REACHABLE "${r:-BLOCKED}"
  r=$(fx sh -c 'ssh -i /root/.ssh/ir_analyst -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR -p 22 ir-analyst@10.78.50.2 hostname 2>/dev/null'); p V-P4 "admin network 10.78.50.0/24 -> parrot-vm SSH" REACHABLE "$([ "$r" = parrot-vm ] && echo REACHABLE || echo BLOCKED)"
  r=$(fx sh -c 'ssh -i /root/.ssh/ir_analyst -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR -p 2222 ir-analyst@10.78.50.2 hostname 2>/dev/null'); p V-P5 "quarantine path :2222 closed" BLOCKED "$([ "$r" = parrot-vm ] && echo REACHABLE || echo BLOCKED)"
  r=$(gx "curl -s -m 6 http://10.78.99.66:8080/ | grep -c drop-site" 30 2>/dev/null); p V-P6 "parrot-vm -> IOC drop site" BLOCKED "$([ "${r:-0}" -gt 0 ] && echo REACHABLE || echo BLOCKED)"
  column -t -s $'\t' "$out"
}

docker ps --format '{{.Names}}' | has -x ir-hv || { echo "lab not running"; exit 1; }

# ---------------------------------------------------------------- R0 evidence gate
: > "$T/01_r0_evidence_gate.txt"
{
  step r0_gate
  echo "# Recovery destroys the compromised state. Gate: every evidence item must re-verify first."
  for t in task1_environment_setup task2_log_analysis task3_containment task4_evidence_management; do
    ( cd "$IR/$t/evidence" && grep -E '^[0-9a-f]{64}  \./' EVIDENCE-INDEX-SHA256.txt | shasum -a 256 -c - ) > "$EV/gate/${t%%_*}_check.txt" 2>&1
  done
  ( cd "$BIG" && cat "$IR/task3_containment/evidence/EVIDENCE-INDEX-SHA256.txt" "$IR/task4_evidence_management/evidence/EVIDENCE-INDEX-SHA256.txt" \
      | grep -E '^[0-9a-f]{64}  [^.]' | shasum -a 256 -c - ) > "$EV/gate/large_items_check.txt" 2>&1
  ( cd "$EVID/baseline" && grep -E '^[0-9a-f]{64}  [^.]' "$IR/task1_environment_setup/evidence/EVIDENCE-INDEX-SHA256.txt" | shasum -a 256 -c - ) >> "$EV/gate/large_items_check.txt" 2>&1
  for f in task1_check task2_check task3_check task4_check large_items_check; do echo "$f: $(grep -c ': OK$' "$EV/gate/$f.txt") OK, $(grep -vc ': OK$' "$EV/gate/$f.txt") not OK"; done
  cat "$EV/gate/large_items_check.txt"
  BAD=$(cat "$EV/gate/"*.txt | grep -vc ': OK$')
  [ "$BAD" -eq 0 ] && echo "GATE PASSED: evidence preserved - recovery may proceed" || { echo "GATE FAILED - stop"; exit 1; }
} 2>&1 | cap "$T/01_r0_evidence_gate.txt"
grep -q "GATE PASSED" "$T/01_r0_evidence_gate.txt" || exit 1

# ---------------------------------------------------------------- R1 record state + verify recovery source
: > "$T/02_r1_record_and_source.txt"
{
  step r1_record
  echo "# record the contained state before it is overwritten   [VBoxManage snapshot parrot-vm take pre-recovery --live]"
  vm hmp 'savevm pre-recovery'; vm hmp 'info snapshots'
  echo; echo "# verify the recovery source of last resort: the golden image (rebuild path)"
  echo "recorded: $(cut -d' ' -f1 "$GOLD/parrot-vm-golden.sha256")"
  echo "now:      $(shasum -a 256 "$GOLD/parrot-vm-golden.qcow2" | cut -d' ' -f1)"
  [ "$(cut -d' ' -f1 "$GOLD/parrot-vm-golden.sha256")" = "$(shasum -a 256 "$GOLD/parrot-vm-golden.qcow2" | cut -d' ' -f1)" ] && echo "golden image: MATCH" || echo "golden image: CHANGED"
} 2>&1 | cap "$T/02_r1_record_and_source.txt"

# ---------------------------------------------------------------- R2 environment restoration
: > "$T/03_r2_restore.txt"
{
  step r2_restore
  echo "# restore the clean snapshot taken before the incident   [VBoxManage snapshot parrot-vm restore baseline-clean]"
  vm hmp 'loadvm baseline-clean'
  vm wait-agent 120
  echo; echo "# adapters back to production wiring   [setlinkstate1 on ; setlinkstate2 off]"
  vm qmp set_link '{"name":"nic0","up":true}'; vm qmp set_link '{"name":"nic1","up":false}'
  echo; echo "# what the restored host looks like BEFORE fixes: clean of artifacts, but the root cause is back"
  gx 'ls -la /home/test.nurse/.cache 2>&1 | head -3; crontab -l -u test.nurse 2>&1; id test.nurse; passwd -S test.nurse; iptables -S | head -3'
} 2>&1 | cap "$T/03_r2_restore.txt"

# ---------------------------------------------------------------- R3 system recovery + R4 network recovery
: > "$T/04_r3_r4_recover.txt"
{
  step r3_system
  echo "# R4 network first (the host needs NTP and package mirrors reachable for validation)"
  gx 'IF0=$(ip -o link | awk -F": " "/52:54:00:0a:00:10/{print \$2}"); IF1=$(ip -o link | awk -F": " "/52:54:00:0a:00:50/{print \$2}");
      ip addr flush dev $IF1; ip link set $IF1 down; netplan apply; sleep 4;
      echo "clinical=$IF0 quarantine=$IF1"; ip -br link; ip -br addr; ip route; cat /etc/resolv.conf | grep -v "^#"'
  echo; echo "# clock after restore (guest resumes at snapshot time):"; skew
  gx 'systemctl restart systemd-timesyncd; for i in $(seq 1 30); do [ "$(timedatectl show -p NTPSynchronized --value)" = yes ] && break; sleep 2; done; timedatectl | sed -n "1,6p"' 90
  echo "# clock after NTP resync:"; skew
  echo; echo "# R3 recover_harden.sh"
  gx "$(cat "$LAB/recover_harden.sh")" 180
  echo; echo "# wait for monitoring to come back before validating (the restored agent must reconnect to the manager)"
  gx "for i in \$(seq 1 60); do grep -q \"status='connected'\" /var/ossec/var/run/wazuh-agentd.state && break; sleep 3; done; grep -E '^status' /var/ossec/var/run/wazuh-agentd.state" 240
  step r4_network
} 2>&1 | cap "$T/04_r3_r4_recover.txt"

# ---------------------------------------------------------------- R5 validation, R6 reboot + validation, R7 snapshot
for run in 1 2; do
  : > "$T/0$((4 + run))_validation_run$run.txt"
  {
    if [ $run = 2 ]; then
      step r6_reboot
      echo "# R6 reboot, then repeat every check (proves the fixes persist)"
      docker exec ir-hv python3 -c 'import sys; sys.path.insert(0, "/lab"); import vmctl; print(vmctl.qga("guest-shutdown", {"mode": "reboot"}))' 2>&1 | tail -1
      sleep 15; vm wait-agent 300; sleep 20
      gx 'uptime; systemctl is-system-running'
      gx "for i in \$(seq 1 60); do grep -q \"status='connected'\" /var/ossec/var/run/wazuh-agentd.state && break; sleep 3; done; grep -E '^status' /var/ossec/var/run/wazuh-agentd.state" 240
    else
      step r5_validate
    fi
    echo "# in-guest checklist (validate_recovery.sh)"
    gx "$(cat "$LAB/validate_recovery.sh")" 180 > "$EV/validation/checklist_run$run.tsv"
    column -t -s $'\t' "$EV/validation/checklist_run$run.tsv" | cut -c1-150
    echo "checklist run $run: $(grep -c 'PASS$' "$EV/validation/checklist_run$run.tsv") PASS, $(grep -c 'FAIL$' "$EV/validation/checklist_run$run.tsv") FAIL"
    echo; echo "# network probes from the other hosts"; probes "run$run"
    echo "probes run $run: $(grep -c 'PASS$' "$EV/validation/network_probes_run$run.tsv") PASS, $(grep -c 'FAIL$' "$EV/validation/network_probes_run$run.tsv") FAIL"
    echo; echo "# clock"; skew | tee "$EV/validation/clock_run$run.txt"
  } 2>&1 | cap "$T/0$((4 + run))_validation_run$run.txt"
done

: > "$T/07_r7_snapshot.txt"
{
  step r7_snapshot
  echo "# new known-good baseline   [VBoxManage snapshot parrot-vm take recovered-validated --live]"
  vm hmp 'savevm recovered-validated'; vm hmp 'info snapshots'
  gx 'cat /etc/iptables/rules.v4' > "$EV/validation/firewall_baseline_rules.v4"
  step done
  ( cd "$EV" && find . -type f ! -name EVIDENCE-INDEX-SHA256.txt ! -path './transcripts/07_r7_snapshot.txt' | sort | xargs shasum -a 256 ) > "$EV/EVIDENCE-INDEX-SHA256.txt"
  echo "evidence index: $(grep -cE '^[0-9a-f]{64} ' "$EV/EVIDENCE-INDEX-SHA256.txt") files"
} 2>&1 | cap "$T/07_r7_snapshot.txt"
echo "done $(now)"
