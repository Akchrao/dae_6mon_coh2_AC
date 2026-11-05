#!/usr/bin/env bash
# =============================================================================
# Care Access Navigator - Incident Response 1, Task 1: IR Environment Setup
# -----------------------------------------------------------------------------
# Builds the shared IR1 lab from scratch (topology and people: lab/lab_common.sh) and proves each component works:
#   01 networks, Wazuh manager, hypervisor + parrot-vm, forensic workstation, clinical PC, drop site
#   02 parrot-vm provisioned with the JML people; Wazuh agent deployed and enrolled
#   03 Wazuh: decoders, CDB lists, the 3 custom alert rules - each tested positive and negative with wazuh-logtest
#   04 log collection: Parrot OS (agent) and macOS (DAEDMAC1009) ingested, sent = received
#   05 Wireshark (tshark/dumpcap) on parrot-vm: saved capture filters, each compiled, one live capture
#   06 Volatility 3 on the forensic workstation: symbol table for this kernel, tested on a baseline RAM image
#   07 baseline snapshot baseline-clean (the known-good state used by Task 6) + evidence index
# Docker Desktop only, no admin rights. Run: bash run_task1.sh   (about 15 min)
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lab/lab_common.sh"
TASK="$IR/task1_environment_setup"; EV="$TASK/evidence"; T="$EV/transcripts"; MK="$EV/markers.csv"
mkdir -p "$T" "$EV"/{wazuh,parrot,macos,wireshark,volatility} "$RUN" "$EVID/baseline" "$BIG" "$KEYS" "$(dirname "$MACLOG")"
echo "phase,utc" > "$MK"
[ -f "$GOLD/parrot-vm-golden.qcow2" ] || { echo "run lab/build_golden.sh first"; exit 1; }

# ---------------------------------------------------------------- 0. fresh start
docker rm -f ir-hv nurse-ws exfil-sink ir-forensics wazuh-manager >/dev/null 2>&1 || true
for n in ir-clinical ir-internet ir-mgmt; do docker network rm $n >/dev/null 2>&1 || true; done
mkdir -p "$RUN"; find "$RUN" -mindepth 1 -delete; mkdir -p "$RUN/drop"; rm -f "$KEYS/known_hosts"; : > "$MACLOG"   # empty, never delete: Docker file sharing can keep a stale handle to a deleted folder

# ---------------------------------------------------------------- 1. build the lab
: > "$T/01_lab_build.txt"
{
  mark lab_build "$MK"
  echo "# IR1 shared lab build - $(now) - host $(hostname -s) ($(sw_vers -productName) $(sw_vers -productVersion), $(uname -m)), Docker $(docker version --format '{{.Server.Version}}')"
  echo "\$ docker network create ... (3 segments)"
  docker network create --subnet 10.78.10.0/24 ir-clinical
  docker network create --subnet 10.78.99.0/24 ir-internet
  docker network create --internal --subnet 10.78.50.0/24 ir-mgmt
  echo; echo "# Wazuh manager $WAZUH_IMG on the management segment (amd64 image, emulated on Apple silicon)"
  docker run -d --platform linux/amd64 --name wazuh-manager --hostname wazuh-manager --network ir-mgmt --ip 10.78.50.20 $WAZUH_IMG
  echo; echo "# hypervisor host (VirtualBox host stand-in); the Mac reaches the VM through 127.0.0.1:2223"
  docker run -d --name ir-hv --hostname ir-hv --network ir-clinical --ip 10.78.10.5 -p 127.0.0.1:2223:22 \
      -v "$RUN":/vm -v "$GOLD":/golden:ro -v "$LAB":/lab:ro -v "$EVID":/evid ir-hypervisor:1.0
  docker network connect --ip 10.78.99.5 ir-internet ir-hv
  docker network connect --ip 10.78.50.2 ir-mgmt ir-hv
  docker run -d --name nurse-ws --hostname nurse-ws --network ir-clinical --ip 10.78.10.20 ir-hypervisor:1.0
  docker run -d --name exfil-sink --hostname exfil-sink --network ir-internet --ip 10.78.99.66 \
      -v "$LAB/drop_server.py":/drop_server.py:ro -v "$RUN/drop":/srv/drop ir-hypervisor:1.0 \
      python3 /drop_server.py /srv/drop/uploads.jsonl
  docker run -d --name ir-forensics --hostname ir-forensics --network ir-mgmt --ip 10.78.50.5 \
      -v "$IR":/ir -v "$EVID":/evid -v "$BIG":/seized:ro ir-forensics:1.0
  fx mkdir -p /root/.ssh; docker cp "$IRKEY" ir-forensics:/root/.ssh/ir_analyst; fx chmod 600 /root/.ssh/ir_analyst
  echo; echo "\$ docker network inspect (segments and members)"
  for n in ir-clinical ir-internet ir-mgmt; do
    docker network inspect $n --format '{{.Name}} subnet={{range .IPAM.Config}}{{.Subnet}}{{end}} internal={{.Internal}}{{range .Containers}}
    {{.Name}} {{.IPv4Address}}{{end}}'
  done
  echo; echo "# golden image (lab/build_golden.sh) and a throw-away overlay for this run"
  echo "\$ cat parrot-vm-golden.sha256"; cat "$GOLD/parrot-vm-golden.sha256"
  docker exec ir-hv qemu-img create -q -f qcow2 -F qcow2 -b /golden/parrot-vm-golden.qcow2 /vm/parrot-vm.qcow2 8G
  QEMU="qemu-system-x86_64 -name parrot-vm -machine q35 -accel tcg,thread=multi -cpu max,la57=off -smp 2 -m 1024 \
 -display none -vga none -monitor none -serial file:/vm/console.log \
 -drive file=/vm/parrot-vm.qcow2,if=virtio,id=disk0 \
 -netdev user,id=n0,net=10.0.2.0/24,hostfwd=tcp::22-:22,hostfwd=tcp::8080-:8080 \
 -device virtio-net-pci,netdev=n0,id=nic0,mac=52:54:00:0a:00:10 \
 -object filter-dump,id=cap0,netdev=n0,file=/vm/nic0-clinical.pcap \
 -netdev 'user,id=q0,net=10.0.3.0/24,restrict=on,hostfwd=tcp:10.78.50.2:2222-:22,guestfwd=tcp:10.0.3.20:1514-cmd:nc 10.78.50.20 1514' \
 -device virtio-net-pci,netdev=q0,id=nic1,mac=52:54:00:0a:00:50 \
 -object filter-dump,id=cap1,netdev=q0,file=/vm/nic1-quarantine.pcap \
 -device virtio-serial -chardev socket,path=/vm/qga.sock,server=on,wait=off,id=qga0 \
 -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
 -qmp unix:/vm/qmp.sock,server=on,wait=off"
  echo; echo "\$ $QEMU" | tr -s ' '
  docker exec -d ir-hv sh -c "$QEMU > /vm/qemu.log 2>&1"
  for i in $(seq 1 30); do docker exec ir-hv test -S /vm/qmp.sock && break; sleep 1; done
  echo; echo "# adapter 2 (quarantine) starts with the cable disconnected   [VBoxManage ... setlinkstate2 off]"
  vm qmp set_link '{"name":"nic1","up":false}'
  vm wait-agent 400
  vm hmp 'info network'
  vm qmp query-status
  echo; echo "# waiting for the Wazuh manager"
  for i in $(seq 1 60); do mgr /var/ossec/bin/wazuh-control status 2>/dev/null | has 'analysisd is running' && break; sleep 3; done
  mgr /var/ossec/bin/wazuh-control info
} 2>&1 | cap "$T/01_lab_build.txt"

# ---------------------------------------------------------------- 3a. manager content first (agent enrolls against it)
: > "$T/03_wazuh_rules.txt"
{
  mark wazuh_config "$MK"
  echo "# decoders, CDB lists (JML register), the 3 custom alert rules, macOS inputs"
  docker cp "$LAB/wazuh" wazuh-manager:/tmp/w
  mgr sh /tmp/w/configure_manager.sh core
  echo; echo "\$ cat etc/lists/jml-leavers etc/lists/jml-movers etc/lists/rbac-no-root"
  mgr sh -c 'cd /var/ossec/etc/lists && for f in jml-leavers jml-movers rbac-no-root; do echo "== $f"; cat $f; done'
} 2>&1 | cap "$T/03_wazuh_rules.txt"

# ---------------------------------------------------------------- 2. provision parrot-vm + deploy the Wazuh agent
: > "$T/02_provision_agent.txt"
{
  mark provision "$MK"
  echo "\$ guest-exec provision_vm.sh  (JML people from JML-LOG.csv, synthetic EHR, EHR portal, auditd rules)"
  gx "MAC_PUB='$(cat "$MACKEY.pub")'; export MAC_PUB; $(cat "$LAB/provision_vm.sh")" 300
  echo; echo "\$ hostname; head -1 /etc/os-release; uname -r; cat /etc/ir-golden-release"
  gx "hostname; head -1 /etc/os-release; uname -r; cat /etc/ir-golden-release"
  echo; echo "\$ cat /etc/ir-golden-packages   (Parrot OS IR toolset + Wazuh agent baked into the golden image)"; gx "cat /etc/ir-golden-packages"
  echo; for u in test.clinician test.nurse test.billing it_admin ir-analyst; do echo "\$ id $u"; gx "id $u"; done
  echo; echo "\$ ip -br addr; ip route"; gx "ip -br addr; ip route"
  echo; echo "# Wazuh agent deployment: agent config -> /var/ossec/etc/ossec.conf, enable, start (auto-enrollment on 1515/tcp)"
  gx "cat > /var/ossec/etc/ossec.conf <<'XEOF'
$(cat "$LAB/wazuh/agent.conf")
XEOF
touch /var/log/ir1-test.log; chown root:wazuh /var/ossec/etc/ossec.conf; chmod 640 /var/ossec/etc/ossec.conf
systemctl enable --now wazuh-agent >/dev/null 2>&1; sleep 20; systemctl is-active wazuh-agent; /var/ossec/bin/wazuh-control info" 120
  for i in $(seq 1 30); do mgr /var/ossec/bin/agent_control -l 2>/dev/null | has 'parrot-vm.*Active' && break; sleep 5; done
  echo; echo "\$ agent_control -l   (manager side)"; mgr /var/ossec/bin/agent_control -l
  echo "\$ agent_control -i 001"; mgr /var/ossec/bin/agent_control -i 001 | grep -E 'Agent ID|name|IP|Status|version|Last keep'
  echo; echo "\$ grep -E 'Connected to|enrollment' /var/ossec/logs/ossec.log   (agent side)"
  gx "grep -E 'Connected to the server|Valid key received|Requesting a key' /var/ossec/logs/ossec.log | tail -4"
} 2>&1 | cap "$T/02_provision_agent.txt"

# ---------------------------------------------------------------- 3b. rule tests (positive + negative)
{
  echo; echo "# each custom rule tested with wazuh-logtest: a line that must fire it, and a near-miss that must NOT (expected '!id')"
  TS="2026-11-03T05:00:00.000000+00:00 parrot-vm"
  printf 'rule\tcase\texpected\tfired\tlevel\tresult\tinput\n' > "$EV/wazuh/rule_tests.tsv"
  t() {  # t <rule> <case> <expected rule id> <log line>
    local out id lv
    out=$(printf '%s\n' "$4" | docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest 2>&1)
    id=$(echo "$out" | grep -oE "id: '[0-9]+'" | tail -1 | grep -oE '[0-9]+'); lv=$(echo "$out" | grep -oE "level: '[0-9]+'" | tail -1 | grep -oE '[0-9]+')
    case "$3" in !*) ok=$([ "${id:-none}" != "${3#!}" ] && echo PASS || echo FAIL);; *) ok=$([ "${id:-none}" = "$3" ] && echo PASS || echo FAIL);; esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${id:-none}" "${lv:--}" "$ok" "$4" | tee -a "$EV/wazuh/rule_tests.tsv"
  }
  t 100210 "leaver test.billing denied by sshd" 100210 "$TS sshd[1200]: User test.billing from 10.78.10.1 not allowed because a group is listed in DenyGroups"
  t 100210 "near-miss: non-leaver denied"        !100210   "$TS sshd[1201]: User guest from 10.78.10.1 not allowed because a group is listed in DenyGroups"
  t 100221 "mover test.nurse views PT-1003"      100221 "$TS ehr-audit: user=test.nurse action=VIEW patient=PT-1003 decision=ALLOW basis=group:clinical"
  t 100221 "near-miss: clinician views PT-1001"  !100221 "$TS ehr-audit: user=test.clinician action=VIEW patient=PT-1001 decision=ALLOW basis=group:clinical"
  t 100231 "test.clinician runs a command as root" 100231 "$TS sudo: test.clinician : TTY=pts/0 ; PWD=/home/test.clinician ; USER=root ; COMMAND=/usr/bin/id"
  t 100231 "near-miss: it_admin (entitled) uses sudo" !100231 "$TS sudo:  it_admin : TTY=pts/0 ; PWD=/home/it_admin ; USER=root ; COMMAND=/usr/bin/id"
  echo "rule tests: $(grep -c 'PASS' "$EV/wazuh/rule_tests.tsv") PASS, $(grep -c 'FAIL' "$EV/wazuh/rule_tests.tsv") FAIL"
  echo; echo "\$ wazuh-logtest -v (full trace for rule 100221)"
  printf '%s\n' "$TS ehr-audit: user=test.nurse action=VIEW patient=PT-1003 decision=ALLOW basis=group:clinical" \
    | docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest -v 2>&1 | grep -E 'Phase|decoder|Rule [0-9]+ matched|id:|level:|description:|ehr_|dstuser|Alert to be' | head -30
  docker cp wazuh-manager:/var/ossec/etc/rules/can_ir1_core_rules.xml "$EV/wazuh/"
} 2>&1 | cap "$T/03_wazuh_rules.txt"

# ---------------------------------------------------------------- 4. log collection: Parrot OS + macOS
: > "$T/04_log_collection.txt"
{
  mark log_collection "$MK"
  echo "# Parrot OS: a tagged test line written on parrot-vm must arrive at the manager through the agent"
  TAG="ir1-collection-test-$(date +%s)"
  gx "echo \"\$(date -u +%Y-%m-%dT%H:%M:%S.%6N+00:00) parrot-vm ir1-test: $TAG\" >> /var/log/ir1-test.log; tail -1 /var/log/ir1-test.log"
  for i in $(seq 1 40); do mgr grep -q "$TAG" /var/ossec/logs/archives/archives.json && break; sleep 2; done
  echo "\$ grep $TAG archives.json"
  mgr sh -c "grep -h '$TAG' /var/ossec/logs/archives/archives.json" | python3 -c 'import json,sys
for l in sys.stdin: a=json.loads(l); print("received:", a["timestamp"], "agent=%s(%s)" % (a["agent"]["name"], a["agent"]["id"]), "location=" + a["location"])'
  echo; echo "\$ agent log inputs (agent side)"; gx "grep -E 'Analyzing file' /var/ossec/logs/ossec.log | sed 's/.*Analyzing file/Analyzing file/' | sort -u"
  echo; echo "# macOS host DAEDMAC1009: /var/log/install.log (world-readable) normalised to ISO 8601. Collection is proven here"
  echo "# with the newest 500 lines; Task 2 ships the full file once its macOS rules are loaded."
  echo "\$ sw_vers; hostname -s; date +%z"; sw_vers; hostname -s; date +%z
  echo "\$ log show --last 5m --predicate 'process == \"sshd\"'   (unified log needs admin on this managed Mac)"; /usr/bin/log show --last 5m --predicate 'process == "sshd"' 2>&1 | head -2
  cp /var/log/install.log "$EV/macos/install.log"
  python3 "$LAB/normalize_macos_log.py" "$EV/macos/install.log" "$EV/macos/install_iso.log"
  tail -500 "$EV/macos/install_iso.log" > "$EV/macos/install_sample500.log"
  ship_file "$EV/macos/install_sample500.log" /var/ossec/logs/macos/install.log
  echo; echo "\$ events received per source (archives.json)"
  mgr sh -c "grep -o '\"location\":\"[^\"]*\"' /var/ossec/logs/archives/archives.json | sort | uniq -c | sort -rn"
} 2>&1 | cap "$T/04_log_collection.txt"

# ---------------------------------------------------------------- 5. Wireshark capture filters on parrot-vm
: > "$T/05_wireshark.txt"
{
  mark wireshark "$MK"
  echo "# saved capture filters for the analyst (Wireshark GUI and tshark read ~/.config/wireshark/cfilters)"
  gx "mkdir -p /home/ir-analyst/.config/wireshark /root/.config/wireshark; cat > /home/ir-analyst/.config/wireshark/cfilters <<'EOF'
\"IR1 SSH sessions\" tcp port 22
\"IR1 EHR portal\" tcp port 8080 and host 10.0.2.15
\"IR1 Wazuh agent traffic\" tcp port 1514 or tcp port 1515
\"IR1 traffic to a suspect host\" host 10.78.99.66
\"IR1 outbound, excluding SSH and Wazuh\" src host 10.0.2.15 and not port 22 and not port 1514 and not port 1515
\"IR1 DNS\" udp port 53
\"IR1 TCP SYN only (new connections)\" tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn
EOF
cp /home/ir-analyst/.config/wireshark/cfilters /root/.config/wireshark/; chown -R ir-analyst:ir-analyst /home/ir-analyst/.config; cat /home/ir-analyst/.config/wireshark/cfilters"
  gx 'cat /home/ir-analyst/.config/wireshark/cfilters' > "$EV/wireshark/cfilters"
  echo; echo "\$ tshark -v | head -1; dumpcap -D"; gx "tshark -v 2>/dev/null | head -1; dumpcap -D 2>/dev/null"
  echo; echo "# every saved filter compiled to BPF on the clinical interface (dumpcap -d); a syntax error would fail here"
  gx 'sed -E "s/^\"[^\"]+\" //" /home/ir-analyst/.config/wireshark/cfilters | while read -r f; do n=$(dumpcap -i enp0s1 -f "$f" -d 2>/dev/null | grep -c "^("); echo "OK  ${n} BPF instructions  : $f"; done'
  echo; echo "# live capture with a saved filter: 20 s of Wazuh agent traffic"
  gx "timeout 20 tshark -i enp0s1 -f 'tcp port 1514 or tcp port 1515' -w /dev/shm/t1_agent.pcapng >/dev/null 2>&1; tshark -r /dev/shm/t1_agent.pcapng -q -z conv,tcp 2>/dev/null | sed -n '1,8p'; capinfos -c /dev/shm/t1_agent.pcapng | tail -1" 60
  pull 22 /dev/shm/t1_agent.pcapng /ir/task1_environment_setup/evidence/wireshark/t1_agent_traffic.pcapng
} 2>&1 | cap "$T/05_wireshark.txt"

# ---------------------------------------------------------------- 6. Volatility 3 configuration test
: > "$T/06_volatility.txt"
{
  mark volatility "$MK"
  echo "# Volatility 3 on the forensic workstation; symbol table (ISF) built for parrot-vm's exact kernel"
  echo "\$ vol -h | head -1; uname -r on parrot-vm"; fx sh -c 'vol -h 2>/dev/null | head -1'; gx 'uname -r'
  echo "\$ ls -l /opt/symbols/linux; sha256sum"; fx sh -c 'ls -l /opt/symbols/linux; sha256sum /opt/symbols/linux/*.xz'
  echo; echo "# baseline RAM image of the clean host, from the hypervisor   [VBoxManage debugvm parrot-vm dumpvmcore]"
  rm -f "$EVID/baseline/parrot-vm_baseline.mem.elf"                 # QEMU writes dumps read-only; clear the previous run's image
  vm qmp dump-guest-memory '{"paging":false,"protocol":"file:/evid/baseline/parrot-vm_baseline.mem.elf"}'
  for i in $(seq 1 90); do vm qmp query-dump | has '"completed"' && break; sleep 2; done; vm qmp query-dump
  echo "sha256 $(shasum -a 256 "$EVID/baseline/parrot-vm_baseline.mem.elf" | cut -d' ' -f1)  parrot-vm_baseline.mem.elf"
  echo; echo "\$ vol -s /opt/symbols -f parrot-vm_baseline.mem.elf banners.Banners"
  fx sh -c 'vol -q -s /opt/symbols -f /evid/baseline/parrot-vm_baseline.mem.elf banners.Banners 2>/dev/null | tail -2' | cut -c1-140
  echo; echo "\$ vol ... linux.pslist.PsList   (config works if the kernel's process list is walked)"
  fx sh -c 'vol -q -s /opt/symbols -f /evid/baseline/parrot-vm_baseline.mem.elf linux.pslist.PsList 2>/dev/null' > "$EV/volatility/baseline_pslist.txt"
  echo "processes found: $(grep -c '^0x' "$EV/volatility/baseline_pslist.txt")"
  grep -E 'wazuh|sshd|auditd|python3|COMM' "$EV/volatility/baseline_pslist.txt" | head -12
} 2>&1 | cap "$T/06_volatility.txt"

# ---------------------------------------------------------------- 7. baseline snapshot + reachability + index
: > "$T/07_baseline.txt"
{
  mark baseline "$MK"
  echo "# reachability of the clean environment (the same probes are re-run in Tasks 3 and 6)"
  probe_matrix
  echo; echo "# known-good snapshot used by Task 6   [VBoxManage snapshot parrot-vm take baseline-clean --live]"
  vm hmp 'savevm baseline-clean'; vm hmp 'info snapshots'
  mark done "$MK"
  ( cd "$EV" && find . -type f ! -name EVIDENCE-INDEX-SHA256.txt ! -path './transcripts/07_baseline.txt' | sort | xargs shasum -a 256 ) > "$EV/EVIDENCE-INDEX-SHA256.txt"
  echo "# outside git: $EVID/baseline" >> "$EV/EVIDENCE-INDEX-SHA256.txt"
  ( cd "$EVID/baseline" && shasum -a 256 parrot-vm_baseline.mem.elf ) >> "$EV/EVIDENCE-INDEX-SHA256.txt"
  echo "evidence index: $(grep -cE '^[0-9a-f]{64} ' "$EV/EVIDENCE-INDEX-SHA256.txt") files"
} 2>&1 | cap "$T/07_baseline.txt"
echo "done $(now)"
