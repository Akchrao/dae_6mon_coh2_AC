#!/usr/bin/env bash
# =============================================================================
# Care Access Navigator - Incident Response 1, Task 2: Log Analysis with Wazuh
# -----------------------------------------------------------------------------
# Docker Desktop only, no admin rights. Builds:
#   wazuh-manager  real Wazuh 4.9.2 manager (amd64 image, emulated on Apple silicon)
#   parrot-sim     Debian 12 Parrot OS stand-in; rsyslog forwards auth/authpriv/local5
#                  to the manager over syslog/UDP 514 (agentless collection)
#   macOS host     DAEDMAC1009 itself: /var/log/install.log plus a timestamped trail of
#                  every SSH session it opens to parrot-sim (host_ssh_logged.py), both
#                  shipped to the manager as localfile inputs
#
# The scenario replays the people from the Entra ID / Keycloak JML cycle
# (capstone_next_steps/jml-evidence/JML-LOG.csv) on the Linux host:
#   Sathya Hasi  test.clinician  joiner -> Clinician
#   Tara Jones   test.nurse      mover  Nurse -> Billing
#   Jeevan Smith test.billing    leaver (disabled)
# All SSH sessions come from the macOS host through the published port 127.0.0.1:2222.
# Patient records are SYNTHETIC. Run:  bash run_lab.sh
# =============================================================================
set -uo pipefail   # not -e: evidence steps may exit non-zero and must still be recorded
cd "$(dirname "$0")"
LABDIR="$(pwd)"; ROOT="$(cd .. && pwd)"
EV="$ROOT/evidence"; T="$EV/transcripts"; W="$ROOT/wazuh"
NET=ir2-labnet
KEYS="$LABDIR/.keys"; KEY="$KEYS/ir2_lab_ed25519"
MACLOG="$EV/macos/ssh_client.log"
TMPD=$(mktemp -d)
mkdir -p "$T" "$EV/macos" "$EV/parrot" "$EV/wazuh" "$EV/pcap" "$KEYS"

cap() { tee -a "$1"; }
ex()  { docker exec parrot-sim "$@"; }
mgr() { docker exec wazuh-manager "$@"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
# every SSH session from the Mac goes through the logging wrapper
SSH() { python3 "$LABDIR/host_ssh_logged.py" "$MACLOG" -i "$KEY" -p 2222 -o IdentitiesOnly=yes \
          -o StrictHostKeyChecking=no -o UserKnownHostsFile="$KEYS/known_hosts" -o ConnectTimeout=6 "$@"; }

# lab-only passwords (sudo prompts); never written to evidence
PW_C=$(openssl rand -hex 12); PW_N=$(openssl rand -hex 12)

# ---------------------------------------------------------------- 0. start fresh
docker rm -f parrot-sim wazuh-manager >/dev/null 2>&1 || true
docker network rm $NET >/dev/null 2>&1 || true
: > "$MACLOG"; rm -f "$KEYS/known_hosts"
[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -C 'ir2-lab-macos-host' -f "$KEY"

# ---------------------------------------------------------------- 1. build, network, Wazuh manager
: > "$T/01_build_and_wazuh.txt"
{
  echo "# IR1 Task2 lab run - $(now) - host $(hostname -s) ($(uname -sm))"
  echo "\$ docker version --format '{{.Server.Version}} / {{.Server.Arch}}'"
  docker version --format '{{.Server.Version}} / {{.Server.Arch}}'
  echo; echo "\$ docker build -t ir1-parrot-sim:1.0 -f Dockerfile.parrot-sim ."
  docker build -q -t ir1-parrot-sim:1.0 -f Dockerfile.parrot-sim .
  echo; echo "# lab network. Not --internal: Docker cannot publish a port from an internal network, and"
  echo "# the macOS host must reach parrot-sim. The port is bound to 127.0.0.1 only."
  echo "\$ docker network create --subnet 10.77.0.0/24 $NET"
  docker network create --subnet 10.77.0.0/24 $NET
  echo; echo "\$ docker run -d --platform linux/amd64 --name wazuh-manager --network $NET --ip 10.77.0.20 wazuh/wazuh-manager:4.9.2"
  docker run -d --platform linux/amd64 --name wazuh-manager --hostname wazuh-manager \
      --network $NET --ip 10.77.0.20 wazuh/wazuh-manager:4.9.2
  echo "# waiting for wazuh-analysisd ..."
  for i in $(seq 1 40); do mgr /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q 'analysisd is running' && break; sleep 3; done
  echo; echo "\$ /var/ossec/bin/wazuh-control info"; mgr /var/ossec/bin/wazuh-control info
  echo; echo "# install Task 2 decoders, rules, CDB lists, syslog listener and macOS inputs"
  echo "\$ sh configure_manager.sh"
  docker cp "$W" wazuh-manager:/tmp/task2
  mgr sh /tmp/task2/configure_manager.sh
  echo; echo "\$ grep -c '<rule id' local_rules.xml ; grep -c '<decoder name' local_decoder.xml"
  echo "custom rules: $(grep -c '<rule id' "$W/local_rules.xml")   custom decoders: $(grep -c '<decoder name' "$W/local_decoder.xml")"
  echo "\$ grep 'remoted' ossec.log | tail -2"; mgr sh -c "grep 'wazuh-remoted' /var/ossec/logs/ossec.log | tail -2"
} 2>&1 | cap "$T/01_build_and_wazuh.txt"

# ---------------------------------------------------------------- 2. Parrot host + log forwarding
: > "$T/02_parrot_logging.txt"
{
  echo "\$ docker run -d --name parrot-sim --network $NET --ip 10.77.0.10 -p 127.0.0.1:2222:22 ir1-parrot-sim:1.0"
  docker run -d --name parrot-sim --hostname parrot-sim --network $NET --ip 10.77.0.10 \
      -p 127.0.0.1:2222:22 ir1-parrot-sim:1.0
  echo "\$ docker port parrot-sim"; docker port parrot-sim
  echo "\$ docker network inspect $NET"
  docker network inspect $NET --format 'network={{.Name}} subnet={{range .IPAM.Config}}{{.Subnet}} gw={{.Gateway}}{{end}}{{range .Containers}}
  host={{.Name}} ip={{.IPv4Address}}{{end}}'
  echo; echo "\$ cat /etc/os-release | head -1"; ex sh -c "head -1 /etc/os-release"
  echo; echo "# rsyslog: keep local files AND forward auth/authpriv/local5 to the Wazuh manager"
  echo "\$ cat /etc/rsyslog.d/60-wazuh.conf"
  ex sh -c 'cat > /etc/rsyslog.d/60-wazuh.conf <<EOF
local5.*                     /var/log/ehr-audit.log
template(name="WazuhFwd" type="string" string="%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg%\n")
auth,authpriv.*;local5.*     action(type="omfwd" target="10.77.0.20" port="514" protocol="udp" template="WazuhFwd")
EOF
cat /etc/rsyslog.d/60-wazuh.conf; rsyslogd 2>/dev/null; sleep 1; pgrep -a rsyslogd'
  echo; echo "# sshd: verbose auth logging, keys only, deprovisioned accounts blocked by group"
  echo "\$ cat /etc/ssh/sshd_config.d/ir-lab.conf"
  ex sh -c "printf 'LogLevel VERBOSE\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nDenyGroups disabled-users\n' > /etc/ssh/sshd_config.d/ir-lab.conf; cat /etc/ssh/sshd_config.d/ir-lab.conf; ssh-keygen -A >/dev/null 2>&1; /usr/sbin/sshd; sleep 1; ss -ltn | grep ':22 '"
  echo; echo "# collection test: one tagged message must arrive in the manager's archive"
  echo "\$ logger -p auth.info 'ir2-collection-test'"
  ex logger -p auth.info "ir2-collection-test $(now)"; sleep 5
  mgr sh -c "grep -c 'ir2-collection-test' /var/ossec/logs/archives/archives.json | sed 's/^/events received by manager: /'"
} 2>&1 | cap "$T/02_parrot_logging.txt"

# ---------------------------------------------------------------- 3. JML state on the Linux host
: > "$T/03_jml_provisioning.txt"
docker cp "$LABDIR/ehr-view" parrot-sim:/usr/local/bin/ehr-view
docker cp "$KEY.pub" parrot-sim:/tmp/mac_host_key.pub
{
  echo "# mirrors JML-LOG.csv (REQ-2026-0101, CHG-2026-0201, TERM-2026-0301) on parrot-sim"
  ex sh -c '
    chmod 755 /usr/local/bin/ehr-view
    groupadd clinical; groupadd billing; groupadd disabled-users
    useradd -m -s /bin/bash -G sudo it_admin -c "IT Administrator (lab)"
    echo "it_admin ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/it_admin; chmod 440 /etc/sudoers.d/it_admin
    # joiner REQ-2026-0101: Sathya Hasi -> Clinician
    useradd -m -s /bin/bash -G clinical  -c "Sathya Hasi (Physician)"        test.clinician
    # mover CHG-2026-0201: Tara Jones Nurse -> Billing. Billing added; clinical NOT removed on this host.
    useradd -m -s /bin/bash -G clinical  -c "Tara Jones (RN)"                test.nurse
    usermod -aG billing -c "Tara Jones (Billing Specialist)" test.nurse
    # leaver TERM-2026-0301: Jeevan Smith - locked, expired, put in DenyGroups. Key file left in place.
    useradd -m -s /bin/bash -G billing   -c "Jeevan Smith (Billing Specialist)" test.billing
    usermod -L -e 1 -aG disabled-users test.billing
    for u in test.clinician test.nurse test.billing; do
      install -d -m 700 -o $u -g $u /home/$u/.ssh
      install -m 600 -o $u -g $u /tmp/mac_host_key.pub /home/$u/.ssh/authorized_keys
    done
    mkdir -p /srv/ehr/clinical
    printf "SYNTHETIC RECORD PT-1001\nPatient: Test Patient One\nDx: hypertension (synthetic)\n" > /srv/ehr/clinical/PT-1001.txt
    printf "SYNTHETIC RECORD PT-1003\nPatient: Test Patient Three\nDx: type 2 diabetes (synthetic)\n" > /srv/ehr/clinical/PT-1003.txt
    chgrp -R clinical /srv/ehr/clinical; chmod 750 /srv/ehr/clinical; chmod 640 /srv/ehr/clinical/*'
  ex sh -c "echo 'test.clinician:$PW_C' | chpasswd; echo 'test.nurse:$PW_N' | chpasswd"
  echo "(lab passwords set for test.clinician and test.nurse; values not recorded)"
  for u in test.clinician test.nurse test.billing it_admin; do echo "\$ id $u"; ex id $u; done
  echo "\$ getent passwd test.clinician test.nurse test.billing | cut -d: -f1,5"
  ex sh -c "getent passwd test.clinician test.nurse test.billing | cut -d: -f1,5"
  echo "\$ passwd -S test.billing ; chage -l test.billing | grep 'Account expires'"
  ex sh -c "passwd -S test.billing; chage -l test.billing | grep 'Account expires'"
  echo "\$ sshd -T | grep -E '^(loglevel|denygroups|passwordauthentication)'"
  ex sh -c "sshd -T 2>/dev/null | grep -E '^(loglevel|denygroups|passwordauthentication)'"
  echo "\$ ls -l /srv/ehr/clinical"; ex ls -l /srv/ehr/clinical
} 2>&1 | cap "$T/03_jml_provisioning.txt"

# ---------------------------------------------------------------- 4. packet capture on parrot-sim
: > "$T/04_scenario.txt"
docker exec -d parrot-sim sh -c "tshark -i eth0 -f 'tcp port 22' -a duration:240 -w /tmp/ssh_sessions.pcapng >/tmp/capture.log 2>&1"
sleep 3

# ---------------------------------------------------------------- 5. scenario (all sessions from the Mac)
{
  echo "# Scenario run from macOS host $(hostname -s); UTC times; ssh = macOS $(ssh -V 2>&1)"
  echo; echo "[$(now)] S1 baseline - Sathya Hasi (test.clinician) views her patient PT-1001"
  SSH test.clinician@127.0.0.1 'ehr-view PT-1001 | head -1'
  sleep 15
  echo; echo "[$(now)] S2 it_admin adds test.clinician to the sudo group (no change ticket)"
  echo "\$ docker exec -u it_admin parrot-sim sudo -n usermod -aG sudo test.clinician"
  docker exec -u it_admin parrot-sim sudo -n /usr/sbin/usermod -aG sudo test.clinician
  sleep 15
  echo; echo "[$(now)] S3 Sathya Hasi (test.clinician) runs a command as root"
  printf '%s\n' "$PW_C" | SSH test.clinician@127.0.0.1 'sudo -S -p "" id'
  sleep 20
  echo; echo "[$(now)] S4a Tara Jones (test.nurse, now Billing) opens clinical record PT-1003"
  SSH test.nurse@127.0.0.1 'ehr-view PT-1003 | head -1'
  sleep 10
  echo; echo "[$(now)] S4b Tara Jones tries to read the record as root"
  printf '%s\n' "$PW_N" | SSH test.nurse@127.0.0.1 'sudo -S -p "" cat /srv/ehr/clinical/PT-1003.txt'
  sleep 20
  echo; echo "[$(now)] S5a login attempt as Jeevan Smith (test.billing, leaver)"
  SSH -o BatchMode=yes test.billing@127.0.0.1 true
  sleep 25
  echo; echo "[$(now)] S5b second login attempt as test.billing"
  SSH -o BatchMode=yes test.billing@127.0.0.1 true
  sleep 5
  echo; echo "[$(now)] scenario complete"
} 2>&1 | cap "$T/04_scenario.txt"

# ---------------------------------------------------------------- 6. stop capture, read client banners
: > "$T/05_capture.txt"
{
  ex sh -c "pkill -INT tshark; sleep 3; cat /tmp/capture.log | tail -2"
  docker cp parrot-sim:/tmp/ssh_sessions.pcapng "$EV/pcap/ssh_sessions.pcapng"
  echo "\$ tshark -r ssh_sessions.pcapng -q -z conv,tcp | head"
  ex sh -c "tshark -r /tmp/ssh_sessions.pcapng -q -z conv,tcp 2>/dev/null | sed -n '1,20p'"
  echo; echo "# SSH identification strings sent by the CLIENT (dst port 22) - identifies the client software"
  echo "\$ tshark -r ssh_sessions.pcapng -Y 'ssh.protocol && tcp.dstport==22' -T fields -e frame.time_epoch -e ip.src -e tcp.srcport -e ssh.protocol"
  ex sh -c "tshark -r /tmp/ssh_sessions.pcapng -Y 'ssh.protocol && tcp.dstport==22' -T fields -E separator=, -e frame.time_epoch -e ip.src -e tcp.srcport -e ssh.protocol 2>/dev/null" \
    | tee "$EV/pcap/client_banners.csv"
} 2>&1 | cap "$T/05_capture.txt"

# ---------------------------------------------------------------- 7. macOS host logs -> Wazuh
: > "$T/06_macos_logs.txt"
{
  echo "\$ sw_vers ; hostname -s ; date +%z ; ssh -V"
  sw_vers; hostname -s; date +%z; ssh -V 2>&1
  echo; echo "# unified log (auth events) needs admin on this host - recorded as a limitation"
  echo "\$ log show --last 1h --predicate 'process == \"sshd\"'"
  /usr/bin/log show --last 1h --predicate 'process == "sshd"' 2>&1 | head -2
  echo; echo "# 1) /var/log/install.log (world-readable): copy, then normalise the timestamp to ISO 8601"
  echo "#    ('2026-10-20 11:55:22-04 HOST' -> '2026-10-20T11:55:22-04:00 HOST') so Wazuh pre-decodes it"
  cp /var/log/install.log "$EV/macos/install.log"
  python3 "$ROOT/analysis/normalize_macos_log.py" "$EV/macos/install.log" "$EV/macos/install_iso.log"
  wc -l "$EV/macos/install.log" "$EV/macos/install_iso.log" | sed "s#$EV/##"
  echo; echo "# 2) ssh client trail written by host_ssh_logged.py during the scenario"
  echo "\$ wc -l ssh_client.log ; grep 'Authenticating to' ssh_client.log"
  wc -l < "$MACLOG"; grep 'Authenticating to' "$MACLOG"
  echo; echo "# ship both files to the manager's localfile inputs (as a macOS agent would)"
  # in 500-line batches: one bulk append overflows logcollector's 1024-message queue and drops lines
  split -l 500 "$EV/macos/install_iso.log" "$TMPD"/install_part_
  for part in "$TMPD"/install_part_*; do
    docker exec -i wazuh-manager sh -c 'cat >> /var/ossec/logs/macos/install.log' < "$part"; sleep 3
  done
  rm -f "$TMPD"/install_part_*
  docker exec -i wazuh-manager sh -c 'cat >> /var/ossec/logs/macos/ssh_client.log' < "$MACLOG"
  echo "shipped at $(now); waiting for analysisd"
  sleep 45
  echo "\$ lines shipped vs events received by the manager (must match)"
  echo "install.log   shipped=$(grep -c . "$EV/macos/install_iso.log")  received=$(mgr sh -c "grep -c 'macos/install.log' /var/ossec/logs/archives/archives.json")"
  echo "ssh_client.log shipped=$(grep -c . "$MACLOG")  received=$(mgr sh -c "grep -c 'macos/ssh_client.log' /var/ossec/logs/archives/archives.json")"
  mgr sh -c "grep -c 'queue is full' /var/ossec/logs/ossec.log | sed 's/^/logcollector queue-full warnings: /'"
} 2>&1 | cap "$T/06_macos_logs.txt"

# ---------------------------------------------------------------- 8. export Wazuh + host evidence
: > "$T/07_export.txt"
{
  docker cp wazuh-manager:/var/ossec/logs/alerts/alerts.json "$EV/wazuh/alerts.json"
  docker cp wazuh-manager:/var/ossec/etc/ossec.conf "$EV/wazuh/ossec.conf"
  docker cp parrot-sim:/var/log/auth.log      "$EV/parrot/auth.log"
  docker cp parrot-sim:/var/log/ehr-audit.log "$EV/parrot/ehr-audit.log"
  echo "\$ events received by the manager, per source (archives.json, logall_json=yes)"
  mgr sh -c "grep -o '\"location\":\"[^\"]*\"' /var/ossec/logs/archives/archives.json | sort | uniq -c"
  echo; echo "\$ alerts per rule (alerts.json)"
  python3 -c "
import json,collections
c=collections.Counter()
for l in open('$EV/wazuh/alerts.json'):
    a=json.loads(l); r=a['rule']; c[(r['id'],r['level'],r['description'][:70])]+=1
for (i,lv,d),n in sorted(c.items(),key=lambda x:(-x[0][1],x[0][0])): print(f'{n:6}  rule {i:>6}  L{lv:<2} {d}')"
  echo; echo "# alert validation: replay the raw leaver events through wazuh-logtest -v (rule trace)"
  grep -m1 'test.billing.*DenyGroups' "$EV/parrot/auth.log" > "$TMPD/replay.txt"
  echo "\$ wazuh-logtest -v < $(cat "$TMPD/replay.txt" | cut -c1-60)..."
  docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest -v < "$TMPD/replay.txt" 2>&1 \
    | grep -E '\*Rule [0-9]+ matched|^\s+(id|level|description|firedtimes):|Alert to be generated' | tee "$T/08_logtest_trace.txt"
} 2>&1 | cap "$T/07_export.txt"

# ---------------------------------------------------------------- 9. analysis + evidence integrity
[ -f "$ROOT/analysis/analyze.py" ] && python3 "$ROOT/analysis/analyze.py" --evidence "$EV" --jml "$ROOT/../../capstone_next_steps/jml-evidence/JML-LOG.csv" 2>&1 | tee "$T/09_analysis.txt"
( cd "$EV" && find . -type f ! -name 'EVIDENCE-INDEX-SHA256.txt' -print0 | sort -z | xargs -0 shasum -a 256 > EVIDENCE-INDEX-SHA256.txt )
echo; echo "DONE. Evidence in: $EV"
echo "Tear down:  docker rm -f parrot-sim wazuh-manager && docker network rm $NET"
