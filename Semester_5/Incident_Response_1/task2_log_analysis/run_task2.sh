#!/usr/bin/env bash
# =============================================================================
# Care Access Navigator - Incident Response 1, Task 2: Incident Detection and Analysis
# -----------------------------------------------------------------------------
# Runs on the lab built by Task 1. Two phases, with Task 3 in between (lab/run_all.sh calls them in order):
#
#   bash run_task2.sh scenario   load the Task 2 rules, start captures, replay the JML people's activity from the
#                                Mac, and wait for Wazuh to raise the SEV-1 alert (rule 100221). Its time is the
#                                detection time that starts containment (Task 3).
#   bash run_task2.sh analysis   after containment: ship the Mac's SSH log, export Wazuh's alerts and the Parrot logs,
#                                validate alerts, correlate the suspicious leaver login across hosts, build timelines,
#                                and classify the three incidents with the severity matrix.
#
# Scenario (all sessions start on the Mac; patient records are SYNTHETIC):
#   S1 Sathya Hasi (joiner) views her patient PT-1001                         normal work
#   S2 it_admin adds Sathya to sudo with no change ticket                      -> IR1-2026-003
#   S3 Sathya runs a command as root                                           -> IR1-2026-003
#   S4 Jeevan Smith (leaver) tries to log in, twice                            -> IR1-2026-001
#   S5 Tara Jones (mover, now Billing) opens PT-1003 through her old clinical
#      group, stages it, starts an uploader and a cron job to keep it running  -> IR1-2026-002
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lab/lab_common.sh"
TASK="$IR/task2_log_analysis"; EV="$TASK/evidence"; T="$EV/transcripts"; MK="$EV/markers.csv"
mkdir -p "$T" "$EV"/{wazuh,parrot,macos,pcap,analysis}
PHASE="${1:-}"

if [ "$PHASE" = scenario ]; then
echo "phase,utc" > "$MK"
# ---------------------------------------------------------------- 1. Task 2 rules + captures
: > "$T/01_rules_and_capture.txt"
{
  mark task2_rules "$MK"
  echo "# Task 2 adds analysis rules on top of the Task 1 core rules"
  docker cp "$LAB/wazuh" wazuh-manager:/tmp/w2 && mgr sh -c 'rm -rf /tmp/w; mv /tmp/w2 /tmp/w'
  mgr sh /tmp/w/configure_manager.sh task2
  for i in $(seq 1 40); do mgr /var/ossec/bin/agent_control -l 2>/dev/null | has 'parrot-vm.*Active' && break; sleep 3; done
  mgr /var/ossec/bin/agent_control -l | grep parrot-vm
  echo; echo "# macOS host: the full install.log (Task 1 proved the path with a sample), now analysed by the Task 2 macOS rules"
  ship_file "$IR/task1_environment_setup/evidence/macos/install_iso.log" /var/ossec/logs/macos/install.log
  echo; echo "# packet capture on parrot-vm, SSH only (saved filter 'IR1 SSH sessions'), for the whole scenario"
  gx "nohup tshark -i enp0s1 -f 'tcp port 22' -a duration:1800 -w /dev/shm/t2_ssh.pcapng >/dev/shm/t2_cap.log 2>&1 & sleep 3; pgrep -a tshark"
  echo; echo "# lab-only sudo passwords for the people who use sudo in the scenario (values never recorded)"
  PW_C=$(openssl rand -hex 12); echo "$PW_C" > "$RUN/.pw_c"; chmod 600 "$RUN/.pw_c"
  gx "echo 'test.clinician:$PW_C' | chpasswd && echo 'password set for test.clinician'"
} 2>&1 | cap "$T/01_rules_and_capture.txt"

# ---------------------------------------------------------------- 2. scenario (from the Mac)
: > "$T/02_scenario.txt"
{
  echo "# Scenario run from macOS host $(hostname -s); UTC; ssh = $(ssh -V 2>&1)"
  mark scenario_start "$MK"
  echo; echo "[$(now)] S1 Sathya Hasi (test.clinician, joiner) views her patient PT-1001"
  SSH test.clinician@127.0.0.1 'ehr-view PT-1001 | head -1'
  sleep 10
  echo; echo "[$(now)] S2 it_admin adds test.clinician to the sudo group (no change ticket)"
  gx "su - it_admin -c 'sudo -n /usr/sbin/usermod -aG sudo test.clinician' && id test.clinician"
  sleep 10
  echo; echo "[$(now)] S3 Sathya Hasi runs a command as root"
  SSH test.clinician@127.0.0.1 'sudo -S -p "" id' < "$RUN/.pw_c"
  sleep 15
  echo; echo "[$(now)] S4a login attempt as Jeevan Smith (test.billing, leaver)"
  SSH -o BatchMode=yes test.billing@127.0.0.1 true
  sleep 20
  echo; echo "[$(now)] S4b second login attempt as test.billing"
  SSH -o BatchMode=yes test.billing@127.0.0.1 true
  sleep 15
  mark s5_start "$MK"
  echo; echo "[$(now)] S5a Tara Jones (test.nurse, now Billing) logs in and checks her groups"
  SSH test.nurse@127.0.0.1 'id; hostname'
  echo; echo "[$(now)] S5b opens clinical record PT-1003 and stages a copy in a hidden folder"
  SSH test.nurse@127.0.0.1 'mkdir -p ~/.cache/.sync && ehr-view PT-1003 > ~/.cache/.sync/pt1003.txt && ls -la ~/.cache/.sync'
  echo; echo "[$(now)] S5c drops syncd.py (uploader) next to it"
  SSH test.nurse@127.0.0.1 'cat > ~/.cache/.sync/syncd.py && chmod 700 ~/.cache/.sync/syncd.py && sha256sum ~/.cache/.sync/syncd.py' < "$LAB/syncd.py"
  echo; echo "[$(now)] S5d starts it detached from the session"
  SSH test.nurse@127.0.0.1 'setsid nohup python3 ~/.cache/.sync/syncd.py >/dev/null 2>&1 < /dev/null & sleep 1; pgrep -af syncd.py'
  echo; echo "[$(now)] S5e adds a cron job that restarts it (persistence)"
  SSH test.nurse@127.0.0.1 '(crontab -l 2>/dev/null; echo "*/5 * * * * pgrep -f syncd.py >/dev/null || setsid python3 \$HOME/.cache/.sync/syncd.py >/dev/null 2>&1 &") | crontab - && crontab -l'
  mark s5_done "$MK"
} 2>&1 | cap "$T/02_scenario.txt"

# ---------------------------------------------------------------- 3. detection
: > "$T/03_detection.txt"
{
  echo "# waiting for Wazuh to alert on the mover's record access (rule 100221, level 12)"
  DT=$(wait_alert 100221 180)
  if [ -n "$DT" ]; then
    echo "detection,$(python3 -c "import datetime as d,sys; print(d.datetime.strptime(sys.argv[1][:19],'%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%SZ'))" "$DT")" >> "$MK"
    echo "rule 100221 fired at $DT"
    alerts_for 100221 | head -1 | python3 -c 'import json,sys; a=json.loads(sys.stdin.read()); print(json.dumps({k: a[k] for k in ("timestamp","rule","agent","location","full_log","data") if k in a}, indent=1))' | cut -c1-160
  else
    echo "NO ALERT for rule 100221 within 180 s"; exit 1
  fi
  echo; echo "# alerts raised so far by the IR1 rules (triage queue, highest level first)"
  mgr sh -c "grep -h '\"groups\":\[\"care_access_navigator' /var/ossec/logs/alerts/alerts.json" | python3 -c '
import json, sys
rows = [json.loads(l) for l in sys.stdin]
for a in sorted(rows, key=lambda a: (-a["rule"]["level"], a["timestamp"])):
    print(a["timestamp"][11:23], "L%-2d" % a["rule"]["level"], a["rule"]["id"], a["rule"]["description"][:90])'
  echo; echo "# FIM (syscheck) alerts from the agent on the persistence paths"
  mgr sh -c "grep -h '\"syscheck\"' /var/ossec/logs/alerts/alerts.json" | python3 -c '
import json, sys
for l in sys.stdin:
    a = json.loads(l); print(a["timestamp"][11:23], a["rule"]["id"], a["rule"]["description"][:50], a.get("syscheck", {}).get("path", ""))' | tail -8
} 2>&1 | cap "$T/03_detection.txt"
exit 0
fi

if [ "$PHASE" = analysis ]; then
# ---------------------------------------------------------------- 4. macOS SSH trail -> Wazuh
: > "$T/04_macos_logs.txt"
{
  mark analysis_start "$MK"
  echo "# the Mac's SSH client trail (host_ssh_logged.py) shipped to the manager's macOS input"
  echo "\$ wc -l ssh_client.log; grep 'Authenticating to' ssh_client.log"; wc -l < "$MACLOG"; grep 'Authenticating to' "$MACLOG" | cut -c1-140
  ship_file "$MACLOG" /var/ossec/logs/macos/ssh_client.log; sleep 15
  cp "$IR/task1_environment_setup/evidence/macos/install.log" "$EV/macos/install.log"
} 2>&1 | cap "$T/04_macos_logs.txt"

# ---------------------------------------------------------------- 5. export
: > "$T/05_export.txt"
{
  docker cp wazuh-manager:/var/ossec/logs/alerts/alerts.json "$EV/wazuh/alerts.json"
  docker cp wazuh-manager:/var/ossec/etc/ossec.conf "$EV/wazuh/manager_ossec.conf"
  echo "# Parrot logs pulled over the forensic path (the host is contained by now)"
  for f in /var/log/auth.log /var/log/ehr-audit.log; do
    pull 2222 $f /ir/task2_log_analysis/evidence/parrot/$(basename $f)
  done
  fx sh -c "$FS -p 2222 ir-analyst@10.78.50.2 'sudo pkill -INT tshark; sleep 2; sudo cat /dev/shm/t2_ssh.pcapng'" > "$EV/pcap/ssh_sessions.pcapng"
  echo; echo "\$ events received by the manager, per source"
  mgr sh -c "grep -o '\"location\":\"[^\"]*\"' /var/ossec/logs/archives/archives.json | sort | uniq -c | sort -rn"
  echo; echo "# SSH client identification strings in the capture (client -> port 22)"
  fx sh -c "tshark -r /ir/task2_log_analysis/evidence/pcap/ssh_sessions.pcapng -Y 'ssh.protocol && tcp.dstport==22' -T fields -E separator=, -e frame.time_epoch -e ip.src -e tcp.srcport -e ssh.protocol 2>/dev/null" \
    | tee "$EV/pcap/client_banners.csv"
  echo; echo "# alert validation: replay the raw leaver denial through wazuh-logtest -v (rule trace)"
  grep -m1 'test.billing.*not allowed' "$EV/parrot/auth.log" | docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest -v 2>&1 \
    | grep -E '\*Rule [0-9]+ matched|^\s+(id|level|description):|Alert to be generated' | tee "$T/06_logtest_trace.txt"
} 2>&1 | cap "$T/05_export.txt"

# ---------------------------------------------------------------- 5b. host-side validation of the macOS findings
: > "$T/08_macos_validation.txt"
{
  echo "# patch level: installed version vs the updates install.log says were offered"
  echo "\$ sw_vers"; sw_vers
  echo; echo "# remote-access software seen in install.log: is it present, who signed it, does Gatekeeper accept it?"
  echo "\$ pkgutil --pkgs | grep -i splashtop"; pkgutil --pkgs | grep -i splashtop || echo "(none)"
  APP=$(ls -d /Applications/Splashtop*Streamer*.app 2>/dev/null | head -1)
  if [ -n "$APP" ]; then
    echo "\$ codesign -dv --verbose=2 \"$APP\""; codesign -dv --verbose=2 "$APP" 2>&1 | grep -E 'Identifier=|Authority=|TeamIdentifier=|Timestamp='
    echo "\$ spctl -a -vv \"$APP\""; spctl -a -vv "$APP" 2>&1 | head -3
  fi
  echo; echo "# MDM enrolment (managed device => IT-deployed software is plausible)"
  echo "\$ profiles status -type enrollment"; profiles status -type enrollment 2>&1 | head -3
  echo; echo "# processes behind the Software Update entitlement alerts (rule 100242), if still running"
  P=$(python3 -c 'import json,sys
ps=set()
for l in open(sys.argv[1]):
    a=json.loads(l)
    if a["rule"]["id"]=="100242": ps.add(a.get("data",{}).get("client_pid",""))
print(" ".join(sorted(p for p in ps if p)))' "$EV/wazuh/alerts.json")
  echo "PIDs: ${P:-none}"; for p in $P; do ps -p "$p" -o pid=,user=,comm= 2>/dev/null || echo "$p (not running now)"; done
} 2>&1 | cap "$T/08_macos_validation.txt"

# ---------------------------------------------------------------- 6. analysis
python3 -I "$TASK/analysis/analyze.py" --evidence "$EV" --jml "$IR/../../Care_Access_Navigator/06_Evidence/07_JML_Lifecycle/JML-LOG.csv" 2>&1 | tee "$T/07_analysis.txt"
mark analysis_done "$MK"
( cd "$EV" && find . -type f ! -name EVIDENCE-INDEX-SHA256.txt | sort | xargs shasum -a 256 ) > "$EV/EVIDENCE-INDEX-SHA256.txt"
echo "evidence index: $(grep -c . "$EV/EVIDENCE-INDEX-SHA256.txt") files"
exit 0
fi
echo "usage: run_task2.sh scenario|analysis"; exit 2
