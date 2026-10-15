#!/usr/bin/env bash
# =============================================================================
# Care Access Navigator - Incident Response 1, Task 1: Environment Setup (simulated)
# -----------------------------------------------------------------------------
# No admin rights required; Docker Desktop only. Builds an isolated lab host that
# stands in for Parrot OS (Debian 12 - Parrot's own base; no ARM64 Parrot/VirtualBox
# image runs on this Apple-silicon host without admin), configures log collection,
# Wireshark capture filters and Volatility 3, then validates three custom Wazuh-format
# detection rules with sample-log injection (the method `wazuh-logtest` uses).
#
# All command output is saved verbatim under ../evidence/transcripts so the report
# quotes real output. Run:  bash run_lab.sh
# =============================================================================
set -uo pipefail   # not -e: evidence steps may exit non-zero and must still be recorded
cd "$(dirname "$0")"
LAB="$(cd .. && pwd)"
EV="$LAB/evidence"; T="$EV/transcripts"
WSIM="$LAB/wazuh-sim"
NET=ir1-labnet
mkdir -p "$T" "$EV/logs" "$EV/pcap" "$EV/wireshark" "$EV/volatility"

cap() { tee -a "$1"; }   # append to a transcript and echo to screen

# ---------------------------------------------------------------- 0. start fresh
docker rm -f parrot-sim >/dev/null 2>&1 || true
docker network rm $NET  >/dev/null 2>&1 || true

# ---------------------------------------------------------------- 1. build + network
: > "$T/01_build_and_network.txt"
{
  echo "# IR1 Task1 lab run - $(date -u +%Y-%m-%dT%H:%M:%SZ) - host $(hostname) ($(uname -sm))"
  echo "\$ docker version --format '{{.Server.Version}} / {{.Server.Arch}}'"
  docker version --format '{{.Server.Version}} / {{.Server.Arch}}'
  echo; echo "\$ docker build -t ir1-parrot-sim:1.0 -f Dockerfile.parrot-sim ."
  docker build -t ir1-parrot-sim:1.0 -f Dockerfile.parrot-sim . | tail -1
  echo; echo "# isolated lab network (--internal = no internet route; VirtualBox 'Internal Network' equivalent)"
  echo "\$ docker network create --internal --subnet 10.66.0.0/24 $NET"
  docker network create --internal --subnet 10.66.0.0/24 $NET
  echo "\$ docker run -d --name parrot-sim --hostname parrot-sim --network $NET --ip 10.66.0.10 ir1-parrot-sim:1.0"
  docker run -d --name parrot-sim --hostname parrot-sim --network $NET --ip 10.66.0.10 \
      -v "$EV:/evidence" ir1-parrot-sim:1.0
  echo "\$ docker network inspect $NET"
  docker network inspect $NET --format 'network={{.Name}} internal={{.Internal}}{{range .Containers}}
  host={{.Name}} ip={{.IPv4Address}}{{end}}'
} 2>&1 | cap "$T/01_build_and_network.txt"

ex() { docker exec parrot-sim "$@"; }   # shorthand

# ---------------------------------------------------------------- 2. host + log collection
: > "$T/02_host_and_logging.txt"
{
  echo "\$ cat /etc/os-release"; ex cat /etc/os-release; echo
  echo "# start rsyslog so sshd/sudo events land in /var/log/auth.log (Wazuh agent log source)"
  echo "\$ service rsyslog start ; pgrep -a rsyslogd"
  ex sh -c "rsyslogd 2>/dev/null; sleep 1; pgrep -a rsyslogd"; echo
  echo "\$ grep -E 'auth|authpriv' /etc/rsyslog.conf  (auth.log routing = Wazuh 'localfile' source)"
  ex sh -c "grep -nE 'auth(,|priv|\.)' /etc/rsyslog.conf || echo '(default: *.* collected)'"; echo
  echo "# create the lab accounts used in the scenario"
  echo "\$ useradd nurse_jsmith (clinical, non-sudo) ; useradd it_admin (sudo)"
  ex sh -c "useradd -m -s /bin/bash nurse_jsmith 2>/dev/null; useradd -m -s /bin/bash -G sudo it_admin 2>/dev/null; id nurse_jsmith; id it_admin"; echo
  echo "# start sshd with verbose auth logging (so failed/accepted passwords are recorded)"
  echo "\$ ssh-keygen -A ; sshd ; ss -ltn | grep :22"
  ex sh -c "printf 'LogLevel VERBOSE\nMaxAuthTries 6\n' > /etc/ssh/sshd_config.d/ir-lab.conf; ssh-keygen -A >/dev/null 2>&1; /usr/sbin/sshd; sleep 1; ss -ltn | grep ':22' || netstat -ltn 2>/dev/null | grep ':22'"
} 2>&1 | cap "$T/02_host_and_logging.txt"

# ---------------------------------------------------------------- 3. Wireshark capture filters
: > "$T/03_wireshark.txt"
docker cp "$WSIM/cfilters" parrot-sim:/root/cfilters 2>/dev/null || true
{
  echo "\$ tshark --version"; ex tshark --version | head -1; echo
  echo "\$ tshark -D   (capture interfaces)"; ex tshark -D; echo
  echo "# install the saved Wireshark capture filters (used by both Wireshark GUI and tshark)"
  echo "\$ cp cfilters ~/.config/wireshark/cfilters"
  ex sh -c "mkdir -p /root/.config/wireshark && cp /root/cfilters /root/.config/wireshark/cfilters && cp /root/cfilters /evidence/wireshark/cfilters && cat /root/.config/wireshark/cfilters"; echo
  echo "# verify each capture filter compiles (dumpcap/tshark -f). Non-zero exit = bad filter."
  for F in "tcp port 22" "host 10.66.0.66" "tcp[tcpflags] & tcp-syn != 0"; do
    echo "\$ tshark -i eth0 -f \"$F\" -c 0 -a duration:1   (compile check)"
    ex sh -c "tshark -i eth0 -f '$F' -a duration:1 -w /dev/null >/dev/null 2>&1 && echo 'filter OK: $F' || echo 'filter FAILED: $F'"
  done
} 2>&1 | cap "$T/03_wireshark.txt"

# ---------------------------------------------------------------- 4. live packet capture (benign SSH)
: > "$T/04_capture.txt"
{
  echo "# capture SSH traffic to prove the filter works end to end. tshark runs with capture"
  echo "# filter 'tcp port 22'; we then generate one ordinary SSH handshake to parrot-sim."
  echo "\$ tshark -i any -f 'tcp port 22' -a duration:12 -w /evidence/pcap/ssh_capture.pcapng &"
  docker exec -d parrot-sim sh -c "tshark -i any -f 'tcp port 22' -a duration:12 -w /evidence/pcap/ssh_capture.pcapng >/evidence/pcap/capture.log 2>&1"
  sleep 2
  echo "\$ ssh nurse_jsmith@10.66.0.10  x3  (three handshakes over eth0 -> real port-22 packets)"
  ex sh -c "for i in 1 2 3; do ssh -o StrictHostKeyChecking=no -o ConnectTimeout=4 -o BatchMode=yes nurse_jsmith@10.66.0.10 true 2>&1 | head -1; sleep 1; done; true"
  sleep 11
  echo "\$ capinfos / tshark -r ssh_capture.pcapng  (packet count + first/last)"
  ex sh -c "tshark -r /evidence/pcap/ssh_capture.pcapng -q -z io,stat,0 2>/dev/null | sed -n '1,8p'"
  ex sh -c "echo 'packets captured:' \$(tshark -r /evidence/pcap/ssh_capture.pcapng 2>/dev/null | wc -l)"
} 2>&1 | cap "$T/04_capture.txt"

# ---------------------------------------------------------------- 5. Volatility 3
: > "$T/05_volatility.txt"
{
  echo "\$ vol --help | head -1   (framework version)"; ex sh -c "vol --help 2>&1 | head -1"; echo
  echo "# configure symbol/cache dirs and record the Linux memory-forensics plugins available"
  echo "\$ vol -h | grep linux.   (memory plugins ready for Task 4)"
  ex sh -c "mkdir -p /opt/volatility/symbols /opt/volatility/cache; printf '[volatility]\nsymbol_dirs=/opt/volatility/symbols\ncache=/opt/volatility/cache\n' > /evidence/volatility/vol_config.ini; vol -h 2>/dev/null | grep -oE 'linux\.[a-zA-Z_]+' | sort -u | tee /evidence/volatility/linux_plugins.txt | sed -n '1,12p'"
  echo "\$ wc -l linux_plugins.txt"; ex sh -c "echo 'linux memory plugins available:' \$(sort -u /evidence/volatility/linux_plugins.txt | wc -l)"
  echo "\$ cat vol_config.ini"; ex cat /evidence/volatility/vol_config.ini
} 2>&1 | cap "$T/05_volatility.txt"

# ---------------------------------------------------------------- 6. detection rules (sample-log injection)
: > "$T/06_detection_rules.txt"
cp "$WSIM/sample_auth.log" "$EV/logs/auth.log"
{
  echo "# 3 custom Wazuh-format rules validated by injecting a sample auth.log (wazuh-logtest method)."
  echo "\$ xmllint --noout local_rules.xml  (well-formed check)"
  if command -v xmllint >/dev/null 2>&1; then xmllint --noout "$WSIM/local_rules.xml" && echo "local_rules.xml: well-formed XML"; \
    else python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse('$WSIM/local_rules.xml'); print('local_rules.xml: well-formed XML')"; fi
  echo; echo "\$ grep '<rule id' local_rules.xml"
  grep -E '<rule id' "$WSIM/local_rules.xml" | sed 's/^ *//'
  echo; echo "\$ python3 detect_engine.py --rules local_rules.xml --log sample_auth.log --out ../evidence"
  ( cd "$WSIM" && python3 detect_engine.py --rules local_rules.xml --log sample_auth.log --out "$EV" )
} 2>&1 | cap "$T/06_detection_rules.txt"

# ---------------------------------------------------------------- 7. evidence integrity
: > "$T/07_evidence_index.txt"
{
  echo "# SHA-256 over every evidence artifact (chain-of-custody baseline for Task 4)"
  cd "$EV"
  find . -type f ! -name 'EVIDENCE-INDEX-SHA256.txt' ! -path './transcripts/07_*' -print0 \
    | sort -z | xargs -0 shasum -a 256 | tee EVIDENCE-INDEX-SHA256.txt
} 2>&1 | cap "$T/07_evidence_index.txt"

echo
echo "DONE. Evidence in: $EV"
echo "To tear the lab down:  docker rm -f parrot-sim && docker network rm $NET"
