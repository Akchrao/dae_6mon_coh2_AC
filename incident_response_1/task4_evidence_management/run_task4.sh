#!/usr/bin/env bash
# =============================================================================
# Care Access Navigator - Incident Response 1, Task 4: Digital Evidence Management
# -----------------------------------------------------------------------------
# Case IR1-2026-002, on the contained lab left by Task 3 (parrot-vm reachable only from ir-forensics 10.78.50.5
# over the quarantine path 10.78.50.2:2222). Steps:
#   01 evidence intake: re-verify every Task 3 hash (first chain-of-custody check)
#   02 live data collection on parrot-vm (lab/ir_live_response.sh, RAM-only output, per-command hashes)
#   03 memory analysis of the Task 3 RAM image with Volatility 3 (image hash checked before and after)
#   04 disk acquisition: seize the virtual disk at the hypervisor from snapshot ir-contained, then image it
#      read-only with dc3dd on the Parrot forensic workstation, verify, and examine with The Sleuth Kit
#   05 chain of custody + super-timeline (analysis/*.py) + evidence index
# Large images stay outside git in ~/ir1-vm-lab/evidence/IR1-2026-002 (hashes recorded here).
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lab/lab_common.sh"
TASK="$IR/task4_evidence_management"; EV="$TASK/evidence"; T="$EV/transcripts"; T3="$IR/task3_containment"
for d in transcripts intake live_response memory disk coc timeline; do rm -rf "$EV/$d"; mkdir -p "$EV/$d"; done
rm -f "$EV/steps.csv" "$EV/EVIDENCE-INDEX-SHA256.txt"
FS2="$FS -p 2222 ir-analyst@10.78.50.2"
V="vol -q -s /opt/symbols -f $CBIG/${CASE}_parrot-vm.mem.elf"
echo "step,utc" > "$EV/steps.csv"; step() { echo "$1,$(now)" >> "$EV/steps.csv"; echo "[$(now)] >>> $1"; }
docker ps --format '{{.Names}}' | has -x ir-hv || { echo "lab is not running - run Tasks 1-3 first"; exit 1; }

# ---------------------------------------------------------------- 00. forensic workstation
: > "$T/00_workstation.txt"
{
  echo "# IR1 Task4 run - $(now) - analyst host $(hostname -s); case $CASE"
  echo "# Parrot forensic workstation ir-forensics (built in Task 1): dc3dd, Sleuth Kit, ewf-tools, Volatility 3, tshark"
  echo "\$ tool versions"
  fx sh -c 'dc3dd --version 2>&1 | head -1; mmls -V; ewfacquire -V 2>&1 | head -1; vol -h 2>&1 | head -1; tshark -v | head -1; ls -l /opt/symbols/linux'
  echo "\$ sha256sum /opt/symbols/linux/*.json.xz   (ISF built with dwarf2json v0.9.0 from linux-image-6.1.0-54-cloud-amd64-dbg)"
  fx sh -c 'sha256sum /opt/symbols/linux/*.json.xz'
  echo "\$ $FS2 hostname   (forensic path to the contained host)"; fx sh -c "$FS2 hostname"
} 2>&1 | cap "$T/00_workstation.txt"

# ---------------------------------------------------------------- 01. intake verification (CoC check #1)
: > "$T/01_intake_verification.txt"
{
  step intake_verify
  echo "# re-hash every Task 3 evidence item against its acquisition hash (task3 EVIDENCE-INDEX-SHA256.txt)"
  chmod a-w "$BIG"/* 2>/dev/null; ls -l "$BIG"
  ( cd "$T3/evidence" && grep -E '^[0-9a-f]{64}  \./' EVIDENCE-INDEX-SHA256.txt | shasum -a 256 -c - ) > "$EV/intake/task3_repo_items_check.txt" 2>&1
  ( cd "$BIG" && grep -E '^[0-9a-f]{64}  [^.]' "$T3/evidence/EVIDENCE-INDEX-SHA256.txt" | shasum -a 256 -c - ) > "$EV/intake/task3_large_items_check.txt" 2>&1
  echo "repo items:  $(grep -c ': OK$' "$EV/intake/task3_repo_items_check.txt") OK, $(grep -vc ': OK$' "$EV/intake/task3_repo_items_check.txt") not OK"
  echo "large items: $(grep -c ': OK$' "$EV/intake/task3_large_items_check.txt") OK, $(grep -vc ': OK$' "$EV/intake/task3_large_items_check.txt") not OK"
  cat "$EV/intake/task3_large_items_check.txt"
  grep -v ': OK$' "$EV/intake/task3_repo_items_check.txt" | head -5
} 2>&1 | cap "$T/01_intake_verification.txt"

# ---------------------------------------------------------------- 02. live data collection
: > "$T/02_live_response.txt"
{
  step live_response
  echo "# ir_live_response.sh streamed to the host over the forensic SSH channel; output kept in RAM (/dev/shm/lr)"
  echo "\$ sha256sum ir_live_response.sh"; shasum -a 256 "$LAB/ir_live_response.sh" | cut -d' ' -f1
  echo "# clock reference: forensic workstation (NTP-synced macOS host) vs the suspect host's own clock"
  echo "workstation UTC before collection: $(now)"
  { echo "CASE=$CASE"; cat "$LAB/ir_live_response.sh"; } | docker exec -i ir-forensics sh -c "$FS2 'sudo sh -s'"
  echo "workstation UTC after collection:  $(now)"
  fx sh -c "$FS2 'sudo tar -C /dev/shm/lr -cf - .' > /ir/task4_evidence_management/evidence/live_response/${CASE}_live_response.tar"
  fx sh -c "$FS2 'sudo rm -rf /dev/shm/lr'"
  echo "\$ sha256sum ${CASE}_live_response.tar"; fx sha256sum /ir/task4_evidence_management/evidence/live_response/${CASE}_live_response.tar
  fx sh -c "cd /ir/task4_evidence_management/evidence/live_response && tar -xf ${CASE}_live_response.tar && rm ${CASE}_live_response.tar"
  echo; echo "# every output file re-hashed against the hash the collector logged at collection time"
  python3 -I - "$EV/live_response" <<'PY'
import csv, hashlib, os, sys
d = sys.argv[1]; ok = bad = 0
for r in csv.DictReader(open(os.path.join(d, "00_collection_log.tsv")), delimiter="\t"):
    h = hashlib.sha256(open(os.path.join(d, r["output"]), "rb").read()).hexdigest()
    ok, bad = (ok + 1, bad) if h == r["sha256"] else (ok, bad + 1)
    print(f'{r["seq"]:>2} {r["utc_start"]}  exit={r["exit"]}  {"MATCH" if h == r["sha256"] else "MISMATCH"}  {r["output"]}')
print(f"{ok} outputs match the collection log, {bad} do not")
PY
} 2>&1 | cap "$T/02_live_response.txt"

# ---------------------------------------------------------------- 03. memory analysis (Volatility 3)
: > "$T/03_memory_analysis.txt"
{
  step memory_analysis
  echo "# E01 RAM image from Task 3 (QMP dump-guest-memory). Hash before analysis:"
  fx sha256sum $CBIG/${CASE}_parrot-vm.mem.elf
  run() { local n="$1"; shift; echo "\$ vol $*"; fx sh -c "$V $* 2>/dev/null" > "$EV/memory/vol_$n.txt"; echo "  -> memory/vol_$n.txt ($(grep -c . "$EV/memory/vol_$n.txt") lines)"; }
  run banners   banners.Banners
  run pslist    linux.pslist.PsList
  run pstree    linux.pstree.PsTree
  run psaux     linux.psaux.PsAux
  U=$(awk '/syncd\.py/{print $1; exit}' "$EV/memory/vol_psaux.txt"); echo "# uploader PID in memory: $U"
  run envars_uploader   linux.envars.Envars --pid "$U"
  run lsof_uploader     linux.lsof.Lsof --pid "$U"
  run sockstat          linux.sockstat.Sockstat
  run maps_uploader     linux.proc.Maps --pid "$U"
  run bash              linux.bash.Bash
  run lsmod             linux.lsmod.Lsmod
  run check_modules     linux.check_modules.Check_modules
  run check_syscall     linux.check_syscall.Check_syscall
  run malfind           linux.malfind.Malfind
  run kmsg              linux.kmsg.Kmsg
  echo; echo "# dump the uploader's memory regions and search them for the patient record"
  fx sh -c "rm -rf /tmp/maps && mkdir /tmp/maps && cd /tmp/maps && $V -o /tmp/maps linux.proc.Maps --pid $U --dump >/dev/null 2>&1; ls | wc -l | sed 's/^/regions dumped: /'; grep -l -a 'SYN-0003' * | sed 's/^/region holding MRN SYN-0003: /'; grep -a -o -h 'SYNTHETIC RECORD PT-1003[^\\x00]\{0,90\}' * | head -2 | tr '\\n' ' '" | tee "$EV/memory/uploader_region_search.txt"
  echo; echo "# E01 hash after analysis (analysis must not change the image):"
  fx sha256sum $CBIG/${CASE}_parrot-vm.mem.elf
} 2>&1 | cap "$T/03_memory_analysis.txt"

# ---------------------------------------------------------------- 04. disk acquisition
: > "$T/04_disk_acquisition.txt"
{
  step disk_seize
  echo "# 4a seize: export the virtual disk as it was at snapshot ir-contained   [VBoxManage clonemedium disk ... --format RAW]"
  docker exec ir-hv qemu-img info -U /vm/parrot-vm.qcow2 | sed -n '1,4p;/Snapshot list/,$p'
  echo "export start $(now)"
  docker exec ir-hv qemu-img convert -U -l snapshot.name=ir-contained -O raw /vm/parrot-vm.qcow2 $CBIG/${CASE}_parrot-vm_seized.raw
  echo "export end   $(now)"; ls -l "$BIG/${CASE}_parrot-vm_seized.raw"
  chmod a-w "$BIG/${CASE}_parrot-vm_seized.raw"
  echo "seized sha256 $(shasum -a 256 "$BIG/${CASE}_parrot-vm_seized.raw" | cut -d' ' -f1)  ${CASE}_parrot-vm_seized.raw"
  step disk_image
  echo; echo "# 4b image with dc3dd on the Parrot workstation; source attached READ-ONLY (/seized is a :ro mount = write blocker)"
  fx sh -c "touch /seized/x 2>&1 | head -1"
  fx sh -c "dc3dd if=/seized/${CASE}_parrot-vm_seized.raw of=$CBIG/${CASE}_vda.dd hash=sha256 log=/ir/task4_evidence_management/evidence/disk/dc3dd_acquisition.log >/dev/null 2>&1; cat /ir/task4_evidence_management/evidence/disk/dc3dd_acquisition.log"
  echo "\$ sha256sum ${CASE}_vda.dd   (verify the image against dc3dd's input hash)"; fx sha256sum $CBIG/${CASE}_vda.dd
  chmod a-w "$BIG/${CASE}_vda.dd"
  step disk_examine
  echo; echo "# 4c examine the image with The Sleuth Kit"
  IMG=$CBIG/${CASE}_vda.dd
  echo "\$ mmls $IMG"; fx mmls $IMG | tee "$EV/disk/mmls.txt"
  # root file system = the largest allocated partition
  OFF=$(awk '/^[0-9]+:/ && $2 ~ /^[0-9]+$/ {if ($5+0 > max) {max=$5+0; off=$3+0}} END {print off}' "$EV/disk/mmls.txt")
  echo "# root file system starts at sector $OFF"
  echo "\$ fsstat -o $OFF $IMG | head"; fx sh -c "fsstat -o $OFF $IMG" > "$EV/disk/fsstat.txt"; sed -n '1,22p' "$EV/disk/fsstat.txt" | grep -E 'File System Type|Volume Name|Last Written|Last Mounted|Last Checked|Journal|Volume ID'
  echo "\$ fls -r -p -o $OFF $IMG | grep incident paths"
  fx sh -c "fls -r -p -o $OFF $IMG 2>/dev/null | grep -E 'test\.nurse|ir-quarantine|00-ir-containment|iptables\.' " | tee "$EV/disk/fls_incident_paths.txt"
  echo; echo "# recover the planted files from the image and compare with the Task 3 live copies"
  for p in home/test.nurse/.cache/.sync/syncd.py home/test.nurse/.cache/.sync/pt1003.txt var/spool/cron/crontabs/test.nurse; do
    INO=$(grep -E "[[:space:]]$p\$" "$EV/disk/fls_incident_paths.txt" | head -1 | sed -E 's/^[^ ]+ \*? ?([0-9]+).*/\1/; s/:.*//')
    H_IMG=$(fx sh -c "icat -o $OFF $IMG $INO | sha256sum | cut -d' ' -f1")
    H_T3=$(grep -E "  /$p\$" "$T3/evidence/filesystem/artifact_sha256_source.txt" | cut -d' ' -f1)
    echo "/$p inode=$INO image=$H_IMG task3=$H_T3 $([ "$H_IMG" = "$H_T3" ] && echo MATCH || echo DIFFERENT)"
  done | tee "$EV/disk/recovered_vs_task3.txt"
  INO=$(grep -E "\.sync/syncd\.py$" "$EV/disk/fls_incident_paths.txt" | head -1 | sed -E 's/^[^ ]+ \*? ?([0-9]+).*/\1/; s/:.*//')
  echo "\$ istat -o $OFF $IMG $INO   (syncd.py)"; fx sh -c "istat -o $OFF $IMG $INO" | sed -n '1,30p' | tee "$EV/disk/istat_syncd.txt" | grep -E 'inode|uid|mode|size|Accessed|Modified|Changed|File Created|Allocated'
  echo; echo "# logs as they were at snapshot ir-contained (after C7), recovered from the image for the timeline"
  for f in var/log/auth.log var/log/ehr-audit.log; do
    INO=$(fx sh -c "ifind -n /$f -o $OFF $IMG")
    fx sh -c "icat -o $OFF $IMG $INO > /ir/task4_evidence_management/evidence/disk/image_$(basename $f)"; echo "/$f inode=$INO -> disk/image_$(basename $f) ($(wc -l < "$EV/disk/image_$(basename $f)") lines)"
  done
  echo; echo "# body file of the incident-relevant directories for the timeline (mactime, UTC)"
  fx sh -c "fls -r -m / -o $OFF $IMG 2>/dev/null | grep -E '\|/(home/test\.nurse|var/spool/cron|root/ir-quarantine|etc/(group|passwd|ssh/sshd_config\.d|netplan)|srv/ehr|var/log/(auth|ehr-audit|kern)\.log)' > /ir/task4_evidence_management/evidence/disk/bodyfile_incident.txt; wc -l < /ir/task4_evidence_management/evidence/disk/bodyfile_incident.txt"
  fx sh -c "mactime -b /ir/task4_evidence_management/evidence/disk/bodyfile_incident.txt -z UTC -d -y 2026-11-02 > /ir/task4_evidence_management/evidence/disk/mactime_incident.csv; wc -l < /ir/task4_evidence_management/evidence/disk/mactime_incident.csv"
} 2>&1 | cap "$T/04_disk_acquisition.txt"

# ---------------------------------------------------------------- 05/06. chain of custody, timeline, index
: > "$T/05_coc_timeline.txt"
{
  step coc_timeline
  python3 -I "$TASK/analysis/chain_of_custody.py"
  python3 -I "$TASK/analysis/build_timeline.py"
  step done
  ( cd "$EV" && find . -type f ! -name EVIDENCE-INDEX-SHA256.txt ! -path './transcripts/05_coc_timeline.txt' | sort | xargs shasum -a 256 ) > "$EV/EVIDENCE-INDEX-SHA256.txt"
  echo "# outside git: $BIG" >> "$EV/EVIDENCE-INDEX-SHA256.txt"
  ( cd "$BIG" && shasum -a 256 ${CASE}_parrot-vm_seized.raw ${CASE}_vda.dd ) >> "$EV/EVIDENCE-INDEX-SHA256.txt"
  echo "evidence index: $(grep -cE '^[0-9a-f]{64} ' "$EV/EVIDENCE-INDEX-SHA256.txt") files"
} 2>&1 | cap "$T/05_coc_timeline.txt"
echo "done $(now)"
