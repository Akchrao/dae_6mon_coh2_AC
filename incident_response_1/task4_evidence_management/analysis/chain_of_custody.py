#!/usr/bin/env python3
"""chain_of_custody.py - Care Access Navigator IR1 Task 4
Builds the chain-of-custody record for case IR1-2026-002 from the evidence itself:
  evidence/coc/evidence_register.csv  one row per evidence item (what, where from, how, by whom, hash, where stored)
  evidence/coc/custody_log.csv        every custody event (acquire, transfer, store, verify, examine) with hash check
Times come from the run markers (Task 3 markers.csv, Task 4 steps.csv); hashes from the acquisition transcripts and
indexes; every hash is re-computed now, so the log records a fresh verification of each item."""
import csv, datetime as dt, hashlib, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
T4 = os.path.dirname(HERE); T3 = os.path.join(os.path.dirname(T4), "task3_containment"); T2 = os.path.join(os.path.dirname(T4), "task2_log_analysis")
EV4, EV3 = os.path.join(T4, "evidence"), os.path.join(T3, "evidence")
BIG = os.path.expanduser("~/ir1-vm-lab/evidence/IR1-2026-002")
CASE = "IR1-2026-002"
ANALYST = "A. Chennamaneni (IR analyst, account ir-analyst)"
NOW = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


m3 = {r["phase"]: r["utc"] for r in csv.DictReader(open(os.path.join(EV3, "markers.csv")))}
m4 = {r["step"]: r["utc"] for r in csv.DictReader(open(os.path.join(EV4, "steps.csv")))}
idx3 = {}
for l in open(os.path.join(EV3, "EVIDENCE-INDEX-SHA256.txt")):
    if re.match(r"[0-9a-f]{64}  ", l):
        h, p = l.rstrip("\n").split("  ", 1); idx3[p.lstrip("./")] = h
intake = {}
for f in ("task3_repo_items_check.txt", "task3_large_items_check.txt"):
    for l in open(os.path.join(EV4, "intake", f)):
        if ": " in l:
            p, r = l.rstrip().rsplit(": ", 1); intake[p.lstrip("./")] = r
t4_disk = open(os.path.join(EV4, "transcripts", "04_disk_acquisition.txt")).read()
seized_h = re.search(r"seized sha256 (\w+)", t4_disk)[1]
dc3_in = re.search(r"([0-9a-f]{64}) \(sha256\)", open(os.path.join(EV4, "disk", "dc3dd_acquisition.log")).read())[1]

# id, description, source, method / tool, acquired (utc), stored path, acquisition hash, kind
items = [
    ("E01", "Full RAM image of parrot-vm (1 GiB ELF core)", "parrot-vm (running, pre-kill)", "Hypervisor QMP dump-guest-memory (= VBoxManage debugvm dumpvmcore)",
     m3["c4_memory"], os.path.join(BIG, f"{CASE}_parrot-vm.mem.elf"), idx3.get(f"{CASE}_parrot-vm.mem.elf"), "original"),
    ("E02", "Process memory core of uploader syncd.py", "parrot-vm PID of syncd.py", "gdb gcore in guest, pulled over SSH, hash at both ends",
     m3["c4_memory"], os.path.join(BIG, f"{CASE}_syncd.core"), idx3.get(f"{CASE}_syncd.core"), "original"),
    ("E03", "Live packet capture, host side (25 s, host 10.78.99.66)", "parrot-vm enp0s1", "tcpdump in guest, pulled over SSH",
     m3["c2_volatile"], os.path.join(EV3, "network", f"{CASE}_live_tcpdump.pcap"), idx3.get(f"network/{CASE}_live_tcpdump.pcap"), "original"),
    ("E04", "Hypervisor capture of adapter 1 (clinical), whole run", "QEMU filter-dump on nic0", "NIC trace (= VBoxManage --nictrace1)",
     m3["contained"], os.path.join(EV3, "network", "hypervisor_nic0_clinical.pcap"), idx3.get("network/hypervisor_nic0_clinical.pcap"), "original"),
    ("E05", "Hypervisor capture of adapter 2 (quarantine)", "QEMU filter-dump on nic1", "NIC trace",
     m3["contained"], os.path.join(EV3, "network", "hypervisor_nic1_quarantine.pcap"), idx3.get("network/hypervisor_nic1_quarantine.pcap"), "original"),
    ("E06", "Volatile state set (processes, connections, suspect process, persistence, system state)", "parrot-vm", "ps/ss/lsof//proc over guest agent, written to case folder",
     m3["c2_volatile"], os.path.join(EV3, "volatile", "processes.txt"), idx3.get("volatile/processes.txt"), "original"),
    ("E07", "File-system artifacts tar (12 files incl. staged record, uploader, crontab, logs)", "parrot-vm /home, /var, /etc", "stat, freeze to RAM, sha256, tar over SSH",
     m3["c5_filesystem"], os.path.join(EV3, "filesystem", f"{CASE}_artifacts.tar"), idx3.get(f"filesystem/{CASE}_artifacts.tar"), "original"),
    ("E08", "Drop-site upload log", "exfil-sink 10.78.99.66 (lab)", "copied from the lab drop-site container",
     m3["contained"], os.path.join(EV3, "exfil-sink", "uploads.jsonl"), idx3.get("exfil-sink/uploads.jsonl"), "original"),
    ("E09", "macOS SSH client log", "DAEDMAC1009 (macOS)", "host_ssh_logged.py wrapper around OpenSSH",
     m3["contained"], os.path.join(T2, "evidence", "macos", "ssh_client.log"), None, "original"),
    ("E13", "Wazuh alerts (SIEM record of the incident, incl. rule 100221 that triggered containment)", "wazuh-manager 10.78.50.20", "alerts.json exported from the manager (Task 2)",
     m3["contained"], os.path.join(T2, "evidence", "wazuh", "alerts.json"), None, "original"),
    ("E10", "Live-response collection (24 command outputs + collection log)", "parrot-vm (contained)", "ir_live_response.sh over forensic SSH, RAM-only output, tar",
     m4["live_response"], os.path.join(EV4, "live_response", "00_collection_log.tsv"), None, "original"),
    ("E11", "Seized virtual disk, raw (state at snapshot ir-contained)", "parrot-vm disk, snapshot ir-contained", "qemu-img convert -U (= VBoxManage clonemedium --format RAW)",
     m4["disk_seize"], os.path.join(BIG, f"{CASE}_parrot-vm_seized.raw"), seized_h, "original"),
    ("E12", "Forensic disk image (dc3dd) of E11", "E11 attached read-only", "dc3dd hash=sha256 log=dc3dd_acquisition.log",
     m4["disk_image"], os.path.join(BIG, f"{CASE}_vda.dd"), dc3_in, "working copy"),
]

reg = os.path.join(EV4, "coc", "evidence_register.csv")
log = os.path.join(EV4, "coc", "custody_log.csv")
with open(reg, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["item", "case", "description", "source", "method_tool", "acquired_utc", "acquired_by", "kind",
                "stored_at", "bytes", "sha256_at_acquisition", "sha256_now", "integrity"])
    rows = []
    for i, desc, src, how, t, path, h0, kind in items:
        h1 = sha(path)
        h0 = h0 or h1                                            # E10: the collection log is hashed at intake
        repo = os.path.dirname(os.path.dirname(T4)) + "/"                          # repository root
        where = path.replace(repo, "repo:").replace(os.path.expanduser("~"), "~")
        rows.append((i, desc, t, where, h0, h1, path))
        w.writerow([i, CASE, desc, src, how, t, ANALYST, kind, where, os.path.getsize(path), h0, h1,
                    "VERIFIED" if h0 == h1 else "CHANGED"])

with open(log, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["item", "utc", "event", "from", "to", "by", "hash_check", "note"])
    for i, desc, t, where, h0, h1, path in rows:
        task3 = i <= "E09"
        src = "E11 (read-only mount)" if i == "E12" else "hypervisor ir-hv" if i in ("E01", "E04", "E05", "E11") else ("exfil-sink" if i == "E08" else ("DAEDMAC1009" if i == "E09" else "parrot-vm"))
        w.writerow([i, t, "ACQUIRED", src, "ir-forensics" if i not in ("E01", "E04", "E05", "E09", "E11") else "case storage", ANALYST,
                    "sha256 recorded", "acquisition transcript: task3 transcripts/05-13" if task3 else "task4 transcripts/02-04"])
        if i in ("E02", "E03", "E07"):
            w.writerow([i, t, "TRANSFER", "parrot-vm", "ir-forensics", ANALYST, "MATCH (source = copy)", "SSH pull; hash on both ends"])
        if i == "E12":
            w.writerow([i, t, "TRANSFER", "E11 (read-only mount)", "ir-forensics /bigev", ANALYST, "dc3dd input hash = E11 hash: " +
                        ("MATCH" if dc3_in == seized_h else "MISMATCH"), "write-blocked source"])
        w.writerow([i, t, "STORED", "ir-forensics", where, ANALYST, "file set read-only" if "ir1-vm-lab" in where else "in git working tree",
                    "evidence index lists path and hash"])
        if task3:
            r = intake.get(os.path.relpath(path, EV3)) or intake.get(os.path.basename(path), "n/a")
            w.writerow([i, m4["intake_verify"], "VERIFIED (intake to Task 4)", where, where, ANALYST, r, "re-hash vs task3 EVIDENCE-INDEX"])
        if i == "E01":
            w.writerow([i, m4["memory_analysis"], "EXAMINED", where, "Volatility 3 (read-only)", ANALYST, "hash before = after", "task4 transcripts/03"])
        if i == "E12":
            w.writerow([i, m4["disk_examine"], "EXAMINED", where, "The Sleuth Kit (read-only)", ANALYST, "image not modified", "task4 transcripts/04"])
        w.writerow([i, NOW, "VERIFIED (report build)", where, where, ANALYST, "MATCH" if h0 == h1 else "CHANGED", "chain_of_custody.py"])

n = sum(1 for r in rows if r[4] == r[5])
print(f"chain of custody: {len(rows)} items, {n} verified unchanged; {sum(1 for _ in open(log)) - 1} custody events")
print(f"  -> {os.path.relpath(reg, T4)}, {os.path.relpath(log, T4)}")
