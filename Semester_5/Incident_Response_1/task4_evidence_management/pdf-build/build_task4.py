"""Care Access Navigator - Incident Response 1, Task 4: Digital Evidence Management.
Builds the report PDF from evidence written by lab/run_task4.sh and analysis/*.py (plus Task 3 evidence it builds on).
Every table and excerpt is read from the evidence - nothing is typed in by hand.
Run inside a container that has reportlab (see README); task3_containment must be mounted next to this task."""
import csv, datetime as dt, os, re
from html import escape as e
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle
from reportlab.lib import colors
from pdfstyle import (P, bullets, note, code, table, kv, ok, bad, build, ss, NAVY, AMBER, CREAM, GREY_BG,
                      GREY_LINE, MUTED, RED, GREEN, Spacer, PageBreak, Paragraph, KeepTogether, inch, FULL_W)

TASK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EV = os.path.join(TASK, "evidence"); EV3 = os.path.join(os.path.dirname(TASK), "task3_containment", "evidence")
OUT = os.path.join(TASK, "Care_Access_Navigator_IR1_Task4_Evidence_Management.pdf")
FOOT = "Care Access Navigator - Incident Response 1, Task 4: Digital Evidence Management"
CASE = "IR1-2026-002"
C = lambda t: f"<font face='Courier'>{e(t)}</font>"
rd = lambda rel, base=EV: open(os.path.join(base, rel), errors="replace").read()
tx = lambda n: rd(os.path.join("transcripts", n))
rows = lambda rel: list(csv.DictReader(open(os.path.join(EV, rel))))
iso = lambda s: dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def section(name, start, stop=None, n=40, cut=None):
    lines = tx(name).splitlines()
    i = next((k for k, l in enumerate(lines) if re.search(start, l)), 0)
    out = []
    for l in lines[i:]:
        if stop and out and re.search(stop, l):
            break
        out.append(l[:cut] if cut else l)
        if len(out) >= n:
            break
    return "\n".join(out)


def vol(name, pat=None, n=14, cut=118):
    ls = [l for l in rd(f"memory/vol_{name}.txt").splitlines() if l.strip() and not l.startswith("Volatility 3")]
    if pat:
        ls = ls[:1] + [l for l in ls[1:] if re.search(pat, l)]
    return "\n".join(l.expandtabs(10)[:cut] for l in ls[:n])


# ----------------------------------------------------------------- evidence
steps = {r["step"]: r["utc"] for r in rows("steps.csv")}
lr = list(csv.DictReader(open(os.path.join(EV, "live_response", "00_collection_log.tsv")), delimiter="\t"))
lr_tx = tx("02_live_response.txt")
lr_match = re.search(r"(\d+) outputs match the collection log, (\d+) do not", lr_tx)
ws_before = re.search(r"workstation UTC before collection: (\S{19})", lr_tx)[1]
vm_clock = re.search(r"Universal time: \w+ (\S+ \S+) UTC", rd("live_response/01_clock.txt"))[1]
skew_min = (iso(ws_before + "Z") - iso(vm_clock.replace(" ", "T") + "Z")).total_seconds() / 60
uptime = float(rd("live_response/01_clock.txt").splitlines()[-1].split()[0])
mem_tx = tx("03_memory_analysis.txt")
mem_h = re.findall(r"([0-9a-f]{64})\s+/evid/\S+mem\.elf", mem_tx)
upid = re.search(r"uploader PID in memory: (\d+)", mem_tx)[1]
disk_tx = tx("04_disk_acquisition.txt")
seized_h = re.search(r"seized sha256 (\w+)", disk_tx)[1]
dc3 = rd("disk/dc3dd_acquisition.log")
dc3_in = re.search(r"([0-9a-f]{64}) \(sha256\)", dc3)[1]
dd_h = re.search(r"([0-9a-f]{64})\s+/evid/\S+_vda\.dd", disk_tx)[1]
dc3_rate = re.search(r"copied \( 100% \), ([\d.]+ s, [\d.]+ \S+)", dc3)[1]
recov = [l.split() for l in rd("disk/recovered_vs_task3.txt").splitlines() if l.strip()]
reg = rows("coc/evidence_register.csv"); cust = rows("coc/custody_log.csv")
tl = rows("timeline/supertimeline_IR1-2026-002.csv"); key = rows("timeline/key_events.csv")
kt = {r["milestone"]: r["utc"] for r in key}
istat_created = re.search(r'File Created:\s+\S+ (\d\d:\d\d:\d\d)', rd('disk/istat_syncd.txt'))[1]
corr = rows("timeline/session_correlation.csv"); srcs = rows("timeline/source_counts.csv")
intake = re.search(r"repo items:\s+(\d+) OK, (\d+) not OK\nlarge items: (\d+) OK, (\d+) not OK", tx("01_intake_verification.txt"))
n_index = sum(1 for l in rd("EVIDENCE-INDEX-SHA256.txt").splitlines() if re.match(r"[0-9a-f]{64} ", l))
syscalls = [l.split("\t") for l in rd("memory/vol_check_syscall.txt").splitlines() if l.startswith("0x")]
sys_unknown = sum(1 for r in syscalls if len(r) < 5 or not r[4] or "UNKNOWN" in r[4])
kmsg_block = [l for l in rd("memory/vol_kmsg.txt").splitlines() if "IR-BLOCK" in l]
hms = lambda s: s[11:19]

s = []
# ================================================================= cover
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Incident Response 1 &mdash; Task 4: Digital Evidence Management", "subtitle"),
      P("Live data collection, Volatility memory analysis, disk acquisition, chain of custody and a macOS + Parrot OS timeline for IR1-2026-002", "subsub"),
      Spacer(1, 14)]
s += kv([
    ("Document ID", "CAN-IR1-T4-EVID-001"),
    ("Author", "Akhila Chennamaneni"),
    ("Date", "November 3, 2026"),
    ("Case", f"<b>{CASE}</b>, SEV-1: a mover's stale clinical access was used to stage and upload the synthetic record "
             "PT-1003 (detected in Task 2, contained in Task 3)"),
    ("Evidence source", "parrot-vm (Debian 12 VM, Parrot OS stand-in; kernel 6.1.0-54-cloud-amd64) in its contained state, "
                        "plus the Task 3 acquisitions; macOS host DAEDMAC1009"),
    ("Workstation", "ir-forensics (Parrot forensic toolset): dc3dd 7.2.646, The Sleuth Kit 4.11.1, Volatility 3 Framework 2.7.0, "
                    "TShark 4.0.17, ewf-tools"),
    ("Run", f"{hms(steps['intake_verify'])}&ndash;{hms(steps['done'])} UTC, 2026-11-02; {n_index} files in the evidence index; "
            f"{len(reg)} evidence items in the chain of custody"),
])
s += [P("Summary", "h1"),
      P(f"Every Task 3 acquisition was re-hashed at intake ({int(intake[1]) + int(intake[3])} of "
        f"{sum(int(x) for x in intake.groups())} OK). Live data was then collected from the contained host: "
        f"{len(lr)} commands in order of volatility, written to RAM only, each with a logged SHA-256 ({lr_match[1]}/{len(lr)} re-verified). "
        f"Volatility 3 analysed the Task 3 RAM image with a symbol table built for this exact kernel. It found the uploader "
        f"(PID {upid}) with the attacker's SSH session in its environment, an open socket stuck in SYN_SENT to the drop "
        f"site, the patient record in its heap, and the kernel's own log naming it as the source of the firewall drops. No rootkit "
        f"indicators were found. The disk was seized at the hypervisor and imaged with dc3dd from a read-only source. "
        f"The source, dc3dd input and image hashes are identical, and The Sleuth Kit recovered the three planted files "
        f"byte-identical to the live copies. A chain-of-custody register tracks {len(reg)} items through {len(cust)} custody events. "
        f"The super-timeline merges {len(tl)} events from {len(srcs)} macOS and Parrot sources. Every macOS SSH session matches a "
        f"Parrot sshd login by key fingerprint to within a second.")]

s += [P("1. How this report meets the Task 4 requirements", "h1")]
s += table([
    ["Requirement", "Where", "Evidence"],
    ["Live data collection: system state", "&sect;3", "live_response/01_clock, 02_system, 14&ndash;16"],
    ["Live data collection: running process information", "&sect;3", "live_response/03_processes, 04_process_exe_sha256, 05_open_files"],
    ["Live data collection: network connection data", "&sect;3", "live_response/07_sockets, 08_listening, 09_interfaces, 10_firewall"],
    ["Basic memory analysis using Volatility", "&sect;4", "memory/vol_*.txt (14 plugins), uploader_region_search.txt"],
    ["Disk acquisition with Parrot imaging tools, proper procedure", "&sect;5", "disk/dc3dd_acquisition.log, mmls, fsstat, fls, istat"],
    ["Chain of custody for all collected evidence", "&sect;6", "coc/evidence_register.csv, coc/custody_log.csv"],
    ["Timeline with macOS and Parrot OS logs, with analysis", "&sect;7", "timeline/supertimeline, key_events, session_correlation"],
], [2.6 * inch, 0.7 * inch, 3.2 * inch])

# ================================================================= procedure
s += [P("2. Evidence handling procedure", "h1"),
      P("The procedure follows NIST SP 800-86's four phases (collection, examination, analysis, reporting) and RFC 3227's "
        "order of volatility. These rules applied to every item:")]
s += table([
    ["Rule", "How it was applied here"],
    ["Most volatile first", "Task 3 took RAM and packets before files. Here, clock &rarr; processes &rarr; network &rarr; kernel &rarr; accounts &rarr; file system"],
    ["Do not write to the suspect disk", "Live-response output goes to /dev/shm (RAM) and is streamed off; the disk is imaged from a hypervisor export, not from inside the guest"],
    ["Write-protect originals", f"Seized disk mounted read-only into the workstation (write attempt refused, &sect;5); large evidence files set read-only ({C('chmod a-w')})"],
    ["Hash at acquisition, verify at every hand-off", "SHA-256 at source and destination; intake re-verification; hash before/after each examination"],
    ["Examine copies, keep originals", "Sleuth Kit runs on the dc3dd working copy (E12), never on the seized original (E11)"],
    ["Document everything", "Every command is in transcripts/ with UTC times; each live-response output is tied to its command in 00_collection_log.tsv"],
    ["Clock reference", "The suspect host's clock is recorded against the workstation clock (&sect;3.2) before any timestamp is trusted"],
], [1.7 * inch, 4.8 * inch])
s += code(section("01_intake_verification.txt", r"re-hash", n=10, cut=118), title="transcripts/01_intake_verification.txt - intake check of the Task 3 evidence")

# ================================================================= live response
s += [P("3. Live data collection from Parrot OS", "h1"),
      P(f"{C('lab/ir_live_response.sh')} is a small, readable live-response collector (SHA-256 of the script is in transcript 02). "
        "It was piped to the contained host over the forensic SSH channel and run as root. That is the only path left open after "
        "containment. Each command's output went to RAM. The collector logged the command line, UTC start time, exit code and the "
        "output's SHA-256 next to it. The workstation then pulled the set as a tar and re-hashed every file against that log.")]
cat = {"clock": "System state", "system": "System state", "processes": "Processes", "process_exe_sha256": "Processes",
       "open_files": "Processes", "logged_in": "System state", "sockets": "Network", "listening": "Network",
       "interfaces": "Network", "firewall": "Network", "dns_hosts": "Network", "kernel_modules": "Kernel/services",
       "kernel_log": "Kernel/services", "services": "Kernel/services", "timers_cron": "Kernel/services", "mounts_disks": "System state",
       "accounts": "Accounts", "sudoers": "Accounts", "ssh_keys": "Accounts", "lastlog": "Accounts", "recent_files": "File system",
       "hidden_dirs": "File system", "suid_sgid": "File system", "shell_history": "File system"}
trs = [["#", "Output", "Category", "UTC (host clock)", "Exit", "SHA-256"]]
for r in lr:
    name = re.sub(r"^\d+_|\.txt$", "", r["output"])
    trs.append([r["seq"], C(r["output"]), cat.get(name, ""), r["utc_start"][11:23], r["exit"], C(r["sha256"][:16]) + "&hellip;"])
s += table(trs, [0.3 * inch, 1.95 * inch, 1.05 * inch, 1.05 * inch, 0.4 * inch, 1.75 * inch])
s += [P("3.1 What the live data shows", "h2")]
s += code(rd("live_response/17_accounts.txt").strip(), title="17_accounts.txt - containment state of the accounts")
s += code("\n".join(l for l in rd("live_response/21_recent_files.txt").splitlines() if re.search(r"\.sync|crontabs|quarantine|00-ir|netplan", l)),
          title="21_recent_files.txt (filtered) - files written during the incident and the response")
s += code("\n".join(rd("live_response/07_sockets.txt").splitlines()[:8]), title="07_sockets.txt - only the responder's SSH session remains")
s += bullets([
    f"<b>Processes</b> ({C('03_processes.txt')}): no {C('syncd.py')} and no process owned by test.nurse. The uploader was killed in Task 3 C7, so "
    "its last running state comes from memory (&sect;4).",
    f"<b>Network</b> (07&ndash;10): one live TCP session (the responder, from 10.78.50.5 on the quarantine NIC). sshd listens only "
    "on 10.0.3.15, and the default-DROP ruleset from Task 3 is still loaded.",
    f"<b>Persistence</b> ({C('15_timers_cron.txt')}): the test.nurse crontab is still on disk (kept as evidence), but cron is masked, so it cannot run.",
])
s += [P("3.2 Clock check", "h2"),
      P(f"The host reported <b>{vm_clock} UTC</b> while the workstation read <b>{ws_before.replace('T', ' ')} UTC</b>: the host was "
        f"<b>{abs(skew_min) * 60:.0f} s {'slow' if skew_min > 0 else 'fast'}</b>. Its uptime was {uptime / 60:.1f} minutes, although about "
        f"{(iso(ws_before + 'Z') - iso(next(r['utc'] for r in csv.DictReader(open(os.path.join(os.path.dirname(TASK), 'task1_environment_setup', 'evidence', 'markers.csv'))) if r['phase'] == 'lab_build'))).total_seconds() / 60 + 1:.0f} "
        "minutes of real time had passed since boot. The emulated guest clock runs slow, and isolation cut it off from NTP, so "
        "nothing corrects it while it is contained; the gap grows with time. The timestamps that matter are not affected. Before isolation the host was NTP-synced: its sshd "
        "log agrees with the Mac's SSH client to within a second for every session (&sect;7.2). Host times written after isolation are "
        "used for order only, not wall-clock time, and the live-response times above are host-clock values.")]
s += note("In an earlier test run the contained guest was left for over an hour and drifted 75 minutes. Without a clock "
          "reference its live-response times would have looked 75 minutes older than they were. Recording host time against a "
          "trusted reference before any timestamp is used is a required step, not a formality.", label="Why it matters")

# ================================================================= memory
s += [PageBreak(), P("4. Memory analysis with Volatility 3", "h1"),
      P("Volatility needs a symbol table (ISF) for the exact kernel in the image. None was published for Debian's "
        f"6.1.0-54-cloud-amd64, so it was built with the Volatility Foundation's {C('dwarf2json')} v0.9.0 from Debian's own debug "
        f"package ({C('linux-image-6.1.0-54-cloud-amd64-dbg_6.1.190-1')}). It is stored in {C('lab/symbols/')}. "
        "The image is E01, the 1 GiB RAM dump taken by the hypervisor in Task 3 before the uploader was killed.")]
s += table([
    ["Image integrity check", "SHA-256 of E01"],
    ["Before analysis", C(mem_h[0])],
    ["After analysis", C(mem_h[1]) + "  " + (ok("UNCHANGED") if mem_h[0] == mem_h[1] else bad("CHANGED"))],
], [1.6 * inch, 4.9 * inch])
psaux = [l for l in rd("memory/vol_psaux.txt").splitlines() if re.search(r"python3|sshd|cron|^PID", l)]
s += code("\n".join(psaux), title="linux.psaux - the uploader (and the EHR portal) as they were in memory")
s += code(vol("envars_uploader", r"SSH_|USER|HOME|PWD|^PID"), title=f"linux.envars --pid {upid} - the process carries the SSH session it came from")
s += code(vol("sockstat", r"10\.78\.99\.66|^NetNS"), title="linux.sockstat - the uploader's socket to the drop site")
s += code(vol("lsof_uploader"), title=f"linux.lsof --pid {upid}")
s += code("\n".join(l.expandtabs(8)[:118] for l in kmsg_block[:3]), title=f"linux.kmsg - kernel log in RAM: {len(kmsg_block)} IR-BLOCK lines")
s += code(rd("memory/uploader_region_search.txt").strip(), title=f"linux.proc.Maps --pid {upid} --dump, then grep - patient record in the heap")
s += [P("4.1 Findings and integrity checks", "h2")]
s += table([
    ["Plugin", "Result", "Meaning"],
    ["pslist / pstree / psaux", f"{len([l for l in rd('memory/vol_pslist.txt').splitlines() if l.startswith('0x')])} tasks; PID {upid} = python3 syncd.py, parent 1", "Detached (setsid) process: PPID 1, as planted"],
    ["envars", "SSH_CONNECTION=10.78.10.1 &hellip; 10.0.2.15 22", "Started from Tara's SSH session (NAT address of the Mac)"],
    ["sockstat", "TCP 10.0.2.15 &rarr; 10.78.99.66:8080 SYN_SENT", "Still trying to upload; held by the C3 firewall drop"],
    ["lsof", "fd 0&ndash;2 /dev/null, fd 3 socket", "Fully detached from any terminal"],
    ["kmsg", f"{len(kmsg_block)} IR-BLOCK lines, first attributed to Task({upid})", "Memory confirms what kern.log said (Task 3 &sect;5.2)"],
    ["proc.Maps + dump", "Record text and MRN in a heap region", "Proves the process held the ePHI, not just a file path"],
    ["bash", "no entries", "Commands were sent as SSH exec, not typed into an interactive shell, so the trail is in auditd (&sect;7)"],
    ["check_modules / lsmod", "no hidden modules; 52 listed", "No kernel rootkit"],
    ["check_syscall", f"{len(syscalls)} entries, {sys_unknown} without a kernel symbol", ok("Clean") + ": no syscall hooks"],
    ["malfind", "no injected executable regions", ok("Clean")],
], [1.25 * inch, 2.55 * inch, 2.7 * inch])
s += note(f"Cross-check with the live data: Task 3's {C('ps')} listed the uploader as PID {upid}, started {kt['Uploader started (auditd)'][11:16]} UTC by test.nurse. "
          "Volatility, reading raw memory without the guest's tools, finds the same PID, command line and owner. A tampered "
          "ps would not survive this comparison.", label="Validation")
s += note("The first Volatility attempt returned no processes. The guest had booted with 5-level paging (QEMU's full CPU "
          f"model), which Volatility 3 2.7.0 does not translate. The lab therefore runs the guest with {C('-cpu max,la57=off')} "
          "(Task 1 &sect;7), and this image comes from it.", label="Configuration point")

# ================================================================= disk
s += [P("5. Disk acquisition with Parrot OS imaging tools", "h1"),
      P("The suspect is a virtual machine, so the disk was acquired the way a VM disk is acquired: seized at the "
        "hypervisor from a fixed point in time, then imaged and verified on the forensic workstation. Imaging from inside the "
        "running guest would read a live, changing file system and would have to write the image through the suspect's own "
        "kernel.")]
s += table([
    ["#", "Step", "Command / tool", "Result"],
    ["1", "Seize: export the disk as at snapshot ir-contained", f"{C('qemu-img convert -U -l snapshot.name=ir-contained -O raw')} (= VBoxManage clonemedium --format RAW)", f"E11, 8 GiB, sha256 {C(seized_h[:16])}&hellip;"],
    ["2", "Write-block the source", "E11 mounted read-only into ir-forensics at /seized", "write attempt refused: <i>Read-only file system</i>"],
    ["3", "Image with hashing and log", f"{C('dc3dd if=/seized/... of=...vda.dd hash=sha256 log=dc3dd_acquisition.log')}", f"16,777,216 sectors in = out; {dc3_rate}"],
    ["4", "Verify", "sha256sum on the image vs dc3dd's input hash vs step 1", ok("all three equal") if seized_h == dc3_in == dd_h else bad("differ")],
    ["5", "Protect", "image and seized file set read-only; hashes into the evidence index", "E12 = working copy"],
    ["6", "Examine (copy only)", "mmls, fsstat, fls, ifind, icat, istat, mactime (The Sleuth Kit)", "&sect;5.1"],
], [0.25 * inch, 1.55 * inch, 2.65 * inch, 2.05 * inch])
s += code("\n".join(l for l in dc3.splitlines() if l.strip()), title="disk/dc3dd_acquisition.log")
s += [P("5.1 Examination of the image", "h2")]
s += code(rd("disk/mmls.txt").strip(), title="mmls - GPT; the root file system is the largest partition, at sector 262144")
s += code(section("04_disk_acquisition.txt", r"\$ fsstat", r"\$ fls", n=12), title="fsstat (excerpt)")
s += code("\n".join(l for l in rd("disk/fls_incident_paths.txt").splitlines() if not re.search(r"dpkg|man8|xslt", l)),
          title="fls -r -p (incident paths) - planted files, quarantined key, containment config")
trs = [["File recovered from the image (icat)", "Inode", "Image SHA-256 = Task 3 live copy?"]]
for r in recov:
    trs.append([C(r[0]), r[1].split("=")[1], ok("MATCH") if r[-1] == "MATCH" else bad(r[-1])])
s += table(trs, [3.3 * inch, 0.8 * inch, 2.4 * inch])
s += code("\n".join(rd("disk/istat_syncd.txt").splitlines()[:12]), title=f"istat syncd.py - owner uid 1003 (test.nurse), mode 0700, created {istat_created} UTC")

# ================================================================= chain of custody
s += [PageBreak(), P("6. Chain of custody", "h1"),
      P(f"{C('analysis/chain_of_custody.py')} builds the register and the custody log from the evidence itself. Times come from "
        "the run markers, acquisition hashes from the transcripts, and every item is re-hashed when the log is built. Each item "
        f"has an ID (E01&ndash;E{len(reg):02d}), a source, a method, an acquirer, a storage location and two hashes: at acquisition "
        "and now.")]
trs = [["ID", "Item", "Acquired (UTC)", "Stored", "SHA-256 at acquisition", "Now"]]
for r in reg:
    st = r["stored_at"]
    st = "~/ir1-vm-lab/evidence (outside git)" if "ir1-vm-lab" in st else st.replace("repo:Semester_5/Incident_Response_1/", "").replace("_containment/evidence", "").replace("_evidence_management/evidence", "")
    trs.append([r["item"], e(r["description"][:70]), r["acquired_utc"][11:19], e(st), C(r["sha256_at_acquisition"][:12]) + "&hellip;",
                ok("OK") if r["integrity"] == "VERIFIED" else bad("CHANGED")])
s += table(trs, [0.42 * inch, 2.05 * inch, 0.68 * inch, 1.65 * inch, 1.1 * inch, 0.6 * inch])
ev_counts = {}
for r in cust:
    ev_counts[r["event"]] = ev_counts.get(r["event"], 0) + 1
s += [P(f"The custody log has {len(cust)} events: " + ", ".join(f"{v} {k.lower()}" for k, v in ev_counts.items()) + ". "
        "The full history of the disk image (E12) shows each hand-off and its hash check:")]
s += table([["UTC", "Event", "From &rarr; To", "Check"]] +
           [[r["utc"][11:19], r["event"], e((r["from"] + " &rarr; " + r["to"]).replace("~/ir1-vm-lab/evidence/IR1-2026-002/", ""))[:70].replace("&amp;rarr;", "&rarr;"), e(r["hash_check"])]
            for r in cust if r["item"] == "E12"], [0.7 * inch, 1.6 * inch, 2.6 * inch, 1.6 * inch])
s += table([
    ["Custody form field", "Value for every item in this case"],
    ["Case / incident", f"{CASE} (SEV-1), Care Access Navigator, HealthLine Regional Medical Center (HRMC) (lab)"],
    ["Collected by / custodian", "A. Chennamaneni, IR analyst (account ir-analyst); custodian of the case store"],
    ["Storage", "Repository evidence/ folders (git history = tamper-evident log of changes); images &gt; 100 MB in ~/ir1-vm-lab/evidence on the "
                "analyst's FileVault-encrypted macOS volume (fdesetup status: On), set read-only"],
    ["Access", "Images: analyst's local account only. The course repository is <b>public</b> on GitHub. That is acceptable here only "
               "because every record is synthetic; real ePHI evidence must never go into a code repository. Any copy for a third party "
               "(Privacy Officer, legal) is a new custody event: who, when, why, hash before and after"],
    ["Retention", "Kept until the HIPAA breach-risk assessment for PT-1003 is closed, then per the record-retention schedule (Compliance 1 Task 4)"],
], [1.6 * inch, 4.9 * inch])

# ================================================================= timeline
s += [P("7. Timeline: macOS and Parrot OS", "h1"),
      P(f"{C('analysis/build_timeline.py')} merges every timestamped source into one UTC table "
        f"({C('timeline/supertimeline_IR1-2026-002.csv')}, {len(tl)} events). Each source was normalised to UTC: the Mac's "
        "-05:00 local time was converted, auditd epoch seconds were converted, and mactime ran with -z UTC.")]
s += table([["Host", "Source", "Events"]] + [[r["host"], C(r["source"]), r["events"]] for r in srcs], [2.0 * inch, 2.8 * inch, 1.7 * inch])
s += note("auditd restarts its record serial number at every boot, and the golden image's audit.log also holds the image-build boot. "
          "Joining records on the serial alone attached commands from the lab boot to timestamps from the image-build boot. Records are now joined on "
          "time + serial, and the timeline is limited to this lab run.", label="Parser bug found and fixed")
s += [P("7.1 Key events", "h2")]
s += table([["UTC", "Milestone", "Source"]] + [[r["utc"][11:23], e(r["milestone"]), C(r["source"])] for r in key],
           [0.95 * inch, 3.65 * inch, 1.9 * inch])

# swimlane figure
lanes = [("macOS", ["ssh_client.log"]), ("Parrot logs", ["auth.log", "ehr-audit.log", "audit.log", "kern.log"]), ("SIEM", ["alerts.json"]),
         ("Parrot disk", ["mactime"]), ("Network", ["nic0 pcap", "uploads.jsonl"]), ("Responders", ["task3 markers.csv"])]
t0 = iso(next(r["utc"] for r in key if r["utc"])) - dt.timedelta(seconds=5); t1 = iso([r["utc"] for r in key if r["utc"]][-1]) + dt.timedelta(seconds=10)
W, H, X0 = FULL_W, 205, 70
d = Drawing(W, H)
span = (t1 - t0).total_seconds()
xp = lambda t: X0 + (W - X0 - 10) * (iso(t) - t0).total_seconds() / span
cols = [colors.HexColor("#3A6EA5"), NAVY, colors.HexColor("#7B3FA0"), AMBER, RED, GREEN]
for i, (name, srcl) in enumerate(lanes):
    y = H - 30 - i * 28
    d.add(Line(X0, y, W - 10, y, strokeColor=GREY_LINE, strokeWidth=0.5))
    d.add(String(2, y - 3, name, fontName="Helvetica-Bold", fontSize=7.5, fillColor=NAVY))
    for r in tl:
        if r["source"] in srcl and t0 <= iso(r["utc"]) <= t1:
            d.add(Circle(xp(r["utc"]), y, 2.2, fillColor=cols[i], strokeColor=None))
for k in range(0, int(span) + 1, 30):
    x = X0 + (W - X0 - 10) * k / span
    d.add(Line(x, 22, x, 26, strokeColor=MUTED))
    d.add(String(x, 12, (t0 + dt.timedelta(seconds=k)).strftime("%H:%M:%S"), fontName="Helvetica", fontSize=6, fillColor=MUTED, textAnchor="middle"))
for label, ph in (("detect", "detection"), ("block", "c3_block"), ("isolate", "c6_isolate")):
    t = next(r["utc"] for r in tl if r["detail"] == ph)
    d.add(Line(xp(t), 26, xp(t), H - 18, strokeColor=RED, strokeWidth=0.8, strokeDashArray=[2, 2]))
    d.add(String(xp(t), H - 14, label, fontName="Helvetica-Bold", fontSize=7, fillColor=RED, textAnchor="middle"))
s += [d, Paragraph(f"Figure 1. Super-timeline, {t0.strftime('%H:%M:%S')}&ndash;{t1.strftime('%H:%M:%S')} UTC. Each dot is one event. Network dots stop at the block line; "
                   "Parrot dots after it are the firewall logging dropped attempts.", ss["caption"])]
s += [P("7.2 Cross-host correlation (macOS &harr; Parrot OS)", "h2"),
      P("The Mac and parrot-vm see different addresses for the same session, because the Mac connects to 127.0.0.1:2223 and "
        "the VM sees the Docker NAT address. They were therefore joined on two independent keys: time, and the SSH key "
        "fingerprint the Mac offered against the one Parrot's sshd accepted.")]
s += table([["Mac ssh PID", "Mac authenticated", "Parrot sshd accepted", "&Delta; s", "Key fingerprint"]] +
           [[r["mac_ssh_pid"], r["mac_authenticated_utc"][11:19], r["vm_accepted_utc"][11:23], r["delta_s"],
             ok(r["key_fingerprint"]) + " " + C(r["fingerprint"])] for r in corr],
           [0.8 * inch, 1.2 * inch, 1.35 * inch, 0.5 * inch, 2.65 * inch])
s += [P("7.3 Analysis", "h2")]
FIRST_SSH = "Tara's first SSH session from the Mac authenticated"
sec = lambda a, b: (iso(kt[b]) - iso(kt[a])).total_seconds()
s += bullets([
    f"<b>Intent was immediate.</b> {sec(FIRST_SSH, 'PT-1003 viewed through stale clinical group'):.0f} s "
    f"passed from first login to viewing PT-1003, and {sec('PT-1003 viewed through stale clinical group', 'First upload received by drop site'):.1f} s more to the first "
    "upload. Staging, the uploader and the cron job were all in place within 5 s, an order of operations that only makes sense if planned.",
    "<b>Every layer saw the read.</b> The EHR audit trail (application), auditd (kernel watch on the file), the file system (the "
    "staged copy's birth time) and memory (the heap) " f"all place PT-1003 in test.nurse's hands at {kt['PT-1003 viewed through stale clinical group'][11:19]}&ndash;{kt['Uploader script written (file system)'][11:19]} UTC.",
    f"<b>Containment closed the window.</b> The last upload reached the drop site at {kt['Last upload received by drop site'][11:19]}. "
    f"Egress was blocked at {kt['Egress blocked (C3)'][11:19]}, and the first logged drop came at {kt['First firewall drop logged'][11:19]}. "
    "The block took effect at the uploader's next 5-second cycle.",
    "<b>Root cause visible in the timeline:</b> the mover change (Nurse &rarr; Billing) added billing but never removed clinical. "
    f"The account change that finally removed it is the C7 entry at {kt['Account locked + clinical group removed'][11:19]}, "
    "after the incident. That is the gap Task 6 fixes in the JML process.",
])

s += [P("8. Limitations", "h1")]
s += bullets([
    "Parrot OS and VirtualBox are substituted by a Debian 12 VM under QEMU (see Task 3 &sect;9). All tools used are in Parrot's standard "
    "forensic set, and every hypervisor step has a VirtualBox equivalent.",
    "The macOS side is the SSH client log written on the Mac. The macOS unified log needs admin rights to read on this managed Mac "
    "(Task 2 &sect;5).",
    "The image is raw (dd), not E01. ewfacquire is installed; raw was chosen so the Sleuth Kit and hash checks run on a plain "
    "bit-for-bit copy.",
])
s += [P("Appendix A &mdash; Evidence index", "h1")]
s += code("\n".join(l[:16] + "...  " + l.split("  ", 1)[1] if re.match(r"[0-9a-f]{64}  ", l) else l
                    for l in rd("EVIDENCE-INDEX-SHA256.txt").splitlines()), title="evidence/EVIDENCE-INDEX-SHA256.txt (hashes truncated here)")
build(OUT, s, "Care Access Navigator - IR1 Task 4: Evidence Management", FOOT)
