"""Care Access Navigator - Incident Response 1, Task 3: Incident Response and Containment.
Builds the PDF from the evidence written by run_task3.sh (plus the Task 1 baseline and the Task 2 alert it starts from).
Every table and excerpt is read from the evidence. Run from Semester_5/Incident_Response_1/ (see README)."""
import csv, datetime as dt, json, os, re, tarfile
from html import escape as e
from pdfstyle import (P, bullets, note, code, table, kv, ok, bad, build, ss, Spacer, PageBreak, Paragraph, inch, FULL_W)

TASK = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); IR = os.path.dirname(TASK)
EV = os.path.join(TASK, "evidence"); E1 = os.path.join(IR, "task1_environment_setup", "evidence"); E2 = os.path.join(IR, "task2_log_analysis", "evidence")
OUT = os.path.join(TASK, "Care_Access_Navigator_IR1_Task3_Containment.pdf")
FOOT = "Care Access Navigator - Incident Response 1, Task 3: Incident Response and Containment"
CASE = "IR1-2026-002"
C = lambda t: f"<font face='Courier'>{e(t)}</font>"
rd = lambda p: open(p, errors="replace").read()
tx = lambda n: rd(os.path.join(EV, "transcripts", n))


def section(name, start, stop=None, n=40, cut=118):
    lines = tx(name).splitlines()
    i = next((k for k, l in enumerate(lines) if re.search(start, l)), 0)
    out = []
    for l in lines[i:]:
        if stop and out and re.search(stop, l):
            break
        out.append(l[:cut])
        if len(out) >= n:
            break
    return "\n".join(out)


ts = lambda s: dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
hms = lambda d: d.strftime("%H:%M:%S")
marks = {r["phase"]: ts(r["utc"]) for r in csv.DictReader(open(os.path.join(EV, "markers.csv")))}
ups = [json.loads(l) for l in open(os.path.join(EV, "exfil-sink", "uploads.jsonl"))]
posts = [float(l.split("\t")[0]) for l in open(os.path.join(EV, "network", "ioc_posts_nic0.tsv")) if l.strip()]
probe = lambda txt: [l for l in txt.splitlines() if re.match(r"P[1-6] ", l)]
before, after = probe(rd(os.path.join(E1, "transcripts", "07_baseline.txt"))), probe(tx("09_c8_verification.txt"))
stat_rows = [l.split("|") for l in rd(os.path.join(EV, "filesystem", "artifact_stat.txt")).splitlines() if "|" in l]
src_h = dict(reversed(l.split("  ", 1)) for l in rd(os.path.join(EV, "filesystem", "artifact_sha256_source.txt")).splitlines() if l.strip())
cpy_h = dict(reversed(l.split("  ", 1)) for l in rd(os.path.join(EV, "filesystem", "artifact_sha256_copy.txt")).splitlines() if l.strip())
with tarfile.open(os.path.join(EV, "filesystem", f"{CASE}_artifacts.tar")) as tf:
    kern = tf.extractfile("./var/log/kern.log").read().decode(errors="replace")
    ehr_lines = tf.extractfile("./var/log/ehr-audit.log").read().decode().splitlines()
ehr_read = ts(next(l for l in ehr_lines if "PT-1003" in l).split()[0])
blocks = [l for l in kern.splitlines() if "IR-BLOCK" in l]
block_uids = sorted(set(re.findall(r"UID=(\d+)", "\n".join(blocks))))
mem_tx = tx("05_c4_memory.txt")
ram_sha = re.search(r"sha256 (\w+)\s+\S+mem\.elf", mem_tx)[1]
ram_bytes = int(re.search(r'"total": (\d+)', mem_tx)[1])
core = re.search(r"acquired \S+ -> \S+_syncd\.core\s+bytes=(\d+)\n\s+sha256 source\S+=(\w+)\n\s+sha256 copy\S+=(\w+)\s+(\w+)", mem_tx)
pcap = re.search(r"acquired \S+ -> \S+live_tcpdump\.pcap\s+bytes=(\d+)\n\s+sha256 source\S+=(\w+)\n\s+sha256 copy\S+=(\w+)\s+(\w+)", tx("03_c2_volatile.txt"))
capinfo = {m[0]: (m[1], m[2], m[3]) for m in re.findall(r"capinfos (\S+)\nNumber of packets:\s+(.+)\nFirst packet time:\s+(.+)\nLast packet time:\s+(.+)", tx("10_export.txt"))}
siem_t = re.search(r"(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) wazuh-agentd: INFO: \(4102\): Connected to the server \(\[10\.0\.3\.20\]", tx("07_c6_isolate.txt"))
alert = json.loads(next(l for l in open(os.path.join(E2, "wazuh", "alerts.json")) if '"id":"100221"' in l))
t_alert = ts(alert["timestamp"][:23] + "Z")
upid = re.search(r"PID=(\d+)", rd(os.path.join(EV, "volatile", "suspect_process.txt")))[1]
n_index = sum(1 for l in rd(os.path.join(EV, "EVIDENCE-INDEX-SHA256.txt")).splitlines() if re.match(r"[0-9a-f]{64} ", l))
t_det, t_block, t_iso, t_done = marks["detection"], marks["c3_block"], marks["c6_isolate"], marks["contained"]
leak_after_detect = sum(1 for u in ups if ts(u["ts"]) > t_alert); leak_after_block = sum(1 for u in ups if ts(u["ts"]) > t_block)
secs = lambda a, b: int((b - a).total_seconds())

s = []
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Incident Response 1 &mdash; Task 3: Incident Response and Containment", "subtitle"),
      P(f"Network isolation, evidence preservation and a tested containment playbook, started by a live Wazuh alert ({CASE})", "subsub"),
      Spacer(1, 14)]
s += kv([
    ("Document ID", "CAN-IR1-T3-CONT-002 (replaces 001: same lab, people and incident numbers as Tasks 1&ndash;2 and 4&ndash;6)"),
    ("Author", "Akhila Chennamaneni"), ("Date", "November 3, 2026"),
    ("Incident", f"<b>{CASE}</b> SEV-1: Tara Jones ({C('test.nurse')}, mover Nurse &rarr; Billing) read synthetic record PT-1003 through her "
                 "old clinical group and sent it off the host. Also contained in the same session: IR1-2026-001 (leaver key) and IR1-2026-003 (sudo grant)"),
    ("Trigger", f"Wazuh rule 100221 (level 12) on agent parrot-vm at {alert['timestamp'][11:23]} UTC; containment began at that alert"),
    ("Host", "parrot-vm (Parrot OS stand-in, QEMU VM built in Task 1) with Wazuh agent 001"),
    ("Run", f"{hms(t_det)}&ndash;{hms(t_done)} UTC, 2026-11-03; {n_index} evidence files hashed"),
])
s += [P("Summary", "h1"),
      P(f"Tara Jones read PT-1003 at {hms(ehr_read)} UTC, staged a copy, and started an uploader with a cron job to restart it. "
        f"The Wazuh agent shipped the EHR audit line and rule 100221 fired {(t_alert - ehr_read).total_seconds():.1f} s later, at "
        f"{alert['timestamp'][11:19]} UTC. That alert started this task. Containment followed playbook CAN-IR-PB-02 RB-02: a live snapshot, "
        f"volatile evidence, then an egress block <b>{secs(t_det, t_block)} s after the alert</b>. Nothing reached the drop site after the "
        f"block ({leak_after_block} uploads after it; {len(ups)} in total). Memory, a full RAM image and the file artifacts were preserved "
        "with matching hashes at both ends. The host was then isolated at the hypervisor: clinical cable out, quarantine adapter in. "
        "The Wazuh agent was moved to a single forwarded port, so monitoring continued. Finally the process, persistence, the EHR portal "
        "and the account were shut down, and the two queued incidents were contained on the same host. The six probes from Task 1 were "
        f"re-run: every production path went {ok('REACHABLE')} &rarr; {bad('BLOCKED')}, and only the forensic path opened.")]
s += [P("1. How this report meets the Task 3 requirements", "h1")]
s += table([["Requirement", "Where", "Evidence"],
    ["Network isolation: interface configuration", "&sect;4.1", "transcripts/07"],
    ["Network isolation: basic firewall rules", "&sect;4.2", "containment/iptables.containment.rules, kern.log"],
    ["Network isolation: segmentation using (VirtualBox) networking", "&sect;4.3", "transcripts/07, 09; Task 1 baseline"],
    ["Evidence preservation: network traffic captures", "&sect;5.1", "network/*.pcap"],
    ["Evidence preservation: basic memory dumps", "&sect;5.2", "memory/, transcripts/05"],
    ["Evidence preservation: file system artifacts", "&sect;5.3", "filesystem/"],
    ["Containment playbook: host isolation steps in VirtualBox", "&sect;3 (C1, C6)", "VBoxManage column"],
    ["Containment playbook: network traffic blocking", "&sect;3 (C3, C6d)", "transcripts/04, 07"],
    ["Containment playbook: service shutdown procedures", "&sect;3 (C7), &sect;6", "transcripts/08"],
    ["Documentation and evidence of functionality", "&sect;7", "timeline, measures, evidence index"]], [2.6 * inch, 1.05 * inch, 2.85 * inch])

s += [P("2. From alert to decision", "h1")]
s += code(json.dumps({k: alert[k] for k in ("timestamp", "agent", "location", "full_log")} | {"rule": {k: alert["rule"][k] for k in ("id", "level", "description")}}, indent=1),
          title="The alert that started containment (task2 evidence/wazuh/alerts.json)")
s += code(section("01_triage.txt", r"tail -2", n=30), title="transcripts/01_triage.txt - triage on the host")

# ---------------------------------------------------------------- playbook
s += [PageBreak(), P("3. Containment playbook CAN-IR-PB-02 RB-02 (executed as written)", "h1"),
      P("The order follows volatility: capture what disappears first, stop the loss as soon as it is captured, and keep every "
        "change reversible until the evidence is safe.")]
s += table([["Step", "Action", "Executed here", "VirtualBox / Parrot OS"],
    ["C1", "Live snapshot (undo point; preserves RAM + disk)", "HMP savevm ir-pre-containment", "VBoxManage snapshot parrot-vm take ir-pre-containment --live"],
    ["C2", "Volatile data: packets, processes, connections, persistence", "tcpdump 25 s; ps/ss/lsof/proc over the guest agent", "same tools; output to case storage"],
    ["C3", "<b>Block the traffic</b>, keep the process alive", "iptables chain IR-EGRESS-BLOCK on OUTPUT", "same iptables rules"],
    ["C4", "Memory: process core + full RAM", "gdb gcore; QMP dump-guest-memory", "gcore; VBoxManage debugvm dumpvmcore"],
    ["C5", "File artifacts: stat &rarr; freeze &rarr; hash &rarr; tar &rarr; verify", "stat, tar to RAM, sha256sum, tar over SSH", "same"],
    ["C6", "<b>Isolate</b>: cable out, quarantine adapter in, default-deny, keep the SIEM", "QMP set_link; ip; iptables -P DROP; agent via 10.0.3.20:1514", "setlinkstate1 off; setlinkstate2 on (intnet quarantine)"],
    ["C7", "<b>Shut down</b> process, persistence, exposed service; lock account; contain the queued incidents", "pkill; mask cron; disable portal; usermod -L; gpasswd -d; keys moved", "same systemctl / usermod"],
    ["C8", "Verify with the Task 1 probes; snapshot", "probe matrix; savevm ir-contained", "VBoxManage snapshot ... take ir-contained"]],
    [0.4 * inch, 2.1 * inch, 2.0 * inch, 2.0 * inch])
s += note(f"The uploader (PID {upid}) was not killed when found. Killing it would have lost its memory, which holds the record and the "
          "drop-site URL (&sect;5.2). It was cut off from the network first and killed only after the memory images were hashed.", label="Design choice")

# ---------------------------------------------------------------- isolation
s += [P("4. Network isolation", "h1"), P("4.1 Interface configuration", "h2")]
s += code(section("07_c6_isolate.txt", r"C6a", r"C6d", n=22), title="transcripts/07 - hypervisor link change and guest interfaces")
s += [P("4.2 Firewall rules", "h2"),
      P(f"Two stages. <b>C3</b> drops and logs everything to the IOC while leaving the host up for evidence collection. <b>C6d</b> sets "
        "every policy to DROP and opens two paths only: SSH from the forensic workstation on the quarantine interface, and the Wazuh "
        f"agent to the quarantine SIEM forward. Before the incident the ruleset was empty ({C('iptables.pre-containment.rules')}): the "
        "host had no firewall, a finding for Task 6.")]
s += code(rd(os.path.join(EV, "containment", "iptables.containment.rules")), title="containment/iptables.containment.rules")
s += [P(f"The kernel logged {len(blocks)} IR-BLOCK lines before the artifacts were frozen, each tagged {C('UID=' + ','.join(block_uids))} "
        f"(test.nurse) by {C('--log-uid')}. The firewall itself names the account behind every blocked packet.")]
s += [P("4.3 Segmentation and monitoring: before and after", "h2")]
rows_ = [["#", "Path", "Before (Task 1)", "After", "Result"]]
for b, a in zip(before, after):
    k, rest = b.split(" ", 1); path, bv = rest.rsplit(":", 1); av = a.rsplit(":", 1)[1].strip()
    want = "REACHABLE" if k == "P6" else "BLOCKED"
    rows_.append([k, e(path.strip()), ok(bv.strip()) if "REACH" in bv else bad(bv.strip()), ok(av) if "REACH" in av else bad(av),
                  ok("PASS") if av.startswith(want) else bad("FAIL")])
s += table(rows_, [0.35 * inch, 3.15 * inch, 1.15 * inch, 1.05 * inch, 0.8 * inch])
s += [P("<b>SIEM kept during quarantine.</b> The quarantine network has no route anywhere. Its only exit is one forward the hypervisor "
        "provides, 10.0.3.20:1514 &rarr; wazuh-manager. The agent was re-pointed to it and reconnected"
        f"{' at ' + siem_t[1][11:] + ' UTC' if siem_t else ''}, so containment and everything after it stayed visible to the SIEM.")]
s += code(section("07_c6_isolate.txt", r"C6e", n=6), title="transcripts/07 (C6e)")

# ---------------------------------------------------------------- evidence
s += [PageBreak(), P("5. Evidence preservation with Parrot OS tools", "h1"), P("5.1 Network traffic captures", "h2")]
s += table([["Capture", "Taken by", "Packets", "Purpose"],
    [C(f"{CASE}_live_tcpdump.pcap"), "tcpdump on parrot-vm (C2a)", capinfo[f"{CASE}_live_tcpdump.pcap"][0], "Host-side proof of the uploads"],
    [C("hypervisor_nic0_clinical.pcap"), "hypervisor NIC trace (= --nictrace)", capinfo["hypervisor_nic0_clinical.pcap"][0], "All adapter-1 traffic for the whole exercise; the guest cannot tamper with it"],
    [C("hypervisor_nic1_quarantine.pcap"), "hypervisor NIC trace", capinfo["hypervisor_nic1_quarantine.pcap"][0], "Only forensic SSH and the agent after isolation"]],
    [2.0 * inch, 1.6 * inch, 0.7 * inch, 2.2 * inch])
s += [P(f"The hypervisor capture holds <b>{len(posts)}</b> HTTP POSTs to the IOC, the same number the drop site logged ({len(ups)}). "
        f"The live capture's hash matches at both ends ({pcap[4]}).")]
s += [P("5.2 Memory dumps", "h2")]
s += table([["Dump", "Tool", "Size", "SHA-256", "Stored"],
    [f"Process core of PID {upid} (syncd.py)", "gdb gcore (guest)", f"{int(core[1]) / 1e6:.1f} MB", f"{C(core[2][:20])}&hellip; {ok(core[4])}", "~/ir1-vm-lab/evidence (outside git)"],
    ["Full RAM of parrot-vm", "QMP dump-guest-memory", f"{ram_bytes / 2**30:.2f} GiB", f"{C(ram_sha[:20])}&hellip;", "~/ir1-vm-lab/evidence (outside git)"]],
    [1.6 * inch, 1.25 * inch, 0.65 * inch, 1.9 * inch, 1.1 * inch])
s += code(rd(os.path.join(EV, "memory", "syncd_core_strings.txt")), title="memory/syncd_core_strings.txt - what the uploader held in memory")
s += [P("5.3 File-system artifacts", "h2"),
      P("Metadata was read with stat <i>before</i> anything opened the files. Live logs keep growing, so a point-in-time copy was "
        "frozen into RAM, hashed, sent as a tar over SSH, and every file in the received tar was re-hashed.")]
s += table([["Artifact", "Owner", "Mode", "Modified (UTC)", "Match"]] +
           [[C(r[0]), r[2], r[3], r[5].split("=", 1)[1][:19], ok("MATCH") if src_h.get(r[0]) and src_h.get(r[0]) == cpy_h.get(r[0]) else bad("NO")] for r in stat_rows],
           [2.6 * inch, 1.15 * inch, 0.5 * inch, 1.3 * inch, 0.95 * inch])

# ---------------------------------------------------------------- shutdown
s += [P("6. Service shutdown and account containment (all three incidents)", "h1")]
s += code(section("08_c7_shutdown.txt", r"## IR1-2026-002", n=40), title="transcripts/08_c7_shutdown.txt")
s += table([["Target", "Procedure", "Why"],
    ["Uploader + test.nurse processes", "pkill after memory was preserved", "Ends the transfer; evidence already hashed"],
    ["cron (persistence)", "stop + mask", "The */5 job would restart the uploader; the crontab is kept as evidence"],
    ["ehr-portal", "stop + disable", "A compromised host must not serve ePHI; restored in Task 6"],
    ["test.nurse (IR1-2026-002)", "lock + expire; remove clinical; keys moved", "Removes the root cause on this host"],
    ["test.clinician sudo (IR1-2026-003)", "gpasswd -d test.clinician sudo", "The grant had no change record"],
    ["test.billing key (IR1-2026-001)", "authorized_keys moved to /root/ir-quarantine", "The leaver's standing credential"],
    ["sshd", "ListenAddress quarantine only; AllowUsers ir-analyst", "Kept as the forensic channel for Task 4"]], [1.9 * inch, 2.3 * inch, 2.3 * inch])

# ---------------------------------------------------------------- timeline
s += [P("7. Containment timeline and measures", "h1")]
names = [("detection", "Wazuh rule 100221 alert (SEV-1)"), ("triage", "Host triage confirms disclosure in progress"),
         ("c1_snapshot", "C1 live snapshot"), ("c2_volatile", "C2 volatile evidence"), ("c3_block", "C3 egress blocked"),
         ("c4_memory", "C4 memory preserved"), ("c5_filesystem", "C5 artifacts preserved"), ("c6_isolate", "C6 isolated, SIEM kept"),
         ("c7_shutdown", "C7 shutdown; IR1-2026-001 and -003 contained"), ("c8_verify", "C8 probes re-run"), ("contained", "Snapshot ir-contained")]
s += table([["UTC", "Phase", "Event"]] + [[hms(marks[k]), k, v] for k, v in names if k in marks], [0.75 * inch, 1.2 * inch, 4.55 * inch])
s += table([["Measure", "Value"],
    ["Record read &rarr; Wazuh alert", f"{(t_alert - ehr_read).total_seconds():.1f} s"],
    ["Alert &rarr; egress blocked", f"<b>{secs(t_det, t_block)} s</b>"],
    ["Uploads: total / after the alert / after the block", f"{len(ups)} / {leak_after_detect} / <b>{leak_after_block}</b>"],
    ["Alert &rarr; isolated", f"{secs(t_det, t_iso)} s"], ["Alert &rarr; contained and verified", f"{secs(t_det, t_done)} s"]], [3.5 * inch, 3.0 * inch])
s += [P("8. Limitations and hand-off", "h1")]
s += bullets(["VirtualBox &rarr; QEMU and Parrot OS &rarr; Debian 12; each step lists its VirtualBox command.",
              "Eradication and recovery are left to Task 6, and the forensic analysis to Task 4.",
              "The lab stays running in the contained state, with snapshots baseline-clean, ir-pre-containment and ir-contained."])
s += [P("Appendix A &mdash; Evidence index", "h1")]
s += code("\n".join(l[:16] + "...  " + l.split("  ", 1)[1] if re.match(r"[0-9a-f]{64}  ", l) else l
                    for l in rd(os.path.join(EV, "EVIDENCE-INDEX-SHA256.txt")).splitlines()), title="evidence/EVIDENCE-INDEX-SHA256.txt")
build(OUT, s, "Care Access Navigator - IR1 Task 3: Containment", FOOT)
