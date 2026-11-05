"""Care Access Navigator - Incident Response 1, Task 6: Post-Incident Procedures.
Builds the PDF from the Task 6 evidence (lab/run_task6.sh) plus the Task 3/4 evidence and the tracker that the
root-cause analysis draws on. Run from incident_response_1/ (see README)."""
import csv, datetime as dt, json, os, re, sqlite3
from html import escape as e
from pdfstyle import (P, bullets, note, code, table, kv, ok, bad, build, ss, Spacer, PageBreak, Paragraph, inch, FULL_W)

TASK = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); IR = os.path.dirname(TASK)
EV = os.path.join(TASK, "evidence"); E3 = os.path.join(IR, "task3_containment", "evidence"); E4 = os.path.join(IR, "task4_evidence_management", "evidence")
OUT = os.path.join(TASK, "Care_Access_Navigator_IR1_Task6_Post_Incident.pdf")
FOOT = "Care Access Navigator - Incident Response 1, Task 6: Post-Incident Procedures"
I = "IR1-2026-002"
C = lambda t: f"<font face='Courier'>{e(t)}</font>"
rd = lambda p: open(p, errors="replace").read()
tx = lambda n: rd(os.path.join(EV, "transcripts", n))
rows = lambda p: list(csv.DictReader(open(p)))
tsv = lambda n: [l.split("\t") for l in rd(os.path.join(EV, "validation", n)).splitlines()[1:]]
iso = lambda s: dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
hms = lambda s: s[11:19]


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


steps = {r["step"]: r["utc"] for r in rows(os.path.join(EV, "steps.csv"))}
m3 = {r["phase"]: r["utc"] for r in rows(os.path.join(E3, "markers.csv"))}
key = {r["milestone"]: r["utc"] for r in rows(os.path.join(E4, "timeline", "key_events.csv"))}
v1, v2 = tsv("checklist_run1.tsv"), tsv("checklist_run2.tsv")
p1, p2 = tsv("network_probes_run1.tsv"), tsv("network_probes_run2.tsv")
ups = [json.loads(l) for l in open(os.path.join(E3, "exfil-sink", "uploads.jsonl"))]
gate = re.findall(r"(\w+_check): (\d+) OK, (\d+) not OK", tx("01_r0_evidence_gate.txt"))
skews = re.findall(r"skew ([+-][\d.]+) s", tx("04_r3_r4_recover.txt"))
clk = [rd(os.path.join(EV, "validation", f"clock_run{i}.txt")).strip() for i in (1, 2)]
db = sqlite3.connect(os.path.join(IR, "task5_ir_documentation", "tracker", "incidents.db")); db.row_factory = sqlite3.Row
hist = {r["status"]: r["at_utc"] for r in db.execute("SELECT * FROM status_history WHERE incident=?", (I,))}
sec = lambda a, b: (iso(b) - iso(a)).total_seconds()
# testing procedure of each check, read from the checklist script itself
proc = {}
for l in rd(os.path.join(IR, "lab", "validate_recovery.sh")).splitlines():
    m = re.match(r'r (\S+) \S+ "[^"]*" "?[^"]*"? "\$\((.*)\)"$', l.strip())
    if m:
        proc[m[1]] = m[2]
cmds = [r for r in rows(os.path.join(E4, "timeline", "supertimeline_IR1-2026-002.csv")) if r["event"].startswith("command executed by test.nurse")]
upid = re.search(r"PID=(\d+)", rd(os.path.join(E3, "volatile", "suspect_process.txt")))[1]
_ist = open(os.path.join(E4, "disk", "istat_syncd.txt")).read()
ist_ino = re.search(r"inode: (\d+)", _ist)[1]; ist_cr = re.search(r"File Created:\s+\S+ (\d\d:\d\d:\d\d)", _ist)[1]
snap_t = re.search(r"baseline-clean\s+\S+ \S+ \S+ (\d\d:\d\d):\d\d", open(os.path.join(IR, "task1_environment_setup", "evidence", "transcripts", "07_baseline.txt")).read())[1]
pass_n = lambda v: sum(1 for r in v if r[-1] == "PASS")

s = []
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Incident Response 1 &mdash; Task 6: Post-Incident Procedures", "subtitle"),
      P("Environment and system recovery, root cause analysis, a tested recovery validation checklist, and IR process improvements for IR1-2026-002", "subsub"),
      Spacer(1, 14)]
s += kv([
    ("Document ID", "CAN-IR1-T6-POST-002"), ("Author", "Akhila Chennamaneni"), ("Date", "November 3, 2026"),
    ("Incident", f"{I}, SEV-1 (contained in Task 3, evidence in Task 4, documented in Task 5)"),
    ("Recovery run", f"{hms(steps['r0_gate'])}&ndash;{hms(steps['done'])} UTC; snapshots before and after; validation run twice (before and after a reboot)"),
    ("Result", f"Checklist {pass_n(v1)}/{len(v1)} and {pass_n(v2)}/{len(v2)}; network probes {pass_n(p1)}/{len(p1)} and {pass_n(p2)}/{len(p2)}; "
               f"clock skew {clk[1].split('skew ')[1]}"),
])
s += [P("Summary", "h1"),
      P("Recovery did not try to clean the compromised host. The evidence was re-verified first, then the VM was returned to the clean "
        "snapshot taken before the incident. That snapshot is clean of attacker files but still has the conditions that let the "
        "incident happen: Tara's stale clinical group, no host firewall, open cron, leaver keys. Recovery therefore went on to "
        "<b>fix the root cause on the restored system</b>, restore the network and services, and prove the result with a "
        f"{len(v1)}-item checklist and six network probes, twice, with a reboot between. The root cause analysis traces the incident to a "
        "joiner/mover/leaver process that covered the identity provider but not local hosts. Five contributing factors and twelve "
        "improvements are listed, each with an owner and a due date.")]
s += [P("1. How this report meets the Task 6 requirements", "h1")]
s += table([
    ["Requirement", "Where", "Evidence"],
    ["Recovery procedure: VirtualBox environment restoration", "&sect;2.2", "transcripts/02&ndash;03, snapshots"],
    ["Recovery procedure: Parrot OS system recovery", "&sect;2.3", "lab/recover_harden.sh, transcripts/04"],
    ["Recovery procedure: network configuration recovery", "&sect;2.4", "transcripts/04, validation/firewall_baseline_rules.v4"],
    ["RCA: event timeline", "&sect;3.1", "task4 timeline/ (176 events)"],
    ["RCA: contributing factors", "&sect;3.2&ndash;3.3", "5 Whys, factor table"],
    ["RCA: technical findings from Parrot OS tools", "&sect;3.4", "Volatility, Sleuth Kit, auditd, tcpdump outputs"],
    ["Recovery validation checklist with testing procedures, created and implemented", "&sect;4", "lab/validate_recovery.sh, validation/*.tsv"],
    ["IR process improvement recommendations from lessons learned", "&sect;5", "&sect;5.1&ndash;5.3"],
], [2.9 * inch, 0.9 * inch, 2.7 * inch])

# ================================================================= recovery
s += [P("2. Recovery procedures", "h1"), P("2.1 Strategy", "h2")]
s += table([["Option", "When to use", "Decision for IR1-2026-002"],
    ["Clean in place (delete the attacker's files)", "Never for a compromised host: you cannot prove you found everything", bad("Rejected")],
    ["Restore the last known-good snapshot", "A snapshot from before the incident exists and its integrity is known", ok("Chosen") + f": baseline-clean (taken {snap_t} UTC in Task 1, before the first user login)"],
    ["Rebuild from the golden image", "No trusted snapshot, or the snapshot may contain the attacker", "Fallback: golden image hash verified (&sect;2.2 step 3)"],
], [2.0 * inch, 2.6 * inch, 1.9 * inch])
s += note("Whatever the choice, a known-good state is only as good as the configuration it holds. The baseline snapshot was taken "
          "after provisioning, so it contains the incident's root cause (Tara's clinical group). Restoring is step one; fixing is step two.",
          label="Key point")
s += [P("2.2 VirtualBox environment restoration", "h2")]
s += table([["#", "Step", "VirtualBox command", "Lab (executed)", "Result"],
    ["1", "Evidence gate: re-verify everything before destroying the compromised state", "(none)", "shasum -c on the Task 3 and Task 4 indexes",
     ", ".join(f"{a.split('_')[0]} {b}/{int(b) + int(c)}" for a, b, c in gate)],
    ["2", "Record the compromised state", "snapshot take pre-recovery --live", "HMP savevm pre-recovery", "kept for reference"],
    ["3", "Verify the rebuild source", "sha256 of the golden VDI/OVA", "shasum golden.qcow2 vs recorded", "MATCH" if "golden image: MATCH" in tx("02_r1_record_and_source.txt") else "CHANGED"],
    ["4", "Restore the clean snapshot", "snapshot &lt;vm&gt; restore baseline-clean", "HMP loadvm baseline-clean", "guest agent up"],
    ["5", "Production wiring: adapter 1 in, adapter 2 out", "controlvm setlinkstate1 on; setlinkstate2 off", "QMP set_link nic0 on / nic1 off", "&sect;2.4"],
    ["6", "Fix, validate, reboot, validate (&sect;2.3, &sect;4)", "(none)", "recover_harden.sh, validate_recovery.sh", f"{pass_n(v2)}/{len(v2)}"],
    ["7", "New known-good baseline", "snapshot take recovered-validated --live", "HMP savevm recovered-validated", "done"],
], [0.25 * inch, 1.75 * inch, 1.6 * inch, 1.6 * inch, 1.3 * inch])
s += code(section("01_r0_evidence_gate.txt", r"task1_check", n=12), title="transcripts/01_r0_evidence_gate.txt")
s += code(section("07_r7_snapshot.txt", r"List of snapshots", n=9), title="Snapshot inventory after recovery (transcripts/07)")
s += [P("2.3 Parrot OS system recovery", "h2"),
      P("Right after the restore, the host was clean of the attacker's artifacts but showed the root cause again:")]
s += code(section("03_r2_restore.txt", r"BEFORE fixes", n=10), title="transcripts/03_r2_restore.txt")
s += table([["Section", "Fix (lab/recover_harden.sh)", "Why"],
    ["R2.1 Identity", f"{C('gpasswd -d test.nurse clinical')}; {C('gpasswd -d test.clinician sudo')}; keep test.nurse disabled pending HR; move authorized_keys off disabled accounts (test.nurse, test.billing)", "Root cause of IR1-2026-002; leaver finding of IR1-2026-001"],
    ["R2.2 Persistence", f"{C('/etc/cron.allow')} = root", "Users can no longer plant cron jobs"],
    ["R2.3 Firewall", f"Default DROP in and out; SSH only from admin net 10.78.50.0/24; portal only from clinical LAN; egress DNS/NTP/DHCP/HTTP(S) only; IOC chain; loaded at boot by {C('ir-firewall.service')}", "The host had no firewall; the uploader used a non-standard port"],
    ["R2.4 Services", "unmask + enable cron, ehr-portal; remove the containment sshd drop-in", "Back to normal service"],
    ["R2.5 Audit", f"keep the incident watches; add {C('-w /etc/sudoers.d -k sudoers')}", "IR1-2026-003 (unapproved sudo) becomes visible"],
], [1.05 * inch, 3.6 * inch, 1.85 * inch])
s += code(section("04_r3_r4_recover.txt", r"R2.1 identity", r"R2.3", n=12), title="transcripts/04 (R2.1-R2.2)")
s += [P("2.4 Network configuration recovery", "h2")]
s += bullets([
    "<b>Adapters</b> (hypervisor): clinical adapter cable in, quarantine adapter cable out.",
    f"<b>Interfaces</b> (guest): quarantine interface flushed and down; {C('netplan apply')} brings the clinical interface up with DHCP (10.0.2.15/24, gateway 10.0.2.2, DNS 10.0.2.3).",
    f"<b>Firewall</b>: {C('/etc/iptables/rules.v4')} restored at boot by a oneshot unit before the network comes up (rules below).",
    f"<b>Time</b>: after the restore the guest clock was at snapshot time, {skews[0]} s behind. {C('timedatectl')} still said "
    "&lsquo;System clock synchronized: yes&rsquo;, a stale flag carried in the snapshot, while the RTC line showed the correct time. "
    f"systemd-timesyncd corrected it before validation (skew {clk[0].split('skew ')[1]}). Lesson: measure the offset; don't trust the flag.",
])
s += code(section("04_r3_r4_recover.txt", r"clinical=", r"^$", n=12), title="Interfaces and routes after recovery (transcripts/04)")
s += code(rd(os.path.join(EV, "validation", "firewall_baseline_rules.v4")), title="validation/firewall_baseline_rules.v4 - the persistent host firewall")

# ================================================================= RCA
s += [PageBreak(), P("3. Root cause analysis", "h1"), P("3.1 Event timeline", "h2")]
tl = [(key["Tara's first SSH session from the Mac authenticated"], "Tara Jones logs in from the Mac (key-based SSH)"),
      (key["PT-1003 viewed through stale clinical group"], "Reads PT-1003 through the clinical group left over from her move"),
      (key["Uploader started (auditd)"], "Stages the record, starts syncd.py"),
      (key["First upload received by drop site"], "First copy reaches the drop site"),
      (key["Persistence: crontab written (auditd)"], "Adds a */5 cron job to restart the uploader"),
      (m3["detection"], "Wazuh rule 100221 alert (SEV-1); containment starts"),
      (key["Last upload received by drop site"], f"Last copy reaches the drop site ({len(ups)} in total)"),
      (m3["c3_block"], "Egress blocked (C3)"), (m3["c6_isolate"], "Host isolated (C6)"), (m3["contained"], "Contained"),
      (steps["r2_restore"], "Restored to baseline-clean (eradication)"), (steps["r7_snapshot"], "Recovered and validated")]
t0 = iso(tl[0][0])
s += table([["UTC", "T+", "Event"]] + [[hms(t), "+%d:%02d:%02d" % (lambda x: (x // 3600, x % 3600 // 60, x % 60))(int((iso(t) - t0).total_seconds())), e(w)] for t, w in tl],
           [0.85 * inch, 0.85 * inch, 4.8 * inch])
s += table([["Measure", "Value"],
    ["Attack to detection (first record read &rarr; detection)", f"{sec(key['PT-1003 viewed through stale clinical group'], m3['detection']):.0f} s"],
    ["Detection to egress block", f"{sec(m3['detection'], m3['c3_block']):.0f} s"],
    ["Detection to contained", f"{sec(m3['detection'], m3['contained']) / 60:.1f} min"],
    ["Detection to recovered and validated", f"{sec(m3['detection'], steps['r7_snapshot']) / 60:.0f} min (includes Task 4 evidence work)"],
    ["Copies disclosed", f"{len(ups)} (one record)"]], [3.6 * inch, 2.9 * inch])
s += [P("3.2 Five whys", "h2")]
s += table([["Why?", "Answer", "Evidence"],
    ["1. Why did the record leave the host?", "A process run by test.nurse uploaded it to 10.78.99.66 every 5 s", "pcap 21 POSTs; Volatility sockstat; kern.log UID=1003"],
    ["2. Why could test.nurse read the record?", "She was still in the clinical group, which the EHR viewer trusts", "ehr-audit basis=group:clinical; /etc/group"],
    ["3. Why was she still in clinical?", "Her mover change added Billing on the host but removed nothing", "auth.log usermod add 'billing' only; JML-LOG CHG-2026-0201"],
    ["4. Why did the mover step not remove it?", "The JML process ran in Entra ID and Keycloak (which removed Nurse automatically) but local host groups were never part of it", "JML-09 evidence; Task 2 &sect;7"],
    ["5. Why were hosts outside JML?", "Identity was designed IdP-first; local accounts were treated as lab setup, with no owner and no reconciliation", "design doc v1.2; no host reconciliation job"],
], [1.85 * inch, 2.75 * inch, 1.9 * inch])
s += note("Access changes for movers were applied at the identity provider but not on Linux hosts, and nothing reconciled the two. "
          "A user whose role changed kept the old role's access on the host.", label="Root cause")
s += [P("3.3 Contributing factors", "h2")]
s += table([["Area", "Factor", "Effect on this incident"],
    ["Process", "No host access reconciliation; access review not run on hosts (finding F-05)", "The mover change added Billing on the host and removed nothing; no step compared host groups with the IdP"],
    ["Technology", "No host firewall; no egress filtering", "Uploads to an unknown host on port 8080 were allowed"],
    ["Technology", "Any user could create cron jobs", "Persistence in one command"],
    ["Identity", "Disabled accounts kept SSH keys; passwd -S 'L' looked like locked", "Leaver path open (IR1-2026-001); false sense of safety"],
    ["Detection / response", "The alert was automatic but containment was run by hand", f"{sec(m3['detection'], m3['c3_block']):.0f} s from alert to block; {len(ups)} copies out. Auto-block on alert + outbound would cut this to seconds"],
], [1.1 * inch, 2.65 * inch, 2.75 * inch])
s += [P("3.4 Technical findings from the Parrot OS tools", "h2")]
s += table([["Tool", "Finding", "Significance"],
    ["auditd / ausearch", f"{len(cmds)} commands by test.nurse, {hms(cmds[0]['utc'])}&ndash;{hms(cmds[-1]['utc'])}: ehr-view PT-1003, copy to ~/.cache/.sync, python3 syncd.py, crontab", f"Intent: the whole chain took {sec(cmds[0]['utc'], cmds[-1]['utc']):.1f} s, so it was scripted and planned"],
    ["tcpdump / tshark", f"{len(ups)} HTTP POSTs, User-Agent syncd/0.3, 127 bytes each, none after the block", "Proves volume and that containment worked"],
    ["iptables (LOG --log-uid)", "Every dropped packet tagged UID=1003", "Attribution from the firewall itself"],
    ["gdb gcore + strings", "Process memory holds the MRN, the file path and the URL", "Proves the process held the data"],
    ["Volatility 3", f"PID {upid}: SSH_CONNECTION=10.78.10.1; socket SYN_SENT to the IOC; no hidden modules, no syscall hooks, malfind clean", "Ties the process to the SSH session; rules out a rootkit"],
    ["Sleuth Kit", f"syncd.py inode {ist_ino}, uid 1003, created {ist_cr}; files hash-identical to the live copies", "Disk agrees with memory and logs"],
    ["timeline + sshd VERBOSE", "5/5 Mac sessions matched to Parrot logins by key fingerprint, &lt; 1 s apart", "The actions came from that Mac, with that key"],
], [1.3 * inch, 3.0 * inch, 2.2 * inch])

# ================================================================= validation
s += [PageBreak(), P("4. Recovery validation checklist", "h1"),
      P(f"{C('lab/validate_recovery.sh')} is the checklist written as code: each line is one test with an expected value, so it runs "
        f"the same way every time and leaves a PASS/FAIL record. It runs inside the guest over the guest agent; {C('run_task6.sh')} adds "
        "six network probes from the other machines. The whole set ran twice, before and after a reboot, to prove the fixes survive a restart.")]
trs = [["ID", "Check", "Testing procedure", "Expected", "Run 1", "Run 2"]]
for a, b in zip(v1, v2):
    pr = proc.get(a[0], "systemctl is-active / is-enabled" if a[0].startswith("SVC-") else ("su / setpriv + ehr-view" if a[0] in ("IAM-06", "IAM-07") else ""))
    trs.append([a[0], e(a[2]), C(pr[:70]), e(a[3]) or "(empty)", ok("PASS") if a[-1] == "PASS" else bad("FAIL"), ok("PASS") if b[-1] == "PASS" else bad("FAIL")])
s += table(trs, [0.78 * inch, 1.72 * inch, 2.0 * inch, 0.7 * inch, 0.62 * inch, 0.68 * inch])
s += table([["ID", "Network probe (from another host)", "Expected", "Run 1", "Run 2"]] +
           [[a[0], e(a[1]), a[2], ok(a[3]) if a[-1] == "PASS" else bad(a[3]), ok(b[3]) if b[-1] == "PASS" else bad(b[3])] for a, b in zip(p1, p2)],
           [0.5 * inch, 2.75 * inch, 0.95 * inch, 1.15 * inch, 1.15 * inch])
s += note("Test runs of the checklist before this exercise found three defects in the checklist itself, not in the host. "
          f"{C('pgrep -f syncd.py')} matched the checklist's own command line. The audit-rule count looked for {C('key=')}, while "
          f"{C('auditctl -l')} prints watches as {C('-k')}. And {C('dpkg -V')} flagged 264 files that the Wazuh agent legitimately "
          "rewrites in its own folder, so the check was split into INT-01 (OS packages) and INT-01b (agent binaries). A checklist "
          "needs testing too.", label="Checklist defects found and fixed")
s += code(section("06_validation_run2.txt", r"R6 reboot", r"in-guest", n=6), title="Reboot before run 2 (transcripts/06) - the guest agent never answers a shutdown command, so the TimeoutError is expected")

# ================================================================= lessons
s += [P("5. Lessons learned and IR process improvements", "h1"), P("5.1 What went well", "h2")]
s += bullets([
    f"Wazuh raised rule 100221 {sec(key['PT-1003 viewed through stale clinical group'], m3['detection']):.0f} s after the record was read, and egress was blocked {sec(m3['detection'], m3['c3_block']):.0f} s after the alert. The rule was built and tested in Task 1 for exactly this event.",
    "Monitoring never stopped: the Wazuh agent kept reporting through the quarantine forward during isolation, and again from the recovered host.",
    "Order of volatility held. The uploader's memory, sockets and packets were captured before it was killed, and that memory "
    "later answered questions the logs could not.",
    "Every evidence item was hashed at both ends and re-verified three times (Task 4 intake, Task 4 report, Task 6 gate) with no mismatch.",
    "Snapshots made every risky step reversible and gave a clean recovery point.",
])
s += [P("5.2 What did not go well", "h2")]
s += table([["Problem found while building and running the response", "Impact", "Fix now in the procedure"],
    ["Firewall allow-rule written for the NAT gateway address; the hypervisor forwards the real client IP", "Forensic SSH blocked after isolation (first run)", "Playbook: test the allow path before setting DROP"],
    ["Live logs hashed before copying; they changed in between", "2 hash mismatches (first run)", "Freeze to RAM (cp -a), then hash and copy"],
    ["Guest CPU used 5-level paging", "Volatility found no processes", "VM template: LA57 off; note in tools guide"],
    ["dc3dd will not write to a pipe or FIFO", "Live imaging over SSH failed", "Seize at hypervisor, image read-only on the workstation"],
    ["auditd serials restart at boot", "Wrong times on the first timeline", "Join on time + serial"],
    ["Isolated host lost NTP (75 min slow in an earlier test run); stale 'synchronized' flag after restore", "Timestamps misleading without a reference", "Measure offset against the workstation at every step"],
    ["Recovery checklist had 3 defects (self-match, -k vs key=, agent state files)", "False FAILs in test runs", "Test the checklist on a known-good host first"],
    ["The Mac slept during a test run", "Scenario paused 8 min; packet capture window expired", "Keep the analyst workstation awake (caffeinate) for the whole response"],
    ["Wazuh log collector exited under emulation", "macOS lines lost in a test run", "ship_file: check the collector after every batch, restart and resend; count sent vs received"],
    ["'Agent Active' read before the agent had reconnected", "False confidence in monitoring", "Wait for the agent's own 'Connected to [quarantine forward]' line"],
    ["Validation started before the restored agent reconnected (test run)", "MON-05 failed on run 1", "Wait for agent status 'connected' before the checklist runs"],
], [2.7 * inch, 1.8 * inch, 2.0 * inch])
s += [P("5.3 Improvement plan", "h2")]
s += table([["#", "Improvement", "Type", "Owner", "Due", "Measure of success"],
    ["1", "Reconcile host groups and SSH keys with the IdP nightly; extend the JML runbook to hosts", "Process", "IAM owner", "2026-11-16", "0 stale groups in the nightly report"],
    ["2", "Mover access review at 30/60/90 days (closes F-05)", "Process", "IAM owner", "2026-11-30", "100% of movers reviewed"],
    ["3", "Roll out the host firewall baseline (egress allow-list) to every EHR host", "Technology", "System owner", "2026-11-16", "All hosts pass NET-04/05"],
    ["4", "cron.allow = root fleet-wide", "Technology", "System owner", "2026-11-16", "INT-03/IAM-08 pass everywhere"],
    ["5", "Auto-containment: rule 100221 + outbound connection triggers RB-02 C3 (Wazuh active response)", "Detection", "Security lead", "2026-12-15", "Block &lt; 10 s in the next exercise"],
    ["6", "Alert on any new outbound destination from EHR hosts", "Detection", "Security lead", "2026-12-15", "Alert in exercise replay"],
    ["7", "Lock = expire + remove keys in the leaver step (not passwd -l alone)", "Process", "IAM owner", "2026-11-09", "IAM-03/04 pass on all hosts"],
    ["8", "Every sudo grant needs a change record and an expiry (IR1-2026-003)", "Process", "IT admin", "2026-11-16", "0 grants without a ticket"],
    ["9", "VM template: LA57 off, guest agent, NIC trace on, snapshot policy", "Technology", "IR analyst", "2026-11-09", "Volatility works on next dump"],
    ["10", "Time: quarantine network gets an NTP source; offset logged at every IR step", "Process", "IR analyst", "2026-11-09", "Skew &lt; 1 s in reports"],
    ["11", "Run validate_recovery.sh after every change to an EHR host", "Process", "System owner", "ongoing", f"{len(v1)}/{len(v1)} on each run"],
    ["12", "Repeat this exercise every 6 months; update CAN-IR-PB-02", "Governance", "IR analyst", "2027-05-02", "Playbook version bump"],
], [0.25 * inch, 2.4 * inch, 0.75 * inch, 0.85 * inch, 0.75 * inch, 1.5 * inch])
s += note("Items 1&ndash;2 and 7&ndash;8 also close project audit findings (F-05 access review). The live Keycloak findings F-01 (MFA), "
          "F-02 (lockout) and F-04 (password policy) are outside this host incident and are still open on the project board.",
          label="Link to the project")
s += [P("6. Limitations", "h1")]
s += bullets([
    "VirtualBox and Parrot OS are substituted by QEMU and a Debian 12 VM; each step lists its VirtualBox command (Task 3 &sect;2).",
    "test.nurse stays disabled: whether to restore her Billing-only access is an HR decision (recorded as D3), not a technical one.",
    "Recovery was validated on one host. Items 3&ndash;4 of the plan apply the same baseline to the others.",
])
build(OUT, s, "Care Access Navigator - IR1 Task 6: Post-Incident Procedures", FOOT)
