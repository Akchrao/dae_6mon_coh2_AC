"""Care Access Navigator - Incident Response 1, Task 1: IR Environment Setup.
Builds the PDF from the evidence written by run_task1.sh (every table and excerpt is read from evidence/).
Run from Semester_5/Incident_Response_1/ (see README)."""
import csv, os, re
from html import escape as e
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon
from reportlab.lib import colors
from pdfstyle import (P, bullets, note, code, table, kv, ok, bad, build, ss, NAVY, AMBER, CREAM, GREY_BG, MUTED, RED, GREEN,
                      Spacer, PageBreak, Paragraph, inch, FULL_W)

TASK = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); IR = os.path.dirname(TASK)
EV = os.path.join(TASK, "evidence"); LAB = os.path.join(IR, "lab")
OUT = os.path.join(TASK, "Care_Access_Navigator_IR1_Task1_Environment_Setup.pdf")
FOOT = "Care Access Navigator - Incident Response 1, Task 1: IR Environment Setup"
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


marks = {r["phase"]: r["utc"] for r in csv.DictReader(open(os.path.join(EV, "markers.csv")))}
tests = list(csv.DictReader(open(os.path.join(EV, "wazuh", "rule_tests.tsv")), delimiter="\t"))
t2 = tx("02_provision_agent.txt"); t4 = tx("04_log_collection.txt"); t5 = tx("05_wireshark.txt"); t6 = tx("06_volatility.txt"); t7 = tx("07_baseline.txt")
golden = re.search(r"([0-9a-f]{64})\s+\S+golden\.qcow2", tx("01_lab_build.txt"))[1]
pkgs = re.findall(r"^(\S+) (\d\S*)$", section("02_provision_agent.txt", r"ir-golden-packages", r"^\$ id", n=20), re.M)
sample = re.search(r"sent=(\d+)\s+received=(\d+)\s+logcollector restarts=(\d+)\s+(\w+)", t4)
full_lines = sum(1 for _ in open(os.path.join(EV, "macos", "install_iso.log")))
cf = [l for l in rd(os.path.join(EV, "wireshark", "cfilters")).splitlines() if l.strip()]
compiled = re.findall(r"^OK\s+(\d+) BPF instructions\s+: (.*)$", t5, re.M)
nproc = re.search(r"processes found: (\d+)", t6)[1]
probes = [l for l in t7.splitlines() if re.match(r"P[1-6] ", l)]
agent = re.search(r"ID: 001, Name: parrot-vm, IP: (\S+), (\w+)", t2)
recv = re.search(r"received: (\S+) agent=(\S+) location=(\S+)", t4)

s = []
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Incident Response 1 &mdash; Task 1: IR Environment Setup", "subtitle"),
      P("One lab for all six IR tasks: a Parrot OS VM with a Wazuh agent, a Wazuh manager, Wireshark, Volatility, and macOS log collection", "subsub"),
      Spacer(1, 14)]
s += kv([
    ("Document ID", "CAN-IR1-T1-ENV-002 (replaces version 001: same lab and same people as Tasks 2&ndash;6)"),
    ("Author", "Akhila Chennamaneni"), ("Date", "November 3, 2026"),
    ("SIEM", "Wazuh manager 4.9.2 (real) + Wazuh agent 4.9.2 deployed on the Parrot OS host"),
    ("Parrot OS host", f"parrot-vm: a virtual machine (Debian 12, kernel 6.1.0-54-cloud-amd64, Parrot stand-in) under the QEMU hypervisor, "
                       f"built from a checksum-verified golden image ({C(golden[:16])}&hellip;)"),
    ("macOS host", "DAEDMAC1009 (the analyst's Mac): install.log and an SSH client trail shipped to Wazuh"),
    ("People", "The JML users from the Entra ID / Keycloak cycle: Sathya Hasi (joiner), Tara Jones (mover), Jeevan Smith (leaver), it_admin"),
    ("Run", f"{marks['lab_build'][11:19]}&ndash;{marks['done'][11:19]} UTC, 2026-11-03"),
])
s += [P("Summary", "h1"),
      P("This task builds the single lab that all six Incident Response tasks use. The same machines, people and incident numbers "
        "run through to recovery in Task 6. A Wazuh manager runs on a management network. The Parrot OS host is a real virtual "
        f"machine with the <b>Wazuh agent deployed and enrolled</b> (agent 001, status {agent[2] if agent else '?'}). The agent collects "
        "the host's authentication, kernel, EHR-audit and auditd logs and watches persistence paths in real time. macOS logs from the "
        f"analyst's Mac are collected too: {sample[1]} of {sample[2]} sample lines received, none lost. Three custom rules turn the JML "
        "register into detections: a leaver logging in, a mover reading patient records through an old role, and root used by a role "
        f"with no root entitlement. Each rule was tested with a line that must fire it and a near-miss that must not: "
        f"<b>{sum(1 for t in tests if t['result'] == 'PASS')}/{len(tests)} tests pass</b>. Wireshark has seven saved capture filters, all "
        f"compiled. Volatility 3 has a symbol table built for this exact kernel and walked {nproc} processes in a baseline memory image. "
        "The clean state is saved as snapshot <i>baseline-clean</i>.")]
s += [P("1. How this report meets the Task 1 requirements", "h1")]
s += table([["Requirement", "Where", "Evidence"],
    ["Wazuh installed and configured, Parrot OS in a hypervisor", "&sect;2, &sect;3", "transcripts/01, 03"],
    ["Basic agent deployment", "&sect;3.2", "transcripts/02 (agent_control, enrollment)"],
    ["Log collection configuration from Parrot OS", "&sect;3.2, &sect;4", "lab/wazuh/agent.conf, transcripts/04"],
    ["3 custom alert rules for security events", "&sect;5", "lab/wazuh/can_ir1_core_rules.xml, wazuh/rule_tests.tsv"],
    ["Wireshark on Parrot OS with proper capture filters", "&sect;6", "wireshark/cfilters, transcripts/05, t1_agent_traffic.pcapng"],
    ["Volatility in Parrot OS with memory-analysis configuration", "&sect;7", "transcripts/06, volatility/baseline_pslist.txt"],
    ["Parrot OS and macOS logs ingested into Wazuh", "&sect;4", "transcripts/04 (sent = received)"],
    ["Documentation and evidence of functionality", "all; App. A", "EVIDENCE-INDEX-SHA256.txt"],
], [2.75 * inch, 0.9 * inch, 2.85 * inch])

# ---------------------------------------------------------------- lab
s += [P("2. The lab", "h1"),
      P("Everything runs in Docker Desktop with no administrator rights. VirtualBox cannot run here: it needs admin rights and "
        "does not run x86 guests on Apple silicon. So the Parrot OS host is a real VM under QEMU, inside a hypervisor container, "
        "and each hypervisor action maps to a VBoxManage command. The same lab carries the incident through Tasks 2&ndash;6.")]


def box(d, x, y, w, h, title, lines, fill=GREY_BG, stroke=NAVY):
    d.add(Rect(x, y, w, h, fillColor=fill, strokeColor=stroke, strokeWidth=1, rx=4, ry=4))
    d.add(String(x + w / 2, y + h - 12, title, fontName="Helvetica-Bold", fontSize=8, fillColor=NAVY, textAnchor="middle"))
    for i, t in enumerate(lines):
        d.add(String(x + w / 2, y + h - 24 - i * 9.5, t, fontName="Helvetica", fontSize=6.8, fillColor=colors.HexColor("#333333"), textAnchor="middle"))


def arrow(d, x1, y1, x2, y2, col=NAVY, label=""):
    import math
    d.add(Line(x1, y1, x2, y2, strokeColor=col, strokeWidth=1.2))
    a = math.atan2(y2 - y1, x2 - x1); L = 6
    d.add(Polygon([x2, y2, x2 - L * math.cos(a - 0.4), y2 - L * math.sin(a - 0.4), x2 - L * math.cos(a + 0.4), y2 - L * math.sin(a + 0.4)], fillColor=col, strokeColor=col))
    if label:
        d.add(String((x1 + x2) / 2, (y1 + y2) / 2 + 4, label, fontName="Helvetica", fontSize=6.8, fillColor=MUTED, textAnchor="middle"))


d = Drawing(FULL_W, 235)
box(d, 0, 160, 125, 70, "macOS DAEDMAC1009", ["user SSH sessions -> :2223", "install.log, ssh_client.log", "shipped to Wazuh"], CREAM)
box(d, 0, 55, 125, 80, "ir-clinical 10.78.10.0/24", ["nurse-ws .20", "ir-hv .5 (port-forwards)", "EHR portal :8080"])
box(d, 150, 70, 170, 160, "ir-hv (VirtualBox host stand-in)", ["QEMU 7.2, x86_64 guest"], colors.HexColor("#E8EEF7"))
box(d, 163, 80, 144, 125, "parrot-vm (Parrot OS)", ["Debian 12, kernel 6.1.0-54", "Wazuh agent 4.9.2", "tshark/dumpcap, tcpdump", "gdb, dc3dd, sleuthkit, auditd", "nic0 clinical (NAT)", "nic1 quarantine (cable out)"], CREAM, AMBER)
box(d, 350, 160, 125, 70, "ir-internet 10.78.99.0/24", ["exfil-sink .66", "(lab 'outside')"], colors.HexColor("#FBE9E7"), RED)
box(d, 350, 20, 125, 125, "ir-mgmt 10.78.50.0/24", ["--internal", "wazuh-manager .20", "  4.9.2, 1514/1515 tcp", "ir-forensics .5", "  Volatility 3, dc3dd,", "  Sleuth Kit, tshark", "ir-hv .2"], colors.HexColor("#E7F4EC"), GREEN)
arrow(d, 125, 190, 163, 175); arrow(d, 125, 95, 163, 110)
arrow(d, 307, 120, 350, 100, GREEN, "agent 1514/tcp")
s += [d, Paragraph("Figure 1. The IR1 lab (shared by Tasks 1&ndash;6).", ss["caption"])]
s += table([["Person (JML register)", "Account on parrot-vm", "JML event", "State built in Task 1"],
    ["Sathya Hasi", "test.clinician", "Joiner REQ-2026-0101 &rarr; Clinician", "group clinical"],
    ["Tara Jones", "test.nurse", "Mover CHG-2026-0201 Nurse &rarr; Billing", "billing added; <b>clinical not removed</b> (as in the live lab)"],
    ["Jeevan Smith", "test.billing", "Leaver TERM-2026-0301", "locked, expired, DenyGroups; <b>SSH key still present</b>"],
    ["IT administrator", "it_admin", "&mdash;", "sudo"],
    ["IR analyst", "ir-analyst", "&mdash;", "forensic access (key only)"]], [1.3 * inch, 1.15 * inch, 1.95 * inch, 2.1 * inch])
s += note("The two weaknesses in bold are deliberate. They mirror what the JML evidence showed in the live Entra ID / Keycloak lab, and "
          "they are what Tasks 2&ndash;6 detect, contain and fix.", label="Scenario")
s += table([["Lab component", "VirtualBox equivalent"],
    ["QEMU VM from the golden image (checksum-verified Debian cloud image + IR toolset)", "Parrot OS VM imported from an OVA"],
    ["nic0: NAT with port forwards 22, 8080", "Adapter 1: NAT + port forwarding"],
    ["nic1: restricted network, link down", "Adapter 2: internal network 'quarantine', cable disconnected"],
    ["QMP savevm / dump-guest-memory / set_link", "VBoxManage snapshot / debugvm dumpvmcore / setlinkstate"]], [3.4 * inch, 3.1 * inch])

# ---------------------------------------------------------------- Wazuh
s += [PageBreak(), P("3. Wazuh", "h1"), P("3.1 Manager", "h2")]
s += code(section("01_lab_build.txt", r"wazuh-control info", n=4) + "\n" + section("03_wazuh_rules.txt", r"configure_manager|ruleset|can_ir1", n=14), title="Manager version, content installed (transcripts/01, 03)")
s += [P("3.2 Agent deployment on Parrot OS", "h2"),
      P(f"The golden image installs {C('wazuh-agent 4.9.2')} from Wazuh's signed repository. Task 1 writes the agent configuration "
        f"({C('lab/wazuh/agent.conf')}): manager 10.78.50.20:1514/tcp, auto-enrollment, five log inputs, and real-time FIM on the home, "
        "cron, sudoers and sshd paths. It then starts the agent. The agent enrolled itself on 1515/tcp and connected.")]
s += table([["Package (golden image)", "Version"]] + [[a, b] for a, b in pkgs], [3.2 * inch, 3.3 * inch])
s += code(section("02_provision_agent.txt", r"agent_control -l", n=10), title="Manager side: agent 001 parrot-vm Active (transcripts/02)")
s += code("\n".join(l for l in rd(os.path.join(LAB, "wazuh", "agent.conf")).splitlines() if "localfile" in l or "directories" in l or "address" in l),
          title="lab/wazuh/agent.conf - what the agent collects and watches")

# ---------------------------------------------------------------- log collection
s += [P("4. Log collection: Parrot OS and macOS", "h1")]
s += [P(f"<b>Parrot OS.</b> A tagged test line written on parrot-vm reached the manager through the agent "
        f"(received {recv[1] if recv else '?'}, {C(recv[2]) if recv else ''}, location {C(recv[3]) if recv else ''}). The agent reports "
        "which files it is reading:")]
s += code(section("04_log_collection.txt", r"agent log inputs", r"^$", n=8), title="Agent inputs (transcripts/04)")
s += [P(f"<b>macOS.</b> The Mac's unified log needs admin rights on this managed Mac (shown below), so the readable "
        f"{C('/var/log/install.log')} ({full_lines:,} lines) was normalised to ISO 8601. The newest 500 lines were shipped to the manager's "
        f"macOS input to prove the path: sent {sample[1]}, received {sample[2]}, {sample[4]}. Task 2 ships the whole file and the Mac's "
        "SSH client trail for analysis.")]
s += code(section("04_log_collection.txt", r"sw_vers", r"install_sample", n=8), title="macOS host (transcripts/04)")
s += code(section("04_log_collection.txt", r"events received per source", n=12), title="Events received by the manager, per source")
s += note("Under emulation the manager's log collector can exit (seen once in testing). Shipping goes through "
          f"{C('ship_file')}: after every batch it checks the collector, restarts it and resends the batch if needed, and ends with a "
          "sent-versus-received count.", label="Reliability")

# ---------------------------------------------------------------- rules
s += [PageBreak(), P("5. Three custom alert rules", "h1"),
      P("Each rule ties a bundled Wazuh detection to the JML register through CDB lists, so the SIEM knows <i>who</i> should not be "
        "doing <i>what</i>. They are the rules that later detect the three incidents.")]
s += table([["Rule", "Level", "Fires when", "Incident it will catch"],
    ["100210", "10", "sshd denies an account on the jml-leavers list (child of 5718/5710/5716/5760)", "IR1-2026-001 Jeevan Smith"],
    ["100221", "12", "EHR audit: a jml-movers account now in Billing views a record through group clinical (child of 100220)", "IR1-2026-002 Tara Jones"],
    ["100231", "12", "sudo to root by a role on rbac-no-root (child of 5402/5403)", "IR1-2026-003 Sathya Hasi"]],
    [0.6 * inch, 0.45 * inch, 3.7 * inch, 1.75 * inch])
s += code(rd(os.path.join(LAB, "wazuh", "can_ir1_core_rules.xml")).split("-->", 1)[1].strip(), title="lab/wazuh/can_ir1_core_rules.xml")
s += [P("5.1 Rule tests", "h2"),
      P(f"Each rule was replayed through {C('wazuh-logtest')} with a line that must fire it and a near-miss that must not "
        "(expected '!id').")]
s += table([["Rule", "Test", "Expected", "Fired (level)", "Result"]] +
           [[t["rule"], e(t["case"]), t["expected"], f"{t['fired']} ({t['level']})", ok("PASS") if t["result"] == "PASS" else bad("FAIL")] for t in tests],
           [0.6 * inch, 2.9 * inch, 0.9 * inch, 1.2 * inch, 0.9 * inch])
s += code(section("03_wazuh_rules.txt", r"full trace for rule 100221", n=24), title="wazuh-logtest -v trace for 100221 (transcripts/03)")

# ---------------------------------------------------------------- Wireshark
s += [P("6. Wireshark on Parrot OS", "h1"),
      P(f"Seven named capture filters were saved to {C('~/.config/wireshark/cfilters')} for the analyst. Wireshark's GUI and tshark both "
        f"read this file. Each filter was compiled to BPF on the clinical interface with {C('dumpcap -d')}, so a typo fails now, "
        "not mid-incident. One filter was then used for a live capture.")]
s += table([["Saved filter", "BPF instructions"]] + [[e(f), n] for n, f in compiled], [5.0 * inch, 1.5 * inch])
s += code(section("05_wireshark.txt", r"live capture", n=14), title="Live capture with 'IR1 Wazuh agent traffic' (transcripts/05)")

# ---------------------------------------------------------------- Volatility
s += [P("7. Volatility 3", "h1"),
      P("Volatility 3 runs on the Parrot forensic workstation. It needs a symbol table (ISF) that matches the exact kernel in the "
        f"image. It was built with the Volatility Foundation's {C('dwarf2json')} v0.9.0 from Debian's debug kernel package. To prove the "
        f"configuration works, the hypervisor dumped the clean VM's RAM and Volatility walked its process list: {nproc} processes, "
        "including the Wazuh agent.")]
s += code(section("06_volatility.txt", r"vol -h", n=30), title="transcripts/06_volatility.txt")
s += note(f"The guest CPU is configured {C('-cpu max,la57=off')}. With 5-level paging on, Volatility 3 finds the kernel but no "
          "processes, which was found in an earlier run. VirtualBox guests normally use 4-level paging.", label="Configuration point")

# ---------------------------------------------------------------- baseline
s += [P("8. Baseline", "h1"), P("Reachability of the clean environment, re-run in Tasks 3 and 6:")]
s += table([["#", "Path", "State"]] + [[p.split()[0], e(p.split(" ", 1)[1].rsplit(":", 1)[0].strip()), p.rsplit(":", 1)[1].strip()] for p in probes],
           [0.4 * inch, 4.4 * inch, 1.7 * inch])
s += code(section("07_baseline.txt", r"known-good snapshot", n=5), title="Snapshot baseline-clean (used by Task 6)")
s += [P("9. Substitutions and limitations", "h1")]
s += bullets([
    "VirtualBox &rarr; QEMU, and Parrot OS &rarr; Debian 12 with the Parrot IR toolset. The commands are identical; confirm with the instructor.",
    "No Wazuh dashboard. The indexer and dashboard images exist only for x86 and would run under emulation beside the VM on an "
    "8 GB Docker VM. Ingestion is shown from the manager itself (archives.json and alerts.json), which is the data the dashboard displays.",
    "macOS logs are shipped as files: a macOS agent needs admin rights on this managed Mac.",
])
s += [P("Appendix A &mdash; Evidence index", "h1")]
s += code("\n".join(l[:16] + "...  " + l.split("  ", 1)[1] if re.match(r"[0-9a-f]{64}  ", l) else l
                    for l in rd(os.path.join(EV, "EVIDENCE-INDEX-SHA256.txt")).splitlines()), title="evidence/EVIDENCE-INDEX-SHA256.txt")
build(OUT, s, "Care Access Navigator - IR1 Task 1: Environment Setup", FOOT)
