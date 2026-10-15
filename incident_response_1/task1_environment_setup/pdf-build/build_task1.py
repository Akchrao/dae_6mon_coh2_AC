"""Care Access Navigator - Incident Response 1, Task 1: Environment Setup.
Builds the evidence PDF from the real transcripts produced by lab/run_lab.sh.
Run inside a container that has reportlab (see build.sh)."""
import csv, os, re
from pdfstyle import (P, bullets, note, step, code, table, kv, ok, bad, build, ss,
                      Spacer, PageBreak, Paragraph, KeepTogether, inch, FULL_W)

TASK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # task1_environment_setup/
EV = os.path.join(TASK, "evidence")
OUT = os.path.join(TASK, "Care_Access_Navigator_IR1_Task1_Environment_Setup.pdf")
FOOT = "Care Access Navigator - Incident Response 1, Task 1: Environment Setup (simulated lab)"


def tx(name):
    return open(os.path.join(EV, "transcripts", name)).read()


def excerpt(name, start_pat, nlines=24, drop=r"Running as user|This could be dangerous|^#\d|DONE |transferring|resolve |sha256:|load (meta|build|\.docker)"):
    """Pull lines from a transcript starting at the first line matching start_pat."""
    lines = tx(name).splitlines()
    i = next((k for k, l in enumerate(lines) if re.search(start_pat, l)), 0)
    out = []
    for l in lines[i:]:
        if re.search(drop, l):
            continue
        out.append(l)
        if len(out) >= nlines:
            break
    return "\n".join(out).rstrip()


s = []

# ----------------------------------------------------------------- cover
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Incident Response 1 &mdash; Task 1: Incident Response Environment Setup", "subtitle"),
      P("SOC / SIEM lab, detection rules, packet capture and memory-forensics tooling", "subsub"),
      Spacer(1, 14)]
s += kv([
    ("Document ID", "CAN-IR1-T1-ENV-001"),
    ("Author", "Akhila Chennamaneni"),
    ("Date", "October 15, 2026"),
    ("Environment", "Apple M4 (arm64), macOS; Docker Desktop 29.x; no administrator rights"),
    ("Lab host", "parrot-sim &mdash; Debian 12 (bookworm), stand-in for Parrot OS Security"),
    ("Data classification", "Synthetic lab data only &mdash; no real ePHI, no live system attacked"),
    ("Status", "Delivered (equivalent lab; see Scope &amp; Substitution)"),
])

s += [P("1. Objective", "h1"),
      P("This task builds and documents the incident-response lab that the rest of the Incident Response course runs on: "
        "a monitored host, a SIEM-style detection layer with custom rules, network packet capture, and memory-forensics "
        "tooling. The deliverables are (1) a configured lab host with centralized log collection, (2) three custom "
        "detection rules in Wazuh rule syntax with evidence that each one fires, (3) Wireshark capture filters, and "
        "(4) a configured Volatility 3 install for later memory analysis.")]

# ----------------------------------------------------------------- scope / substitution
s += [P("2. Scope and tool substitution", "h1"),
      P("The Incident Response 1 rubric names <b>Wazuh SIEM on Parrot OS inside VirtualBox</b>, with a Wazuh dashboard "
        "and macOS log ingestion. This lab delivers the same capabilities with an equivalent, honestly-labelled setup, "
        "because of two hard constraints on the build machine:")]
s += bullets([
    "<b>No administrator rights.</b> VirtualBox and the macOS Wazuh agent both require admin installation, which this "
    "account does not have. Docker Desktop is available and needs no admin rights per run.",
    "<b>Apple-silicon (arm64) host.</b> There is no maintained Parrot OS VirtualBox image for arm64. Parrot is built on "
    "Debian, so a Debian 12 container (<font face='Courier'>parrot-sim</font>) is used as the stand-in OS.",
])
s += [P("This is the &ldquo;equivalent lightweight SIEM/log-analysis simulation&rdquo; the capstone design document "
        "allows for, and it is recorded as an approved scope decision in <font face='Courier'>docs/adr/ADR-SIEM-choice.md</font> "
        "and the project exception register. What is <b>real</b> in this lab: the host OS and services, the sshd/sudo "
        "log format, the Wazuh rule syntax, the packet capture, and the Volatility 3 install. What is <b>simulated</b>: "
        "the SIEM is a Python rule engine (not a Wazuh manager + dashboard), and the suspicious activity is injected as "
        "sample log lines, which is exactly how Wazuh's own <font face='Courier'>wazuh-logtest</font> validates rules.")]
s += note("Before final grading, confirm in writing that the instructor accepts this substitution for the Wazuh-, "
          "Parrot- and VirtualBox-specific rubric items. The identity and detection evidence stands on its own; only "
          "the named platform differs.", label="Action required")

# mapping table
s += [P("3. How this meets the Environment Setup rubric", "h1")]
s += table([
    ["Rubric item", "Delivered as", "Evidence"],
    ["SIEM installed/configured", "Wazuh-syntax rules evaluated by detect_engine.py (SIEM-equivalent)", "&sect;6, &sect;7"],
    ["Basic agent / host deployment", "parrot-sim host on an isolated Docker network", "&sect;4"],
    ["Log collection from the host", "rsyslog &rarr; /var/log/auth.log (sshd, sudo)", "&sect;5"],
    ["3 custom alert rules", "Rules 100101, 100102, 100110 (brute force, compromise, priv-esc)", "&sect;6"],
    ["Wireshark with capture filters", "5 saved tshark/Wireshark capture filters + live 63-packet capture", "&sect;8"],
    ["Volatility configured", "Volatility 3 Framework 2.7.0, 25 Linux plugins, config file", "&sect;9"],
    ["Parrot + macOS logs", "Parrot-sim auth.log (real) + macOS install.log sample (real)", "&sect;10"],
], [1.7 * inch, 3.3 * inch, 1.5 * inch])

# ----------------------------------------------------------------- architecture
s += [P("4. Lab architecture and isolated network", "h1"),
      P("The lab runs two logical zones on a Docker <b>--internal</b> network (no route to the internet &mdash; the "
        "equivalent of a VirtualBox &ldquo;Internal Network&rdquo; for segmentation and containment). The monitored "
        "host plays the victim clinical workstation; a separate source address (10.66.0.66) represents the attacker in "
        "the scenario the rules detect.")]
s += code(
    "  Docker --internal network  ir1-labnet  (10.66.0.0/24, no internet route)\n"
    "  +-----------------------------------------------------------------+\n"
    "  |                                                                 |\n"
    "  |   parrot-sim  10.66.0.10   (Debian 12 = Parrot OS stand-in)     |\n"
    "  |     - sshd (verbose auth logging)   - rsyslog -> auth.log       |\n"
    "  |     - tshark / Wireshark filters    - Volatility 3              |\n"
    "  |     - detect_engine.py  (loads local_rules.xml)                 |\n"
    "  |                                                                 |\n"
    "  |   attacker source 10.66.0.66  (scenario origin in sample log)   |\n"
    "  +-----------------------------------------------------------------+\n"
    "        host: Apple M4 macOS + Docker Desktop (also a log source)",
    title="Figure 1. Lab topology")
s += step(1, "Build the host and the isolated network", prefix="")
s += [P("Real output from <font face='Courier'>lab/run_lab.sh</font> (Docker server version, the isolated network, and "
        "the two hosts on it):")]
s += code(excerpt("01_build_and_network.txt", r"docker version --format", 16), title="transcripts/01_build_and_network.txt")

# ----------------------------------------------------------------- log collection
s += [P("5. Log collection", "h1"),
      P("rsyslog routes authentication events to <font face='Courier'>/var/log/auth.log</font>, the file a Wazuh agent "
        "would tail as a <font face='Courier'>localfile</font> source. sshd runs with <font face='Courier'>LogLevel "
        "VERBOSE</font> so both failed and accepted passwords are recorded. Two lab accounts are created: "
        "<font face='Courier'>nurse_jsmith</font> (a clinical, non-privileged role) and <font face='Courier'>it_admin</font> "
        "(in the sudo group).")]
s += code(excerpt("02_host_and_logging.txt", r"rsyslog start", 18), title="transcripts/02_host_and_logging.txt")

# ----------------------------------------------------------------- custom rules
s += [P("6. Three custom detection rules", "h1"),
      P("The rules are written in Wazuh local-rules syntax and live in "
        "<font face='Courier'>wazuh-sim/local_rules.xml</font>. A real Wazuh manager would load this file unchanged. "
        "They build on a base SSH-failure rule (100100) and encode the scenario of an off-hours attack on a clinical "
        "account:")]
s += table([
    ["Rule", "Level / severity", "Fires when", "MITRE ATT&amp;CK"],
    ["100101 &mdash; SSH brute force", "10 / High", "&ge;6 failed logins from one source IP within 120 s", "T1110"],
    ["100102 &mdash; login after brute force", "12 / Critical", "a successful login from a source that just tripped 100101", "T1110, T1078"],
    ["100110 &mdash; privilege escalation", "12 / Critical", "a clinical (nurse_*) account invokes sudo to root", "T1548.003"],
], [1.75 * inch, 1.15 * inch, 2.45 * inch, 1.15 * inch])
rules_xml = open(os.path.join(TASK, "wazuh-sim", "local_rules.xml")).read()
rule1 = rules_xml[rules_xml.index("<!-- CUSTOM RULE 1"):rules_xml.index("<!-- CUSTOM RULE 2")].rstrip()
s += code(rule1, title="wazuh-sim/local_rules.xml (Rule 100101, the brute-force rule)")

# ----------------------------------------------------------------- rule validation
s += [P("7. Rule validation (sample-log injection)", "h1"),
      P("Each rule is validated by replaying a synthetic <font face='Courier'>auth.log</font> through the rule engine &mdash; "
        "the same approach as Wazuh's <font face='Courier'>wazuh-logtest</font>. The sample contains eight failed logins "
        "against <font face='Courier'>nurse_jsmith</font> from 10.66.0.66, then a successful login, then a sudo-to-root "
        "attempt. A benign admin login is included as a control that must <i>not</i> alert.")]
s += code(excerpt("06_detection_rules.txt", r"xmllint|well-formed", 10, drop=r"Running as user|dangerous"),
          title="transcripts/06_detection_rules.txt (rule file check + engine run)")

# alerts table from the real CSV
with open(os.path.join(EV, "alerts.csv")) as f:
    rows = list(csv.DictReader(f))
key = [r for r in rows if r["rule_id"] in ("100101", "100102", "100110")]
seen = set(); keyu = []
for r in key:
    if (r["rule_id"], r["srcip"]) not in seen:
        seen.add((r["rule_id"], r["srcip"])); keyu.append(r)
s += [P("The alerts the engine raised (full set in <font face='Courier'>evidence/alerts.csv</font>; the six "
        "Low base-rule hits are omitted here):")]
sev_cell = lambda r: (ok(r["severity"]) if r["severity"] == "High" else bad(r["severity"]) if r["severity"] == "Critical" else r["severity"])
s += table([["Time (UTC)", "Rule", "Severity", "Source", "Detection"]] +
           [[r["time_utc"][11:19], r["rule_id"], sev_cell(r), r["srcip"], r["description"]] for r in keyu],
           [0.75 * inch, 0.6 * inch, 0.75 * inch, 0.95 * inch, 3.45 * inch])
s += note("All three custom rules fired on the correct events, in order, and the benign <font face='Courier'>it_admin</font> "
          "login produced no alert &mdash; so the rules detect the attack without a false positive on normal activity.",
          label="Result")

# ----------------------------------------------------------------- wireshark
s += [P("8. Wireshark capture filters and live capture", "h1"),
      P("Five capture filters are saved to the Wireshark profile (<font face='Courier'>~/.config/wireshark/cfilters</font>), "
        "usable from both the Wireshark GUI and <font face='Courier'>tshark</font>. Each filter is compile-checked, then "
        "a live capture on port 22 records real SSH traffic.")]
s += code(excerpt("03_wireshark.txt", r"tshark --version", 20, drop=r"Running as user|dangerous"),
          title="transcripts/03_wireshark.txt (version, interfaces, saved filters, compile checks)")
s += code(excerpt("04_capture.txt", r"capture SSH traffic|tshark -i any", 16, drop=r"Running as user|dangerous|IO Statistics|Col 1|^\|\s*$|Interval:"),
          title="transcripts/04_capture.txt (live capture of SSH traffic)")
s += note("63 packets were captured to <font face='Courier'>evidence/pcap/ssh_capture.pcapng</font> with the "
          "<font face='Courier'>tcp port 22</font> filter, confirming the capture pipeline works end to end.", label="Result")

# ----------------------------------------------------------------- volatility
s += [P("9. Volatility 3 (memory forensics)", "h1"),
      P("Volatility 3 is installed and configured with symbol and cache directories for the memory analysis performed in "
        "Task 4. 25 Linux plugins are available, including the ones used to investigate a compromised host "
        "(<font face='Courier'>linux.pslist</font>, <font face='Courier'>linux.pstree</font>, "
        "<font face='Courier'>linux.bash</font>, <font face='Courier'>linux.sockstat</font>).")]
s += code(excerpt("05_volatility.txt", r"vol --help", 18, drop=r"Running as user|dangerous"),
          title="transcripts/05_volatility.txt")

# ----------------------------------------------------------------- logs both OSes
s += [P("10. Parrot and macOS log sources", "h1"),
      P("The rubric asks for both Parrot and macOS logs. The Parrot-sim side is the real "
        "<font face='Courier'>auth.log</font> used throughout this task. For the macOS host, the unified log "
        "<font face='Courier'>auth</font> store needs administrator rights to read; the readable, real macOS log used "
        "here is <font face='Courier'>/var/log/install.log</font>. A full macOS <font face='Courier'>log stream</font> "
        "feed is noted as a follow-up for when admin rights are available.")]
macos_lines = open(os.path.join(EV, "macos", "macos_install_log_sample.log")).read().splitlines()
s += code("\n".join(macos_lines[:9]),
          title="evidence/macos/macos_install_log_sample.log (real macOS log, first lines)")

# ----------------------------------------------------------------- evidence integrity
s += [P("11. Evidence integrity and chain of custody", "h1"),
      P("Every artifact is hashed with SHA-256 at the end of the run into "
        "<font face='Courier'>evidence/EVIDENCE-INDEX-SHA256.txt</font>. This is the baseline that Task 4 (Digital "
        "Evidence) extends with a formal chain-of-custody record.")]
idx = open(os.path.join(EV, "EVIDENCE-INDEX-SHA256.txt")).read().splitlines()
s += table([["SHA-256 (first 16 hex)", "Artifact"]] +
           [[h[:16] + "…", "evidence/" + p.lstrip("./ ")] for h, p in (l.split("  ", 1) for l in idx if l.strip())],
           [1.7 * inch, 4.8 * inch])

# ----------------------------------------------------------------- reproduce
s += [P("12. How to reproduce", "h1"),
      P("The whole lab is one script and needs only Docker Desktop:")]
s += code("cd \"incidence response_1/task1_environment_setup/lab\"\n"
          "bash run_lab.sh          # builds host, configures tools, runs rules, writes evidence/\n\n"
          "# tear down when finished:\n"
          "docker rm -f parrot-sim && docker network rm ir1-labnet", title="Reproduce")
s += [P("Files: <font face='Courier'>lab/</font> (Dockerfile + run_lab.sh), "
        "<font face='Courier'>wazuh-sim/</font> (local_rules.xml, detect_engine.py, sample_auth.log, cfilters), "
        "<font face='Courier'>evidence/</font> (transcripts, pcap, alerts, hashes).")]

build(OUT, s, "CAN IR1 Task1 - Environment Setup", FOOT)
