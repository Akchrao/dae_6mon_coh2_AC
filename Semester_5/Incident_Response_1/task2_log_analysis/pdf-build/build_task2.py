"""Care Access Navigator - Incident Response 1, Task 2: Incident Detection and Analysis.
Builds the PDF from the evidence written by run_task2.sh and analysis/analyze.py (nothing typed in by hand).
Run from Semester_5/Incident_Response_1/ (see README)."""
import csv, json, os, re
from html import escape as e
from pdfstyle import (P, bullets, note, code, table, kv, ok, bad, build, ss, Spacer, PageBreak, Paragraph, inch, FULL_W)
from reportlab.platypus import CondPageBreak

TASK = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); IR = os.path.dirname(TASK)
EV = os.path.join(TASK, "evidence"); AN = os.path.join(EV, "analysis"); LAB = os.path.join(IR, "lab")
OUT = os.path.join(TASK, "Care_Access_Navigator_IR1_Task2_Log_Analysis.pdf")
FOOT = "Care Access Navigator - Incident Response 1, Task 2: Incident Detection and Analysis"
C = lambda t: f"<font face='Courier'>{e(t)}</font>"
rd = lambda p: open(p, errors="replace").read()
tx = lambda n: rd(os.path.join(EV, "transcripts", n))
rows = lambda n: list(csv.DictReader(open(os.path.join(AN, n))))


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
byrule = rows("alerts_by_rule.csv"); corr = rows("correlation_ir1_2026_001.csv"); tl = rows("timeline_ir1_2026_001.csv")
lat = rows("detection_latency.csv")
mf = json.load(open(os.path.join(AN, "macos_findings.json"))); ke = json.load(open(os.path.join(AN, "key_events.json")))
tot = ke["alert_totals"]["by_source"]; fa = ke["first_alert_log_time"]
rec = {m[0]: (int(m[1]), int(m[2])) for m in re.findall(r"(\S+) -> \S+\s+sent=(\d+)\s+received=(\d+)", tx("01_rules_and_capture.txt") + tx("04_macos_logs.txt"))}
inst = rec.get("install_iso.log", (0, 0)); sshl = rec.get("ssh_client.log", (0, 0))
val = tx("08_macos_validation.txt")
osver = re.search(r"ProductVersion:\s+(\S+)", val)[1]
lat_v = [float(r["latency_s"]) for r in lat]
n_rules = sum(len(re.findall(r'<rule id=', rd(os.path.join(LAB, "wazuh", f)))) for f in ("can_ir1_core_rules.xml", "can_ir1_task2_rules.xml"))
hms = lambda s: s[11:19]
det = marks["detection"]

s = []
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Incident Response 1 &mdash; Task 2: Incident Detection and Analysis", "subtitle"),
      P("Parrot OS and macOS log analysis with Wazuh, a correlated suspicious-login investigation, and severity classification of three incidents", "subsub"),
      Spacer(1, 14)]
s += kv([
    ("Document ID", "CAN-IR1-T2-LOG-002 (replaces version 001: same lab, people and incident numbers as Tasks 1 and 3&ndash;6)"),
    ("Author", "Akhila Chennamaneni"), ("Date", "November 3, 2026"),
    ("SIEM", f"Wazuh manager 4.9.2 + agent on parrot-vm (Task 1); {n_rules} custom rules, 3 CDB lists from the JML register"),
    ("Hosts", "<b>Parrot OS</b>: parrot-vm (agent 001). <b>macOS</b>: DAEDMAC1009, the analyst's Mac (install.log + SSH client trail)"),
    ("People", "Sathya Hasi (joiner), Tara Jones (mover), Jeevan Smith (leaver), it_admin; patient records are synthetic"),
    ("Run", f"scenario {hms(marks['scenario_start'])} UTC; Wazuh SEV-1 alert {hms(det)} UTC; analysis done {hms(marks['analysis_done'])} UTC, 2026-11-03"),
])
s += [P("Summary", "h1"),
      P(f"The JML people acted on parrot-vm from the Mac, and Wazuh analysed both hosts' logs. It raised {ke['alert_totals']['all']:,} alerts: "
        f"{tot.get('Parrot parrot-vm', 0)} from the Parrot agent and {tot.get('macOS DAEDMAC1009', 0):,} from macOS. "
        f"{ke['alert_totals']['level_ge_10']} were at level 10 or higher. Every high-level Parrot alert was raised within "
        f"{max(lat_v):.1f} s of the event it reports. Three incidents came out of it, and each one maps to a JML failure. "
        f"Tara Jones (mover) read a patient record through a group she should have lost: rule 100221 fired at {hms(det)} and started "
        "containment (Task 3). Sathya Hasi (joiner) was given sudo with no change record and used root. Jeevan Smith (leaver) tried to "
        "log in twice. His attempts were investigated end to end and matched across the Mac's SSH client, a packet capture, the "
        "Parrot sshd log and Wazuh. The severity matrix rates them " + bad("SEV-1") + " (IR1-2026-002), " + bad("SEV-2") +
        " (IR1-2026-003) and <b>SEV-3</b> (IR1-2026-001). The macOS analysis found patch lag, a remote-access tool whose approval is not yet confirmed, and a "
        "recurring false-positive pattern, with a tuning proposal.")]
s += [P("1. How this report meets the Task 2 requirements", "h1")]
s += table([["Requirement", "Where", "Evidence"],
    ["Parrot OS and macOS logs analysed with Wazuh", "&sect;4, &sect;5", "wazuh/alerts.json, analysis/alerts_by_rule.csv"],
    ["Methodology documented", "&sect;3", "lab/wazuh/*.xml, lists/"],
    ["1 suspicious login: correlation host &harr; Parrot", "&sect;6.1", "analysis/correlation_ir1_2026_001.csv, pcap/"],
    ["Event timeline", "&sect;6.2", "analysis/timeline_ir1_2026_001.csv"],
    ["Alert validation process", "&sect;6.3", "transcripts/06, 08"],
    ["3 incidents classified with the severity matrix", "&sect;7", "&sect;7.2"],
    ["Security implications", "&sect;4.2, &sect;5.2, &sect;8", ""]], [2.6 * inch, 1.1 * inch, 2.8 * inch])

# ---------------------------------------------------------------- data + method
s += [P("2. Data collected", "h1")]
s += table([["Source", "Host", "Collection", "Received"],
    [f"{C('/var/log/auth.log')}, {C('ehr-audit.log')}, {C('kern.log')}, {C('audit.log')} + FIM", "Parrot", "Wazuh agent 001 (live)", f"{tot.get('Parrot parrot-vm', 0)} alerts"],
    [f"{C('/var/log/install.log')}", "macOS", "file shipped to a manager input (Task 1 proved the path)", f"{inst[1]:,} / {inst[0]:,} lines"],
    [f"{C('ssh_client.log')} (OpenSSH client trail)", "macOS", "file shipped", f"{sshl[1]} / {sshl[0]} lines"],
    [f"{C('ssh_sessions.pcapng')}", "Parrot", "tshark, saved filter 'IR1 SSH sessions'", "client banners"]],
    [2.6 * inch, 0.6 * inch, 2.1 * inch, 1.2 * inch])
s += code(section("02_scenario.txt", r"S1 Sathya", r"s5_done", n=40), title="transcripts/02_scenario.txt - what the people did (from the Mac)")
s += [P("3. Analysis method", "h1")]
s += table([["#", "Step", "What was done"],
    ["1", "Collect", "Parrot logs live through the agent; macOS logs shipped; sent = received checked for every file"],
    ["2", "Decode", "Wazuh pre-decoders, bundled decoders and the custom ones (ehr-audit, usermod-group, macOS)"],
    ["3", "Detect", f"Bundled rules (sshd, sudo, PAM, FIM, audit) + {n_rules} custom rules that look identities up in the JML CDB lists"],
    ["4", "Triage", "Sort by level; the SEV-1 alert (100221) goes straight to containment, the rest queue by severity"],
    ["5", "Validate", "Five checks per high alert: raw log re-read, wazuh-logtest replay, cross-host corroboration, business context (JML ticket), false-positive test"],
    ["6", "Correlate", "Mac &harr; Parrot by time, SSH client banner, TCP port (pcap &harr; sshd) and outcome"],
    ["7", "Timeline", "All sources in UTC, plus the JML register events"],
    ["8", "Classify", "Impact &times; Urgency matrix &rarr; SEV-1&ndash;4 (playbook CAN-IR-PB-02 &sect;0)"]], [0.3 * inch, 0.9 * inch, 5.3 * inch])

# ---------------------------------------------------------------- Parrot analysis
s += [CondPageBreak(3 * inch), P("4. Parrot OS log analysis", "h1"), P("4.1 Alerts (Parrot, level 5 and above)", "h2")]
s += table([["Rule", "Lvl", "Description", "Count", "First (UTC)"]] +
           [[r["rule_id"], r["level"], e(r["description"][:80]), r["count"], r["first_utc"][11:19]]
            for r in byrule if r["source"].startswith("Parrot") and int(r["level"]) >= 5],
           [0.6 * inch, 0.35 * inch, 3.9 * inch, 0.5 * inch, 1.15 * inch])
s += code(section("03_detection.txt", r"triage queue", r"FIM", n=16), title="Triage queue when the SEV-1 fired (transcripts/03)")
s += [P("4.2 Findings and implications (Parrot)", "h2")]
s += table([["ID", "Finding", "Implication"],
    ["P-1", f"Rule 100221 (L12) at {hms(det)}: test.nurse, now Billing, viewed PT-1003 through group clinical. The FIM alerts that followed show files appearing in a hidden folder in her home and a new crontab.",
     "ePHI exposed through privilege creep; the files and cron entry point to staging and persistence. SEV-1 &rarr; containment started at the alert (Task 3)."],
    ["P-2", f"Rules 100230 + 100231 at {fa.get('100230', '')[11:19]}&ndash;{fa.get('100231', '')[11:19]}: it_admin added test.clinician to sudo, then she ran a command as root.",
     "Root for a role with no root entitlement and no change record: a least-privilege and SoD breach on an ePHI host."],
    ["P-3", f"Rules 100210 + 100211 from {fa.get('100210', '')[11:19]}: leaver test.billing tried SSH twice; sshd refused (DenyGroups).",
     "Blocked, but the leaver's SSH key is still on the host (investigated in &sect;6)."]], [0.45 * inch, 3.1 * inch, 2.95 * inch])

# ---------------------------------------------------------------- macOS analysis
s += [CondPageBreak(3 * inch), P("5. macOS log analysis", "h1"),
      P(f"Source: DAEDMAC1009's {C('/var/log/install.log')} ({mf['install_log_lines']:,} lines from {e(mf['window_start'][:10])}) and its SSH "
        f"client trail. The unified log needs admin rights on this managed Mac, so it could not be read.")]
s += table([["Rule", "Lvl", "Description", "Count"]] +
           [[r["rule_id"], r["level"], e(r["description"][:90]), r["count"]] for r in byrule if r["source"].startswith("macOS")],
           [0.6 * inch, 0.35 * inch, 4.95 * inch, 0.6 * inch])
upd = mf["updates_offered"]
inst_pk = [p for p in mf["packages_installed"] if p["rule"] == "100244"]
s += [P("5.1 Host-side validation", "h2")]
s += code(val, title="transcripts/08_macos_validation.txt")
s += [P("5.2 Findings and implications (macOS)", "h2")]
s += table([["ID", "Finding", "Validation", "Implication"],
    ["M-1", f"Running macOS {osver}; updates offered and not installed: " + "; ".join(f"{e(u['update'])} ({u['times_offered']}&times;)" for u in upd[:4]),
     f"True positive: sw_vers = {osver}", "Missing security fixes on a clinical workstation; patch and plan the major upgrade"],
    ["M-2", ("Remote-access tool installed: " + "; ".join(f"{e(p['package'])} {p['time_utc'][:10]}" for p in inst_pk)) if inst_pk else "No remote-access tool installed in the window",
     "Signature and Gatekeeper result in &sect;5.1", "Persistent inbound remote-control path (T1219): confirm with IT that it is approved, MFA-protected and logged"],
    ["M-3", f"{mf['entitlement_violations']} Software Update 'not entitled' events (PIDs {', '.join(mf['entitlement_pids']) or 'n/a'})",
     "Process check in &sect;5.1", "Benign app behaviour seen before (Safari): tune by validated process, not by ignoring the rule"],
    ["M-4", f"{mf['sleeps']} sleep / {mf['wakes']} wake events", "Context", "The host was in use when the scenario sessions left it"],
    ["M-5", "Unified log not readable; no agent on the Mac", "transcript 04 (Task 1)", "Mac authentication is invisible to the SIEM: deploy the agent through MDM"]],
    [0.4 * inch, 2.4 * inch, 1.5 * inch, 2.2 * inch])

# ---------------------------------------------------------------- investigation
s += [PageBreak(), P("6. Investigation: suspicious login (IR1-2026-001)", "h1"),
      P("Two SSH logins as Jeevan Smith (test.billing), terminated on TERM-2026-0301, came from the analyst workstation. "
        "The Mac sees its own connection to 127.0.0.1:2223; parrot-vm sees the Docker gateway. The attempts were therefore matched "
        "on time, the client's SSH banner, the TCP source port (pcap &harr; sshd) and the outcome on both sides.")]
s += [P("6.1 Correlation across hosts", "h2")]
s += table([["Attempt", "Mac (ssh_client.log)", "Network (pcap)", "Parrot sshd", "Wazuh", "&Delta; Mac&rarr;sshd"]] +
           [[c["attempt"], f"{c['mac_time_utc'][11:19]} pid {c['mac_ssh_pid']}<br/>{e(c['mac_outcome'] or '')}", f"{c['pcap_time_utc'][11:23]}<br/>{c['pcap_src']}",
             f"{c['sshd_deny_utc'][11:23]} sshd[{c['sshd_pid']}]<br/>{e(c['sshd_decision'][:60])}", f"{c['wazuh_parrot_rule']}<br/>{c['wazuh_parrot_alert_utc'][11:23]}",
             f"{float(c['delta_mac_to_sshd_s']):+.2f} s"] for c in corr],
           [0.5 * inch, 1.3 * inch, 1.05 * inch, 1.75 * inch, 1.1 * inch, 0.8 * inch])
s += [P("6.2 Timeline", "h2")]
s += table([["UTC", "Host", "Source", "Event"]] + [[r["time_utc"][5:23].replace("T", " "), r["host"], e(r["source"][:30]), e(r["event"][:95])] for r in tl],
           [1.25 * inch, 0.65 * inch, 1.3 * inch, 3.3 * inch])
s += [P("6.3 Alert validation", "h2")]
s += code(tx("06_logtest_trace.txt"), title="wazuh-logtest -v replay of the raw sshd denial (transcripts/06)")
s += table([["Check", "Result"],
    ["Raw log re-read", "auth.log line 'User test.billing ... not allowed because a group is listed in DenyGroups' present for both attempts"],
    ["Replay", "wazuh-logtest reaches 5718 &rarr; 100210 (above): the alert follows from the log alone"],
    ["Cross-host", f"Mac shows {len(corr)} refused sessions at the same seconds (&sect;6.1)"],
    ["Business context", "JML-LOG TERM-2026-0301: Jeevan Smith disabled in Entra ID and Keycloak; no reinstatement ticket"],
    ["False positive?", "No: the account is on jml-leavers and was used. But the SSH key is still authorized on the host, so only one sshd setting stood in the way"]],
    [1.4 * inch, 5.1 * inch])

# ---------------------------------------------------------------- classification
s += [CondPageBreak(3 * inch), P("7. Classification with the severity matrix", "h1"),
      P("Impact &times; Urgency, each 1&ndash;3. The scores follow the prioritization factors in NIST SP 800-61r2 &sect;3.2.6, and "
        "the product maps to the playbook's SEV-1&ndash;4 levels (CAN-IR-PB-02 &sect;0). If the course's own matrix differs, only "
        "this mapping changes.")]
s += table([["I \\ U", "U = 1", "U = 2", "U = 3"],
    ["I = 3", "3 &rarr; SEV-3", "6 &rarr; SEV-2", "9 &rarr; " + bad("SEV-1")],
    ["I = 2", "2 &rarr; SEV-4", "4 &rarr; SEV-3", "6 &rarr; SEV-2"],
    ["I = 1", "1 &rarr; SEV-4", "2 &rarr; SEV-4", "3 &rarr; SEV-3"]], [1.0 * inch, 1.83 * inch, 1.83 * inch, 1.84 * inch])
s += [P("7.2 The three incidents", "h2")]
s += table([["Incident", "Who / JML", "I", "U", "Severity", "Rationale"],
    ["<b>IR1-2026-002</b><br/>ePHI read via stale role", f"Tara Jones, mover CHG-2026-0201; 100221 at {hms(det)}", "3", "3", bad("SEV-1") + " (9)",
     "Patient record read by a Billing employee; FIM shows staging and persistence. Access still open: disclosure likely in progress"],
    ["<b>IR1-2026-003</b><br/>Unapproved root", f"Sathya Hasi, joiner REQ-2026-0101; it_admin; 100230/100231", "3", "2", bad("SEV-2") + " (6)",
     "Root on an ePHI host for a role without entitlement, no change record; used once (id), no data touched"],
    ["<b>IR1-2026-001</b><br/>Leaver login attempts", "Jeevan Smith, leaver TERM-2026-0301; 100210/100211", "2", "2", "<b>SEV-3</b> (4)",
     "Blocked, so no access; but it exposed a live gap (key still authorized) and was repeated"]],
    [1.15 * inch, 1.45 * inch, 0.25 * inch, 0.25 * inch, 0.8 * inch, 2.6 * inch])
s += note("The SEV-1 did not wait for this analysis: containment started at the alert (Task 3), and this classification "
          "confirmed it afterwards. The SEV-2 and SEV-3 were queued and contained in the same session (Task 3, C7). Recovery and the "
          "root-cause fix for all three are in Task 6.", label="What happened next")
s += [P("8. Security implications", "h1")]
s += bullets([
    "<b>One root cause, three incidents.</b> JML changes reached Entra ID and Keycloak but not the Linux host's own groups and keys.",
    "<b>Identity context is what made the alerts loud.</b> Bundled rules scored these events 3&ndash;5. The JML lists raised them to 10&ndash;12.",
    "<b>NAT hides the source.</b> Without the Mac's own log and the packet capture, the leaver attempts end at the Docker gateway.",
    "<b>Endpoint hygiene.</b> Patch lag and an unconfirmed remote-access tool on the analyst's Mac widen the attack surface.",
])
s += [P("Appendix A &mdash; Evidence index", "h1")]
s += code("\n".join(l[:16] + "...  " + l.split("  ", 1)[1] if re.match(r"[0-9a-f]{64}  ", l) else l
                    for l in rd(os.path.join(EV, "EVIDENCE-INDEX-SHA256.txt")).splitlines()), title="evidence/EVIDENCE-INDEX-SHA256.txt")
build(OUT, s, "Care Access Navigator - IR1 Task 2: Log Analysis", FOOT)
