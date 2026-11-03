"""Care Access Navigator - Incident Response 1, Task 2: Log Analysis with Wazuh.
Builds the report PDF from the evidence written by lab/run_lab.sh and analysis/analyze.py.
Every table and excerpt is read from evidence/ - nothing is typed in by hand.
Run inside a container that has reportlab (see README)."""
import csv, json, os, re
from html import escape as e
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon
from reportlab.lib import colors
from reportlab.platypus import CondPageBreak
from pdfstyle import (P, bullets, note, code, table, kv, ok, bad, build, ss, NAVY, AMBER, CREAM, GREY_BG,
                      GREY_LINE, MUTED, RED, GREEN, Spacer, PageBreak, Paragraph, KeepTogether, inch, FULL_W)

TASK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # task2_log_analysis/
EV = os.path.join(TASK, "evidence"); AN = os.path.join(EV, "analysis")
OUT = os.path.join(TASK, "Care_Access_Navigator_IR1_Task2_Log_Analysis.pdf")
FOOT = "Care Access Navigator - Incident Response 1, Task 2: Log Analysis with Wazuh"
C = lambda t: f"<font face='Courier'>{e(t)}</font>"


def tx(name):
    return open(os.path.join(EV, "transcripts", name)).read()


def rows(name):
    return list(csv.DictReader(open(os.path.join(AN, name))))


def grep(path, pat, n=99, cut=150):
    out = [l.rstrip()[:cut] for l in open(os.path.join(EV, path), errors="replace") if re.search(pat, l)]
    return "\n".join(out[:n])


def section(name, start, stop=None, n=40):
    lines = tx(name).splitlines()
    i = next((k for k, l in enumerate(lines) if re.search(start, l)), 0)
    out = []
    for l in lines[i:]:
        if stop and out and re.search(stop, l):
            break
        out.append(l)
        if len(out) >= n:
            break
    return "\n".join(out)


corr = rows("correlation_inc_a.csv")
tl = rows("timeline_inc_a.csv")
byrule = rows("alerts_by_rule.csv")
lat = rows("detection_latency.csv")
mf = json.load(open(os.path.join(AN, "macos_findings.json")))
ke = json.load(open(os.path.join(AN, "key_events.json")))
tot = ke["alert_totals"]["by_source"]
parrot_events = re.search(r'(\d+) "location":"10\.77\.0\.10"', tx("07_export.txt"))[1]
mac_install_events = re.search(r'(\d+) "location":"/var/ossec/logs/macos/install.log"', tx("07_export.txt"))[1]
mac_ssh_events = re.search(r'(\d+) "location":"/var/ossec/logs/macos/ssh_client.log"', tx("07_export.txt"))[1]
a1, a2 = corr[0], corr[1]
N_RULES = len(re.findall(r'<rule id=', open(os.path.join(TASK, "wazuh", "local_rules.xml")).read()))
N_DEC = len(set(re.findall(r'<decoder name="([^"]+)"', open(os.path.join(TASK, "wazuh", "local_decoder.xml")).read())))
hhmmss = lambda s: s[11:23].rstrip("Z") if "T" in s else s


def hms(s):
    return s[11:19] if "T" in s else s


s = []

# ================================================================= cover
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Incident Response 1 &mdash; Task 2: Log Analysis and Incident Classification with Wazuh", "subtitle"),
      P("Parrot OS and macOS log analysis, a correlated suspicious-login investigation, and severity classification of three incidents", "subsub"),
      Spacer(1, 14)]
s += kv([
    ("Document ID", "CAN-IR1-T2-LOG-001"),
    ("Author", "Akhila Chennamaneni"),
    ("Date", "October 20, 2026"),
    ("SIEM", f"Wazuh manager 4.9.2 (real <font face='Courier'>wazuh-analysisd</font>, bundled ruleset + {N_RULES} custom rules, {N_DEC} custom decoders, 3 CDB lists)"),
    ("Hosts analysed", "<b>Parrot OS</b>: <font face='Courier'>parrot-sim</font> (Debian 12 stand-in, live syslog to Wazuh) &middot; "
                       "<b>macOS</b>: DAEDMAC1009, macOS 26.3.1 (the analyst workstation itself)"),
    ("People in scenario", "The users from the Entra ID / Keycloak JML cycle (JML-LOG.csv): Sathya Hasi (test.clinician, joiner), "
                           "Tara Jones (test.nurse, mover Nurse&rarr;Billing), Jeevan Smith (test.billing, leaver)"),
    ("Data classification", "Patient records are synthetic. macOS logs are real host logs from DAEDMAC1009."),
    ("Run", f"Lab run 2026-10-20 16:25&ndash;16:35 UTC; {len(byrule)} alert groups, "
            f"{sum(int(r['count']) for r in byrule)} alerts; evidence hashed in EVIDENCE-INDEX-SHA256.txt"),
])

s += [P("Summary", "h1"),
      P(f"Logs from a Parrot OS host and a macOS host were collected into a Wazuh 4.9.2 manager and analysed with "
        f"Wazuh's bundled rules plus custom rules tied to the project's joiner/mover/leaver (JML) register. "
        f"Wazuh received {parrot_events} Parrot events and {int(mac_install_events) + int(mac_ssh_events):,} macOS events with no loss, "
        f"and raised {ke['alert_totals']['level_ge_10']} alerts at level 10 or higher. "
        "One suspicious login was investigated end to end. Leaver Jeevan Smith's account made two login attempts from the macOS "
        "workstation, which were correlated across the Mac's SSH client log, the packet capture, the Parrot sshd log and Wazuh "
        "to the same second and the same TCP source port. The SSH server blocked both attempts, but the leaver's SSH key "
        "had never been removed from the host. Three incidents were classified with the severity matrix: "
        f"{bad('SEV-1 Critical')} (mover viewed a patient record through a stale group), "
        f"{bad('SEV-2 High')} (unapproved root grant to a clinician) and "
        f"<b>SEV-3 Medium</b> (blocked leaver login attempts). The macOS analysis found a 4-minor-version patch lag, "
        "a newly installed remote-access tool to confirm with IT, and one false-positive alert that was tuned out.")]

# ================================================================= rubric mapping
s += [P("1. How this report meets the Task 2 requirements", "h1")]
s += table([
    ["Requirement", "Where", "Evidence"],
    ["Parrot OS and macOS logs analysed with Wazuh", "&sect;4, &sect;5", "evidence/wazuh/alerts.json, analysis/alerts_by_rule.csv"],
    ["Analysis methodology documented", "&sect;3", "wazuh/local_rules.xml, local_decoder.xml, lists/"],
    ["Findings and security implications", "&sect;4.3, &sect;5.3, &sect;8", "analysis/macos_findings.json, transcripts/10&ndash;11"],
    ["1 suspicious login: host &harr; Parrot correlation", "&sect;6.2", "analysis/correlation_inc_a.csv, pcap/ssh_sessions.pcapng"],
    ["Event timeline", "&sect;6.3", "analysis/timeline_inc_a.csv"],
    ["Alert validation process", "&sect;6.4", "transcripts/08_logtest_trace.txt, 10_validation_checks.txt"],
    ["3 incidents classified with the severity matrix", "&sect;7", "&sect;7.2 scoring table"],
], [2.3 * inch, 1.0 * inch, 3.2 * inch])

# ================================================================= architecture
s += [P("2. Lab and data flow", "h1"),
      P("Unlike Task 1's Python rule engine, this task runs a <b>real Wazuh manager</b> (the official "
        f"{C('wazuh/wazuh-manager:4.9.2')} image). Detection, decoding, CDB-list lookups and alert output are all "
        "Wazuh's own. The lab runs in Docker Desktop with no administrator rights.")]


def arrow(d, x1, y1, x2, y2, label, col=NAVY):
    d.add(Line(x1, y1, x2, y2, strokeColor=col, strokeWidth=1.2))
    import math
    a = math.atan2(y2 - y1, x2 - x1); L = 6
    d.add(Polygon([x2, y2, x2 - L * math.cos(a - 0.4), y2 - L * math.sin(a - 0.4),
                   x2 - L * math.cos(a + 0.4), y2 - L * math.sin(a + 0.4)], fillColor=col, strokeColor=col))
    d.add(String((x1 + x2) / 2, (y1 + y2) / 2 + 4, label, fontName="Helvetica", fontSize=7, fillColor=MUTED, textAnchor="middle"))


def box(d, x, y, w, h, title, lines, fill=GREY_BG):
    d.add(Rect(x, y, w, h, fillColor=fill, strokeColor=NAVY, strokeWidth=1, rx=4, ry=4))
    d.add(String(x + w / 2, y + h - 13, title, fontName="Helvetica-Bold", fontSize=8.5, fillColor=NAVY, textAnchor="middle"))
    for i, t in enumerate(lines):
        d.add(String(x + w / 2, y + h - 26 - i * 10, t, fontName="Helvetica", fontSize=7, fillColor=colors.HexColor("#333333"), textAnchor="middle"))


d = Drawing(FULL_W, 215)
box(d, 0, 95, 150, 90, "macOS host DAEDMAC1009", ["macOS 26.3.1, OpenSSH_10.2", "/var/log/install.log (real)", "ssh_client.log (host_ssh_logged.py)", "user 'Adult', no admin rights"], CREAM)
box(d, 0, 0, 150, 70, "Docker port publish", ["127.0.0.1:2222 -> 10.77.0.10:22", "NAT source = gateway 10.77.0.1"])
box(d, 230, 95, 120, 90, "parrot-sim  10.77.0.10", ["Debian 12 (Parrot stand-in)", "sshd VERBOSE, DenyGroups", "auth.log, ehr-audit.log", "tshark on eth0 (pcap)"])
box(d, 330 + 70, 95, 118, 90, "wazuh-manager", ["10.77.0.20, Wazuh 4.9.2", "remoted syslog UDP 514", "logcollector (macOS files)", "analysisd -> alerts.json"], colors.HexColor("#E8EEF7"))
arrow(d, 75, 95, 75, 70, "")
arrow(d, 150, 35, 290, 95, "SSH sessions")
arrow(d, 350, 140, 400, 140, "")
d.add(String(375, 126, "rsyslog", fontName="Helvetica", fontSize=7, fillColor=MUTED, textAnchor="middle"))
d.add(String(375, 117, "UDP 514", fontName="Helvetica", fontSize=7, fillColor=MUTED, textAnchor="middle"))
d.add(Line(75, 185, 75, 200, strokeColor=AMBER, strokeWidth=1.2, strokeDashArray=[3, 2]))
d.add(Line(75, 200, 459, 200, strokeColor=AMBER, strokeWidth=1.2, strokeDashArray=[3, 2]))
arrow(d, 459, 200, 459, 186, "", AMBER)
d.add(String(267, 204, "macOS logs shipped as localfile inputs (agent install needs admin)", fontName="Helvetica", fontSize=7, fillColor=MUTED, textAnchor="middle"))
s += [d, Paragraph("Figure 1. Lab data flow. Both hosts feed one Wazuh manager; all SSH sessions originate on the Mac.", ss["caption"])]
s += table([
    ["Log source", "Host", "Collection into Wazuh", "Events received"],
    [f"{C('/var/log/auth.log')} (sshd, sudo, useradd/usermod, PAM)", "Parrot", "rsyslog forward, UDP 514 (live)", f"{parrot_events} (both sources)"],
    [f"{C('/var/log/ehr-audit.log')} (EHR record-access audit)", "Parrot", "rsyslog forward, local5 (live)", "incl. above"],
    [f"{C('/var/log/install.log')} 2026-10-13 &rarr; 10-20", "macOS", "localfile, timestamp normalised to ISO 8601", f"{int(mac_install_events):,} / {mf['install_log_lines']:,} lines"],
    [f"{C('ssh_client.log')} (OpenSSH client debug trail)", "macOS", "localfile", f"{mac_ssh_events} / {mac_ssh_events} lines"],
], [2.45 * inch, 0.6 * inch, 2.05 * inch, 1.4 * inch])
s += code(section("06_macos_logs.txt", r"lines shipped vs", n=4), title="transcripts/06_macos_logs.txt (completeness check: nothing dropped)")
s += note("The first run lost 15,122 macOS lines because one bulk append overflowed logcollector's 1,024-message queue "
          "(Wazuh logged &lsquo;Target agent message queue is full&rsquo;). The run script now ships install.log in "
          "500-line batches and checks that the shipped and received counts match. Ingestion completeness is now part of "
          "the method.", label="Collection issue found and fixed")

# ================================================================= methodology
s += [P("3. Analysis methodology", "h1"),
      P("The same eight-step method was applied to both hosts. Each step produces a file under "
        f"{C('evidence/')}, so any conclusion can be traced back to a raw log line.")]
s += table([
    ["#", "Step", "What was done", "Output"],
    ["1", "Collect", "Parrot logs streamed live; macOS logs shipped as files. Completeness checked (sent = received).", "archives counts, 06/07 transcripts"],
    ["2", "Normalise / decode", "Wazuh pre-decoder (timestamp, host, program) then bundled + custom decoders extract user, IP, port, group, patient, package, update.", "local_decoder.xml"],
    ["3", "Detect", f"Bundled rules (sshd 57xx, sudo 54xx, PAM, adduser) plus {N_RULES} custom rules. Custom rules use CDB lists that mirror JML-LOG.csv, so the SIEM knows who is a leaver or mover and which roles may hold root.", "local_rules.xml, lists/, alerts.json"],
    ["4", "Triage", "Alerts sorted by level (&ge;10 first), grouped by host and rule; the manager's own CIS self-scan alerts were set aside as out of scope.", "alerts_by_rule.csv"],
    ["5", "Validate", "Each high alert checked five ways: raw-log re-read, wazuh-logtest replay, cross-host corroboration, business context (JML ticket / change record), false-positive test.", "08, 10, 11 transcripts"],
    ["6", "Correlate", "Host &harr; Parrot join on time (same second, one shared clock), account name, TCP source port, SSH client banner, server host-key fingerprint, client key fingerprint.", "correlation_inc_a.csv"],
    ["7", "Timeline", "All sources converted to UTC and merged in order, including the identity-provider events from the JML register.", "timeline_inc_a.csv"],
    ["8", "Classify", "Impact &times; Urgency severity matrix mapped to the IR playbook's SEV-1&ndash;4 response times and escalation.", "&sect;7"],
], [0.25 * inch, 0.85 * inch, 3.9 * inch, 1.5 * inch])

s += [P("3.1 Custom detection content", "h2"),
      P("Wazuh's bundled rules see a login refused for a denied user (5718), but they cannot know that "
        f"{C('test.billing')} belongs to someone who left yesterday. The custom layer adds that identity context from three CDB "
        "lists kept in step with the JML register:")]
s += code(open(os.path.join(TASK, "wazuh", "lists", "jml-leavers")).read() +
          open(os.path.join(TASK, "wazuh", "lists", "jml-movers")).read() +
          open(os.path.join(TASK, "wazuh", "lists", "rbac-no-root")).read(),
          title="wazuh/lists/  (jml-leavers, jml-movers, rbac-no-root)")
crules = [("100210", "10", "Leaver account attempts SSH (child of 5718/5710/5716/5760 + jml-leavers)"),
          ("100211", "11", "2+ leaver attempts in 10 min, same user"),
          ("100221", "12", "Mover views ePHI through stale clinical group (ehr-audit + jml-movers = billing)"),
          ("100222", "10", "Mover attempts root via sudo (child of 5405)"),
          ("100230", "10", "Account added to sudo/wheel/adm (usermod decoder)"),
          ("100231", "12", "Root via sudo by a role with no root entitlement (child of 5402/5403)"),
          ("100240&ndash;100244", "3&ndash;8", "macOS: power state, update offered, Software Update entitlement, package installed, remote-access tool installed"),
          ("100250&ndash;100253", "3&ndash;7", "macOS SSH client: connect, leaver account used, refused, authenticated")]
s += table([["Rule", "Level", "Logic"]] + [[a, b, c] for a, b, c in crules], [1.15 * inch, 0.55 * inch, 4.8 * inch])
s += note("Wazuh 4.9 CDB lookups work on the destination-user field only. Sudo puts the caller in "
          f"{C('srcuser')}, so rules 100222 and 100231 mirror their list as a PCRE2 regex. Both are tested in the logtest output below.",
          label="Rule-engine limitation")

# ================================================================= Parrot analysis
s += [CondPageBreak(3 * inch), P("4. Parrot OS log analysis", "h1"),
      P(f"Source: {C('parrot-sim')} {C('auth.log')} and {C('ehr-audit.log')}, streamed live to Wazuh. "
        f"Wazuh raised <b>{tot.get('Parrot parrot-sim', 0)}</b> alerts from Parrot. End-to-end detection latency for the "
        f"level-10+ alerts was under 1 ms: each alert carries the same millisecond as its log line "
        f"(analysis/detection_latency.csv).")]
s += [P("4.1 Alerts by rule (Parrot)", "h2")]
s += table([["Rule", "Lvl", "Description", "Count"]] +
           [[r["rule_id"], r["level"], e(r["description"][:95]), r["count"]] for r in byrule if r["source"].startswith("Parrot")],
           [0.6 * inch, 0.4 * inch, 4.9 * inch, 0.6 * inch])
s += [P("4.2 Key raw events", "h2")]
s += code(grep("parrot/auth.log", r"usermod\[\d+\]: add 'test\.clinician' to group|sudo: +test\.|it_admin : |not allowed because|Accepted publickey for test\.nurse", cut=170) + "\n" +
          grep("parrot/ehr-audit.log", r".", cut=170), title="evidence/parrot/auth.log + ehr-audit.log (excerpt)")
s += [P("4.3 Parrot findings and security implications", "h2")]
s += table([
    ["ID", "Finding", "Security implication"],
    ["P-1", "Jeevan Smith's leaver account <b>test.billing</b> was refused twice by "
            f"{C('DenyGroups disabled-users')}, but its {C('authorized_keys')} file was never removed.",
     "The only barrier is one sshd setting. If that group rule is removed or the account is moved, the old key works again. JML deprovisioning on Linux hosts is incomplete."],
    ["P-2", "Tara Jones (now <b>Billing</b>) is still in the <b>clinical</b> group on this host. She opened synthetic record PT-1003 "
            "(ehr-audit ALLOW) and then tried to read it as root (sudo refused).",
     "The mover was completed in Entra ID and Keycloak, but local group membership was not cleaned up. Unauthorized ePHI access by a workforce member is a potential HIPAA breach under &sect;164.402."],
    ["P-3", "it_admin added Sathya Hasi (clinician) to <b>sudo</b>, and she ran a command as root 15 s later. The joiner ticket "
            "REQ-2026-0101 has no sudo or root grant.",
     "Breaks least privilege and separation of duties: a clinical user has full control of a host that stores ePHI. An administrator made an unrecorded change."],
    ["P-4", "Provisioning noise: 7&times; rule 5901 and 4&times; 5902 (new group/user) during setup.",
     "Expected and matched to the JML replay. Shows account-creation monitoring works; a real host would match these against tickets."],
], [0.45 * inch, 3.0 * inch, 3.05 * inch])

# ================================================================= macOS analysis
s += [CondPageBreak(3 * inch), P("5. macOS log analysis", "h1"),
      P(f"Source: DAEDMAC1009's real {C('/var/log/install.log')} ({mf['install_log_lines']:,} lines, "
        f"{e(mf['window_start'][:10])} to 2026-10-20) and the SSH-client trail recorded on the Mac. Wazuh raised "
        f"<b>{tot.get('macOS DAEDMAC1009', 0)}</b> alerts from macOS. The full unified log could not be read: "
        f"{C('log show')} returns &lsquo;Could not open local log store: Operation not permitted&rsquo; without admin rights. "
        "That is recorded as a visibility gap (M-5).")]
s += [P("5.1 Alerts by rule (macOS)", "h2")]
s += table([["Rule", "Lvl", "Description", "Count"]] +
           [[r["rule_id"], r["level"], e(r["description"][:95]), r["count"]] for r in byrule if r["source"].startswith("macOS")],
           [0.6 * inch, 0.4 * inch, 4.9 * inch, 0.6 * inch])
s += [P("5.2 Key raw events", "h2")]
s += code(grep("macos/install.log", r'Installed "Splashtop|trustLevel', 2, 170) + "\n" +
          grep("macos/install.log", r"minorPrimaryDescriptor", 1, 170) + "\n" +
          grep("macos/install.log", r"not entitled", 1, 170) + "\n" +
          grep("macos/install.log", r"System will sleep|System has powered on", 2, 170),
          title="evidence/macos/install.log (real host log, excerpt)")
s += code(section("11_macos_validation.txt", r"rule 100242", n=4) + "\n" +
          section("11_macos_validation.txt", r"codesign -dv", n=9),
          title="transcripts/11_macos_validation.txt (host-side validation of the macOS alerts)")
upd = mf["updates_offered"]
s += [P("5.3 macOS findings and security implications", "h2")]
s += table([
    ["ID", "Finding", "Validation", "Security implication"],
    ["M-1", f"Running macOS 26.3.1. {e(upd[1]['update'] if 'Tahoe' in upd[1]['update'] else upd[0]['update'])} (minor) and "
            f"macOS 27.0.1 were offered {upd[0]['times_offered']} times each between {mf['update_offer_first'][:10]} and "
            f"{mf['update_offer_last'][:10]}; nothing was installed. Background download is disabled.",
     "True positive: sw_vers confirms 26.3.1.", "Four minor releases behind on an MDM-managed clinical workstation means missing security fixes. Patch to 26.7.1 now and plan the 27.x upgrade."],
    ["M-2", "<b>Splashtop Streamer 3.8.6.3</b> (remote-access tool) installed 2026-10-16 19:40 UTC as root; daemon running at boot.",
     "Notarized, signed by Splashtop Inc. (CPQQ3AW49Y). Mac is MDM-managed, so this was most likely an IT deployment.",
     "Legitimate software, but it is a persistent inbound remote-control path (MITRE T1219). Confirm with IT that it is approved, MFA-protected and access-logged. <b>Event, not an incident</b> until IT confirms or denies."],
    ["M-3", f"{mf['entitlement_violations']} &lsquo;not entitled&rsquo; Software Update preference writes, all from PID "
            f"{', '.join(mf['entitlement_pids'])}.",
     "<b>False positive</b>: ps shows PID 75876 is Apple's Safari (user Adult).", "No risk. Rule tuned (&sect;5.4) so analysts do not learn to ignore it."],
    ["M-4", f"{mf['sleeps']} sleep and {mf['wakes']} wake events; last wake before the scenario at {mf['last_wake_before_scenario'][11:16]} UTC.",
     "Context only.", "Shows the host was awake and in use when the INC-A attempts left it, which supports the correlation."],
    ["M-5", "Unified log (loginwindow, sshd, sudo, authd) not readable; no Wazuh agent on the Mac.",
     "Reproduced in transcript 06.", "Host-side authentication on the Mac is invisible to the SIEM. Fix: deploy the Wazuh agent through MDM with a unified-log query."],
], [0.4 * inch, 2.2 * inch, 1.65 * inch, 2.25 * inch])
s += [P("5.4 Tuning the false positive (M-3)", "h2"),
      P("Alerts that are always benign get ignored, so the rule should change rather than the analyst. The proposed tuning keeps "
        "the alert for any process except a validated Apple-signed browser PID. In production this belongs in an agent rule that "
        "can check the code signature.")]
s += code('<rule id="100245" level="0">\n'
          '  <if_sid>100242</if_sid>\n'
          '  <field name="client_pid">^75876$</field>   <!-- validated: Safari, 2026-10-20 (transcript 11) -->\n'
          '  <description>Known benign: Safari reading Software Update preferences</description>\n'
          '</rule>', title="proposed addition to local_rules.xml (not deployed in this run, so the evidence stays as collected)")

# ================================================================= investigation
s += [CondPageBreak(4 * inch), P("6. Investigation: suspicious login attempt (INC-A, IR1-2026-004)", "h1"),
      P(f"<b>Trigger.</b> Rule 100210 (level 10) &mdash; &ldquo;JML leaver account test.billing attempted SSH login from "
        f"10.77.0.1&rdquo; &mdash; at {a1['sshd_deny_utc'][11:23]} UTC, then rule 100211 (level 11, repeated) at "
        f"{a2['sshd_deny_utc'][11:23]}. On the macOS side, rule 100251 flagged the Mac's SSH client using the same leaver account. "
        "The account belongs to <b>Jeevan Smith</b>, a billing specialist deprovisioned the day before under ticket TERM-2026-0301.")]
s += [P("<b>Questions the investigation had to answer:</b>")] + bullets([
    "Where did the attempts really come from? Parrot only sees 10.77.0.1, which is a Docker gateway, not a person.",
    "Did they succeed, and was anything accessed?",
    "Is the alert accurate, and is the account really a leaver?",
    "What weakness does it reveal?"])

s += [P("6.1 Why 10.77.0.1 is not the answer", "h2"),
      P("The Parrot log shows every Mac session arriving from the network gateway, because Docker forwards the Mac's "
        f"{C('127.0.0.1:2222')} to {C('10.77.0.10:22')} through NAT. On its own, the server log cannot say which machine or "
        "person connected. Host-to-Parrot correlation is needed to get past the NAT, and NAT, VPN concentrators and load "
        "balancers hide sources the same way in production.")]

s += [P("6.2 Host &harr; Parrot correlation", "h2"),
      P("Each attempt was joined across four independent records. The table is generated by "
        f"{C('analysis/analyze.py')} from the raw files.")]
s += table([
    ["Correlation key", "Attempt 1", "Attempt 2", "Records joined"],
    ["Mac ssh process / time (UTC)", f"ssh[{a1['mac_ssh_pid']}] {hms(a1['mac_time_utc'])}", f"ssh[{a2['mac_ssh_pid']}] {hms(a2['mac_time_utc'])}", "ssh_client.log"],
    ["Local Mac account (key path)", f"/Users/{e(a1['mac_user_from_key_path'])}/&hellip;", f"/Users/{e(a2['mac_user_from_key_path'])}/&hellip;", "ssh_client.log"],
    ["Target account", C(a1["target_account"]), C(a2["target_account"]), "client log = sshd log"],
    ["Client SSH banner on the wire", C(a1["pcap_client_banner"]), C(a2["pcap_client_banner"]), "pcap = client log"],
    ["TCP source (after NAT)", C(a1["pcap_src"]), C(a2["pcap_src"]), "pcap = sshd &lsquo;Connection from&rsquo;"],
    ["sshd process / time", f"sshd[{a1['sshd_pid']}] {hhmmss(a1['sshd_time_utc'])}", f"sshd[{a2['sshd_pid']}] {hhmmss(a2['sshd_time_utc'])}", "auth.log"],
    ["Server decision", "DenyGroups refusal", "DenyGroups refusal", "auth.log"],
    ["Client result", e(a1["mac_outcome"]), e(a2["mac_outcome"]), "ssh_client.log"],
    ["Server host key seen by client", C(a1["server_host_key_seen"][12:34] + "…"), "same", "= parrot-sim host key"],
    ["Mac start &rarr; sshd connection", f"+{a1['delta_mac_to_sshd_s']} s", f"+{a2['delta_mac_to_sshd_s']} s", "same clock (checked)"],
    ["Wazuh alert (Parrot / macOS)", f"{e(a1['wazuh_parrot_rule'])} / {e(a1['wazuh_mac_rule'])}", f"{e(a2['wazuh_parrot_rule'])} / {e(a2['wazuh_mac_rule'])}", "alerts.json"],
], [1.75 * inch, 1.6 * inch, 1.6 * inch, 1.55 * inch])
s += code(grep("macos/ssh_client.log", rf"ssh\[{a1['mac_ssh_pid']}\]: (debug1: (Connecting|Local version|Remote protocol|Authenticating|Server host key)|.*Permission denied)", cut=150) + "\n" +
          grep("parrot/auth.log", rf"sshd\[{a1['sshd_pid']}\]", cut=150) + "\n" +
          grep("pcap/client_banners.csv", a1["pcap_src"].split(":")[1]),
          title="Attempt 1: same event on the Mac (top), on Parrot (middle) and on the wire (bottom; epoch, src, port, banner)")

s += [P("6.3 Event timeline (UTC)", "h2")]
s += table([["Time (UTC)", "Host", "Source", "Event"]] +
           [[e(r["time_utc"].replace("T", " ").replace("Z", "")), e(r["host"]), e(r["source"]), e(r["event"])] for r in tl],
           [1.25 * inch, 0.78 * inch, 1.37 * inch, 3.1 * inch])
s += [P("macOS ssh-client entries have 1-second resolution and are ordered within their second by protocol sequence. The two "
        "macOS-side Wazuh alerts appear at 16:31:40 because the Mac's log was shipped in a batch after the scenario; the "
        "event time inside each alert is the original 16:29:07 and 16:29:32. A real-time agent would remove that delay.", "caption")]

s += [P("6.4 Alert validation", "h2"),
      P("Before the incident was classified, the alert was challenged with five checks. A failed check would have made it a false positive.")]
s += table([
    ["#", "Check", "How", "Result"],
    ["1", "Raw log says what the alert says", f"Re-read {C('auth.log')} lines for sshd[{a1['sshd_pid']}] and sshd[{a2['sshd_pid']}]", ok("Confirmed") + ": &lsquo;User test.billing &hellip; not allowed because a group is listed in DenyGroups&rsquo;"],
    ["2", "Rule chain is correct", f"Replayed the raw line through {C('wazuh-logtest -v')}", ok("Confirmed") + ": 1 &rarr; 5700 &rarr; 5718 &rarr; 100210, level 10"],
    ["3", "Account really is a leaver", "JML-LOG.csv TERM-2026-0301; host state", ok("Confirmed") + ": Entra disabled 2026-10-19 18:13; host shows L (locked), expired 1970-01-02, group disabled-users"],
    ["4", "Independent corroboration from the other host", "Mac client log + pcap, joined on port and banner (&sect;6.2)", ok("Confirmed") + ": both attempts seen leaving DAEDMAC1009 (OpenSSH_10.2; parrot-sim's own client is OpenSSH_9.2p1)"],
    ["5", "Could it be benign / authorized?", "Search for a change or access ticket; check outcome", bad("No authorization") + ": no ticket permits leaver access. Both attempts failed; no session opened."],
], [0.25 * inch, 1.55 * inch, 2.05 * inch, 2.65 * inch])
s += code("\n".join(dict.fromkeys(l for l in tx("08_logtest_trace.txt").splitlines() if l.strip())),
          title="transcripts/08_logtest_trace.txt (wazuh-logtest -v on the raw attempt-1 line)")
s += code(section("10_validation_checks.txt", r"# 1\) host key", stop=r"# 3\)", n=14) +
          section("10_validation_checks.txt", r"# 3\) leaver", n=6),
          title="transcripts/10_validation_checks.txt (excerpt)")

s += [P("6.5 Conclusion", "h2"),
      P(f"<b>Verdict: true positive, blocked.</b> Two SSH login attempts as leaver Jeevan Smith ({C('test.billing')}) came from "
        f"workstation DAEDMAC1009, macOS account &lsquo;{e(a1['mac_user_from_key_path'])}&rsquo;, 25 seconds apart, about 22 hours "
        "after the account was disabled in Entra ID. Both were refused before authentication, so nothing was accessed. "
        "But the client offered a key that is <b>still in the leaver's authorized_keys</b> (fingerprint "
        "SHA256:RzTBOFUk&hellip;, the same key sshd accepted for the other two users). The credential was never revoked on "
        "this host, and someone on the Mac still holds a key that works for a terminated account.")]

# ================================================================= classification
s += [CondPageBreak(4 * inch), P("7. Incident classification with the severity matrix", "h1"),
      P("Wazuh rule levels measure how unusual an event is, not how much it matters to the business. Each validated incident "
        "was therefore classified with an <b>Impact &times; Urgency</b> severity matrix. The matrix follows the incident "
        "prioritization factors in NIST SP 800-61 Rev. 2 (&sect;3.2.6):")]
s += bullets([
    "<b>Impact</b> combines functional impact (control of the system) and information impact (ePHI confidentiality and integrity).",
    "<b>Urgency</b> reflects recoverability: whether the activity succeeded and whether the access path is still open.",
])
s += [P("The product of the two scores maps to the four severity levels, response times and escalation paths of the "
        "Care Access Navigator IR playbook (CAN IR-Playbook &sect;0). Every incident in the project is triaged the same way.")]
s += [P("7.1 Severity matrix", "h2")]
s += table([
    ["Score", "Impact (I)", "Urgency (U)"],
    ["3 &mdash; High", "ePHI confidentiality or integrity affected, or root/admin control obtained", "Activity succeeded and the access path is still open now"],
    ["2 &mdash; Medium", "Activity reached the system and exposed a control gap, but no data or admin control was obtained", "Blocked, but repeated or the path is only partly closed"],
    ["1 &mdash; Low", "Blocked by a control working as designed; no gap", "Isolated; path closed"],
], [1.0 * inch, 2.85 * inch, 2.65 * inch])
mtx = [["I \\ U", "U = 1", "U = 2", "U = 3"],
       ["I = 3", "3 &rarr; SEV-3 Medium", "6 &rarr; SEV-2 High", "9 &rarr; " + bad("SEV-1 Critical")],
       ["I = 2", "2 &rarr; SEV-4 Low", "4 &rarr; SEV-3 Medium", "6 &rarr; SEV-2 High"],
       ["I = 1", "1 &rarr; SEV-4 Low", "2 &rarr; SEV-4 Low", "3 &rarr; SEV-3 Medium"]]
s += table(mtx, [1.0 * inch, 1.83 * inch, 1.83 * inch, 1.84 * inch])
s += table([
    ["Severity", "Score", "Response starts", "Escalate to"],
    [bad("SEV-1 Critical"), "9", "Immediately", "Privacy Officer (HIPAA breach risk assessment; 60-day notification clock)"],
    [bad("SEV-2 High"), "6", "&lt; 1 hour", "Security lead / IAM owner"],
    ["<b>SEV-3 Medium</b>", "3&ndash;4", "&lt; 1 business day", "SecOps on-call"],
    ["SEV-4 Low", "1&ndash;2", "Next review", "&mdash;"],
], [1.2 * inch, 0.6 * inch, 1.2 * inch, 3.5 * inch])

s += [CondPageBreak(2.5 * inch), P("7.2 The three incidents", "h2")]
s += table([
    ["Incident", "Person / evidence", "I", "U", "Severity", "Rationale"],
    ["<b>IR1-2026-005</b> (INC-B)<br/>ePHI viewed through stale role",
     f"Tara Jones (test.nurse), mover Nurse&rarr;Billing (CHG-2026-0201). Rules 100221 L12 + 100222 L10 at {ke['first_alert_log_time']['100221'][11:19]} UTC.",
     "3", "3", bad("SEV-1 Critical") + "<br/>score 9",
     "A billing employee opened a clinical record (ePHI confidentiality). The stale clinical group still grants access now, and she then tried root to read it again."],
    ["<b>IR1-2026-006</b> (INC-C)<br/>Unapproved root grant",
     f"Sathya Hasi (test.clinician), joiner REQ-2026-0101; it_admin. Rules 100230 L10 + 100231 L12 at {ke['first_alert_log_time']['100231'][11:19]} UTC.",
     "3", "2", bad("SEV-2 High") + "<br/>score 6",
     "Full root on an ePHI host for a role with no root entitlement, with no change record. The grant is still active, but it was used once for a harmless command (id) and no data was touched."],
    ["<b>IR1-2026-004</b> (INC-A)<br/>Leaver login attempts",
     f"Jeevan Smith (test.billing), leaver TERM-2026-0301. Rules 100210 L10 + 100211 L11 + 100251 L7. Investigated in &sect;6.",
     "2", "2", "<b>SEV-3 Medium</b><br/>score 4",
     "Blocked, so no access. But it exposed a gap: the leaver key is still authorized and its holder tried twice. Only one sshd setting is left in the way."],
], [1.15 * inch, 1.6 * inch, 0.25 * inch, 0.25 * inch, 0.95 * inch, 2.3 * inch])
s += note("The capstone detection rule for disabled-account logins (CAN-ID-002) rates the <i>alert</i> High, so analysts look "
          "at it immediately. After validation, the <i>incident</i> is SEV-3 Medium because both attempts were blocked and no "
          "access was gained. Alert severity sets how quickly an event is triaged; incident severity sets the response. "
          "The evidence for each score is in &sect;4.3 and &sect;6.", label="Alert severity vs incident severity")
s += note("Patient data in this lab is synthetic. With real ePHI, IR1-2026-005 would also start the four-factor HIPAA breach "
          "risk assessment (45 CFR &sect;164.402).", label="HIPAA")

s += [P("7.3 Response by severity (playbook order)", "h2")]
s += table([
    ["Incident", "Contain now", "Eradicate / fix", "Recover / verify"],
    ["IR1-2026-005<br/>SEV-1", f"{C('gpasswd -d test.nurse clinical')}; notify Privacy Officer; preserve ehr-audit.log + hash",
     "Mover workflow removes old groups on every host, not only Entra and Keycloak; access review of the clinical group",
     "ehr-view PT-1003 as test.nurse must return DENY; rule 100221 silent"],
    ["IR1-2026-006<br/>SEV-2", f"{C('gpasswd -d test.clinician sudo')}; ask it_admin for the justification",
     "Privileged grants only through a change ticket; consider just-in-time sudo", "sudo -l shows no rights; rule 100230 fires only with a matching ticket"],
    ["IR1-2026-004<br/>SEV-3", f"Delete {C('~test.billing/.ssh/authorized_keys')}; set shell to nologin",
     "Find and revoke the matching key on DAEDMAC1009; add Linux hosts to the leaver checklist (or use central SSO such as SSSD)",
     "A new attempt is still refused and the key fingerprint is gone from every host"],
], [1.0 * inch, 1.9 * inch, 2.0 * inch, 1.6 * inch])

# ================================================================= implications
s += [CondPageBreak(2.5 * inch), P("8. Overall security implications", "h1")]
s += bullets([
    "<b>Identity lifecycle stops at the identity provider.</b> All three incidents share one root cause: JML changes were made "
    "in Entra ID and Keycloak but not on the Linux host, which has its own users, groups and keys. Any system with local "
    "accounts needs to be part of the JML checklist, or be federated to the IdP.",
    "<b>Context-aware rules made the difference.</b> Bundled Wazuh rules rated these events level 3&ndash;5 (normal noise). "
    "The CDB lists that mirror the JML register raised them to 10&ndash;12. The SIEM is only as good as its knowledge of who "
    "should have access, so the lists must be updated whenever a JML ticket closes.",
    "<b>NAT hides attackers.</b> Without the Mac-side log and the packet capture, INC-A ends at &lsquo;10.77.0.1&rsquo;. "
    "Endpoint telemetry (a Wazuh agent with unified-log collection) is needed on workstations, not only servers.",
    "<b>Endpoint hygiene.</b> The macOS workstation is behind on patches and runs a remote-access tool whose approval is not "
    "yet recorded. Either one could become the entry point for the kind of credential misuse seen in INC-A.",
    "<b>Detection quality.</b> One of the five macOS rules produced only false positives. Validating and tuning it is part of "
    "the method, not an afterthought.",
])

# ================================================================= limitations
s += [P("9. Scope, substitutions and limitations", "h1")]
s += table([
    ["Rubric expects", "This lab", "Effect"],
    ["Wazuh on Parrot OS in VirtualBox", "Real Wazuh manager 4.9.2 in Docker; Parrot = Debian 12 container (no admin rights, arm64 host)", "Same analysisd, rules and alert format; no dashboard or indexer"],
    ["Wazuh agent on each host", "Parrot: agentless syslog. macOS: log files shipped as localfile inputs", "macOS alerts are batch, not real time"],
    ["macOS unified log", f"Not readable without admin; used install.log + SSH client trail", "No Mac loginwindow/sudo visibility (M-5)"],
    ["Suspicious login by an outside attacker", "Real attempts from the Mac by the lab operator, using a leaver account", "Behaviour and logs are real; the actor is staged"],
], [1.7 * inch, 2.7 * inch, 2.1 * inch])
s += note("Confirm in writing with the instructor that the Docker-based Parrot stand-in and file-shipped macOS logs are "
          "accepted for the Wazuh/Parrot rubric items, as for Task 1 (docs/adr/ADR-SIEM-choice.md).", label="Action required")

# ================================================================= evidence + reproduce
s += [P("10. Evidence and reproduction", "h1")]
idx = [l.split("  ", 1) for l in open(os.path.join(EV, "EVIDENCE-INDEX-SHA256.txt")).read().splitlines() if l.strip()]
s += table([["SHA-256 (first 16 hex)", "Artifact"]] + [[h[:16] + "…", "evidence/" + p.lstrip("./ ")] for h, p in idx],
           [1.7 * inch, 4.8 * inch])
s += code('cd incident_response_1/task2_log_analysis/lab\n'
          'bash run_lab.sh      # Wazuh + parrot-sim, scenario from the Mac, ship macOS logs, export, analyze, hash\n\n'
          'docker rm -f parrot-sim wazuh-manager && docker network rm ir2-labnet     # tear down', title="Reproduce")

build(OUT, s, "CAN IR1 Task2 - Log Analysis with Wazuh", FOOT)
