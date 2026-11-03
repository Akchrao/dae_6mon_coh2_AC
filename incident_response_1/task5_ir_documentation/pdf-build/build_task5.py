"""Care Access Navigator - Incident Response 1, Task 5: IR Documentation & Reporting.
Builds the PDF from: playbook/*.md and tools/*.md (rendered as-is), tracker/incidents.db (live queries), and the
evidence of Tasks 3, 4 and 6 for the incident report. Run from incident_response_1/ (see README)."""
import csv, datetime as dt, json, os, re, sqlite3, sys
from html import escape as e
from pdfstyle import (P, bullets, note, code, table, kv, ok, bad, build, ss, Spacer, PageBreak, Paragraph, inch, FULL_W)
from mdpdf import render

TASK = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); IR = os.path.dirname(TASK)
E3, E4, E6 = (os.path.join(IR, d, "evidence") for d in ("task3_containment", "task4_evidence_management", "task6_post_incident"))
OUT = os.path.join(TASK, "Care_Access_Navigator_IR1_Task5_Documentation_Reporting.pdf")
FOOT = "Care Access Navigator - Incident Response 1, Task 5: IR Documentation & Reporting"
I = "IR1-2026-002"
C = lambda t: f"<font face='Courier'>{e(t)}</font>"
rows = lambda p: list(csv.DictReader(open(p)))
iso = lambda s: dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
hms = lambda s: s[11:19]
rd = lambda p: open(p, errors="replace").read()

db = sqlite3.connect(os.path.join(TASK, "tracker", "incidents.db")); db.row_factory = sqlite3.Row
inc = db.execute("SELECT * FROM incident WHERE id=?", (I,)).fetchone()
hist = {r["status"]: r["at_utc"] for r in db.execute("SELECT * FROM status_history WHERE incident=?", (I,))}
acts = db.execute("SELECT * FROM action WHERE incident=? ORDER BY at_utc", (I,)).fetchall()
evts = db.execute("SELECT * FROM event WHERE incident=? ORDER BY at_utc", (I,)).fetchall()
evid = db.execute("SELECT * FROM evidence WHERE incident=? ORDER BY item", (I,)).fetchall()
regi = rows(os.path.join(TASK, "tracker", "incidents_register.csv"))
m3 = {r["phase"]: r["utc"] for r in rows(os.path.join(E3, "markers.csv"))}
ups = [json.loads(l) for l in open(os.path.join(E3, "exfil-sink", "uploads.jsonl"))]
key = {r["milestone"]: r["utc"] for r in rows(os.path.join(E4, "timeline", "key_events.csv"))}
v1 = [l.split("\t") for l in rd(os.path.join(E6, "validation", "checklist_run1.tsv")).splitlines()[1:]]
v2 = [l.split("\t") for l in rd(os.path.join(E6, "validation", "checklist_run2.tsv")).splitlines()[1:]]
p1 = [l.split("\t") for l in rd(os.path.join(E6, "validation", "network_probes_run1.tsv")).splitlines()[1:]]
reg4 = rows(os.path.join(E4, "coc", "evidence_register.csv"))
record = rd(os.path.join(IR, "lab", "provision_vm.sh"))
pt1003 = re.search(r'printf "(SYNTHETIC RECORD PT-1003[^"]+)"', record)[1].replace("\\n", " | ").rstrip(" |")
n_cmds = sum(1 for r in rows(os.path.join(E4, "timeline", "supertimeline_IR1-2026-002.csv")) if r["event"].startswith("command executed by test.nurse"))
sec_read_alert = (iso(m3["detection"]) - iso(key["PT-1003 viewed through stale clinical group"])).total_seconds()
mins = lambda a, b: (iso(b) - iso(a)).total_seconds() / 60

s = []
# ================================================================= cover
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Incident Response 1 &mdash; Task 5: IR Documentation &amp; Reporting", "subtitle"),
      P("Host IR playbook, an incident tracking system, the incident report for IR1-2026-002, and a Parrot OS IR tools guide", "subsub"),
      Spacer(1, 14)]
s += kv([
    ("Document ID", "CAN-IR1-T5-DOC-002"), ("Author", "Akhila Chennamaneni"), ("Date", "November 3, 2026"),
    ("Deliverables", f"{C('playbook/CAN-IR-PB-02_Host_Incident_Response_Playbook.md')} &middot; {C('tracker/irtrack.py')} + "
                     f"{C('incidents.db')} &middot; incident report (&sect;4) &middot; {C('tools/PARROT_IR_TOOLS.md')}"),
    ("Tested on", f"{I} (SEV-1), run end to end in Tasks 3, 4 and 6; the playbook and tools guide quote the commands that were actually run"),
])
s += [P("Summary", "h1"),
      P("This task turns the work of Tasks 1&ndash;4 and 6 into documents a hospital security team could use. The <b>playbook</b> "
        "(CAN-IR-PB-02) sets severities, roles and a first-15-minutes checklist, and gives six runbooks for the incidents this "
        "environment actually sees. Each runbook lists Parrot OS commands and evidence steps. The <b>tracking system</b> is a "
        "working tool, not a spreadsheet: a SQLite database with a command-line interface. It enforces a forward-only status "
        "workflow, measures response times against the severity targets, and exports the incident register. It holds "
        f"{len(regi)} incidents. The <b>incident report</b> for {I} follows the NIST SP 800-61 structure and includes the "
        "HIPAA breach risk assessment. The <b>tools guide</b> documents every tool used, with the exact command and its pitfalls.")]
s += [P("1. How this report meets the Task 5 requirements", "h1")]
s += table([
    ["Requirement", "Where", "Artifact"],
    ["IR playbook: response procedures for common incidents", "&sect;2 (RB-01&ndash;06)", "playbook/CAN-IR-PB-02_*.md"],
    ["Playbook: tool-specific commands for Parrot OS", "&sect;2 runbooks, &sect;2 section 5", "same"],
    ["Playbook: evidence collection steps", "&sect;2 section 4, RB-02 C2&ndash;C5", "same"],
    ["Incident tracking system implemented", "&sect;3", "tracker/irtrack.py, incidents.db, load_cases.py"],
    ["Tracking: incident details, response actions, timeline of events", "&sect;3.2, &sect;4", "tables incident / action / event / evidence"],
    ["Complete incident report for 1 event, standard format", "&sect;4", f"{I} (NIST SP 800-61r2 layout)"],
    ["Documentation of IR tools and procedures in Parrot OS", "&sect;5", "tools/PARROT_IR_TOOLS.md"],
], [2.75 * inch, 1.45 * inch, 2.3 * inch])

# ================================================================= playbook
s += [PageBreak(), P("2. Incident response playbook (CAN-IR-PB-02)", "h1"),
      P(f"Rendered from {C('playbook/CAN-IR-PB-02_Host_Incident_Response_Playbook.md')}. The Markdown file is the controlled copy.")]
s += render(rd(os.path.join(TASK, "playbook", "CAN-IR-PB-02_Host_Incident_Response_Playbook.md")), h1="h2", h2="h2")

# ================================================================= tracker
s += [PageBreak(), P("3. Incident tracking system (irtrack)", "h1"),
      P(f"{C('tracker/irtrack.py')} uses only Python's standard library and keeps one SQLite file. That makes it portable "
        "(Mac, Windows, Parrot) and simple to audit. It does three things a spreadsheet does not: status can only move forward, "
        "every change is time-stamped, and response times are computed and checked against the playbook's severity targets.")]
s += [P("3.1 Design", "h2")]
s += table([
    ["Table", "Holds", "Key fields"],
    ["incident", "One row per incident", "id, title, type, severity, status, detected_utc, source, handler, assets, summary"],
    ["status_history", "Every status change", "incident, status, at_utc, note (New &rarr; Triage &rarr; Contained &rarr; Eradicated &rarr; Recovered &rarr; Closed)"],
    ["action", "Response actions", "incident, at_utc, phase, by_whom, what, result"],
    ["event", "Timeline of events", "incident, at_utc, host, source, what"],
    ["evidence", "Linked evidence", "incident, item (E01&hellip;), description, sha256, location"],
], [1.15 * inch, 1.5 * inch, 3.85 * inch])
s += table([["Severity", "Start response within", "Measured as"]] +
           [[k, f"{v} min" if v < 600 else (f"{v // 60} h" if v < 1440 else f"{v // 1440} days"), "detected_utc &rarr; first action"]
            for k, v in {"SEV-1": 15, "SEV-2": 60, "SEV-3": 480, "SEV-4": 7200}.items()], [1.2 * inch, 2.0 * inch, 3.3 * inch])
s += [P("3.2 Using it", "h2")]
s += code(rd(os.path.join(TASK, "tracker", "cli_walkthrough.txt")), title="tracker/cli_walkthrough.txt - workflow on a scratch database, then the real register", width=118)
s += [P("3.3 The incident register", "h2"),
      P(f"{C('load_cases.py')} rebuilds the database from the evidence of Tasks 1&ndash;6, so the register always matches what "
        f"actually happened. {C('irtrack.py export')} writes {C('incidents_register.csv')}, which keeps the project's existing "
        "Tableau columns and adds the response metrics.")]
s += table([["ID", "Sev", "Status", "Detected (UTC)", "Respond", "SLA", "Contain", "Recover", "Act/Evt/Ev"]] +
           [[r["incident_id"], r["severity"], r["status"], r["detected_utc"][:16].replace("T", " "),
             (r["time_to_respond_min"] + " m") if r["time_to_respond_min"] else "&ndash;",
             ok(r["response_sla"]) if r["response_sla"] == "MET" else r["response_sla"],
             (r["time_to_contain_min"] + " m") if r["time_to_contain_min"] else "&ndash;",
             (r["time_to_recover_min"] + " m") if r["time_to_recover_min"] else "&ndash;",
             f"{r['actions']}/{r['events']}/{r['evidence_items']}"] for r in regi],
           [1.05 * inch, 0.5 * inch, 0.55 * inch, 1.05 * inch, 0.6 * inch, 0.45 * inch, 0.6 * inch, 0.75 * inch, 0.75 * inch])
s += note("All three IR1 incidents come from one continuous exercise on one lab (Tasks 1&ndash;6), so their detection, containment "
          "and recovery times can be compared directly. This register replaces the project's earlier rows, which listed IR1 incidents "
          "as &lsquo;Resolved&rsquo; before any response had been run. The Tableau extract can be refreshed from this export.", label="Register")

# ================================================================= incident report
s += [PageBreak(), P(f"4. Incident report &mdash; {I}", "h1"),
      P("Format: NIST SP 800-61r2 incident documentation (§3.2.5): summary, details, timeline, scope and impact, "
        "detection and analysis, response, evidence, root cause, notifications, recommendations, sign-off.", "subsub"), Spacer(1, 6)]
s += [P("4.1 Executive summary", "h2"),
      P(f"On 3 November 2026 a Billing employee whose old clinical access was never removed opened patient record PT-1003, "
        f"copied it, and started a hidden program that sent it to an outside address every five seconds. The SIEM (Wazuh) raised its "
        f"patient-record alert {sec_read_alert:.1f} seconds after the record was opened, and the analyst confirmed the transfer on the host. Within <b>{mins(m3['detection'], m3['c3_block']) * 60:.0f} seconds</b> "
        f"of detection the transfer was blocked, and within {mins(m3['detection'], m3['contained']):.0f} minutes the host was isolated and the "
        f"account locked. {len(ups)} copies of the one record reached the outside address. The host was restored from a clean "
        f"snapshot, the access gap was fixed, and {sum(1 for r in v2 if r[-1] == 'PASS')} recovery checks passed before and after a reboot. The record is synthetic; with real "
        "data this would be a reportable HIPAA breach of one individual's ePHI.")]
s += [P("4.2 Incident details", "h2")]
s += table([["Field", "Value"],
    ["Incident ID / title", f"{I} &mdash; {e(inc['title'])}"],
    ["Type / category", e(inc["type"]) + " (NIST: unauthorized access + data exfiltration; MITRE ATT&amp;CK T1078 Valid Accounts, T1048 Exfiltration over alternative protocol, T1053.003 Cron)"],
    ["Severity", f"{bad('SEV-1 Critical')} (Impact 3 &times; Urgency 3 = 9)"],
    ["Status", f"Closed {hist['Closed'][:10]}"],
    ["Detected", f"{inc['detected_utc']} &mdash; {e(inc['source'])}"],
    ["Contained / eradicated / recovered", f"{hist['Contained']} / {hist['Eradicated']} / {hist['Recovered']}"],
    ["Handler / reported by", f"{e(inc['handler'])} / Wazuh rule 100221 on agent parrot-vm (automated)"],
    ["Systems", "parrot-vm (EHR host, Debian 12 / Parrot OS stand-in), 10.0.2.15; EHR portal service; drop site 10.78.99.66 (external, lab)"],
    ["Accounts", "test.nurse &mdash; Tara Jones, mover Nurse &rarr; Billing (CHG-2026-0201)"],
    ["Data", f"1 record (PT-1003, synthetic): {e(pt1003)}"],
], [1.9 * inch, 4.6 * inch])
s += [P("4.3 Timeline (UTC, 2026-11-02)", "h2")]
s += table([["UTC", "Event", "Source"]] + [[r["at_utc"][11:19], e(r["what"]), e(r["source"])] for r in evts],
           [0.8 * inch, 3.8 * inch, 1.9 * inch])
s += [P("4.4 Scope and impact", "h2")]
s += bullets([
    f"<b>Data:</b> one patient record, sent {len(ups)} times (all byte-identical: SHA-256 {C(ups[0]['sha256'][:16])}&hellip;) between "
    f"{hms(ups[0]['ts'])} and {hms(ups[-1]['ts'])}. No other record was read: the EHR audit trail and auditd show one read.",
    f"<b>Systems:</b> one host. No lateral movement: the account had no sudo, and auditd recorded {n_cmds} commands from it. They touched "
    "only its home folder, the one record and its own crontab. Memory analysis found no rootkit (Task 4 &sect;4.1).",
    "<b>Service:</b> the EHR portal on this host was down from containment until recovery (planned trade-off, approved by IC).",
    "<b>Business:</b> potential HIPAA breach notification for one individual; reputational risk; HR matter for the employee.",
])
s += [P("4.5 Detection and analysis", "h2"),
      P("Wazuh rule 100221 (built in Task 1) fires when an account on the JML movers list reads a clinical record; the agent on "
        "parrot-vm delivered the EHR audit line and the alert fired within seconds. On the host, the analyst "
        "confirmed the read in the EHR audit trail and auditd, and saw SYN packets to 10.78.99.66:8080 every 5 s from a process "
        "owned by test.nurse. That confirmed disclosure in progress, so the incident stayed SEV-1. Later analysis (Task 4) "
        "confirmed it from memory, the disk image and a timeline correlated across hosts by SSH key fingerprint.")]
s += [P("4.6 Response actions", "h2")]
s += table([["UTC", "Phase", "Action"]] + [[a["at_utc"][5:16].replace("T", " "), e(a["phase"]), e(a["what"])] for a in acts],
           [0.95 * inch, 1.3 * inch, 4.25 * inch])
s += [P("4.7 Evidence", "h2")]
s += table([["Item", "Description", "SHA-256"]] + [[r["item"], e(r["description"]), C(r["sha256"][:20]) + "&hellip;"] for r in evid],
           [0.45 * inch, 4.3 * inch, 1.75 * inch])
s += [P("Chain of custody: Task 4 &sect;6 (12 items, 51 custody events). All items were re-verified before recovery (Task 6 gate: 100/100 OK).")]
s += [P("4.8 Root cause", "h2"),
      P("<b>Direct cause:</b> the mover change CHG-2026-0201 added the Billing group on the Linux host but did not remove the "
        "clinical group. The identity provider handled its side automatically (Keycloak removed the Nurse role), but local "
        "host groups were outside the JML process. <b>Contributing:</b> no host firewall or egress filtering; users could "
        "create cron jobs; disabled accounts kept SSH keys; detection raised an alert but containment was manual. Full RCA in Task 6.")]
s += [P("4.9 HIPAA breach risk assessment (45 CFR 164.402)", "h2")]
s += table([["Factor", "Assessment", "Risk"],
    ["1. Nature and extent of PHI", "Name, DOB, MRN and diagnosis for one patient: directly identifying, clinical", bad("High")],
    ["2. Unauthorized person", "Unknown recipient at an external address, set up by a workforce member acting outside her role", bad("High")],
    ["3. Actually acquired or viewed?", f"Yes: the drop site logged {len(ups)} complete copies", bad("High")],
    ["4. Extent mitigated", "Host contained; no way to retrieve or confirm destruction at the external address", "Medium"],
    ["Conclusion", "Low probability of compromise <b>cannot</b> be shown &rarr; breach. Notify the individual without unreasonable delay and within 60 days of discovery; record in the HHS annual log (&lt; 500). <i>Lab exercise: the record is synthetic, so no notice was sent.</i>", bad("Notify")],
], [1.6 * inch, 4.0 * inch, 0.9 * inch])
s += [P("4.10 Recovery and validation", "h2"),
      P(f"Restored from the pre-incident snapshot, root cause fixed, then validated twice (before and after a reboot): "
        f"{sum(1 for r in v1 if r[-1] == 'PASS')}/{len(v1)} and {sum(1 for r in v2 if r[-1] == 'PASS')}/{len(v2)} checklist items, "
        f"{sum(1 for r in p1 if r[-1] == 'PASS')}/{len(p1)} network probes. Details: Task 6.")]
s += [P("4.11 Recommendations", "h2")]
s += table([["#", "Recommendation", "Owner", "Due"],
    ["1", "Extend JML to local host groups and SSH keys; reconcile hosts with the IdP every night", "IAM owner", "2026-11-16"],
    ["2", "Monthly access review of all movers for 90 days after a move", "IAM owner / managers", "2026-11-30"],
    ["3", "Host firewall with egress allow-list on every EHR host (done on parrot-vm)", "System owner", "done / 2026-11-16 for others"],
    ["4", "Auto-contain on rule 100221 + outbound connection: run RB-02 C3 automatically, page the IC", "Security lead", "2026-12-15"],
    ["5", "Restrict cron to administrators (cron.allow) fleet-wide (done on parrot-vm)", "System owner", "2026-11-16"],
], [0.3 * inch, 3.7 * inch, 1.4 * inch, 1.1 * inch])
s += [P("4.12 Sign-off", "h2")]
s += table([["Role", "Name", "Date"], ["Prepared by (IR analyst)", "Akhila Chennamaneni", "2026-11-02"],
            ["Incident Commander", "(lab: same person)", "2026-11-02"], ["Privacy Officer review", "(pending, lab)", ""]],
           [2.2 * inch, 2.6 * inch, 1.7 * inch])

# ================================================================= tools
s += [PageBreak(), P("5. IR tools and procedures in Parrot OS", "h1"),
      P(f"Rendered from {C('tools/PARROT_IR_TOOLS.md')}.")]
s += render(rd(os.path.join(TASK, "tools", "PARROT_IR_TOOLS.md")), h1="h2", h2="h2")

build(OUT, s, "Care Access Navigator - IR1 Task 5: Documentation & Reporting", FOOT)
