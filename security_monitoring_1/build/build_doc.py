"""Builds security_monitoring_1/build/sm1.html from the evidence and outputs (then rendered to PDF)."""
import csv, json, html, pathlib, glob
R = pathlib.Path(__file__).resolve().parents[1]
EV, OUT = R / "evidence", R / "outputs"
e = html.escape
m = json.load(open(OUT / "sm1_metrics.json"))
base = list(csv.DictReader(open(OUT / "baselines.csv")))
alerts = json.load(open(EV / "sm1_scenario_alerts.json"))
hc_md = open(OUT / "health_check_latest.md").read().splitlines()
hc_first = json.load(open(sorted(glob.glob(str(OUT / "health_check_2026*.json")))[0]))
net = open(EV / "network_config.txt").read()
hist_n = sum(1 for _ in open(EV / "windows_history_sample.jsonl"))


def table(head, rows, widths=None):
    h = "".join(f'<th{f" style=width:{w}" if widths and w else ""}>{x}</th>' for x, w in zip(head, widths or [None] * len(head)))
    return "<table><tr>" + h + "</tr>" + "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows) + "</table>"


def img(f, cap, h=None):
    return f'<div class="fig"><img src="{f}"{f" style=max-height:{h}px" if h else ""}><div class="cap">{cap}</div></div>'


def full(rid):
    a = next(x for x in alerts if x["rule"]["id"] == rid)
    return e(a.get("full_log", "")), a


hi = [a for a in alerts if a["rule"]["level"] >= 10]
P = [f"""
<h1>Security Monitoring 1: Project Submission</h1>
<div class="meta">Akhila Chennamaneni &middot; DAE 6-Month Cybersecurity Cohort 2 &middot; November 2026<br>
Organization: HealthLine Regional Medical Center (HRMC), the capstone hospital. Platform: Wazuh 4.9.2 (manager, indexer, dashboard) in Docker on macOS. Cost: $0.</div>
<div class="note"><b>Windows source (option B, agreed with the instructor):</b> no live Windows host was available, so Windows Security events were
<b>imported as samples</b> in the Microsoft Security log schema (event IDs 4624, 4625, 4634, 4663, 4732, 5156). Every imported event is tagged
<code>"sample": "imported-synthetic"</code>. The <b>Linux source is live</b>: a Debian 12 server (<code>hrmc-linux-srv01</code>) runs the official Wazuh agent 4.9.2,
connected to the manager over the agent protocol (port 1514/tcp), and its SSH, file and network activity in this report is real.</div>
<h3>Summary</h3>
{table(["Area", "Result"], [
 ["Environment", "Wazuh manager + indexer + dashboard, live Linux agent (Active), imported Windows samples, Keycloak and EHR logs; email routing to Tier 1 and the SOC lead"],
 ["Rules", "15 new rules (100600-100651) for authentication, file access and network activity on Windows and Linux, including 2 cross-source correlations; plus the 13 SOC 1 rules"],
 ["Scenario SM1-SCN-01", f"{m['effectiveness']['steps_detected']} of {m['effectiveness']['scenario_steps']} attack steps detected ({m['effectiveness']['detection_rate_pct']}%); {m['operational']['scenario_alerts_total']} alerts, {m['operational']['scenario_alerts_level10plus']} at level 10+; median {m['operational']['mttd_seconds_median']} s from event to alert"],
 ["Baseline week", f"{hist_n} normal Windows events over 7 days: {m['effectiveness']['normal_week_high_alerts']} high alerts (no false positives at level 10+)"],
 ["Health monitoring", "health_check.py checks collection, processing and storage; it caught a real agent outage, and the disk-space check was added after a real storage incident"],
 ["Reporting", "Alert template for 3 alert types, operational / coverage / effectiveness metrics, summary report, custom dashboard 'HRMC Security Monitoring'"]], ["18%", None])}
<h3>Rubric map</h3>
{table(["Rubric criterion", "Section"], [["Monitoring Environment Setup", "1"], ["Security Event Analysis", "2"], ["Monitoring Implementation", "3"], ["Security Reporting", "4"]], ["45%", None])}
"""]

# ----------------------------------------------------------------- 1
P.append(f"""<h2 class="pb">1. Monitoring Environment Setup</h2>
<h3>1.1 Installation and basic configuration</h3>
{table(["Component", "Version / image", "Configuration"], [
 ["Wazuh manager", "wazuh/wazuh-manager:4.9.2", "Custom rules <code>soc1_rules.xml</code> + <code>zz_sm1_rules.xml</code>; email notification; 5 log files under /var/log/soc1; vulnerability detection disabled (section 3.6)"],
 ["Wazuh indexer", "wazuh/wazuh-indexer:4.9.2 (OpenSearch)", "Single node, TLS certificates from the official generator, 1 GB heap"],
 ["Wazuh dashboard", "wazuh/wazuh-dashboard:4.9.2", "https://localhost:5601; custom dashboard imported as saved objects"],
 ["Linux agent", "hrmc-linux-agent:1.0 (Debian 12 + wazuh-agent 4.9.2)", "auth.log collection, real-time file integrity monitoring of /srv/ehr_exports, outbound TCP command every 30 s"],
 ["MailHog", "mailhog/mailhog:v1.0.1", "Test SMTP server for alert email (port 8025 web inbox)"]], ["18%", "30%", None])}
<h3>1.2 Network configuration</h3>
<pre>{e(net)}</pre>
<p>All components share the Docker bridge network <code>single-node_default</code> (172.21.0.0/16). Only the ports analysts and agents need are published:
1514-1515/tcp (agent events and enrollment), 514/udp (syslog), 55000 (API), 9200 (indexer), 5601 (dashboard), 8025 (mail).</p>
<h3 class="pb">1.3 Log collection from Windows and Linux, with verified connectivity</h3>
{table(["Source type", "How it is collected", "Verification"], [
 ["<b>Linux</b> (hrmc-linux-srv01)", "Wazuh agent 001: /var/log/auth.log, file integrity monitoring, command output", "Agent <b>Active</b> in agent_control and the dashboard (Screenshot 2); agent log: <i>Connected to the server ([wazuh.manager]:1514/tcp)</i>; alerts from agent hrmc-linux-srv01 in the index"],
 ["<b>Windows</b> (HRMC-WS-PFS-02, HRMC-FS01 and 4 other workstations)", "Imported Security log samples (JSON) read by the manager's logcollector from /var/log/soc1/windows_security.json", f"logcollector counted the events; {hist_n} baseline events + scenario indexed as data.src = windows_security; rule tester (wazuh-logtest) decodes them into fields"],
 ["Keycloak sign-in / admin, EHR access", "Capstone logs (JSON) via logcollector", "Alerts with data.src keycloak_login, keycloak_admin, ehr_access"]], ["20%", "38%", None])}
{img("../screenshots/SS-02.png", "Screenshot 2: Wazuh endpoints view: agent 001 hrmc-linux-srv01, Debian 12, v4.9.2, status active", 470)}
<h3 class="pb">1.4 Alert rules for three security scenarios</h3>
{table(["Scenario", "Windows rules", "Linux rules (live agent)", "Application rules"], [
 ["<b>Authentication</b>", "100601 failed logon; 100602 6 failures / 2 min (password guessing); 100604 RDP logon from outside the network; 100605 lockout; 100606 privileged group change", "Built-in 5760 failed SSH password, 5763 SSH brute force, 5551 PAM failures, 40112 failures followed by success", "100501-100507 Keycloak (SOC 1)"],
 ["<b>File access</b>", "100610 file read; 100611 read on the EHR export share (ePHI); 100612 20+ reads in 60 s", "Built-in 554 / 550 / 553 file added / changed / deleted in /srv/ehr_exports (real-time FIM)", "100521 / 100522 EHR record access (SOC 1)"],
 ["<b>Network activity</b>", "100620 connection allowed; 100621 connection to a known-bad address (203.0.113.0/24)", "100630 TCP connection to a known-bad address (outbound_tcp command)", "-"],
 ["<b>Cross-source</b>", "100651 mass EHR export reads + outbound to bad address (same user)", "", "100650 Windows RDP from outside + EHR record access (same user)"]], ["14%", "34%", "30%", None])}
{img("../screenshots/SS-05.png", "Screenshot 5: the rule file zz_sm1_rules.xml in Server management &rarr; Rules", 560)}
<h3 class="pb">1.5 Monitoring workflow: alert routing and notification</h3>
{table(["Alert level", "Routing", "Notification"], [
 ["3-7", "Stored in the indexer; dashboard; daily review", "None"],
 ["8-9", "Tier 1 queue in the dashboard", "None (seen within the shift)"],
 ["10-11", "Tier 1 triage", "Email to soc-tier1@hrmc.lab (email_alert_level 10)"],
 ["12-15", "Tier 1 triage, SOC lead informed immediately", "Email to soc-tier1 <b>and</b> soc-lead@hrmc.lab, no delay (email_alerts, level 12)"]], ["14%", "40%", None])}
<p>During the scenario Wazuh sent <b>{m['operational']['notification_emails_sent']} emails</b>: {', '.join(f"{v} to {k}" for k, v in m['operational']['notification_recipients'].items())} (Screenshot 6).
Full escalation workflow (Tier 1 &rarr; Tier 2 &rarr; Incident Commander) is in the SOC 1 submission, Mermaid diagram <code>soc_alert_workflow.mmd</code>.</p>
{img("../screenshots/SS-06.png", "Screenshot 6: MailHog inbox, level 14 and 15 notifications to soc-lead@hrmc.lab", 470)}
""")

# ----------------------------------------------------------------- 2
f5760, _ = full("5760"); f40112, _ = full("40112"); f554, _ = full("554"); f553, _ = full("553"); f100630, _ = full("100630")
f100604, _ = full("100604"); f100612, _ = full("100612"); f100651, _ = full("100651"); f100650, _ = full("100650")
tl = []
for rid in ["5760", "5763", "40112", "554", "553", "100630", "100602", "100604", "100612", "100651", "100521", "100650"]:
    a = next((x for x in alerts if x["rule"]["id"] == rid), None)
    if a:
        tl.append([a["timestamp"][11:19], a["agent"]["name"], a.get("data", {}).get("src", "agent"), f"{rid} (L{a['rule']['level']})", e(a["rule"]["description"][:110])])
P.append(f"""<h2 class="pb">2. Security Event Analysis</h2>
<h3>2.1 Log types and how to read them</h3>
{table(["Log type", "Key fields", "What to look for"], [
 ["Windows Security log", "event_id, target_user, logon_type (2 local, 3 network, 10 RDP), ip, status (0xC000006A = bad password), object_name, access_mask (0x1 = read), application, dest_ip", "Failures before a success; RDP from outside 10.x; reads on sensitive shares; unusual programs (rclone.exe) talking to the internet"],
 ["Linux auth.log (syslog)", "timestamp, host, program[pid], message: Failed / Accepted password for USER from IP", "Many failures from one source, then Accepted from the same source"],
 ["Wazuh FIM", "file path, event (added / modified / deleted), mode realtime, checksums", "Changes in folders holding ePHI, outside change windows"],
 ["Command output (outbound_tcp)", "local_ip:port -&gt; remote_ip:port", "Connections to addresses that are not the hospital or its suppliers"],
 ["Keycloak / EHR (JSON)", "type, error, username, ip, client / role, patient_id, action", "Role and action mismatch (billing opening charts), volume, source IP"]], ["18%", "45%", None])}
<p><b>Interpretation methodology:</b> (1) identify the source and its schema; (2) normalise time to UTC and the user to the IAM username; (3) compare with the baseline (section 3.5);
(4) group by user, host and source IP; (5) look for sequence (fail &rarr; success &rarr; access &rarr; transfer); (6) confirm across a second source before escalating.</p>
<h3 class="pb">2.2 Annotated log excerpts (real events from this lab)</h3>
<pre>{f5760}</pre><div class="ann">&#9312; Linux sshd: a wrong password for <b>tjones</b> from 172.21.0.7 (the jumpbox). One line means nothing; eight in a few seconds is guessing (rule 5763).</div>
<pre>{f40112}</pre><div class="ann">&#9313; Same user, same source, <b>Accepted</b>: Wazuh rule 40112 joins the earlier failures to this success: the guess worked.</div>
<pre>{f554}{f553}</pre><div class="ann">&#9314; Real-time FIM in the EHR export folder: a new combined file appears (staging) and an original is deleted (covering tracks, T1070.004).</div>
<pre>{f100630}</pre><div class="ann">&#9315; The 30-second network check: the first line is the agent's own channel to the manager (expected); the second is a connection to <b>203.0.113.77:443</b>, a blocked address &rarr; rule 100630.</div>
<pre>{f100604}</pre><div class="ann">&#9316; Windows 4624, <b>logon_type 10</b> = Remote Desktop, from <b>203.0.113.77</b> (not 10.x): rule 100604. <code>sample: imported-synthetic</code> marks an imported event.</div>
<pre>{f100612}</pre><div class="ann">&#9317; Windows 4663 with access_mask 0x1 (ReadData) on \\\\HRMC-FS01\\EHR_Exports, by <b>rclone.exe</b> from a Temp folder: a sync tool, not a clinician's program.</div>
<pre>{f100651}</pre><div class="ann">&#9318; Windows 5156: rclone.exe connects outbound to 203.0.113.77:443 right after the mass reads &rarr; correlated as likely exfiltration (100651, level 15).</div>
<pre>{f100650}</pre><div class="ann">&#9319; EHR audit: billing user opens a patient chart. On its own this is rule 100521; within 15 minutes of the outside RDP logon it becomes the cross-source alert 100650.</div>
<h3 class="pb">2.3 Correlation between log sources</h3>
{table(["Rule", "Sources joined", "Logic", "Result"], [
 ["<b>100650</b> (level 14)", "Windows Security + EHR application", "EHR access by a billing user (100521) AND an RDP logon from outside (100604) for the same username within 15 min", "Fired 6 times (one per chart opened)"],
 ["<b>100651</b> (level 15)", "Windows file access + Windows network", "Connection to a known-bad address (100621) AND mass EHR export reads (100612) for the same username within 15 min", "Fired; email to Tier 1 + SOC lead"],
 ["40112 (level 12, built-in)", "Linux auth failures + success", "Several authentication failures then a success from the same source", "Fired for tjones"]], ["17%", "22%", "41%", None])}
<p><b>Validation finding:</b> on the first run rule 100650 did not fire. The manager log showed <i>"Signature ID '100521' was not found ... Rule '100650' will be ignored"</i>:
Wazuh loads rule files alphabetically, so <code>sm1_rules.xml</code> loaded before <code>soc1_rules.xml</code> and referred to a rule that did not exist yet. Renaming the file to
<code>zz_sm1_rules.xml</code> fixed the order (enabled rules 7,033 &rarr; 7,034) and the re-run fired 100650. Lesson: every new rule is tested end to end, not just loaded.</p>
{img("../screenshots/SS-04.png", "Screenshot 4: the cross-source alert 100650 expanded: EHR source fields, rule groups sm1/correlation/cross_source, level 14, MITRE T1078 + T1213", 560)}
<h3 class="pb">2.4 Complete incident detection scenario: SM1-SCN-01</h3>
<p><b>Story:</b> an attacker guesses the password of a Linux user and of the billing account <code>test.billing1</code>, logs in to the billing workstation by RDP from outside,
reads 30 EHR export files with rclone.exe, sends them to 203.0.113.77 and opens patient charts in the EHR.</p>
{table(["UTC (2026-11-18)", "Agent", "Source", "Rule (level)", "Detection"], tl, ["11%", "14%", "13%", "11%", None])}
{img("../outputs/scenario_timeline.png", "First alert of each level-10+ rule. 100650 appears at minute 5.6 because it fired in the re-run after the load-order fix (section 2.3).", 300)}
<p><b>Conclusions:</b> (1) the same attacker is visible in four sources within six minutes; (2) every step was detected, the highest alerts (100651 level 15, 100650 level 14)
pointed straight at data exfiltration and patient-record misuse; (3) 30 EHR export files and the charts SYN-PT-30500 to 30515 must be treated as exposed, which starts the HIPAA
breach risk assessment; (4) root causes: password-only RDP from the internet and a billing role able to read clinical data.</p>
<h3 class="pb">2.5 Alert triage process</h3>
{table(["Wazuh level", "Severity", "Triage target", "Escalation criteria"], [
 ["15", "SEV-1 Critical", "Start within 15 min", "Always escalate to the Incident Commander; Privacy Officer if ePHI"],
 ["12-14", "SEV-1 / SEV-2", "Start within 15-60 min", "Escalate if confirmed or if ePHI involved; SOC lead already emailed"],
 ["10-11", "SEV-3", "Start within 8 h", "Escalate if a success follows failures or the source is outside the network"],
 ["7-9", "SEV-4", "Same shift", "Escalate only if part of a sequence"]], ["13%", "17%", "20%", None])}
<p><b>Severity assessment</b> = Impact (data and systems involved) &times; Urgency (still happening?), as in the SOC 1 and IR1 playbooks.</p>
{table(["False-positive check", "Example from this lab", "Decision"], [
 ["Is there an approved change?", "4732 'helpdesk2 added to Administrators' on 11 Nov, ticket CHG-2026-0315", "Benign true positive: documented, closed"],
 ["Is it a test account or test window?", "Keycloak failures for test.vendor1 (44, z = 2.2): the lockout test", "False positive for attack; confirms the lockout control"],
 ["Is the volume an artefact?", "100612 fired twice for one burst (frequency rule re-arming)", "Duplicate: one case, not two"],
 ["Does a second source agree?", "RDP from 203.0.113.77 + EHR access by the same user", "True positive: escalate"]], ["24%", "46%", None])}
""")

# ----------------------------------------------------------------- 3
hc_rows = [l.strip("|").split("|") for l in hc_md if l.startswith("| ") and not l.startswith("| Area")]
P.append(f"""<h2 class="pb">3. Monitoring Implementation</h2>
<h3>3.1 Monitoring architecture and data flows</h3>
{img("../diagrams/sm1_architecture.png", "Source: diagrams/sm1_architecture.mmd")}
<h3>3.2 Data sources integrated, with evidence of collection</h3>
{table(["Data source", "Integration", "Evidence"], [
 ["Linux server (live agent)", "Agent enrollment to wazuh.manager:1515, events on 1514/tcp", "Agent 001 Active; alerts 5760, 5763, 40112, 553, 554, 100630"],
 ["Windows Security (imported samples)", "JSON file + localfile log_format json", f"{hist_n} baseline events + scenario; rules 100600-100651 fire"],
 ["Keycloak sign-in events", "JSON file (capstone export)", "data.src keycloak_login alerts"],
 ["EHR access audit", "JSON file (capstone export)", "data.src ehr_access alerts, 100521 / 100650"],
 ["Keycloak admin events", "JSON file (capstone export)", "data.src keycloak_admin alerts (SOC 1)"]], ["24%", "36%", None])}
<h3 class="pb">3.3 Integration steps</h3>
<ol>
<li>Start the Wazuh single-node stack (official wazuh-docker v4.9.2): generate TLS certificates, <code>docker compose up -d</code>.</li>
<li>Add rule files by mounting them under <code>/wazuh-config-mount/etc/rules/</code> (soc1_rules.xml, zz_sm1_rules.xml) and log sources as <code>&lt;localfile&gt;</code> entries in ossec.conf.</li>
<li>Configure email: <code>email_notification yes</code>, <code>smtp_server mailhog</code>, <code>email_alert_level 10</code>, plus an <code>email_alerts</code> block for level 12 to the SOC lead.</li>
<li>Build the Linux agent image (<code>lab/Dockerfile.linux-agent</code>): Wazuh apt repository, <code>WAZUH_MANAGER=wazuh.manager apt-get install wazuh-agent=4.9.2-1</code>, extra config for auth.log, FIM and outbound TCP.</li>
<li>Run it on the same Docker network; it enrolls automatically (authd, no password in the lab) and appears as agent 001.</li>
<li>Import Windows samples with <code>scenario/windows_events.py history</code>; test each rule with <code>wazuh-logtest</code> before relying on it.</li>
<li>Import the dashboard (<code>lab/build_dashboard.py</code>, saved-objects API) and schedule <code>lab/health_check.py</code>.</li></ol>
<h3>3.4 Configuration files</h3>
{table(["File", "Purpose"], [["<code>wazuh_config/zz_sm1_rules.xml</code> (repo: sm1_rules.xml)", "15 Security Monitoring rules"], ["<code>lab/agent_ossec_extra.conf</code>", "Agent: auth.log, FIM, outbound_tcp command, no auto-restart"],
 ["<code>lab/Dockerfile.linux-agent</code>, <code>lab/entrypoint.sh</code>", "Linux server image with the agent"], ["<code>wazuh_config/hrmc_security_dashboard.ndjson</code>", "Dashboard saved objects"],
 ["SOC 1: <code>wazuh_config/ossec_soc1_excerpt.conf</code>, <code>soc1_rules.xml</code>", "Email settings, log sources, application rules"]], ["45%", None])}
<h3 class="pb">3.5 Performance baselines and alert thresholds</h3>
{table(["Metric", "Basis", "Mean", "Std dev", "P95", "Max", "Alert threshold"], [[e(b[k]) for k in ("metric", "basis", "mean", "std_dev", "p95", "max", "alert_threshold")] for b in base], ["24%", "18%", "8%", "8%", "10%", "7%", None])}
<p>Thresholds are set above normal: at least mean + 3 standard deviations and above the highest value seen in the normal week, rounded to a number the rule can use.
The scenario was far beyond them (7 failures in 18 s, 30 reads in 30 s), while the normal week stayed below every threshold (0 high alerts).
<b>Processing baseline:</b> {m['operational']['events_dropped']} events dropped, analysisd queues at 0%, median {m['operational']['mttd_seconds_median']} s (max {m['operational']['mttd_seconds_max']} s) from event to alert.</p>
{img("../outputs/trend_week.png", "Left: the normal week used for the baseline. Right: alerts by level on the scenario day.", 280)}
<h3 class="pb">3.6 Health monitoring</h3>
<p><code>lab/health_check.py</code> runs every 15 minutes (cron / launchd) and checks <b>collection status</b> (agents, services, log files, last alert per source),
<b>processing performance</b> (events decoded and dropped, queue usage, remoted discards) and <b>storage utilization</b> (index health and size, indexer disk, host disk, manager queue folder).
Exit code 0 = OK, 1 = warning, 2 = critical; results go to <code>outputs/health_check_*.json</code>.</p>
{table(["Area", "Check", "Value", "Status", "Threshold"], [[e(c.strip()) for c in r] for r in hc_rows], ["11%", "30%", "24%", "9%", None])}
<p><b>Health-check procedure:</b> OK &rarr; nothing; WARNING &rarr; Tier 1 checks within the shift (the two warnings above are explained: the Keycloak admin source only replays on demand; the Mac has 9% disk free);
CRITICAL &rarr; SOC lead paged, monitoring gap recorded as an incident.</p>
<div class="ok"><b>Real health findings during this project.</b>
(1) The first health-check run returned <b>CRITICAL: agent hrmc-linux-srv01 Disconnected</b> ({hc_first['run_utc']}). Cause: the manager restart pushed shared configuration,
the agent restarted itself, and nothing in the container started it again. Fix: agent restarted and <code>auto_restart</code> disabled; next run OK.
(2) Earlier the host disk fell below 1 GB: Wazuh's vulnerability detector had downloaded 18.6 GB of feeds. It was disabled, the cache removed and the space returned;
the host-disk and manager-queue checks were added so this is caught early next time.</div>
""")

# ----------------------------------------------------------------- 4
P.append(f"""<h2 class="pb">4. Security Reporting</h2>
<h3>4.1 Standardized alert documentation (3 alert types)</h3>
{table(["Field", "100604 Remote RDP logon from outside", "100612 / 100651 Mass EHR export reads &rarr; exfiltration", "100630 Linux connection to a known-bad address"], [
 ["Level / severity", "10 / SEV-3 (SEV-1 if followed by data access)", "12 / 15 &rarr; SEV-1", "12 &rarr; SEV-2"],
 ["Source", "Windows Security 4624", "Windows 4663 + 5156", "Linux agent, outbound_tcp command"],
 ["MITRE ATT&amp;CK", "T1021.001, T1078", "T1005, T1039, T1041", "T1041"],
 ["Trigger logic", "logon_type 10 and ip not 10.x / 127.x", "20+ reads on EHR_Exports in 60 s by one user; then connection to 203.0.113.0/24", "remote address in 203.0.113.0/24 in the 30 s connection list"],
 ["Triage steps", "Is the user expected to work remotely? VPN record? Failures before it?", "Which files, which process, where did data go?", "Which process holds the socket (ss -tnp)? Who is logged in?"],
 ["False positives", "Approved remote support through a jump host", "Approved bulk export job (scheduled task, change ticket)", "Monitoring or update servers mis-listed"],
 ["Escalation", "To Tier 2 if from outside AND followed by access", "Incident Commander + Privacy Officer immediately", "Tier 2; isolate host if confirmed"],
 ["Response", "Disable account, revoke sessions, block IP", "Disable account, block IP, preserve file-server logs, start HIPAA assessment", "Block egress, isolate container/host, collect volatile data"],
 ["Example in this lab", "HRMC\\test.billing1 from 203.0.113.77 (19:17:27 UTC)", "30 reads by rclone.exe, then 203.0.113.77:443 (19:18:13)", "172.21.0.6:53766 -&gt; 203.0.113.77:443 (19:16:56)"]], ["14%", "29%", "29%", None])}
<h3 class="pb">4.2 Security metrics</h3>
{table(["Category", "Metric", "Value", "How it is measured"], [
 ["Operational", "Events dropped", str(m['operational']['events_dropped']), "analysisd state file"],
 ["Operational", "Mean time to detect (event &rarr; alert)", f"median {m['operational']['mttd_seconds_median']} s, max {m['operational']['mttd_seconds_max']} s", "alert timestamp minus event_time, scenario events"],
 ["Operational", "Alert volume (scenario day)", f"{m['operational']['scenario_alerts_total']} total, {m['operational']['scenario_alerts_level10plus']} at level 10+", "indexer query from scenario start"],
 ["Operational", "Notifications sent", f"{m['operational']['notification_emails_sent']}", "MailHog inbox export"],
 ["Coverage", "Log sources", e(m['coverage']['log_sources_reporting']), "configured localfiles + agents vs. alerts per data.src"],
 ["Coverage", "Scenario types", e(m['coverage']['scenario_types_covered']), "rules per scenario (section 1.4)"],
 ["Coverage", "ATT&amp;CK techniques with a detection", f"{len(m['coverage']['attack_techniques_with_rules'])}: {', '.join(m['coverage']['attack_techniques_with_rules'])}", "rule.mitre.id on alerts that fired"],
 ["Coverage", "Servers with an agent", e(m['coverage']['linux_servers_with_agent']), "agent_control"],
 ["Effectiveness", "Detection rate", f"{m['effectiveness']['steps_detected']}/{m['effectiveness']['scenario_steps']} = {m['effectiveness']['detection_rate_pct']}%", "attack steps with at least one alert"],
 ["Effectiveness", "False positives at level 10+ in the normal week", f"{m['effectiveness']['normal_week_high_alerts']} ({m['effectiveness']['false_positive_rate_high_alerts_pct']}%)", "high alerts with data.src windows_security before the scenario"],
 ["Effectiveness", "Rule defects found by testing", "1 (100650 load order), fixed", "manager log + re-run"]], ["13%", "27%", "28%", None])}
<h3 class="pb">4.3 Security summary report (18 November 2026)</h3>
<p><b>Overview.</b> Monitoring covered 1 live Linux server, 6 Windows workstations and a file server (imported samples), Keycloak and the EHR. A normal 7-day week was quiet
(no high alerts). On 18 November the attack scenario produced {m['operational']['scenario_alerts_total']} alerts in about 6 minutes, {m['operational']['scenario_alerts_level10plus']} of them high or critical.</p>
<p><b>Alert trend.</b> Windows activity in the normal week followed working days (file reads 34-59 a day, failed logons 0-5 a day) and fell at the weekend; the scenario day spike is
entirely the attack (see the trend chart in 3.5 and the dashboard below).</p>
<p><b>Significant findings.</b></p>
<ol><li><b>Critical:</b> likely exfiltration of 30 EHR export files by rclone.exe to 203.0.113.77 (100651).</li>
<li><b>Critical:</b> billing account used from outside the network to open patient charts (100650): HIPAA breach risk assessment required.</li>
<li><b>High:</b> SSH password guessing succeeded on hrmc-linux-srv01 (40112), followed by staging and deletion in /srv/ehr_exports.</li>
<li><b>Operational:</b> one agent outage and one storage incident in the monitoring platform itself, both fixed (section 3.6).</li></ol>
<p><b>Recommendations.</b> (1) Block RDP from the internet; require VPN + MFA for remote access. (2) Remove clinical-data access from the billing role (least privilege, capstone RBAC).
(3) Use SSH keys and fail2ban-style lockout on Linux servers. (4) Allow-list outbound connections from servers and workstations; alert on sync tools like rclone.
(5) Deploy real Windows agents when hosts are available, to replace the imported samples. (6) Keep the health check scheduled and review the dashboard each shift.</p>
<h3>4.4 Real-time dashboard</h3>
{img("../screenshots/SS-01.png", "Screenshot 1: custom dashboard 'HRMC Security Monitoring' (auto-refresh every 30 s): totals, high alerts, alerts by source and agent, alerts over time by level, top rules, users with high alerts, MITRE techniques", 640)}
{img("../screenshots/SS-03.png", "Screenshot 3: Threat Hunting, rule.groups:sm1 and rule.level >= 10: 18 hits, from cross-source 100650 down to the password guessing 100602", 600)}
<h2 class="pb">Files in this submission</h2>
{table(["Path (security_monitoring_1/)", "Content"], [
 ["wazuh_config/sm1_rules.xml", "Rules 100600-100651 (loaded as zz_sm1_rules.xml)"], ["wazuh_config/hrmc_security_dashboard.ndjson", "Dashboard saved objects"],
 ["lab/Dockerfile.linux-agent, agent_ossec_extra.conf, entrypoint.sh", "Live Linux agent server"], ["lab/health_check.py", "Health monitoring"], ["lab/build_dashboard.py", "Dashboard import"],
 ["scenario/windows_events.py, run_scenario.sh", "Windows samples (baseline + attack) and the full scenario"], ["analysis/sm1_analysis.py", "Baselines, metrics, charts"],
 ["evidence/", "Scenario alerts (JSON), Windows baseline sample, network config, mail and analysisd exports"], ["outputs/", "Baselines, metrics, health checks, charts"],
 ["screenshots/", "6 dashboard and mailbox screenshots"], ["diagrams/sm1_architecture.mmd", "Architecture (Mermaid)"]], ["45%", None])}
""")

CSS = """body{font-family:"DejaVu Sans",Arial,sans-serif;color:#1F2D33;font-size:10pt;line-height:1.42;margin:0}
h1{font-family:"DejaVu Serif",Georgia,serif;color:#16324F;font-size:22pt;margin:0 0 4px}
h2{font-family:"DejaVu Serif",Georgia,serif;color:#16324F;font-size:15pt;margin:20px 0 8px;border-bottom:2px solid #C8553D;padding-bottom:3px}
h3{color:#2B6F8E;font-size:11.5pt;margin:14px 0 5px}
.meta{color:#5B6B70;font-size:9.5pt;margin-bottom:10px}
table{border-collapse:collapse;width:100%;margin:5px 0 10px}tr{page-break-inside:avoid}
th,td{border:1px solid #D3DEE6;padding:4px 6px;vertical-align:top;text-align:left;font-size:8.8pt}th{background:#E6EFF5;color:#16324F}
code,pre{font-family:"DejaVu Sans Mono",monospace;font-size:8pt}pre{background:#F4F6F8;border:1px solid #DDE3E8;padding:6px 8px;white-space:pre-wrap;word-break:break-all;margin:6px 0 2px;page-break-inside:avoid}
.ann{font-size:9pt;color:#2B4B5E;margin:0 0 8px 6px}
.note{background:#FBF1E6;border-left:4px solid #C8553D;padding:7px 10px;font-size:9.5pt;margin:8px 0}
.ok{background:#EAF5EE;border-left:4px solid #2E8B57;padding:7px 10px;font-size:9.5pt;margin:8px 0}
.fig{text-align:center;margin:6px 0 10px;page-break-inside:avoid}.fig img{max-width:100%;border:1px solid #ddd}.cap{color:#5B6B70;font-size:8.5pt;text-align:center}
.pb{page-break-before:always} ul,ol{margin:4px 0 6px 20px;padding:0} li{margin:2px 0}"""
open(R / "build/sm1.html", "w").write(f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{''.join(P)}</body></html>")
print("ok")
