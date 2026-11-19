"""Builds cybersecurity_basics_2/build/cb2.html (combined), then split per criterion with compliance_2/build/split_criteria.py."""
import csv, json, html, pathlib, re
R = pathlib.Path(__file__).resolve().parents[1]
REPO = R.parent
e = html.escape


def table(head, rows, widths=None):
    h = "".join(f'<th{f" style=width:{w}" if widths and w else ""}>{x}</th>' for x, w in zip(head, widths or [None] * len(head)))
    return "<table><tr>" + h + "</tr>" + "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows) + "</table>"


def img(f, cap, h=None):
    return f'<div class="fig"><img src="{f}"{f" style=max-height:{h}px" if h else ""}><div class="cap">{cap}</div></div>'


def md(path):
    """very small Markdown -> HTML for the knowledge-base documents (headings, tables, lists, code, bold)"""
    out, lines, i = [], open(path).read().splitlines(), 0
    inl = lambda s: re.sub(r"`([^`]+)`", r"<code>\1</code>", re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", e(s)))
    while i < len(lines):
        l = lines[i]
        if l.strip().startswith("```"):
            j = i + 1; buf = []
            while not lines[j].strip().startswith("```"): buf.append(lines[j].strip()); j += 1
            out.append("<pre>" + e("\n".join(buf)) + "</pre>"); i = j + 1; continue
        if l.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                if not re.match(r"^\|[-| :]+\|$", lines[i]): rows.append([inl(c.strip()) for c in lines[i].strip("|").split("|")])
                i += 1
            out.append(table(rows[0], rows[1:])); continue
        if l.startswith("# "): out.append(f"<h4 class='doc'>{inl(l[2:])}</h4>")
        elif l.startswith("## "): out.append(f"<h5>{inl(l[3:])}</h5>")
        elif re.match(r"^(\d+\.|-)\s", l):
            tag = "ol" if re.match(r"^\d+\.", l) else "ul"; items = []
            start = int(l.split(".")[0]) if tag == "ol" else 1
            while i < len(lines) and (re.match(r"^(\d+\.|-)\s", lines[i]) or re.match(r"^\s{2,}-\s", lines[i])):
                if re.match(r"^\s{2,}-\s", lines[i]):
                    items[-1] += "<br>&bull; " + inl(re.sub(r"^\s*-\s", "", lines[i]))
                else:
                    items.append(inl(re.sub(r"^(\d+\.|-)\s", "", lines[i])))
                while i + 1 < len(lines) and lines[i + 1].startswith("   ") and not re.match(r"^\s*(\d+\.|-)\s", lines[i + 1]) and not lines[i + 1].strip().startswith("```"):
                    i += 1; items[-1] += " " + inl(lines[i].strip())
                i += 1
            out.append(f"<{tag} start='{start}'>" + "".join(f"<li>{x}</li>" for x in items) + f"</{tag}>"); continue
        elif l.strip(): out.append(f"<p>{inl(l)}</p>")
        i += 1
    return "".join(out)


tr = open(R / "evidence/remediation_transcript.txt").read()
cases = {c: open(R / f"case_management/{c}_record.md").read() for c in ("CB2-2026-001", "CB2-2026-002")}
cust = list(csv.DictReader(open(R / "evidence/cb2_custody_log.csv")))
ir_cust = list(csv.DictReader(open(REPO / "incident_response_1/task4_evidence_management/evidence/coc/custody_log.csv")))
ir_reg = list(csv.DictReader(open(REPO / "incident_response_1/task4_evidence_management/evidence/coc/evidence_register.csv")))
la = json.load(open(R / "evidence/cb2_linux_alerts.json"))

P = [f"""<h1>Cybersecurity Basics 2: Project Submission</h1>
<div class="meta">Akhila Chennamaneni &middot; DAE 6-Month Cybersecurity Cohort 2 &middot; November 2026<br>
Organization: HealthLine Regional Medical Center (HRMC), the Care Access Navigator capstone hospital. Lab: Microsoft Entra ID + Keycloak (capstone), Wazuh 4.9.2 with a live Linux agent, IR1 forensic lab. Cost: $0.</div>
<div class="note"><b>How this course fits the capstone.</b> Every criterion is shown on the same hospital, accounts, roles, risks and tools as the Care Access Navigator
project, reusing evidence from earlier courses where it already exists and adding new, real work where the rubric asks for it: two incidents on the live Linux
server were investigated and <b>resolved on 2026-11-19</b> (cases CB2-2026-001 and CB2-2026-002), and a security policy, procedure, guide, two playbooks and a knowledge base were written.</div>
<h3>Rubric map</h3>
{table(["Rubric criterion", "Section", "Main evidence"], [
 ["Implement and Explain Advanced Cybersecurity Defense Strategies", "1", "Zero Trust across 4 layers (tests), defense in depth (7 layers), supply-chain case (172 &rarr; 0 vulnerabilities), Clark-Wilson model applied"],
 ["Implement Incident Response and Handling", "2", "5-step IRP, Volatility 3 + dc3dd, chain of custody (IR1 13 items; CB2 3 items), 3 incident types triaged, post-incident lessons"],
 ["Demonstrate SOC Fundamentals", "3", "4 SOC roles, Wazuh with a live agent (2 network activity types), 2 alerts generated &rarr; investigated &rarr; resolved, threat analysis"],
 ["Develop and Implement Security Policies and Governance", "4", "POL-SEC-01 (access control, data protection, system use), RACI, NIST CSF / ISO 27001 / HIPAA references, banner + enforcement evidence"],
 ["Produce Effective Security Documentation", "5", "PROC-SEC-03, GUIDE-SEC-01, playbooks PB-01 / PB-02, knowledge base with 7 categories"]], ["30%", "8%", None])}
"""]

# ---------------------------------------------------------------- 1
P.append(f"""<h2 class="pb">1. Advanced Cybersecurity Defense Strategies</h2>
<h3>1.1 Zero Trust Architecture: access enforced at every layer</h3>
<p>Zero Trust means <i>never trust, always verify</i>: no user, device or network location is trusted by default, every request is checked against identity,
role and context, and access is the minimum needed. In the capstone, a request has to pass <b>four layers</b>, each able to stop it on its own:</p>
{img("../diagrams/zero_trust.png", "Source: diagrams/zero_trust.mmd")}
{table(["Layer", "Control (Care Access Navigator)", "Evidence that it is enforced"], [
 ["1. Identity provider (Entra ID)", "Assignment required on the Keycloak broker app; MFA via Security defaults; app roles carry the job role", "Control test AC-01 #3 'Entra assignment required' PASS (audit CAN-IA-2026-01); EV-17 Security defaults; leaver Jeevan Smith refused at Microsoft sign-in"],
 ["2. Identity broker (Keycloak)", "Role mapped from Entra with sync FORCE; MFA for privileged and payment roles; lockout after 10 failures", "Screenshot CB2-03: billing user <b>MFA_REQUIRED</b>; test.vendor1 locked after 10 failures; CAN-ID-001 brute-force alert"],
 ["3. Application gate", "Each app admits only approved roles (EHR: clinician, nurse; Billing: billing)", "Screenshot CB2-02: clinician <b>LOGGED_IN</b> to the EHR but <b>DENIED</b> on billing-app"],
 ["4. Continuous verification", "Wazuh correlates sign-ins, record access and connections; a session is not trusted just because it started", "SOC 1 and Security Monitoring 1: cross-source rule 100650, account-compromise rule 100507"],
 ["Host (servers)", "SSH keys only, MaxAuthTries 3, system-use banner (added 2026-11-19)", "Password login refused: 'Permission denied (publickey)' (section 3.3)"]], ["18%", "38%", None])}
<div class="fig2">{img("../screenshots/CB2-02_app_gate_denied.png", "CB2-02: application gate (can_iam.py verify, live run 2026-11-17)", 300)}{img("../screenshots/CB2-03_mfa_lockout_alert.png", "CB2-03: MFA and lockout enforced, brute-force alert raised (same run)", 300)}</div>
<h3 class="pb">1.2 Defense in depth</h3>
<p>Defense in depth layers different controls so that one failure is caught by the next. HRMC uses seven layers; at least three of them stopped or exposed each attack in the labs:</p>
{img("../diagrams/defense_in_depth.png", "Source: diagrams/defense_in_depth.mmd", 820)}
{table(["Attack (lab)", "Layers that acted"], [
 ["Leaver Jeevan Smith tried to sign in (capstone JML)", "Identity (Entra disabled) &rarr; identity broker (Keycloak copy disabled, after the 12-minute gap) &rarr; monitoring (CAN-ID-002)"],
 ["SSH password guessing on hrmc-linux-srv01 (CB2-2026-001)", "Monitoring (5763, 40112) &rarr; host (keys only, account locked) &rarr; policy (banner, PB-01)"],
 ["Billing account reading EHR exports and sending them out (SM1-SCN-01)", "Application (billing not approved for clinical data, 100521) &rarr; data (FIM / object-access logging) &rarr; monitoring (100651 level 15)"]], ["40%", None])}
<h3>1.3 Supply-chain security: one risk identified and mitigated</h3>
{table(["", "Before (baseline image)", "After (hardened image)"], [
 ["Base image", "python:3.12-slim (general-purpose, unpinned tag)", "Chainguard Python, <b>pinned by sha256 digest</b>, multi-stage build"],
 ["Known vulnerabilities (Trivy, 2026-10-06)", "<b>172</b>: 44 High, 63 Medium, 63 Low, 2 Unknown", "<b>0</b>"],
 ["Software bill of materials", "none", "CycloneDX SBOM, 39 components (<code>reports/hardened/sbom.cdx.json</code>)"],
 ["Runtime", "root, writable, shell + pip present", "UID 65532, read-only filesystem, all capabilities dropped, no-new-privileges, no shell, no pip"]], ["22%", "36%", None])}
<p><b>Risk:</b> third-party code inherited through the container base image (and through any later tag change upstream). <b>Mitigation:</b> minimal base, digest pinning
(the build cannot silently change), vulnerability scanning in the build, SBOM for future CVE look-ups, and a locked-down runtime. Source: Cloud Security 1, Criterion 3
(<code>cloud_security_1/can-ehr-container/</code>). The pinned base image is kept locally so the build stays reproducible.</p>
<h3 class="pb">1.4 Advanced security model: Clark-Wilson applied to Care Access Navigator</h3>
<p>Healthcare needs <b>integrity</b> as much as confidentiality: a wrong role or a changed record harms patients. <b>Bell-LaPadula</b> (no read up, no write down) protects
confidentiality with security levels; HRMC uses its idea only for data classification labels (Restricted, Confidential, Internal, Public). <b>Clark-Wilson</b> protects integrity
through well-formed transactions and separation of duties, which is exactly how access is managed in the capstone:</p>
{table(["Clark-Wilson element", "Care Access Navigator implementation"], [
 ["CDIs (constrained data items)", "Access entitlements (Keycloak role mappings and groups), EHR patient records, billing records"],
 ["UDIs (unconstrained data items)", "Access requests from managers, raw log data, imported files"],
 ["TPs (transformation procedures)", "<code>can_iam.py</code> joiner / mover / leaver (the only way entitlements change, with a ticket); EHR application functions behind the role gate"],
 ["IVPs (integrity verification procedures)", "Quarterly access review AR-2026-Q4 (16/16 accounts signed), <code>can_iam.py verify</code>, end-to-end tests TC-01 to TC-10, FIM hash checks"],
 ["Certification rule: separation of duties", "Approver (the department manager) &ne; implementer (IAM analyst), both recorded per ticket in JML-LOG.csv; SoD rules in CAN_DOC_RBAC_SoD_Access_Request_v1.0"],
 ["Certification rule: TPs log what they do", "Append-only <code>can_iam_audit_log.jsonl</code>, hashed into the evidence index"],
 ["Enforcement rule: only TPs change CDIs", "Users cannot change their own roles; Keycloak admin is restricted (EX-03 / EX-04 govern the gaps)"],
 ["Enforcement rule: users are authenticated", "Entra MFA (Security defaults) and Keycloak OTP for privileged roles"],
 ["Enforcement rule: user &rarr; TP &rarr; CDI triples", "Role &rarr; application client &rarr; data: a clinician reaches EHR records only through the EHR app; billing cannot (CB2-02)"]], ["30%", None])}
<p><b>Result:</b> the leaver gap found in the capstone (Keycloak copy still enabled 12 minutes after the Entra disable) was exactly a Clark-Wilson IVP failure caught by verification,
and is tracked as finding CAN-FIND-001 until automatic deprovisioning is built.</p>
""")

# ---------------------------------------------------------------- 2
e01 = next(r for r in ir_reg if r["item"] == "E01")
P.append(f"""<h2 class="pb">2. Incident Response and Handling</h2>
<h3>2.1 Incident Response Plan: five-step framework</h3>
{table(["Step", "What HRMC does", "Where it is defined / proven"], [
 ["1. Preparation", "Playbooks, tracker, Wazuh rules and email routing, evidence store, roles (IC, Privacy Officer), training", "IR1 playbook CAN-IR-PB-02; PB-01 / PB-02 (section 5); SOC 1 rules; irtrack.py"],
 ["2. Identification", "Alert triage, validation, severity = Impact &times; Urgency, open a case", "IR1 Task 2 (3 incidents); SOC 1 and SM1 scenarios; cases CB2-2026-001/002"],
 ["3. Containment", "Short-term (lock account, block IP, isolate host) then long-term; preserve evidence first", "IR1 Task 3 (VM isolated to quarantine network); CB2: account locked, staged file preserved"],
 ["4. Eradication", "Remove the cause and persistence; fix the weakness", "IR1 Task 6 (keys removed, sudo cleaned); CB2: SSH keys-only, staged file removed"],
 ["5. Recovery", "Restore known-good state, validate, monitor closely", "IR1 Task 6: validation 34/34 + 6/6 network probes; CB2: hash of restored file matches known-good"]], ["16%", "40%", None])}
<p>Post-incident review closes every case (section 2.5). Full plan: <code>incident_response_1/task5_ir_documentation/playbook/CAN-IR-PB-02_Host_Incident_Response_Playbook.md</code>.</p>
<h3>2.2 Digital forensics: tools used for data collection</h3>
{table(["Tool", "Used for", "Result (IR1-2026-002)"], [
 ["<b>Volatility 3</b>", "Memory analysis of the RAM image (E01: {e(e01['description'])})", "Found the uploader process (PID 1534) with its SSH session origin, a SYN_SENT socket to the drop site and the patient record in its heap; no rootkit indicators"],
 ["<b>dc3dd</b>", "Forensic disk image from a read-only source, hashing while copying", "Image hash equal to source hash; Sleuth Kit recovered the planted files byte-identical"],
 ["tshark / tcpdump", "Packet capture at host and hypervisor", "Captures of the upload traffic to the drop site (E03, E04 in the register)"],
 ["sha256sum (CB2)", "Hashing the staged file before removal", "Host and case copies match (section 2.3)"]], ["16%", "34%", None])}
<h3 class="pb">2.3 Evidence collection with chain of custody</h3>
<p><b>IR1-2026-002</b> (Incident Response 1, Task 4): {len(ir_reg)} evidence items of different forms (RAM image, process core, packet captures, disk image, logs), {len(ir_cust)} custody events, each with a hash check.</p>
{table(["Item", "Time (UTC)", "Event", "By", "Hash check"], [[r["item"], r["utc"], e(r["event"]), e(r["by"]), e(r["hash_check"])] for r in ir_cust[:6]], ["7%", "20%", "22%", "29%", None])}
<p><b>CB2 cases</b> (this course, 2026-11-19): three items in three forms (log transcript, file, alert export).</p>
{table(["Item", "Case", "Description", "SHA-256", "Integrity"], [[r["item"], r["case"], e(r["description"]), f"<code>{r['sha256'][:16]}&hellip;</code>", e(r["integrity"])] for r in cust], ["6%", "14%", "40%", "18%", None])}
<p>Custody log: <code>cybersecurity_basics_2/evidence/cb2_custody_log.csv</code>. Evidence is copied before anything is removed, hashed at acquisition and re-hashed when moved; the tracker stores the hash of E01 and it still matches.</p>
<h3>2.4 Incident triage and prioritization: three incident types</h3>
{table(["Incident (IR1)", "Type", "Impact", "Urgency", "Severity", "Business impact"], [
 ["IR1-2026-002", "Unauthorized ePHI access by a mover (old clinical group kept), record sent off the host", "3", "3", "<b>SEV-1</b> (9)", "HIPAA breach risk assessment, patient notification possible, regulator reporting"],
 ["IR1-2026-003", "Unapproved privilege: a joiner given sudo without a change record, used root", "3", "2", "<b>SEV-2</b> (6)", "System integrity in doubt; audit finding; possible persistence"],
 ["IR1-2026-001", "Leaver login attempts (blocked, but SSH key still on the host)", "2", "2", "<b>SEV-3</b> (4)", "No access gained; control weakness to fix"]], ["13%", "30%", "7%", "8%", "10%", None])}
<p>Severity = Impact &times; Urgency (each 1-3), NIST SP 800-61 prioritization factors; SEV-1 start within 15 min, SEV-2 60 min, SEV-3 8 h. Today's CB2 cases were rated SEV-2 (server access gained, no ePHI confirmed read).</p>
<h3 class="pb">2.5 Post-incident analysis</h3>
{table(["Case", "Outcome", "Lessons learned"], [
 ["IR1-2026-002 (SEV-1)", "Contained by isolating the VM; recovered from the baseline snapshot; validation 34/34 checks and 6/6 network probes, before and after reboot", "1. A mover's old groups must be removed before new access is added (JML control fixed by recover_harden.sh). 2. Leavers need their SSH keys removed, not only their account disabled."],
 ["CB2-2026-001 (SEV-2)", "Closed: account locked, SSH keys only, re-test refused the password; response 5.9 min (target 60)", "3. Password-only SSH is guessed within seconds: keys only on all servers (PROC-SEC-03). 4. Containment waited 21 h because the compromise was kept for the Security Monitoring 1 evidence; in production containment must start within the SLA."],
 ["CB2-2026-002 (SEV-2)", "Closed: staged copy preserved and removed, deleted export restored, hash matches known-good", "5. Egress allow-lists on servers would have blocked the outbound connection (100630). 6. Keep FIM on every ePHI folder: it was the only record of the staging."]], ["18%", "36%", None])}
""")

# ---------------------------------------------------------------- 3
P.append(f"""<h2 class="pb">3. SOC Fundamentals</h2>
<h3>3.1 SOC functions and roles</h3>
{table(["Role", "Responsibilities", "In the HRMC labs"], [
 ["Tier 1 SOC analyst", "Watch the dashboard and alert email, triage, open cases, escalate by severity", "Triaged SOC1-2026-001 in 4.2 min; CB2 cases in under 6 min"],
 ["Tier 2 incident responder", "Investigate, contain, eradicate, recover; collect evidence", "Contained and resolved CB2-2026-001/002; IR1 containment and forensics"],
 ["Tier 3 threat hunter / detection engineer", "Write and tune rules, hunt for undetected threats, test detections", "Wrote SOC 1 and SM1 rules (100500-100651), found and fixed the rule-load-order defect"],
 ["SOC manager / lead", "Escalation point, metrics, reporting, shift handover, staffing", "Receives level 12+ email; shift handover form (SOC 1); metrics (SM1)"]], ["22%", "40%", None])}
<p>Main SOC functions: continuous monitoring, alert triage, incident response, threat intelligence and hunting, detection engineering, reporting and compliance support.
In the lab one person (the author) performed all four roles.</p>
<h3>3.2 Monitoring tool configured and two types of network activity monitored</h3>
<p><b>Tool:</b> Wazuh 4.9.2 with the live agent <code>hrmc-linux-srv01</code> (configured in Security Monitoring 1). Network activity monitored on it:</p>
{table(["Network activity", "How Wazuh sees it", "Real example"], [
 ["<b>Inbound remote logins (SSH, TCP 22)</b>", "auth.log via the agent: every failed and accepted login with source IP and port", "8 failed logins from 172.21.0.7 then 'Accepted password for tjones' (40112); after hardening 'Accepted publickey for sathya' (5715)"],
 ["<b>Outbound TCP connections</b>", "Agent command every 30 s lists established and pending connections; rule 100630 flags known-bad addresses", "172.21.0.6:53766 -&gt; 203.0.113.77:443 (100630, level 12)"],
 ["Windows network connections (imported samples)", "Event 5156 with application and destination; rule 100621", "rclone.exe -&gt; 203.0.113.77:443 (SM1)"]], ["24%", "38%", None])}
{img("../screenshots/CB2-04_wazuh_agent_active.png", "CB2-04: the monitored server: agent 001 hrmc-linux-srv01 active (Wazuh endpoints)", 300)}
<h3 class="pb">3.3 Alert management: two alerts generated, investigated and resolved</h3>
{img("../screenshots/CB2-01_linux_alert_to_resolution.png", "CB2-01: Wazuh Threat Hunting for hrmc-linux-srv01: the attack on 18 Nov (5760 &rarr; 5763 &rarr; 40112, FIM 554 / 553, 100630) and the resolution on 19 Nov (5715 key login, FIM 553 / 554). Times are US Eastern.", 640)}
{table(["", "Alert 1: SSH brute force &rarr; compromise (CB2-2026-001)", "Alert 2: EHR export staging (CB2-2026-002)"], [
 ["Generated", "5763 (L10) 2026-11-18 19:16:26 UTC; 40112 (L12) 19:16:30 UTC; email to Tier 1", "554 (L5) staged file added 19:16:29; 553 (L7) export deleted 19:16:31; 100630 (L12) outbound 19:16:56"],
 ["Investigated", "Same source failed 8 times then succeeded: true positive; SEV-2; triage 19:22:19 (5.9 min)", "Same host and minute as alert 1; staged file = all exports combined; linked case"],
 ["Contained", "2026-11-19 16:32:30: <code>passwd -l tjones</code>, shell nologin", "16:33:10: staged file preserved in /root/ir_evidence, hashed"],
 ["Resolved", "16:32:31: SSH keys only, MaxAuthTries 3, banner; re-test refused the password", "16:33:16: staged file removed, export_1.csv restored; hash = known-good"],
 ["Closed", "16:40 UTC, lessons recorded", "16:40 UTC, lessons recorded"]], ["12%", "44%", None])}
<pre>{e(tr.split("== VERIFY 3")[0].split("== VERIFY 1")[1][:900])}</pre>
<div class="cap">Excerpt of evidence/remediation_transcript.txt: the attacker's password is refused after hardening; the policy banner is shown.</div>
<h3 class="pb">3.4 Threat detection: analysis of one identified threat</h3>
{table(["Analysis step", "Credential guessing against hrmc-linux-srv01"], [
 ["Threat", "Online password guessing (MITRE ATT&amp;CK T1110.001) followed by valid-account use (T1078) and staging / exfiltration (T1074, T1041)"],
 ["Indicators", "Source 172.21.0.7; 8 'Failed password' lines in about 35 s; success from the same source; new file in /srv/ehr_exports; connection to 203.0.113.77:443"],
 ["How it was detected", "Wazuh built-in rules 5760 &rarr; 5763 (frequency) &rarr; 40112 (correlation: failures then success); FIM real-time 554 / 553; custom rule 100630 on the connection list"],
 ["Why it worked", "Password authentication enabled on SSH; weak, guessable password; no egress filtering"],
 ["Impact", "Server access as a normal user; synthetic export files staged; possible transfer (SEV-2)"],
 ["Response", "PB-01 and PB-02; cases closed with evidence (section 3.3)"],
 ["Detection improvement", "Add a rule for any new file in ePHI folders outside a change window (level 10), and raise 100630 to level 13 when it follows 40112 on the same host"]], ["22%", None])}
""")

# ---------------------------------------------------------------- 4
pol = md(R / "kb/policies/POL-SEC-01_Information_Security_Policy.md")
P.append(f"""<h2 class="pb">4. Security Policies and Governance</h2>
<h3>4.1 Policy development framework</h3>
<p>Policies follow a four-level structure: <b>policy</b> (what is required, approved by the board committee) &rarr; <b>standards</b> (measurable settings, e.g. 12-character passwords)
&rarr; <b>procedures</b> (how to implement, e.g. PROC-SEC-03) &rarr; <b>guides</b> (how users comply, e.g. GUIDE-SEC-01). Life cycle: draft by the CISO's team, review by
Privacy, IT, HR and Legal, approval by the Compliance &amp; Privacy Committee, publication and training, annual review, exceptions with expiry. The policy below covers the three required areas.</p>
<div class="policy">{pol}</div>
<h3 class="pb">4.2 Governance, compliance and implementation evidence</h3>
<p>Roles and responsibilities are in policy section 5 (based on the Compliance 1 RACI); compliance references to NIST CSF 2.0, ISO/IEC 27001 and HIPAA are in section 6.
<b>How the policy is communicated and enforced in the systems:</b></p>
{table(["Policy rule", "Communicated by", "Enforced by (evidence)"], [
 ["2.1 Least privilege by role", "Policy, onboarding, access request form", "Keycloak app gate: clinician DENIED on billing-app (CB2-02); quarterly review 16/16 signed"],
 ["2.3 MFA and lockout", "Policy, sign-in prompts", "MFA_REQUIRED for billing; lockout after 10 failures (CB2-03)"],
 ["2.3 / 4.5 Servers: SSH keys only, banner", "<b>Login banner on every SSH login</b> naming POL-SEC-01 section 4", "sshd: PasswordAuthentication no; password login refused (section 3.3)"],
 ["2.4 Leavers removed and verified", "JML procedure, HR process", "Leaver Jeevan Smith disabled in Entra and Keycloak; gap tracked CAN-FIND-001"],
 ["3.4 Integrity of ePHI folders", "Policy, data owner briefing", "Wazuh FIM real-time on /srv/ehr_exports (553 / 554 alerts)"],
 ["3.6 No unapproved transfer tools", "Policy, training", "Wazuh rules 100621 / 100651 flag rclone to a bad address (SM1)"],
 ["4.4 All use logged and monitored", "Banner text", "Wazuh SIEM, dashboard 'HRMC Security Monitoring', email alerts to the SOC"],
 ["7 Exceptions with expiry", "Exception register", "CISO Assistant exceptions EX-01..EX-08; expired ones escalated automatically (Compliance 2)"]], ["24%", "28%", None])}
""")

# ---------------------------------------------------------------- 5
P.append(f"""<h2 class="pb">5. Effective Security Documentation</h2>
<h3>5.1 Procedure for a security control implementation: PROC-SEC-03</h3>
<div class="policy">{md(R / 'kb/procedures/PROC-SEC-03_SSH_Hardening.md')}</div>
<h3 class="pb">5.2 Step-by-step guide for a security task: GUIDE-SEC-01 incident reporting</h3>
<div class="policy">{md(R / 'kb/guides/GUIDE-SEC-01_Reporting_a_Security_Incident.md')}</div>
<h3 class="pb">5.3 Security playbooks: two incident scenarios</h3>
<div class="policy">{md(R / 'kb/playbooks/PB-01_Account_Compromise.md')}</div>
<div class="policy">{md(R / 'kb/playbooks/PB-02_Data_Exfiltration.md')}</div>
<p>A third playbook with six runbooks (CAN-IR-PB-02, Incident Response 1) is in the knowledge base as PB-03.</p>
<h3 class="pb">5.4 Knowledge base: structured repository with categorized resources</h3>
<p>Location: <code>cybersecurity_basics_2/kb/README.md</code> (index) with sub-folders <code>policies/</code>, <code>procedures/</code>, <code>guides/</code>, <code>playbooks/</code>.
Every entry has an ID scheme by category, and every link was checked to point to an existing file in the repository (20 of 20).</p>
<div class="policy">{md(R / 'kb/README.md')}</div>
""")

CSS = """body{font-family:"DejaVu Sans",Arial,sans-serif;color:#1F2D33;font-size:10pt;line-height:1.42;margin:0}
h1{font-family:"DejaVu Serif",Georgia,serif;color:#16324F;font-size:22pt;margin:0 0 4px}
h2{font-family:"DejaVu Serif",Georgia,serif;color:#16324F;font-size:15pt;margin:20px 0 8px;border-bottom:2px solid #C8553D;padding-bottom:3px}
h3{color:#2B6F8E;font-size:11.5pt;margin:14px 0 5px} h4.doc{color:#16324F;font-size:11pt;margin:6px 0 4px} h5{color:#2B6F8E;font-size:10pt;margin:8px 0 3px}
.meta{color:#5B6B70;font-size:9.5pt;margin-bottom:10px}
table{border-collapse:collapse;width:100%;margin:5px 0 10px}tr{page-break-inside:avoid}
th,td{border:1px solid #D3DEE6;padding:4px 6px;vertical-align:top;text-align:left;font-size:8.8pt}th{background:#E6EFF5;color:#16324F}
code,pre{font-family:"DejaVu Sans Mono",monospace;font-size:8pt}pre{background:#F4F6F8;border:1px solid #DDE3E8;padding:6px 8px;white-space:pre-wrap;page-break-inside:avoid}
.note{background:#FBF1E6;border-left:4px solid #C8553D;padding:7px 10px;font-size:9.5pt;margin:8px 0}
.policy{border:1px solid #D3DEE6;border-left:4px solid #2B6F8E;padding:6px 12px;margin:8px 0;background:#FBFCFD}
.policy p,.policy li{font-size:9.3pt}
.fig{text-align:center;margin:6px 0 10px;page-break-inside:avoid}.fig img{max-width:100%;border:1px solid #ddd}.cap{color:#5B6B70;font-size:8.5pt;text-align:center}
.pb{page-break-before:always} ul,ol{margin:4px 0 6px 20px;padding:0} li{margin:2px 0}"""
open(R / "build/cb2.html", "w").write(f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{''.join(P)}</body></html>")
print("ok")
