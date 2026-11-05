"""Build Criterion 6 (Cloud Security Operations & Incident Response) evidence PDF."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "build_pdf.py"), encoding="utf-8").read()
exec(src.split("\ns = []\n")[0])  # shared style helpers

SEC = os.path.join(SHOTS, "can-secops")
EVID = os.path.join(SEC, "evidence")
OUT = os.path.join(SHOTS, "Care_Access_Navigator_CloudSec1_Criterion_6_Security_Operations_Incident_Response.pdf")


def ev(name):
    p = os.path.join(EVID, name)
    return open(p).read() if os.path.exists(p) else ""


def c6_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(inch, 0.55 * inch, "Care Access Navigator — CloudSec1 Criterion 6: Cloud Security "
                                         "Operations & Incident Response")
    canvas.drawRightString(letter[0] - inch, 0.55 * inch, f"Page {doc.page}")
    canvas.setStrokeColor(GREY_LINE)
    canvas.line(inch, 0.7 * inch, letter[0] - inch, 0.7 * inch)
    canvas.restoreState()


bf = ev("10-bruteforce-alert-fired.txt").strip()
bf_ok = bool(bf)

s = []
# ------------------------------------------------------------------ cover
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("CloudSec1 Rubric — Criterion 6: Cloud Security Operations &amp; Incident Response", "subtitle"),
      P("Evidence Package — Centralized Logging, VNet Flow Logs, Automated Alerting, Threat Detection "
        "(Microsoft Defender for Cloud), Security Dashboard and a Tested Incident-Response Playbook", "subsub"),
      Spacer(1, 14)]
s += kv([
    ("Prepared by:", "Akhila Chennamaneni"),
    ("Capstone:", "Care Access Navigator (HealthLine Regional Medical Center)"),
    ("Rubric criterion:", "Criterion 6 — Cloud Security Operations &amp; Incident Response (CloudSec1)"),
    ("Environment:", "Microsoft Azure — Azure subscription 1 (rg-cloudsec1-can); Log Analytics, Azure Monitor, "
                     "Network Watcher, Microsoft Defender for Cloud"),
    ("Evidence dates:", "October 8 and October 12, 2026"),
])
s += [P("Objective", "h1"),
      P("This criterion requires centralized security logging (control-plane and network flow logs) with "
        "automated alerting, threat detection with a GuardDuty-class service, a security dashboard with key "
        "metrics, and an incident-response playbook covering identification, containment, investigation, "
        "eradication and recovery — <b>tested</b>, with evidence. Every capability below was built on CAN's "
        "live Azure environment and exercised with real events.")]
s += [P("Platform equivalents", "h2")]
s += table([
    ["AWS (rubric)", "Azure implementation in CAN"],
    ["CloudTrail", "Azure Activity Log exported to Log Analytics (8 categories)"],
    ["VPC Flow Logs", "VNet flow logs on both VNets + Traffic Analytics (10-minute processing)"],
    ["CloudWatch Logs agent", "Azure Monitor Agent + data collection rule (VM auth/authpriv/kern syslog)"],
    ["CloudWatch alarms / EventBridge + SNS", "Azure Monitor activity-log and log-search alerts → action group "
                                             "(email)"],
    ["GuardDuty", "Microsoft Defender for Cloud: Servers P2, Resource Manager, Storage (malware scanning)"],
    ["CloudWatch dashboard / Security Hub", "Azure Workbook 'CAN Security Operations Dashboard'"],
], [2.2 * inch, 4.3 * inch])
s += note("Defender plans run on their 30-day free trial (ends 2026-11-07) and will be returned to Free before it "
          "ends; Log Analytics has a 0.15 GB/day cap to stay inside the free allowance; flow-log volume is a few MB. "
          "The VM was deallocated whenever it was not needed.", "Cost")

# ------------------------------------------------------------------ results
s += [PageBreak(), P("Results at a Glance", "h1")]
s += table([
    ["Requirement", "Implementation", "Verified result"],
    ["Centralized logging (CloudTrail)", "Activity Log → Log Analytics; VM auth logs via Azure Monitor Agent",
     ok() + " — attacker actions reconstructed with caller + IP"],
    ["Flow logs (VPC Flow Logs)", "VNet flow logs on 2 VNets, 7-day retention, Traffic Analytics",
     ok() + " — incident SSH flows captured; 3 real Internet scanners denied"],
    ["Automated alerting", "7 activity-log alerts + SSH brute-force log alert → email",
     ok() + " — incident alerts fired ≈ 7.5 min after the change" +
     ("; brute-force alert fired" if bf_ok else "")],
    ["Threat detection (GuardDuty)", "Defender for Cloud: Servers P2, Resource Manager, Storage",
     ok() + " — real malware upload detected in ~20 s; 43 sample alerts across 3 plans"],
    ["Security dashboard", "Azure Workbook: KPI tiles, alerts, SSH failures, changes, policy denials, flows",
     ok() + " — deployed; queries validated against live data"],
    ["IR playbook, tested", "NIST 800-61-aligned playbook; live incident INC-20261008-01",
     ok() + " — contained in 11 min 45 s, recovered in 14 min; lessons-learned control verified"],
], [1.75 * inch, 2.55 * inch, 2.2 * inch])

# ------------------------------------------------------------------ Part A logging
s += [P("Part A — Centralized Logging", "h1")]
s += step("A1", "Control-plane audit log (CloudTrail equivalent)")
s += [P("A subscription diagnostic setting streams all eight Activity Log categories (Administrative, Security, "
        "Policy, Alert, Recommendation, ServiceHealth, ResourceHealth, Autoscale) into the Log Analytics workspace, "
        "giving a single, queryable record of every management-plane action with caller identity and source IP. "
        "Retention is 30 days with a daily ingestion cap as a cost guardrail.")]
s += step("A2", "Host security logs")
s += [P("The Azure Monitor Agent was installed on <b>can-vm-hardened</b> with a system-assigned managed identity, "
        "and data collection rule <font name='Courier'>dcr-can-vm-security-syslog</font> forwards the "
        "<i>auth</i>, <i>authpriv</i> and <i>kern</i> syslog facilities to the same workspace — so SSH "
        "authentication attempts and fail2ban bans are searchable centrally, not only on the host.")]
s += step("A3", "VNet flow logs (VPC Flow Logs equivalent)")
s += [P("VNet flow logs (Azure's successor to NSG flow logs) were enabled on both CAN virtual networks, written to "
        "a tagged, TLS 1.2-only storage account in each region, retained 7 days, and processed by <b>Traffic "
        "Analytics</b> every 10 minutes. The raw records below were decoded from the flow-log blobs: they show the "
        "incident's SSH connections (matching the host log to the second) and three unknown Internet hosts whose "
        "SSH probes were <b>denied</b> by the <font name='Courier'>deny-all-inbound</font> rule.")]
flows = ev("07-vnet-flowlog-ssh-records.txt").replace("UserRule_", "").split("\n   summary by")[0]
flows += ("\n   summary: 24.189.77.111 (admin) 10 allowed sessions via allow-ssh-admin-ip; "
          "103.1.92.138, 142.93.136.140, 62.60.130.219 (unknown Internet hosts) denied by deny-all-inbound")
s += code(flows, "evidence/07-vnet-flowlog-ssh-records.txt")
s += note("Enabling Traffic Analytics was first <b>blocked by CAN's own tagging policy</b> (Criterion 5): the service "
          "auto-creates untagged data-collection endpoints. Instead of disabling the policy, a scoped, expiring "
          "<b>policy exemption</b> (Waiver) was created for the platform-managed monitoring resource group only, and "
          "a second (Mitigated) exemption covers Defender-managed VM extensions. Both exemptions are themselves "
          "watched by the <font name='Courier'>al-policy-exemption</font> alert.", "Governance interaction")
s += code(ev("08-monitoring-configuration.txt"), "evidence/08-monitoring-configuration.txt")

# ------------------------------------------------------------------ Part B alerting
s += [P("Part B — Automated Alerting", "h1")]
s += table([
    ["Alert rule", "Fires on", "Why it matters"],
    ["al-nsg-rule-change / -delete", "Any NSG rule write or delete (incl. attempts)", "Firewall backdoors, exposure"],
    ["al-role-assignment", "New RBAC role assignment", "Privilege escalation / persistence"],
    ["al-policy-assignment-del", "Governance policy removed", "Defence evasion"],
    ["al-policy-exemption", "Policy exemption created or changed", "Guardrail bypass"],
    ["al-storage-listkeys", "Storage account keys retrieved", "Credential access to PHI stores"],
    ["al-defender-alert", "Any Defender for Cloud alert", "Threat detection hand-off"],
    ["sqr-ssh-bruteforce", "Total failed/blocked SSH auths > 1 in 30 min (every 15 min)", "Brute force on hosts"],
], [1.85 * inch, 2.55 * inch, 2.1 * inch])
s += [P("All rules notify action group <b>ag-can-secops</b> (email to the subscription owner) using the common "
        "alert schema; Defender for Cloud additionally emails alerts of Medium severity and above.")]
s += optional_shot("Alert_email.png", "alertemail",
                   "Alert delivery — Defender for Cloud email received by the security contact on 2026-10-12 "
                   "(sample Resource Manager alert used to validate the notification path).", max_h=3.6 * inch)
s += step("B1", "Fixing the brute-force alert (found during testing)")
s += [P("On October 8 the brute-force rule did not fire. Testing on October 12 found two defects: (1) the "
        "15-minute window was shorter than the ~4-minute ingestion delay, so events fell between evaluations; and "
        "(2) the condition counted <i>result rows</i>, but the query returns one row per host, so the threshold "
        "&gt; 1 could never be met. The window was widened to 30 minutes (overlapping evaluations) and the condition "
        "changed to <b>total FailedAttempts &gt; 1</b>.")]
s += code(ev("05-bruteforce-retest.txt") + ("\n" + bf if bf_ok else ""), "evidence/05-bruteforce-retest.txt")

# ------------------------------------------------------------------ Part C detection
s += [CondPageBreak(2.5 * inch), P("Part C — Threat Detection (GuardDuty equivalent)", "h1"),
      P("Microsoft Defender for Cloud is Azure's closest equivalent to GuardDuty: <b>Defender for Resource "
        "Manager</b> analyses control-plane operations (as GuardDuty analyses CloudTrail), <b>Defender for "
        "Storage</b> detects malicious uploads and anomalous access (GuardDuty S3/Malware Protection), and "
        "<b>Defender for Servers P2</b> provides host threat detection and vulnerability assessment.")]
s += step("C1", "Real detection — malware uploaded to PHI storage")
s += [P("The industry-standard EICAR antivirus test file was uploaded to the function's storage account. Defender "
        "for Storage's on-upload malware scanning raised a <b>High</b> alert about 20 seconds later, which was "
        "emailed and routed to the <font name='Courier'>al-defender-alert</font> rule.")]
s += code(ev("09-defender-detections.txt"), "evidence/09-defender-detections.txt")
s += optional_shot("Cloud_Security_1:SecOps_Defender_alert.png", "defalert",
                   "Defender for Cloud portal — a <b>sample</b> storage malware alert (DOS/EICAR_Test_File) from the "
                   "pipeline-validation bundle. The <b>real</b> detection on stcanfunc9a8c964b is shown in the "
                   "evidence output above.")

# ------------------------------------------------------------------ Part D dashboard
s += [P("Part D — Security Dashboard", "h1"),
      P("The Azure Workbook <b>CAN Security Operations Dashboard</b> (definition saved in "
        "<font name='Courier'>can-secops/config/</font>) combines Log Analytics and Azure Resource Graph queries:")]
s += table([
    ["Panel", "Source", "Key metric"],
    ["Key security metrics (tiles)", "AzureActivity, Syslog", "NSG changes, key retrievals, policy denials, RBAC "
     "grants, failed SSH auths"],
    ["Defender alerts by severity / latest 25", "Resource Graph (securityresources)", "Open threats and triage list"],
    ["Failed SSH authentications over time", "Syslog (Azure Monitor Agent)", "Brute-force trend per host"],
    ["Security-relevant control-plane changes", "AzureActivity", "Who changed what, from which IP"],
    ["Requests blocked by Azure Policy", "AzureActivity (policies/deny)", "Guardrail effectiveness"],
    ["Network flows by status; top sources to port 22", "NTANetAnalytics (VNet flow logs)", "Allowed vs denied, "
     "scanning sources"],
    ["Policy compliance per assignment", "Resource Graph (policyresources)", "Non-compliant resources"],
], [2.2 * inch, 2.0 * inch, 2.3 * inch])
s += optional_shot("Cloud_Security_1:SecOps_Dashboard.png", "dashboard",
                   "Azure portal — CAN Security Operations Dashboard (live): 14 failed SSH auth events, 6 policy "
                   "denials, 2 storage key retrievals, 2 NSG rule changes; 44 Defender alerts (16 High).", max_h=5.0 * inch)

# ------------------------------------------------------------------ Part E playbook
s += [CondPageBreak(4.5 * inch), P("Part E — Incident Response Playbook", "h1"),
      P("The playbook (<font name='Courier'>can-secops/IR-Playbook.md</font>) follows NIST SP 800-61r2 and HIPAA "
        "§164.308(a)(6). It defines severities with response targets and HIPAA breach escalation, the alert "
        "sources, and concrete Azure commands and KQL for each phase:")]
s += table([
    ["Phase", "Key actions in the CAN playbook"],
    ["Identification", "Open alert; record time, resource, caller/IP; rule out approved change; assign severity "
     "and incident ID"],
    ["Containment", "Delete rogue NSG rules; rely on/extend fail2ban bans; rotate storage keys; disable "
     "compromised identities; preserve evidence first"],
    ["Investigation", "KQL over AzureActivity (who/what/where), Syslog (host auth), NTANetAnalytics / raw flow logs "
     "(network), SecurityAlert (Defender)"],
    ["Eradication", "Remove every attacker artefact; rotate exposed credentials; rescan policy; search all "
     "operations by the attacker identity/IP"],
    ["Recovery", "Restore approved baseline; verify service and monitoring; heightened monitoring for 7 days"],
    ["Lessons learned", "Timeline, root cause, MTTD/MTTR, and at least one new preventive control"],
], [1.3 * inch, 5.2 * inch])
s += table([
    ["Severity", "Examples", "Response start"],
    ["SEV-1 Critical", "Confirmed PHI exposure, malware on host, attacker with Owner", "Immediately (+ Privacy "
     "Officer)"],
    ["SEV-2 High", "Firewall opened, unexpected key retrieval, new Owner", "< 1 hour"],
    ["SEV-3 Medium", "Blocked brute force, policy exemption created", "< 1 business day"],
    ["SEV-4 Low", "Single failed login, informational recommendation", "Next review"],
], [1.2 * inch, 3.6 * inch, 1.7 * inch])

# ------------------------------------------------------------------ Part F test
s += [P("Part F — Playbook Test: INC-20261008-01", "h1"),
      P("<b>Scenario:</b> an insider-style attacker with stolen admin credentials (1) adds a backdoor firewall rule "
        "allowing SSH to the VM, (2) retrieves storage account keys, and (3) brute-forces SSH with common account "
        "names. The blue team then executed the playbook end to end.")]
s += note("For safety, the simulated backdoor rule allowed SSH only from 203.0.113.66 — an RFC 5737 "
          "documentation address that cannot exist on the Internet — rather than from any source. It produces "
          "exactly the same control-plane event and alert, with zero real exposure.", "Safety")
s += [CondPageBreak(3 * inch)] + step("F1", "Attack simulation")[1:] + code(ev("01-attack-simulation.txt"), "evidence/01-attack-simulation.txt")
s += [CondPageBreak(3 * inch)] + step("F2", "Identification — alerts fired")[1:] + code(ev("02-alerts-fired.txt"), "evidence/02-alerts-fired.txt (Azure Monitor alerts)")
s += [KeepTogether(step("F3", "Containment, eradication and recovery")[1:] + code(ev("03-response-log.txt"), "evidence/03-response-log.txt"))]
s += [KeepTogether(step("F4", "Investigation")[1:] + code(ev("04-investigation.txt"), "evidence/04-investigation.txt (Log Analytics KQL)"))]
s += step("F5", "Timeline and response metrics")
s += table([
    ["Time (UTC)", "Event", "Elapsed"],
    ["20:14:27", "Attack starts", "0:00"],
    ["20:14:29", "Backdoor NSG rule created (A1)", "0:02"],
    ["20:14:31", "Storage keys listed (A2)", "0:04"],
    ["20:14:49", "fail2ban bans brute-force source (automatic host containment)", "0:22"],
    ["20:22:00", "Activity-log alerts fire — <b>MTTD ≈ 7 min 31 s</b>", "7:33"],
    ["20:26:12", "Backdoor rule removed — <b>contained</b>", "11:45"],
    ["20:26:14", "Both storage keys rotated (eradication)", "11:47"],
    ["20:28:08", "Admin access restored (fail2ban unban via Run Command)", "13:41"],
    ["20:28:27", "Baseline, SSH, function and monitoring verified — <b>recovered</b>", "14:00"],
], [1.1 * inch, 4.4 * inch, 1.0 * inch])

# ------------------------------------------------------------------ Part G lessons learned
s += step("F6", "Lessons learned — new preventive control, verified")
s += [P("<b>Root cause:</b> nothing prevented an administrator identity from adding an inbound SSH rule from an "
        "arbitrary source; detection worked, prevention did not. <b>Corrective action:</b> a new custom Azure Policy, "
        "<i>CAN – Management ports (SSH/RDP) only from approved admin IPs</i>, was assigned at the top "
        "management group with the Deny effect. Replaying the attacker's first step was then <b>denied</b>, while "
        "the same rule from the approved admin IP still validates.")]
s += code(ev("06-lessons-learned-control-test.txt"), "evidence/06-lessons-learned-control-test.txt")
s += bullets([
    "Detection latency (≈ 7.5 min) is set by Activity Log delivery; Defender alerts arrived in ~20 s. For "
    "faster response, an automated containment Logic App on al-nsg-rule-change is a candidate next step.",
    "The brute-force rule defects (B1) were found only by testing — alert rules now get a test event after "
    "every change.",
    "fail2ban banned the administrator's own IP during the test; out-of-band recovery through Azure Run Command "
    "worked and is now part of the playbook.",
])

# ------------------------------------------------------------------ issues + compliance
s += [P("Issues Encountered", "h1")]
s += table([
    ["Issue", "Resolution"],
    ["Traffic Analytics blocked by CAN's mandatory-tag policy", "Scoped, expiring Waiver exemption for the "
     "platform-managed monitoring RG"],
    ["Defender sample-alert API rejected the default region (westcentralus) and the body format",
     "Used the centralus endpoint and the correct properties.kind body"],
    ["Brute-force alert did not fire (window shorter than ingestion delay; row-count condition)",
     "30-min window, 'total FailedAttempts > 1'; re-tested"],
    ["Opening SSH to any source for the test was refused by the operator's safety controls",
     "Used an RFC 5737 documentation address — same detection path, no exposure"],
    ["Defender continuous export did not populate SecurityAlert in the workspace",
     "Dashboard reads Defender alerts from Azure Resource Graph instead (always current)"],
], [3.0 * inch, 3.5 * inch])
s += [P("Compliance Mapping", "h2")]
s += table([
    ["Control", "HIPAA Security Rule", "NIST CSF 2.0", "Evidence"],
    ["Centralized audit logging", "§164.312(b) Audit controls", "DE.CM-01, DE.CM-09", "Part A"],
    ["Activity review &amp; alerting", "§164.308(a)(1)(ii)(D)", "DE.AE-02, DE.AE-06", "Part B"],
    ["Threat detection", "§164.308(a)(5)(ii)(B)", "DE.CM-01, DE.AE-02", "Part C"],
    ["Incident procedures", "§164.308(a)(6)(i)–(ii)", "RS.MA-01, RS.AN-03, RS.MI-01", "Parts E–F"],
    ["Recovery &amp; improvement", "§164.308(a)(7)", "RC.RP-01, ID.IM-03", "Part F (F5–F6)"],
], [1.7 * inch, 1.75 * inch, 1.6 * inch, 1.45 * inch])
s += [KeepTogether([P("Implementation Status", "h2"),
      P("<b>Implemented &amp; verified:</b> Activity Log and host logs centralized in Log Analytics; VNet flow logs "
        "with Traffic Analytics on both VNets; eight automated alert rules; Defender for Cloud threat detection "
        "across servers, control plane and storage with a real malware detection; security dashboard; NIST-aligned "
        "playbook tested end to end with measured MTTD/MTTR and a verified lessons-learned control. This work closes "
        "Criterion 5 HIPAA gaps A3 (activity review) and A8 (incident procedures) and partly T3 (audit controls: "
        "Activity Log and host logs are centralized; per-resource diagnostic settings remain planned). Evidence is stored in "
        "<font name='Courier'>can-secops/</font>.")])]

doc = SimpleDocTemplate(OUT, pagesize=letter, leftMargin=inch, rightMargin=inch, topMargin=0.85 * inch,
                        bottomMargin=0.95 * inch,
                        title="CAN CloudSec1 Criterion 6 - Cloud Security Operations & Incident Response",
                        author="Akhila Chennamaneni")
doc.build(s, onFirstPage=c6_footer, onLaterPages=c6_footer)
print("wrote", OUT)
print("brute-force alert evidence present:", bf_ok)
print("optional screenshots not yet supplied:", MISSING or "none")
