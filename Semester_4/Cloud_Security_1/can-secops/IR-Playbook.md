# CAN Cloud Incident Response Playbook

**System:** Care Access Navigator (Azure subscription 1, `rg-cloudsec1-can`)
**Owner:** Akhila Chennamaneni (Cloud Security) · **Version:** 1.0 · **Date:** 2026-10-08
**Applies to:** security alerts from Microsoft Defender for Cloud, Azure Monitor activity-log alerts, and the
SSH brute-force log alert. Aligned to NIST SP 800-61r2 and the HIPAA Security Rule §164.308(a)(6).

---

## 0. Severity and roles

| Severity | Examples | Response start | Escalate to |
|---|---|---|---|
| **SEV-1 Critical** | Confirmed PHI exposure, malware on a host, attacker with Owner rights | Immediately | Privacy Officer (HIPAA breach assessment, 60-day notice clock) |
| **SEV-2 High** | Firewall opened to the Internet, storage keys retrieved unexpectedly, new Owner assignment | < 1 hour | Cloud Security lead |
| **SEV-3 Medium** | Brute-force attempts blocked, policy exemption created | < 1 business day | SecOps on-call |
| **SEV-4 Low** | Single failed login, informational Defender recommendation | Next review | — |

Roles (one person may hold several in this lab): **Incident Commander**, **Investigator**, **Communications/Privacy**.

## 1. Identification

Triggers (all route to action group `ag-can-secops`, email to the subscription owner):

| Alert | Fires on |
|---|---|
| `al-nsg-rule-change` / `al-nsg-rule-delete` | Any NSG rule written or deleted |
| `al-role-assignment` | Any new RBAC role assignment |
| `al-policy-assignment-del` / `al-policy-exemption` | Governance controls removed or bypassed |
| `al-storage-listkeys` | Storage account keys retrieved |
| `al-defender-alert` | Any Microsoft Defender for Cloud alert (Servers, Resource Manager, Storage) |
| `sqr-ssh-bruteforce` | ≥ 2 failed/blocked SSH authentications on a VM in 15 min |

Steps:
1. Open the alert; record **alert name, time fired, resource, caller/IP** in the incident log.
2. Confirm it is not an approved change (check change record / ask the named `Owner` tag holder).
3. Assign severity (table above) and an incident ID `INC-YYYYMMDD-NN`.

## 2. Containment

| Situation | Action (command) |
|---|---|
| Rogue/unsafe NSG rule | `az network nsg rule delete -g <rg> --nsg-name <nsg> -n <rule>` |
| Host under attack | Confirm fail2ban ban (`sudo fail2ban-client status sshd`); if needed apply NSG deny-all inbound on the VM's subnet |
| Leaked storage key | `az storage account keys renew -g <rg> -n <account> --key primary` (and `secondary`) |
| Compromised identity | Disable the user in Entra ID; remove role assignments; revoke sessions |
| Malware in storage | Defender quarantines/flags the blob; block the container (remove access) |

Short-term containment first (stop the bleeding), then preserve evidence before deleting anything.

## 3. Investigation

Run in Log Analytics workspace `DefaultWorkspace-9a8c964b-…-EUS`:

```kusto
// Who changed what, from where (control plane)
AzureActivity
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| where OperationNameValue has_any ("securityRules","roleAssignments","listKeys","policy")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, _ResourceId

// Host authentication activity
Syslog
| where Facility in ("auth","authpriv") and TimeGenerated > ago(1d)
| where SyslogMessage has_any ("not allowed","Invalid user","Accepted","Ban","Unban")
| project TimeGenerated, HostName, SyslogMessage

// Network flows to the affected host (VNet flow logs / Traffic Analytics)
NTANetAnalytics
| where TimeGenerated > ago(1d) and DestPort == 22
| summarize Flows = count() by SrcIp, DestIp, FlowStatus, bin(TimeGenerated, 10m)

// Defender for Cloud alerts
SecurityAlert | where TimeGenerated > ago(1d)
| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Description
```

Determine: initial access vector, scope (which resources/data), whether PHI was accessible, attacker IP(s), and timeline.

## 4. Eradication

1. Remove every artefact the attacker created (rules, role assignments, keys, users, files).
2. Rotate any credential that may have been exposed (storage keys, SSH keys, client secrets).
3. Re-run `az policy state trigger-scan` and confirm no new non-compliance.
4. Search `AzureActivity` for *all* operations by the attacker identity/IP in the window — nothing left behind.

## 5. Recovery

1. Restore the approved baseline (compare NSG rules / role assignments with the documented baseline).
2. Verify service: function `ehr-status` returns 200, admin SSH works, flow logs and alerts still enabled.
3. Increase monitoring for 7 days (review the dashboard daily).
4. Close the incident when no recurrence is observed.

## 6. Post-incident (lessons learned)

Within 5 business days: timeline, root cause, MTTD/MTTR, what worked, what failed, and **at least one preventive
control** (e.g. a new Azure Policy deny rule). Update this playbook and the HIPAA checklist (Criterion 5).
HIPAA: document the risk assessment of whether PHI was compromised (§164.402 four-factor test).
