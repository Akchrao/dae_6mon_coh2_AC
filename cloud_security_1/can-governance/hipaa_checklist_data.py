"""HIPAA Security Rule checklist, gap analysis and remediation plan for CAN on Azure.

Every 'evidence' entry refers to something verified in this environment on 2026-10-08
(CLI output in can-governance/evidence/, Azure Policy results, or earlier criteria).
"""

# (id, safeguard, HIPAA citation, requirement, CAN configuration, status, evidence, NIST CSF 2.0)
CHECKLIST = [
    ("A1", "Administrative", "§164.308(a)(1)(ii)(A)", "Risk analysis",
     "Cloud risk assessment workbook; Trivy image scanning; continuous Azure Policy HIPAA evaluation",
     "Met", "Risk_Assessment.xlsx; Infra PDF Part B; policy scan", "ID.RA-01"),
    ("A2", "Administrative", "§164.308(a)(1)(ii)(B)", "Risk management",
     "Deny guardrails at management-group level (regions, VM sizes, storage baselines, banned resource types)",
     "Met", "Enforcement tests T3–T9", "GV.RM-01, PR.PS-01"),
    ("A3", "Administrative", "§164.308(a)(1)(ii)(D)", "Information system activity review",
     "Activity Log kept 90 days by default only; no export to Log Analytics; no activity-log alerts",
     "Gap", "Policy: 'activity log alert should exist' NonCompliant; 0 subscription diagnostic settings", "DE.CM-09"),
    ("A4", "Administrative", "§164.308(a)(3)(ii)(B)", "Workforce clearance / least privilege",
     "Entra app roles mapped to 7 Keycloak roles; function identity holds one scoped role",
     "Met", "Criterion 4 addendum; Infra PDF Step C2", "PR.AA-05"),
    ("A5", "Administrative", "§164.308(a)(4)(ii)(B)", "Access authorization (privileged access)",
     "Single subscription Owner, and it is a guest (#EXT#) personal Microsoft account",
     "Gap", "Policy: guest owners / more than one owner NonCompliant", "PR.AA-05, GV.RR-02"),
    ("A6", "Administrative", "§164.308(a)(5)(ii)(B)", "Protection from malicious software",
     "VM automatic patching (Azure + unattended-upgrades); container images 0 CVEs; no VM vulnerability scanner",
     "Partial", "Infra PDF Part A; policy: 'vulnerability assessment on VMs' NonCompliant", "PR.PS-02, ID.RA-01"),
    ("A7", "Administrative", "§164.308(a)(5)(ii)(C)", "Log-in monitoring",
     "fail2ban + sshd VERBOSE on VM; Entra sign-in logs (Free tier, 7-day retention)",
     "Partial", "Infra PDF Step A4", "DE.CM-03"),
    ("A8", "Administrative", "§164.308(a)(6)", "Security incident procedures",
     "No documented, tested incident-response playbook yet",
     "Gap", "Delivered by Criterion 6 (Security Operations & IR)", "RS.MA-01"),
    ("A9", "Administrative", "§164.308(a)(7)(ii)(A)", "Data backup plan",
     "No Azure Backup vault; VM not backed up; blob soft-delete on evidence storage only",
     "Gap", "Policy: 'Azure Backup should be enabled for VMs' NonCompliant; 0 Recovery Services vaults", "PR.DS-11"),
    ("A10", "Administrative", "§164.308(a)(7)(ii)(B)", "Disaster recovery plan",
     "No cross-region recovery configured (single-region lab)",
     "Gap", "Policy: 'VMs without disaster recovery' NonCompliant", "RC.RP-01"),
    ("A11", "Administrative", "§164.308(a)(8)", "Evaluation",
     "HITRUST/HIPAA initiative continuously evaluates 90 automated checks; on-demand scans",
     "Met", "evidence/05-compliance-before-after.txt", "ID.IM-01"),
    ("A12", "Administrative", "§164.308(b)(1)", "Business associate agreement",
     "Microsoft HIPAA BAA applies to in-scope Azure services via the Product Terms",
     "Met", "Inherited (shared responsibility)", "GV.SC-05"),
    ("P1", "Physical", "§164.310(a)–(d)", "Facility, workstation and device controls",
     "Azure datacenter physical security (inherited); admin workstation is a shared lab Mac",
     "Partial", "Shared-responsibility model (Fundamentals PDF)", "PR.AA-06"),
    ("T1", "Technical", "§164.312(a)(2)(i)", "Unique user identification",
     "Entra users and per-person Keycloak federated usernames (entra-id.<UPN>)",
     "Met", "Criterion 4 addendum, defect 3 fix", "PR.AA-01"),
    ("T2", "Technical", "§164.312(a)(2)(iv)", "Encryption at rest",
     "Storage and managed disks encrypted with platform-managed keys; no CMK or encryption-at-host",
     "Partial", "Storage keySource=Microsoft.Storage; VM encryptionAtHost=null", "PR.DS-01"),
    ("T3", "Technical", "§164.312(b)", "Audit controls",
     "No diagnostic settings on 12 resources (ACR, ACI, NSGs, VM, VNets, storage, function)",
     "Gap", "Policy: 'Audit diagnostic setting' NonCompliant (12 resources)", "DE.CM-01, PR.PS-04"),
    ("T4", "Technical", "§164.312(c)(1)", "Integrity",
     "Container base images pinned by digest; blob versioning on evidence storage; none on function storage",
     "Partial", "Infra PDF Step B2; blob service properties", "PR.DS-01"),
    ("T5", "Technical", "§164.312(d)", "Person or entity authentication",
     "SSH key-only; managed identities for workloads; Entra MFA (security defaults) not verifiable via CLI",
     "Partial", "Infra PDF A4/C2; MFA status to confirm in portal", "PR.AA-03"),
    ("T6", "Technical", "§164.312(e)(1)", "Transmission security",
     "TLS 1.2 minimum and HTTPS-only enforced by Deny policy; Keycloak lab endpoint is plain HTTP on localhost",
     "Partial", "Enforcement tests T6–T7", "PR.DS-02"),
    ("H1", "HITRUST 01.m", "§164.312(e)(1)", "Network segregation",
     "NSGs on all workload subnets; function VNet-integrated; but evidence storage and ACR accept all networks; "
     "VM SSH open to one IP without JIT",
     "Partial", "Policy: storage network access, ACR service endpoint, JIT NonCompliant", "PR.IR-01"),
    ("H2", "HITRUST 07.a", "§164.310(d)(2)(iii)", "Asset inventory and ownership",
     "Mandatory Owner / Environment / DataClassification tags enforced by Deny policy; all 24 assets tagged",
     "Met", "Tag compliance 0 → 72 compliant", "ID.AM-01, ID.AM-05"),
    ("H3", "HITRUST 01.q", "§164.308(a)(5)(ii)(D)", "Credential management",
     "Container registry admin (shared) credential still enabled; older storage account allows key access",
     "Gap", "ACR adminUserEnabled=true; cloudsecevidencecan allowSharedKeyAccess=true", "PR.AA-01"),
]

# (priority, gap ids, action, owner, target, est. cost, status)
REMEDIATION = [
    ("P1", "H2", "Tag all existing resources and resource groups to the CAN tagging standard",
     "Cloud admin", "2026-10-08", "$0", "Done"),
    ("P1", "A5", "Create a dedicated member admin account (not a guest), grant it Owner, and use it for "
     "administration; keep the personal account as break-glass", "Cloud admin", "2026-10-12", "$0", "Planned"),
    ("P1", "T5", "Confirm Entra Security Defaults (MFA for all users) is enabled; enable if not",
     "Cloud admin", "2026-10-12", "$0", "Planned"),
    ("P1", "H3", "Recreate aci-app-test with a managed identity + AcrPull, then disable the ACR admin user; "
     "disable shared-key access on cloudsecevidencecan", "Cloud admin", "2026-10-15", "$0", "Planned"),
    ("P1", "H1", "Restrict cloudsecevidencecan to selected networks; remove unused AzureBastionSubnet",
     "Cloud admin", "2026-10-15", "$0", "Planned"),
    ("P2", "A3, T3", "Export Activity Log and resource diagnostic logs to the Log Analytics workspace; create "
     "activity-log alerts for policy, NSG and role-assignment changes", "SecOps", "Criterion 6", "~$0 (5 GB free)",
     "Planned"),
    ("P2", "A8", "Write and test the cloud incident-response playbook", "SecOps", "Criterion 6", "$0", "Planned"),
    ("P2", "A7", "Stream Entra sign-in logs to Log Analytics for longer retention (requires P1 licence or "
     "diagnostic export)", "SecOps", "Criterion 6", "$0–licence", "Planned"),
    ("P3", "A9, A10", "Delete the temporary VM (removes the unbacked-up asset); for any production VM, enable "
     "Azure Backup (daily, 30-day retention)", "Cloud admin", "2026-10-15", "~$5/month per VM", "Planned"),
    ("P3", "A6", "Enable a VM vulnerability scanner (Defender for Servers P1 trial) for production hosts",
     "SecOps", "Production", "~$5/server/month", "Deferred (cost)"),
    ("P3", "T2", "Customer-managed keys (Key Vault) and encryption-at-host for PHI stores",
     "Cloud admin", "Production", "~$1–5/month", "Deferred (cost)"),
    ("P3", "T6", "Serve Keycloak over HTTPS with a trusted certificate behind a reverse proxy",
     "App team", "Production", "$0", "Deferred"),
    ("P3", "T4", "Enable blob soft-delete and versioning on stcanfunc9a8c964b", "Cloud admin", "2026-10-15",
     "<$0.01/month", "Planned"),
]

TAG_STANDARD = [
    ("Owner", "Accountable person (email-style alias)", "akhila.chennamaneni"),
    ("Environment", "Lifecycle stage; drives guardrail strictness", "Lab | Dev | Test | Prod"),
    ("DataClassification", "Highest sensitivity of data the resource can hold",
     "Public | Internal | Confidential | PHI"),
]

GUARDRAILS = [
    ("allowed-locations", "Allowed locations", "eastus, northcentralus",
     "Data residency in approved US regions; limits sprawl"),
    ("allowed-rg-locations", "Allowed locations for resource groups", "eastus, northcentralus",
     "Resource-group metadata stays in approved regions"),
    ("denied-resource-types", "Not allowed resource types",
     "bastionHosts, azureFirewalls, applicationGateways, expressRouteCircuits, managedClusters (AKS)",
     "Blocks high-cost services without approval (cost governance)"),
    ("allowed-vm-skus", "Allowed virtual machine size SKUs",
     "B1s, B1ms, B2s, B2ats_v2, F1als_v7, F1as_v7", "Only small, approved VM sizes"),
    ("storage-no-public-access", "Storage account public access should be disallowed", "Deny",
     "No anonymous blob access to PHI"),
    ("storage-secure-transfer", "Secure transfer to storage accounts should be enabled", "Deny",
     "HTTPS only for data in transit"),
    ("storage-min-tls12", "Storage accounts should have the specified minimum TLS version", "Deny, TLS1_2",
     "Blocks legacy TLS 1.0/1.1"),
]

AWS_AZURE = [
    ("AWS Organizations (OUs)", "Management groups (mg-can → workloads / sandbox)"),
    ("Service Control Policies", "Azure Policy assignments with Deny effect at management-group scope"),
    ("Tag policies / mandatory tagging", "Azure Policy 'Require a tag' (Deny) on resources and resource groups"),
    ("AWS Config Rules + conformance pack", "Azure Policy compliance evaluation + built-in HITRUST/HIPAA initiative"),
    ("Config compliance dashboard", "Azure Policy compliance view / Defender for Cloud regulatory compliance"),
]
