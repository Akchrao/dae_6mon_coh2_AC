# Cybersecurity Basics 2

Final project submission (Care Access Navigator / HealthLine Regional Medical Center):
- [`Cybersecurity_Basics_2_Submission.pdf`](Cybersecurity_Basics_2_Submission.pdf) (all criteria, 20 pages)
- one PDF per rubric criterion: `Care_Access_Navigator_CybersecurityBasics2_Criterion_1..5_*.pdf`

| Rubric criterion | Main evidence |
|---|---|
| 1. Advanced Defense Strategies | Zero Trust across 4 layers ([diagram](diagrams/zero_trust.mmd), tests CB2-02 / CB2-03), defense in depth (7 layers), supply chain: container image 172 → 0 vulnerabilities, Clark-Wilson model applied |
| 2. Incident Response and Handling | 5-step IRP, Volatility 3 + dc3dd (IR1), [chain of custody](evidence/cb2_custody_log.csv), 3 incident types triaged, post-incident lessons |
| 3. SOC Fundamentals | 4 SOC roles, Wazuh live agent with 2 network activity types, 2 alerts generated → investigated → **resolved 2026-11-19** ([CB2-2026-001](case_management/CB2-2026-001_record.md), [CB2-2026-002](case_management/CB2-2026-002_record.md)), threat analysis |
| 4. Security Policies and Governance | [POL-SEC-01](kb/policies/POL-SEC-01_Information_Security_Policy.md) (access control, data protection, system use), roles, NIST CSF / ISO 27001 / HIPAA references, login banner + enforcement evidence |
| 5. Security Documentation | [PROC-SEC-03](kb/procedures/PROC-SEC-03_SSH_Hardening.md), [GUIDE-SEC-01](kb/guides/GUIDE-SEC-01_Reporting_a_Security_Incident.md), playbooks [PB-01](kb/playbooks/PB-01_Account_Compromise.md) / [PB-02](kb/playbooks/PB-02_Data_Exfiltration.md), [knowledge base](kb/README.md) |

Real work done for this course on the Security Monitoring 1 lab server `hrmc-linux-srv01`: compromised account locked,
SSH switched to keys only with a system-use banner (`lab/harden_ssh.sh`), staged ePHI copy preserved and removed, deleted
export restored and verified by hash ([transcript](evidence/remediation_transcript.txt)). Everything runs locally at no cost.
