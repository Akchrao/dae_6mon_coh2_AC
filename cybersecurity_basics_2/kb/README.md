# HRMC Cybersecurity Knowledge Base

Structured repository of security references for HealthLine Regional Medical Center (Care Access Navigator capstone).
Every entry has an ID, an owner and a location. Paths are relative to the repository root.

| ID scheme | Category | Use it when |
|---|---|---|
| POL-* | 1. Policies | You need the rule: what is required |
| PROC-* | 2. Procedures | You implement or operate a control |
| GUIDE-* | 3. Guides | You are a user who needs to do something step by step |
| PB-* | 4. Playbooks | You respond to an incident |
| STD-* / REF-* | 5. Standards, mappings and registers | You map, audit or report compliance |
| TOOL-* | 6. Tools and lab references | You run or rebuild a security tool |
| LL-* | 7. Lessons learned | You plan improvements or train others |

## 1. Policies
| ID | Title | Location |
|---|---|---|
| POL-SEC-01 | Information Security Policy (access control, data protection, system use) | `cybersecurity_basics_2/kb/policies/POL-SEC-01_Information_Security_Policy.md` |
| POL-SEC-02 | Authentication and Privileged Access (capstone) | `Care_Access_Navigator/07_GRC/02_Controls/CAN_DOC_Authentication_and_Privileged_Access_v1.0.pdf` |

## 2. Procedures
| ID | Title | Location |
|---|---|---|
| PROC-SEC-01 | Joiner / mover / leaver with can_iam.py | `Care_Access_Navigator/10_Scripts/02_IAM_Automation/README.md` |
| PROC-SEC-02 | Quarterly access review | `Care_Access_Navigator/06_Evidence/05_Access_Reviews/` |
| PROC-SEC-03 | Linux server SSH hardening | `cybersecurity_basics_2/kb/procedures/PROC-SEC-03_SSH_Hardening.md` |
| PROC-SEC-04 | Container hardening and image scanning (supply chain) | `cloud_security_1/can-ehr-container/` + Cloud Security 1 Criterion 3 PDF |

## 3. Guides
| ID | Title | Location |
|---|---|---|
| GUIDE-SEC-01 | How to report a security incident (all staff) | `cybersecurity_basics_2/kb/guides/GUIDE-SEC-01_Reporting_a_Security_Incident.md` |
| GUIDE-SEC-02 | Parrot OS incident-response tools and commands | `incident_response_1/task5_ir_documentation/tools/PARROT_IR_TOOLS.md` |

## 4. Playbooks
| ID | Title | Location |
|---|---|---|
| PB-01 | Account compromise | `cybersecurity_basics_2/kb/playbooks/PB-01_Account_Compromise.md` |
| PB-02 | Data exfiltration from ePHI stores | `cybersecurity_basics_2/kb/playbooks/PB-02_Data_Exfiltration.md` |
| PB-03 | Host incident response, runbooks RB-01 to RB-06 | `incident_response_1/task5_ir_documentation/playbook/CAN-IR-PB-02_Host_Incident_Response_Playbook.md` |

## 5. Standards, mappings and registers
| ID | Title | Location |
|---|---|---|
| STD-01 | Control catalogue and framework mapping (HIPAA, NIST CSF 2.0, SP 800-53, ISO 27001, PCI DSS) | `Care_Access_Navigator/07_GRC/02_Controls/CAN_DOC_Control_Catalog_and_Mapping_v1.0.xlsx` |
| STD-02 | Unified control map incl. GDPR and India DPDP | `compliance_2/HRMC_Compliance2_Workbook.xlsx` (sheet Unified_Controls) |
| REF-01 | Risk register R01-R05 and treatment plan | `Care_Access_Navigator/07_GRC/01_Risks/` |
| REF-02 | HIPAA audit and NIST CSF mapping (CISO Assistant exports) | `Care_Access_Navigator/07_GRC/03_Compliance/` |
| REF-03 | Exceptions and corrective actions | `Care_Access_Navigator/07_GRC/04_Remediation/` |

## 6. Tools and lab references
| ID | Title | Location |
|---|---|---|
| TOOL-01 | Wazuh SOC rules (SOC 1) | `security_operations_center_1/wazuh_config/soc1_rules.xml` |
| TOOL-02 | Wazuh monitoring rules, dashboard, health check (Security Monitoring 1) | `security_monitoring_1/` |
| TOOL-03 | Incident tracker irtrack.py | `incident_response_1/task5_ir_documentation/tracker/irtrack.py` |
| TOOL-04 | Compliance workflow with AI triage | `compliance_2/automation/compliance_workflow.py` |

## 7. Lessons learned
| ID | Lesson | Source |
|---|---|---|
| LL-01 | Federation copies identities: each copy needs its own leaver control (12-minute Keycloak gap) | Capstone JML, CAN-FIND-001 |
| LL-02 | Configured is not working: test the person who should be stopped | Capstone Week 5 hardening |
| LL-03 | Test every rule end to end: rule-file load order silently disabled a correlation rule | Security Monitoring 1, rule 100650 |
| LL-04 | Monitor the monitoring platform: a feed download filled the disk; an agent stopped after a config push | Security Monitoring 1, section 3.6 |
| LL-05 | Password-only SSH on servers is guessable within seconds; keys only | CB2-2026-001 |
