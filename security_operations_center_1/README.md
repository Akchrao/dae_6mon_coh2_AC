# Security Operations Center 1

Final project submission: [`Security_Operations_Center_1_Submission.pdf`](Security_Operations_Center_1_Submission.pdf) (14 pages).

Built on a Wazuh 4.9.2 single-node SIEM (manager, indexer, dashboard) in Docker with a MailHog test mailbox,
fed with the Care Access Navigator capstone logs. Everything runs locally at no cost.

| Rubric criterion | Section | Evidence |
|---|---|---|
| Prepare SOC Operations Documentation | 1 | SOC tools, [Mermaid alert workflow](diagrams/soc_alert_workflow.mmd), shift handover form, NIST incident handling steps, [screenshot 1](screenshots/SS-01.png) |
| Document SIEM Implementation | 2 | [Architecture](diagrams/siem_architecture.mmd), correlation rules 100502 / 100507 / 100522 ([rules](wazuh_config/soc1_rules.xml)), 4 log sources, [email notification settings](wazuh_config/ossec_soc1_excerpt.conf), screenshots [3](screenshots/SS-03.png), [4](screenshots/SS-04.png), [5](screenshots/SS-05.png) |
| Document Threat Detection Principles | 3 | Rule mechanics, 3 detection scenarios, indicator categories, analysis method, investigation of scenario SOC1-SCN-01 ([alerts](evidence/scenario_SOC1-SCN-01_alerts.json), [screenshot 2](screenshots/SS-02.png)) |
| Document Incident Response Methodology | 4 | Initial response protocol, case management ([case record](case_management/SOC1-2026-001_record.md)), escalation matrix, completed IR template |

| Folder | Content |
|---|---|
| `wazuh_config/` | 13 custom rules and the manager settings (email + log sources) |
| `diagrams/` | Mermaid sources and rendered images |
| `scenario/feed_logs.py` | Replays the capstone logs and injects scenario SOC1-SCN-01 (synthetic, labelled) |
| `evidence/` | Alerts at level 8+ (CSV) and the scenario alerts (JSON) |
| `case_management/` | Case database (`irtrack.py` from Incident Response 1) and the SOC1-2026-001 record |
| `screenshots/` | Wazuh dashboard and mailbox screenshots |
| `build/soc1.html` | Source of the PDF |
