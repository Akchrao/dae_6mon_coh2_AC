# Security Monitoring 1

Final project submission: [`Security_Monitoring_1_Submission.pdf`](Security_Monitoring_1_Submission.pdf) (20 pages).

Wazuh 4.9.2 lab for HealthLine Regional Medical Center (HRMC): a **live Linux agent** (`hrmc-linux-srv01`), **imported Windows Security
event samples** (option B, agreed with the instructor: no live Windows host; every imported event is tagged `sample: imported-synthetic`),
plus the capstone Keycloak and EHR logs. Builds on the SOC 1 lab (`../security_operations_center_1/`). Everything runs locally at no cost.

| Rubric criterion | Section | Evidence |
|---|---|---|
| Monitoring Environment Setup | 1 | Agent Active ([screenshot 2](screenshots/SS-02.png)), [network config](evidence/network_config.txt), [rules](wazuh_config/sm1_rules.xml) for authentication, file access, network activity, email routing ([screenshot 6](screenshots/SS-06.png)) |
| Security Event Analysis | 2 | Annotated real log lines, cross-source correlation rules 100650 / 100651 ([screenshot 4](screenshots/SS-04.png)), scenario SM1-SCN-01 timeline, triage process |
| Monitoring Implementation | 3 | [Architecture](diagrams/sm1_architecture.mmd), [baselines](outputs/baselines.csv), [health check](lab/health_check.py) with real findings |
| Security Reporting | 4 | Alert template for 3 alert types, [metrics](outputs/sm1_metrics.json), summary report, [dashboard](wazuh_config/hrmc_security_dashboard.ndjson) ([screenshot 1](screenshots/SS-01.png)) |

Results: 9/9 attack steps detected, 0 false positives at level 10+ in the 7-day baseline week, median 1.5 s from event to alert.

Reproduce (lab running from `~/soc1-lab/wazuh-docker/single-node`): build `lab/Dockerfile.linux-agent`, run it on the
`single-node_default` network, then `python3 scenario/windows_events.py history`, `scenario/run_scenario.sh`,
`python3 lab/build_dashboard.py`, `python3 lab/health_check.py`, `analysis/sm1_analysis.py`, `build/build_doc.py`.

Passwords in these files (`admin`/`SecretPassword`, `Lab-Only-Pass-*`) are the published Wazuh Docker defaults and throwaway
container accounts for this local lab only; they are not used anywhere else.
