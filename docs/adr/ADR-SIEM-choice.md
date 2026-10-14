# ADR: Simulated SIEM Detection Layer Instead of a SIEM Platform Deployment

**Status:** Accepted for the capstone (2026-10-14). Instructor confirmation pending for the Incident Response 1 rubric items that name Wazuh.
**Project:** Care Access Navigator (HRMC), IAM + GRC capstone

## Context
Care Access Navigator protects simulated ePHI with identity controls (Keycloak, federated with Microsoft Entra ID) and GRC processes. The design document defines five monitoring use cases:

1. Repeated failed logins
2. Disabled-user activity
3. Privilege escalation
4. Excessive ePHI access
5. Expired vendor access

The design document's Tech Stack already allows for this: *"Microsoft Sentinel lab **or an equivalent lightweight SIEM/log-analysis simulation** using sample or CSV logs, depending on feasibility within 12 weeks."*

Deploying a full SIEM platform (Wazuh manager + indexer + dashboard, Splunk, or Sentinel with a Log Analytics workspace) would add infrastructure that sits outside the project's IAM/GRC scope:
- Wazuh's indexer stack needs more RAM than the lab host can spare alongside Keycloak and Postgres.
- Sentinel bills per GB ingested on a pay-as-you-go subscription with no credit.
- Neither platform changes the identity controls being demonstrated.

## Decision
Detection is delivered as a **simulated SIEM detection layer**: the `detect` command in `capstone_next_steps/scripts/can_iam.py`. The detection logic, alert format and triage workflow are real; only the SIEM platform is left out.

| SIEM function | How the simulation does it |
|---|---|
| Log collection | Pulls Keycloak login events and admin events (90-day retention set by `harden`), plus an EHR access log CSV |
| Detection rules | CAN-ID-001 to CAN-ID-007 (below) |
| Alerting with severity | `identity_detections.csv`: rule, severity, time (UTC), subject, detail |
| Triage and reporting | Alerts feed the IR playbook (INC-20261020-01) and the Tableau dashboard |

| Rule | Use case | Source | Severity |
|---|---|---|---|
| CAN-ID-001 brute force (≥5 failures / 10 min) | Repeated failed logins | Keycloak `LOGIN_ERROR` | High |
| CAN-ID-002 disabled-account login | Disabled-user activity | Keycloak `user_disabled` | High |
| CAN-ID-003 login while locked out | Repeated failed logins | Keycloak `user_temporarily_disabled` | Medium |
| CAN-ID-004 unauthorized app access | Least privilege / app gate | Keycloak `access_denied` | Medium |
| CAN-ID-005 privilege change | Privilege escalation | Keycloak admin events | High if privileged group/role added, else Medium |
| CAN-ID-006 expired access still in use | Expired vendor access | Keycloak `LOGIN` after `access_end_date` | High |
| CAN-ID-007 excessive patient-record access (≥15 distinct patients / 60 min) | Excessive ePHI access | EHR access log CSV (synthetic) | High |

Wording for deliverables: *"A full SIEM platform (Wazuh/Splunk/Sentinel) was out of scope; detection is demonstrated with a SIEM-equivalent rule engine over real Keycloak authentication and admin events. Platform deployment is listed under Future Considerations."*

## Rationale
- **Scope fit:** the capstone is about identity governance. The detection *logic* is the deliverable, and the platform is replaceable plumbing.
- **Real data:** rules run over real Keycloak events produced by the lab's own attack simulation, not hand-made alerts.
- **Cost:** $0. No Azure ingestion charges (PAYG subscription, no credit).
- **Portable:** the IR 1 work already expressed rules in Wazuh XML syntax, and the CSV output can be ingested by Wazuh, Sentinel or Splunk later without rewriting the logic.
- **Traceable:** every run is logged to `can_iam_audit_log.jsonl` and hashed in `EVIDENCE-INDEX-SHA256.txt`.

## Alternatives considered
- **Wazuh on Parrot OS (VirtualBox):** named in the IR 1 rubric. VirtualBox needs admin rights the lab host doesn't have, and the Wazuh indexer stack competes with Keycloak for memory.
- **Microsoft Sentinel:** strongest enterprise match and named in the design doc. Rejected because of per-GB ingestion billing on a PAYG subscription.
- **Splunk Free / Enterprise trial:** 500 MB/day limit and a trial that ends before Week 12. It adds a tool without adding an identity control.
- **No detection at all:** rejected, because the monitoring use cases and IR 1 require proof of detection.

## Consequences
- No SIEM dashboard screenshots. Evidence is the CSV output, the Tableau "detections by rule" view, and the IR report.
- No correlation across hosts or the network. Detection covers the identity and application layer only, which matches the project's scope.
- CAN-ID-007 runs on a synthetic EHR access log, because the EHR simulator does not emit per-record audit events.
- Detections run on demand (`python3 can_iam.py detect`), not in real time. The time from detection to response is measured from the run time.
- **Rubric risk:** IR 1 Section 1 names "Wazuh on Parrot OS (VirtualBox)". Those items count only if the instructor accepts the substitution in writing. Record the answer here and in the exception register.
- Recorded in the exception register as an approved scope decision. Platform deployment is listed under Future Considerations.

## References
- Design document v1.2: Tech Stack, Monitoring use cases, Section 13 substitution note
- `capstone_next_steps/scripts/can_iam.py` (`detect`) and `README.md` step 8b
- `capstone_next_steps/scripts/sample_ehr_access_log.csv` (synthetic, for CAN-ID-007)
- Readiness Audit & Roadmap v2: §3.6 Monitoring unauthorized access; B6 attack simulation (INC-20261020-01)
- Related: [ADR-OpenCTI-scope](ADR-OpenCTI-scope.md)
