# Incident record SOC1-2026-001

**Compromised nurse account: password guessing, outside sign-in, bulk chart access**

| Field | Value |
|---|---|
| type | Account compromise / unauthorized ePHI access |
| severity | SEV-1 |
| status | Contained |
| detected_utc | 2026-11-17T21:26:49Z |
| source | Wazuh 100502 -> 100507 -> 100522 |
| handler | Akhila Chennamaneni (Tier 1) |
| assets | Keycloak realm care-access-navigator; EHR simulator; account test.nurse2 |
| environment | SOC 1 Wazuh lab (Docker, single-node 4.9.2) |
| course | Security Operations Center 1 |
| time to first response | 4.2 min (target 15 min: MET) |
| time to contain | 9.2 min |
| time to recover |  min |

## Summary

6 failed sign-ins for test.nurse2 from 203.0.113.45, then a successful sign-in from the same IP, then 18 patient charts opened in about 27 seconds from REMOTE-VPN.

## Status history

| UTC | Status | Note |
|---|---|---|
| 2026-11-17T21:26:49Z | New | opened from Wazuh 100502 -> 100507 -> 100522 |
| 2026-11-17T21:31:00Z | Triage | Tier 1 validated the alert chain in the dashboard; true positive; SEV-1 (ePHI read via a compromised account); IC and Privacy Officer paged |
| 2026-11-17T21:36:00Z | Contained | Tabletop containment: account disabled, sessions revoked, IP blocked |

## Response actions

| UTC | Phase | By | Action | Result |
|---|---|---|---|---|
| 2026-11-17T21:31:00Z | Triage | Tier 1 | Pivoted on username and source IP in Threat Hunting; confirmed 6 failures, 1 success, 18 chart views | True positive |
| 2026-11-17T21:36:00Z | Containment | IC (tabletop) | Disable test.nurse2 in Keycloak, end its sessions, block 203.0.113.45 at the edge | Planned in the tabletop; the live capstone realm was not changed |

## Timeline of events

| UTC | Host | Source | Event |
|---|---|---|---|
| 2026-11-17T21:26:49Z | wazuh.manager | rule 100502 (level 10) | CAN-ID-001 password guessing: 5+ failed sign-ins for test.nurse2 within 2 minutes |
| 2026-11-17T21:26:53Z | wazuh.manager | rule 100507 (level 13) | Possible account compromise: test.nurse2 signed in from 203.0.113.45 after the burst |
| 2026-11-17T21:27:17Z | wazuh.manager | rule 100522 (level 12) | CAN-ID-007 bulk access: test.nurse2 opened 15+ records within 60 seconds |

## Evidence

| Item | Description | SHA-256 | Location |
|---|---|---|---|
| E01 | Wazuh alerts for scenario SOC1-SCN-01 (25 alerts, exported from alerts.json) | `d1208f3bb680bff5...` | security_operations_center_1/evidence/scenario_SOC1-SCN-01_alerts.json |
