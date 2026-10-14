# ADR: OpenCTI Documented as a Threat-Intelligence Integration, Not Deployed

**Status:** Accepted for the capstone (2026-10-14). Instructor confirmation pending on whether "documentation only" is final for Cyber Threats & Vulnerabilities.
**Project:** Care Access Navigator (HRMC), IAM + GRC capstone

## Context
OpenCTI is an open-source threat-intelligence platform that stores threat actors, techniques (MITRE ATT&CK) and indicators of compromise, and shares them with other tools. The Cyber Threats & Vulnerabilities course introduced it, and the project documentation describes how it would help. It has not been deployed.

Care Access Navigator is an IAM/GRC project. Its threats are identity threats: credential stuffing, insider snooping on patient records, leftover vendor access, and privilege creep. These are already handled by identity controls and the simulated SIEM detection layer (see [ADR-SIEM-choice](ADR-SIEM-choice.md)).

## Decision
OpenCTI is **documented, not deployed**. The project describes how OpenCTI would plug into Care Access Navigator and uses MITRE ATT&CK directly, through the mapping below, for threat context.

| OpenCTI capability | How it would help Care Access Navigator | What the project uses instead |
|---|---|---|
| ATT&CK technique library | Tie each detection rule to an attacker technique | Static mapping: CAN-ID-001 → T1110 Brute Force; CAN-ID-002/006 → T1078 Valid Accounts; CAN-ID-005 → T1098 Account Manipulation; CAN-ID-007 → T1213 Data from Information Repositories |
| Healthcare threat-actor profiles | Prioritize risks by who targets hospitals | Risk register entries informed by the AgentTesla/APT analysis from Cyber Threats & Vulnerabilities |
| IOC feeds (e.g., AlienVault OTX) | Flag sign-ins from known-bad IPs | Out of scope: lab sign-ins come from localhost/Entra |
| Sharing intel with a SIEM | Enrich alerts automatically | Manual enrichment step in the IR playbook triage |

## Rationale
- **Scope:** threat intelligence is about outside attackers. The project's main risks are inside the identity lifecycle, and OpenCTI does not change any access control.
- **Resources:** OpenCTI's Docker stack (Elasticsearch, Redis, RabbitMQ, MinIO, workers) needs about 8 GB of free RAM, on a host already running Keycloak, Postgres and the EHR simulator.
- **Value per hour:** with about 2.5 weeks left, the time goes to controls the rubrics and design doc require (MFA, JML, access review, the IR scenario).

## Alternatives considered
- **Full OpenCTI deployment with MITRE + OTX connectors:** the roadmap documents how to do this if the instructor requires it (about 3–4 hours plus troubleshooting).
- **MISP:** similar footprint and the same scope problem.
- **No threat context at all:** rejected. The ATT&CK mapping above gives every detection rule threat context at almost no cost.

## Consequences
- No OpenCTI connector or dashboard screenshots. If the Cyber Threats rubric requires deployment, that item stays open until the instructor answers.
- Detection rules and incident reports cite ATT&CK technique IDs directly.
- Listed under Future Considerations: deploy OpenCTI, ingest the ATT&CK and OTX feeds, and enrich `identity_detections.csv` alerts with indicator matches.

## References
- Readiness Audit & Roadmap v2: OpenCTI decision (§3.13)
- MITRE ATT&CK: https://attack.mitre.org
- OpenCTI documentation: https://docs.opencti.io
