# POL-SEC-01 HRMC Information Security Policy

| | |
|---|---|
| Organization | HealthLine Regional Medical Center (HRMC) (fictional capstone hospital) |
| Owner | Chief Information Security Officer (CISO) |
| Approved by | Compliance & Privacy Committee, on behalf of the Board |
| Version / date | 1.0, 2026-11-19 |
| Review | Every 12 months, or after a major incident or regulatory change |
| Applies to | All workforce members, students, contractors and vendors who use HRMC systems or data |

## 1. Purpose

Protect the confidentiality, integrity and availability of patient, payment and workforce information, and meet HIPAA,
PCI DSS and contractual obligations. This policy sets the rules; standards and procedures say how to meet them.

## 2. Access control

1. **Least privilege.** Access is granted through job-role groups only (Clinician, Nurse, Billing, HR, IT-Support,
   Security-Analyst, Vendor), never directly to a person. Each application admits only the roles approved for it.
2. **Identity.** Every user has a unique account in Microsoft Entra ID, federated to Keycloak. Shared accounts are not allowed.
3. **Authentication.** Passwords are at least 12 characters, and identity accounts lock after 10 failed attempts.
   Multi-factor authentication is required for privileged and payment roles. Servers accept SSH keys only, not
   passwords, and close a connection after 3 failed attempts.
4. **Joiners, movers, leavers.** Access is created only from an approved request, changed when the job changes (old
   access removed before new access is added), and removed on the leave date. Removal is verified.
5. **Reviews.** Managers review their staff's access every quarter, and record a decision and signature for every account.
6. **Vendors.** Vendor access is sponsored, time-limited and removed at the end date.

## 3. Data protection

1. **Classification.** Restricted (ePHI, card data), Confidential (workforce data, security logs), Internal, Public.
2. **Encryption.** Restricted and Confidential data are encrypted in transit (TLS 1.2 or higher) and at rest.
3. **Minimum necessary.** Users access only the patient records their role and current task need. Bulk exports of
   Restricted data need the data owner's approval and a change ticket.
4. **Integrity.** Folders holding Restricted data are under file integrity monitoring. Unexpected changes are investigated.
5. **Retention and disposal.** Records are kept as long as the law requires (HIPAA documentation 6 years; security logs
   12 months), then securely deleted.
6. **Transfer.** Restricted data leaves HRMC only through approved channels with a business associate agreement.
   Unapproved sync and transfer tools (for example rclone) are not allowed.

## 4. System use

1. HRMC systems are for approved HRMC work. Limited personal use must not affect patients, security or other people's work.
2. Users must not share credentials, disable security tools, install unapproved software or connect unapproved devices.
3. Remote access is only through the approved VPN with MFA. Remote Desktop from the internet is not allowed.
4. All use is logged and monitored. Users have no expectation of privacy on HRMC systems, within the limits of the law.
5. Every system shows a login banner that refers to this policy.
6. Suspected incidents must be reported straight away (GUIDE-SEC-01).

## 5. Governance: roles and responsibilities

| Role | Responsibility for this policy |
|---|---|
| Board of Trustees / Compliance & Privacy Committee | Approve the policy, accept residual risk, receive quarterly metrics |
| CISO (HIPAA Security Official) | Own the policy, approve exceptions, report compliance |
| Privacy Officer | Data protection rules, breach risk assessments |
| IAM Analyst | Role groups, joiner/mover/leaver, MFA, lockout, access reviews |
| Security Analyst (SOC) | Monitoring, alert triage, incident response, enforcement evidence |
| GRC Analyst | Control mapping, evidence, audits, exception register |
| Department managers | Approve access, complete access reviews, enforce in their teams |
| HR | Leave dates, sanctions, training records |
| All users | Follow the policy, complete training, report incidents |

## 6. Compliance requirements (standards referenced)

| Section | NIST CSF 2.0 | ISO/IEC 27001:2022 Annex A | HIPAA Security Rule |
|---|---|---|---|
| 2 Access control | PR.AA-01, PR.AA-05 | A.5.15, A.5.18, A.8.5 | 164.308(a)(4), 164.312(a)(1), 164.312(d) |
| 3 Data protection | PR.DS-01, PR.DS-02 | A.5.12, A.8.24, A.5.33 | 164.312(c)(1), 164.312(e)(1) |
| 4 System use | GV.PO-01, PR.AT-01, DE.CM-03 | A.5.10, A.6.3, A.8.16 | 164.308(a)(5), 164.312(b) |
| 5 Governance | GV.RR-02 | A.5.2, A.5.4 | 164.308(a)(2) |

## 7. Exceptions

Exceptions need a business reason, compensating controls, an owner and an expiry date, and are approved by the CISO and
recorded in the exception register (CISO Assistant). Expired exceptions are escalated automatically.

## 8. Enforcement

Technical controls enforce this policy where possible (Keycloak role gates, MFA, lockout, SSH keys only, file integrity
monitoring, Wazuh alerting). Violations are handled under the HR sanctions policy and, where required, reported to regulators.

## 9. Communication

The policy is published on the intranet, taught in onboarding and annual security training, acknowledged by each user,
and repeated at every login through the system-use banner.
