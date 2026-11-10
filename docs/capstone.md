---
title: "Care Access Navigator: IAM + GRC Capstone"
permalink: /capstone/
layout: single
toc: true
toc_label: "On this page"
toc_sticky: true
---

{% assign repo = "https://github.com/Akchrao/dae_6mon_coh2_AC" %}

<div style="background:#f8f9fa; padding:1.5rem; border-radius:8px; margin:0 0 2rem; border-left:4px solid #0070f3;">
  <p style="margin:0 0 .5rem;"><strong>What:</strong> Identity and Access Management (IAM) plus Governance, Risk and Compliance (GRC) for a simulated hospital, HealthLine Regional Medical Center</p>
  <p style="margin:0 0 .5rem;"><strong>When:</strong> 12 weeks, Aug 17 – Nov 5, 2026 · 48 of 48 planned tasks completed</p>
  <p style="margin:0 0 .5rem;"><strong>Tech stack:</strong> Microsoft Entra ID, Keycloak, Python, Docker, Wazuh, Microsoft Azure, CISO Assistant</p>
  <p style="margin:0;"><strong>Data:</strong> synthetic people and records only · mapped to HIPAA and NIST concepts, no certification claimed</p>
</div>

## The problem

Hospitals hold patient health information (ePHI) and card data. Access goes wrong in five common ways:

1. People get **more access** than their job needs
2. **Movers** keep the access of their old job
3. Temporary access, like a vendor’s, **never ends**
4. **Leavers** can still sign in
5. Nobody can **prove** any of it is controlled

The capstone answers each one: least privilege, a clean joiner/mover/leaver process, strong sign-in, detection and response, and governance that proves it.

## Architecture

| Layer | What it does |
|---|---|
| **Microsoft Entra ID** | Workforce identities and app roles; MFA through Security defaults |
| **Keycloak** | Identity broker: 7 job roles and groups, MFA for privileged roles, lockout, a sign-in gate per app |
| **4 healthcare apps** | EHR, Patient Portal, Billing, HR (simulated) |
| **Logs and detection** | Sign-in and admin events exported and hashed; 7 identity detection rules; Wazuh SIEM in the incident lab |
| **CISO Assistant** | GRC system: risks, controls, evidence, HIPAA and NIST CSF audits, exceptions, corrective actions |
| **Automation** | `can_iam.py` (Python) runs joiners, movers, leavers, access reviews and checks, logging every action |

## Identity and access

**Federation (Entra ID → Keycloak).** People sign in at Microsoft; an OpenID Connect token carries their app role;
Keycloak’s identity provider maps it to one of 7 realm roles (sync mode FORCE, so Entra always wins); each app admits only its approved roles.

**Least privilege (RBAC).** Access is granted only through job-function groups, never to a person directly:

| Role | EHR | Patient Portal | Billing | HR app | MFA |
|---|:-:|:-:|:-:|:-:|:-:|
| Clinician, Nurse | ✓ | ✓ | – | – | – |
| Billing | – | – | ✓ | – | Required |
| HR | – | – | – | ✓ | – |
| IT-Support | – | – | – | ✓ | Required |
| Security-Analyst, Vendor | – | – | – | – | Required / per request |

**Joiner, mover, leaver.** Tested across Entra ID and Keycloak, then automated:
a new physician gets only clinical apps; a nurse moving to billing loses clinical access before gaining billing;
a leaver is disabled everywhere. The leaver test exposed a real gap: 12 minutes after an Entra disable, the Keycloak copy was still enabled.
It is tracked as a finding and a High risk until automatic deprovisioning is built.

**Sign-in hardening.** MFA for privileged roles, lockout after 10 failures, 12-character passwords and per-app gates,
each proven before and after on the live lab. Control tests passing: **57% → 86%**.

## Detection and incident response

- **7 identity detection rules:** password guessing, disabled-account sign-in, sign-in while locked, unapproved app, privilege change, expired access, bulk patient-record access
- **Logs:** 5 log sets (sign-in, admin, EHR access, detections, automation), exported and indexed with SHA-256
- **Incident response (NIST SP 800-61):** 3 incidents handled with a Wazuh SIEM. The main one, misuse of a patient record by a moved employee, was **detected in 1.3 s and contained 49 s later**, with forensics, root-cause analysis and a HIPAA breach risk assessment

## Risk and GRC

**Risk register:** 5 IAM risks (excessive privileges, terminated account still active, credential compromise, privileged misuse, expired vendor access),
scored on a **5 × 5 likelihood × impact matrix** and evaluated four ways: qualitative scoring, quantitative ALE and EMV,
a weighted business-impact model, and business impact analysis (RTO/RPO).

**GRC in CISO Assistant:**

| | |
|---|---|
| Risks | 5, linked to assets and controls |
| Controls | 18 (12 active) |
| Evidence | 43 files, each with a SHA-256 hash |
| HIPAA (NIST SP 800-66) | 25 access requirements: **17 compliant, 7 partial, 1 non-compliant** |
| NIST CSF 2.0 | 15 subcategories mapped |
| Exceptions | 8, each approved with an expiry date |
| Corrective actions | 19 tracked, 9 verified |

One traceable chain: **lab test → risk → control → evidence → HIPAA requirement → finding → corrective action.**

## Results

- **10 / 10** end-to-end test cases passed (joiner to leaver, lockout, privileged change, vendor expiry, access review)
- **16 / 16** accounts reviewed and signed in the quarterly access review
- **4 of 6** findings from my own compliance audit closed with before-and-after evidence; the other 2 governed as exceptions

## Lessons learned

- **Verify status, don’t trust it:** every “done” points to evidence
- **Configured is not working:** test the person who should be stopped
- **Federation copies identities:** each copy needs its own control
- **Cost limits shape compliance:** govern the gap openly as an exception

## Explore the evidence

- [Project workspace]({{ repo }}/tree/main/Care_Access_Navigator)
- [GRC exports from CISO Assistant]({{ repo }}/tree/main/Care_Access_Navigator/07_GRC)
- [End-to-end test report]({{ repo }}/blob/main/Care_Access_Navigator/06_Evidence/04_Test_Results/CAN_DOC_End_to_End_Test_Report_v1.0.pdf)
- [Entra ID identity governance design]({{ repo }}/blob/main/Care_Access_Navigator/03_IAM_Lab/CAN_DOC_Entra_ID_Identity_Governance_Design_v1.0.pdf)
- [Authentication and privileged access]({{ repo }}/blob/main/Care_Access_Navigator/07_GRC/02_Controls/CAN_DOC_Authentication_and_Privileged_Access_v1.0.pdf)
- [Portfolio index and lessons learned]({{ repo }}/blob/main/Care_Access_Navigator/09_Portfolio/01_Documents/CAN_DOC_Portfolio_Index_and_Lessons_Learned_v1.1.pdf)

<div style="text-align:center; margin-top:3rem; padding:2rem; background:#f8f9fa; border-radius:8px;">
  <h3 style="margin-top:0;">Want to talk about the project?</h3>
  <p><a href="{{ '/contact/' | relative_url }}" style="background:#0070f3; color:white; padding:0.5rem 1.5rem; text-decoration:none; border-radius:99px; font-weight:600;">Get in Touch</a></p>
</div>

<div style="text-align:center; margin-top:2rem;">
  <a href="https://www.mydae.org/" target="_blank" rel="noopener">
    <img src="{{ '/assets/img/dae-logo.png' | relative_url }}" alt="DAE Logo" style="height:40px; opacity:0.8; box-shadow:none;">
  </a>
</div>

<!-- Google tag (gtag.js) -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-4NCZMZSGWD"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){ dataLayer.push(arguments); }
  gtag('js', new Date());
  gtag('config', 'G-4NCZMZSGWD');
</script>
