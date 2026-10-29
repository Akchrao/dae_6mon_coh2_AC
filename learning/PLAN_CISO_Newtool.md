# learning/PLAN.md

> This is my one-page learning plan for the month. I will complete and commit this file during the 15-minute selection clinic. It records the technology I chose to learn, why I chose it for my capstone, the three focused tasks I will complete, and the proof I will capture to show I did the work.

---

## Student commitment

-   **Name:** Akhila
-   **Date created:** 2026-10-28

I commit to treat this plan as my personal roadmap: I will keep dates realistic, finish each small task, capture evidence of success, and update this file if anything changes.

---

## Chosen technology

-   **Technology name:** CISO Assistant Community Edition (intuitem), an open-source GRC platform
-   **Technology version (if applicable):** Latest stable release tag from the project's GitHub Releases page (I will record the exact version number here after the first install). I will not use the `main` branch, since the project says it can have breaking changes.

### Why I chose this technology

Care Access Navigator already includes a risk register, control matrix, evidence index, gap assessment, exceptions and remediation tracking (design doc Weeks 8–11), and I was planning to build these by hand in Excel and Monday.com. CISO Assistant gives me one real GRC platform where I can model my healthcare environment as assets, log IAM risks, link them to applied controls, assess those controls against the HIPAA framework (NIST SP 800-66) and NIST CSF 2.0, attach evidence, and generate dashboard data for my Tableau/management report. This adds the GRC half of my "IAM + GRC" story with a tool that real security teams use.

### Where this fits in the project

| Project week (design doc) | What CISO Assistant adds |
| --- | --- |
| Week 8: Risk assessment | Task 2: risk register with scoring and treatment |
| Week 9: Controls and compliance mapping | Task 2 and 3: applied controls, framework mapping, gap assessment |
| Week 10: Evidence, exceptions, remediation | Task 3: evidence attachments, exceptions, remediation actions |
| Week 11: GRC dashboard | Task 3: analytics export feeding Tableau/summary report |

Scope note: CISO Assistant covers governance, risk and compliance only. Keycloak remains my identity lab, and CSV/SIEM analysis remains my monitoring layer. I will describe results as "mapped to HIPAA/NIST concepts" and will not claim formal compliance or certification, in line with the design document.

---

## First-day actions (complete in the 15-minute selection clinic)

1. Finalize the **Chosen technology** and **Why I chose this technology** fields above.
2. Draft three small integration tasks below with realistic start and target completion dates.
3. Commit this file to the repository at `learning/PLAN.md` before the end of the 15-minute clinic.
4. Record where I will start Task 1 (for example: local branch name or workspace folder) under Task 1.
5. If a task feels too large, I will make it smaller and update the dates here.

---

## My three integration tasks (small, testable, dated)

**Task 1 — Title: Deploy CISO Assistant and model the CareAccess environment**

-   **Description:** Run CISO Assistant locally with Docker Compose, create the superuser, and build the CareAccess Navigator structure: one domain, one project/perimeter, and the assets (Keycloak IdP, Patient Portal, EHR Simulator, Billing App, HR App). Import the HIPAA (NIST SP 800-66) and NIST CSF 2.0 framework libraries.
-   **Start date:** 2026-10-29
-   **Target completion date:** 2026-11-04
-   **Success criterion (explicit):** I can log in at `https://localhost:8443`, both framework libraries show as loaded, and all 5 assets appear in the asset list with an owner and a type (primary or supporting).
-   **Proof method (what I will capture to show success):** Screenshot of the logged-in dashboard, screenshot of the asset list, output of `docker compose ps` showing the containers running, and a short "install steps and issues" note in `learning/README.md`.
-   **Where I will start Task 1:** local branch `feature/ciso-assistant-setup`, workspace folder `learning/ciso-assistant/`

**Task 2 — Title: Build the IAM risk register and applied controls**

-   **Description:** Enter 8–10 risks taken from my project scenarios (for example: stale vendor access, orphaned account after a leaver, excessive ePHI access, privilege escalation, repeated failed logins, missed access review). Score each risk using the platform's risk matrix, link it to assets, and create applied controls (RBAC matrix, JML process, quarterly access review, MFA expectation, SIEM detection) with an owner and status.
-   **Start date:** 2026-11-05
-   **Target completion date:** 2026-11-11
-   **Success criterion (explicit):** At least 8 risks exist with inherent and residual scores, and each risk is linked to at least 1 asset and at least 1 applied control. Every applied control has an owner and a status.
-   **Proof method (what I will capture to show success):** Screenshot of the risk matrix view, an exported risk register (CSV or Excel) saved to `learning/evidence/risk_register_export.csv`, and a short table in `learning/README.md` mapping each risk to its control.

**Task 3 — Title: Run a HIPAA access-control assessment, attach evidence, and export dashboard data**

-   **Description:** Create a compliance assessment against the HIPAA (NIST SP 800-66) framework, limited to access-related requirements (access control, workforce security, authentication, audit controls). Link requirements to my applied controls, attach evidence from the project (RBAC matrix, access review report, incident log, JML test results), and record at least 3 gaps as remediation actions or exceptions with due dates. Then export the dashboard and assessment data for my Tableau or summary report.
-   **Start date:** 2026-11-12
-   **Target completion date:** 2026-11-18
-   **Success criterion (explicit):** At least 15 requirements are assessed with a status, at least 5 have evidence attached, and at least 3 gaps have a remediation action or documented exception with an owner and due date. The compliance chart shows non-zero results.
-   **Proof method (what I will capture to show success):** Screenshot of the assessment progress and compliance chart, screenshot of an evidence item linked to a requirement, exported assessment data saved to `learning/evidence/assessment_export.csv`, and a one-paragraph summary of the gaps in `learning/README.md`.

> Note: Each task is small enough to be one focused build session or one short demo.

---

## Risks, assumptions, and blockers (one-line each)

-   Requires Docker (version 25 or newer) and, on Windows, Docker Desktop with WSL2; I will check this before Task 1.
-   Needs enough RAM and disk for several containers; if my laptop struggles, I will use the free cloud trial instance as a fallback.
-   Framework libraries are loaded from the app's library store; some frameworks need a manual Excel download, so I will use the built-in NIST SP 800-66 (HIPAA) and NIST CSF 2.0 libraries first.
-   Depends on earlier project outputs (RBAC matrix, access review, incident log); if one is missing, I will use a sample file and note it as a gap.
-   Project data must stay synthetic: no real names, patient data, or credentials in screenshots or exports.
-   Do not use the `main` branch of the repo; use a tagged stable release.

---

## My weekly timeline (one-line plan)

-   **Week 1 (Oct 28 – Nov 4):** Commit this PLAN and complete Task 1 (install, frameworks, assets).
-   **Week 2 (Nov 5 – Nov 11):** Complete Task 2 (risk register and applied controls).
-   **Week 3 (Nov 12 – Nov 18):** Complete Task 3 (assessment, evidence, gaps, exports) and get a peer review of the evidence.
-   **Week 4 (Nov 19 – Nov 25):** Finalize exports, write `learning/README.md` and `learning/REFLECTION.md`, and add the CISO Assistant screenshots to my demo materials.
