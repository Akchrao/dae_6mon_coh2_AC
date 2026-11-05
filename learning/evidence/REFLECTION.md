# Reflection: Learning CISO Assistant

> **DRAFT** - written from the project record (2026-11-05). Rewrite each answer in your own words before submitting;
> delete this note when done.

**Name:** Akhila Chennamaneni  
**Technology:** CISO Assistant Community Edition v4.2.1  
**Plan:** [`PLAN.md`](PLAN.md)

---

## 1. What did I set out to do, and what did I deliver?

I planned three tasks: deploy CISO Assistant and model the Care Access Navigator environment, build the IAM risk register
with applied controls, and run a HIPAA access-control assessment with evidence, gaps and exports. All three are done.
The tool now holds 7 assets, 5 risks (R01-R05), 18 controls, 43 evidence items, 25 assessed HIPAA requirements, a
15-subcategory NIST CSF 2.0 mapping, 8 exceptions and 19 findings. One criterion was missed: I entered 5 risks, not 8.

## 2. What was harder than expected?

-   Moving between Windows and the Mac: the database copied while the app was running was corrupt and had to be recovered.
-   Being honest about status: the scripted leaver test passed, but Entra-triggered automatic deprovisioning is not built,
    so R02 had to stay High and the planned control In progress even though it was tempting to mark it done.
-   Telling "progress" (how much of a framework was assessed) apart from "compliance" (the result).

## 3. What did I learn about GRC that I did not know before?

_Prompt: e.g. how risks, controls, evidence, requirements and findings link together; why existing and additional controls
are separated; why an exception needs an expiry date and an approver; what an auditor can trace from one record to the next._

## 4. How does this change my capstone?

CISO Assistant replaced the hand-built Excel registers and the planned Tableau dashboard as the GRC system of record
(exception EX-08, pending instructor acceptance). The Week 8-11 deliverables are now exports from one tool instead of
separate spreadsheets.

## 5. What would I do differently next time?

_Prompt: e.g. stop the stack before copying the database; pin the image version; enter the remaining risks; record due
dates for every finding (CAN-FIND-001 has none yet); capture screenshots as I go instead of at the end._

## 6. Next steps

-   Add three more risks to reach the planned 8 (candidates: missed access review, privilege escalation through a direct
    role, repeated failed logins).
-   Close CA-13 (OTP enrolment) and CA-12 (rotate lab passwords); give CAN-FIND-001 a due date.
-   Build and test Entra-triggered deprovisioning (CAN-CTRL-JML-002 acceptance test AT-01), then re-score R02.
