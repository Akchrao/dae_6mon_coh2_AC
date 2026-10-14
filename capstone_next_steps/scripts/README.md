# can_iam.py: Care Access Navigator IAM automation

One Python file (standard library only, so there's nothing to `pip install` and no admin rights needed). It closes the Compliance 1 audit findings F-01, F-02, F-04 and F-05 in your Keycloak realm, and it produces the evidence for JML, access review, MFA, lockout and SAML SSO.

> **Tested on 2026-10-13** against a replica of your realm (Keycloak 26.0.7, same 7 roles, 4 clients, 7 test users and the same weak settings as evidence E-AC-01/E-AC-02). See `replica-test-evidence/`. The replica is not your lab, so you still need to run it on your Mac to get your own evidence.

---

## Before you start (5 min)

1. Start your lab: open **Terminal**, then run `cd ~/Desktop/dae_6mon_coh2_AC/care-access-navigator-iam-lab && docker compose up -d`
2. Check it's up: open http://localhost:8080 in the browser and sign in to the admin console. **Stop and confirm.**
3. **Export your realm first.** This is your rollback point. In the admin console, open **Realm settings**, then **Action** (top right), then **Partial export**. Tick groups/roles and clients, and save the file as `CAN_realm_export_BEFORE_2026-10-xx.json` in `semester_3/Care_Access_Navigator/03_IAM_Lab/01_Keycloak/02_Realm_Exports/`.
4. In the same Terminal, set your admin login. Use the values from your `.env`, and **never commit them to GitHub**:
   ```bash
   cd ~/Desktop/dae_6mon_coh2_AC/capstone_next_steps/scripts
   export KC_ADMIN='<KC_ADMIN_USERNAME from .env>'
   export KC_ADMIN_PW='<KC_ADMIN_PASSWORD from .env>'
   export CAN_EVIDENCE=./evidence
   ```

## Run order (each line = one evidence step; screenshot the Terminal after each)

| # | Command | What it proves | Closes |
|---|---|---|---|
| 1 | `python3 can_iam.py review --review-id AR-BASELINE` | "Before" access list: direct roles, no MFA, no groups | evidence for F-05 |
| 2 | `python3 can_iam.py verify --username test.billing1 --password '<pw>' --clients billing-app --lockout-user test.vendor1 --unlock` | **Before**: billing logs in without MFA, and 11 bad passwords do **not** lock | baseline (proof the gap was real) |
| 3 | `python3 can_iam.py harden --migrate` | Lockout 10 fails / 30 min, 12-char + history 4, role-based MFA flow, 7 RBAC groups, users moved into groups | F-01, F-02, F-04 |
| 3b | `python3 can_iam.py app-gate` | Per-app gate: only approved roles can sign in (Billing→billing-app, Clinician/Nurse→EHR & Portal, HR/IT-Support→hr-app) | "checking access of applications" |
| 4 | same command as #2, plus `python3 can_iam.py verify --username test.clinician1 --password '<pw>' --clients ehr-simulator billing-app` | **After**: `MFA_REQUIRED`, `PASS (locked after 10 failures)`, clinician `LOGGED_IN` to EHR but `DENIED (role not approved)` on billing-app | Proof of prevention |
| 5 | `python3 can_iam.py joiner --username test.nurse2 --first Maya --last Rivera --email test.nurse2@hrmc.example --role nurse --department "Med-Surg 4W" --manager nurse.manager1 --ticket REQ-2026-0101 --temp-password 'Temp!Onboard2026'` | Joiner: one group, temp password, MFA enrolment if privileged | Week 4 Day 1 |
| 6 | `python3 can_iam.py mover --username test.nurse2 --new-role billing --department "Patient Financial Services" --manager billing.manager1 --ticket CHG-2026-0201` | Mover: old role removed *before* new one added, sessions killed | Week 4 Day 2 |
| 7 | `python3 can_iam.py leaver --username test.nurse1 --manager nurse.manager1 --ticket TERM-2026-0301 --password '<old pw>'` | Leaver: disabled, signed out, groups stripped, login refused | Week 4 Day 3 |
| 8 | `python3 can_iam.py review --review-id AR-2026-Q4` | Quarterly access-review CSV with risk flags. Open it in Excel, fill `reviewer_decision`, and sign. | Week 4 Day 4, F-05 |
| 8b | `python3 can_iam.py detect --ehr-log sample_ehr_access_log.csv` | Simulated SIEM: rules CAN-ID-001 to 007 over Keycloak events (brute force, disabled-account login, login while locked, unapproved app, privilege change, **expired access still in use**) plus the synthetic EHR log (**excessive patient-record access**, 15+ patients in 60 min) → `identity_detections.csv`. To trigger CAN-ID-006, create a vendor with `joiner ... --end-date` set to yesterday, then sign in as them. See `docs/adr/ADR-SIEM-choice.md` | Proof of detection, Week 6; all 5 design-doc monitoring use cases |
| 9 | `python3 can_iam.py saml-demo --username test.clinician1 --password '<pw>'` | SAML 2.0 federation: partner realm logs in through HRMC and receives a signed assertion | Federation (SAML/SSO) |

After each run, `evidence/` holds `can_iam_audit_log.jsonl` (who/what/when, before vs after), the CSVs and XML, and a fresh `EVIDENCE-INDEX-SHA256.txt`.

## Things to know (gotchas)

* **Entra ID users (`entra-id.*`) get their role from Entra**, not from a Keycloak group. `harden --migrate` skips them, `review` doesn't flag their directly mapped role, `app-gate` grants app access through the job role so they aren't blocked, and `mover` refuses them (change their app role in Entra instead). `leaver` still disables the Keycloak copy and reminds you to block sign-in in Entra too.
* **Entra ID users (`entra-id.*`)** log in through Entra, not the Keycloak password form, so Keycloak's OTP step doesn't apply to them. Enforce MFA on the Entra side with **Security defaults** (free) or Conditional Access (needs P1), and write that down as a compensating control.
* `harden` sets the realm's **browser flow** to `browser-mfa-privileged`. MFA then follows the *person* (anyone in Billing, IT-Support or Security-Analysts), not just the app. Clinicians, nurses, HR and vendors are not prompted. Change `PRIVILEGED` at the top of the script if your policy differs.
* Your admin account lives in the **master** realm, so the realm changes don't affect it.
* **Rollback:** set the realm browser flow back to `browser` in the admin console (**Authentication**, then **browser**, then **Bind flow**), or re-import your export from step 3.
* The app gate runs *after* the password and OTP steps, so a privileged user who opens an app they aren't approved for still gets the MFA prompt before the "Access denied" page. In testing, several quick denied sign-ins in a row also tripped Keycloak's quick-login brute-force check. That's why `verify` waits 1.5 s between attempts.
* The `verify` lockout test **locks the user for 30 min** unless you add `--unlock`.
* The SAML demo creates a second realm, `partner-clinic`. Delete it after you've captured your evidence if you like.
