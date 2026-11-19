# PB-01 Playbook: account compromise (password guessing, credential theft)

| | |
|---|---|
| Triggers | Wazuh 5763 / 5551 (SSH brute force), 40112 (failures then success), 100502 / 100507 (Keycloak guessing then success), 100602 / 100604 (Windows guessing, RDP from outside) |
| Default severity | SEV-3 if all attempts failed; SEV-2 if a login succeeded; SEV-1 if ePHI was then accessed |
| Owner | Tier 1 SOC analyst; Tier 2 / Incident Commander for SEV-1/2 |
| Example | CB2-2026-001 (tjones on hrmc-linux-srv01, closed 2026-11-19); SOC1-2026-001 (test.nurse2) |

## 1. Identify (0-15 min)
1. Open a case in the tracker (`irtrack.py new`), with the alert IDs and times.
2. Confirm in the dashboard: source IP, target account, number of failures, and whether a success followed from the same source.
3. Check whether the source is internal, a known scanner or an approved test (false positive), or outside / unknown.
4. Look for what happened after the success: sudo, file changes (FIM), outbound connections, record access.

## 2. Contain (15-60 min)
1. Lock or disable the account (Linux `passwd -l`, Keycloak / Entra: disable and revoke sessions).
2. Block the source IP at the firewall or in the IdP.
3. Preserve evidence first: export the alerts and logs and hash them.

## 3. Eradicate
1. Reset credentials; require MFA for the role.
2. Remove the weakness that allowed guessing (servers: PROC-SEC-03 keys-only SSH).
3. Remove persistence: new keys in authorized_keys, cron jobs, new users.

## 4. Recover
1. Re-enable the user only after the HR / manager check and a new credential.
2. Re-test: the old password is refused, legitimate access works, monitoring still sees the host.

## 5. Close and learn
Record the timeline, actions and evidence; write at least 2 lessons; tune rules if they were noisy or late.
