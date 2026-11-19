# PB-02 Playbook: suspected data exfiltration from ePHI stores

| | |
|---|---|
| Triggers | Wazuh 100612 (mass EHR export reads), 100651 (mass reads then connection to a bad address), 100630 / 100621 (connection to a known-bad address), FIM 553 / 554 / 550 on ePHI folders, 100522 (bulk EHR access) |
| Default severity | SEV-1 if ePHI may have left HRMC; SEV-2 if it was staged but not sent |
| Owner | Incident Commander; Privacy Officer from the start |
| Example | CB2-2026-002 (staging on hrmc-linux-srv01, closed 2026-11-19); SM1-SCN-01 (rclone to 203.0.113.77) |

## 1. Identify (0-15 min)
1. Open a SEV-1/2 case and page the Incident Commander and Privacy Officer.
2. Establish what data: which files or records (FIM paths, 4663 object names, EHR patient IDs), how many, which classification.
3. Establish where to: destination IP and port, process (rclone.exe, nc, scp), user.
4. Establish when: first read, staging, transfer (correlated alerts give the timeline).

## 2. Contain
1. Block the destination at the egress firewall; isolate the host if transfer is still running.
2. Disable the user account involved (PB-01 steps).
3. Preserve evidence: copy staged files to the evidence store and hash them before removing anything.

## 3. Eradicate
1. Remove staged copies and tools (rclone), restore deleted or changed files from the known-good copy, and verify hashes.
2. Close the path: egress allow-list, remove the role's access to the data, approval for bulk exports.

## 4. Recover
1. Verify integrity of the store (hashes match), FIM back to normal, monitoring active.
2. Watch the user, host and destination closely for 30 days.

## 5. Notify and learn
1. Privacy Officer runs the HIPAA four-factor breach risk assessment; notices within 60 days if required (72 h for EU data).
2. Lessons and rule tuning recorded in the case.
