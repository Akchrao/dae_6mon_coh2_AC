# PROC-SEC-03 Linux server SSH hardening

| | |
|---|---|
| Control | Strong authentication for server access (POL-SEC-01 sections 2.3 and 4.5) |
| Standards | NIST CSF 2.0 PR.AA-03; ISO/IEC 27001 A.8.5; HIPAA 164.312(d); CIS Debian benchmark (SSH section) |
| Owner | IT-Support (servers), verified by the Security Analyst |
| First implemented | 2026-11-19 on hrmc-linux-srv01 (case CB2-2026-001) |

## Purpose

Stop password guessing against servers, show the system-use policy at every login and keep a record that the control works.

## Before you start

- Make sure every person who needs access has an SSH key installed (step 2), or you will lock them out.
- Keep a second session open while you change the configuration.

## Steps

1. **Back up the configuration.** `cp -a /etc/ssh /root/ssh-backup-$(date +%F)`
2. **Install keys for approved users.** Add each user's public key to `~/.ssh/authorized_keys`;
   folder permission `700`, file `600`, owned by the user.
3. **Create the banner.** Put the approved system-use text in `/etc/issue.net` (file `lab/system_use_banner.txt`).
4. **Add the hardening file** `/etc/ssh/sshd_config.d/10-hrmc-hardening.conf`:
   ```
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   PermitRootLogin no
   MaxAuthTries 3
   LoginGraceTime 30
   Banner /etc/issue.net
   ```
5. **Validate before applying.** `sshd -t` must print nothing. If it shows an error, fix it and do not continue.
6. **Apply.** Reload sshd (`systemctl reload ssh`, or `kill -HUP $(cat /run/sshd.pid)` on hosts without systemd).
7. **Verify (all must pass):**
   - `sshd -T | grep -E 'passwordauthentication|permitrootlogin|maxauthtries|banner'` shows the values above
   - a password login is refused: `Permission denied (publickey)`
   - a key login works and shows the banner
   - Wazuh shows the successful key login (rule 5715) for the test user
8. **Record.** Save the transcript, add it to the change ticket or incident case, and update the asset record.

## Roll back

Copy the backup from step 1 back to `/etc/ssh`, run `sshd -t`, then reload.

## Evidence from the first run

`cybersecurity_basics_2/evidence/remediation_transcript.txt`: password login refused, key login with banner, `tjones`
locked, effective settings listed.
