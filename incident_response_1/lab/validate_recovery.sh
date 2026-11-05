#!/bin/sh
# validate_recovery.sh - recovery validation checklist, runs INSIDE parrot-vm as root (guest agent).
# Prints one TSV row per check: id, area, check, expected, actual, PASS/FAIL. Host-side network probes are run by
# run_task6.sh from the other machines on the network. Exit code = number of failed checks.
F=0
r() {  # r <id> <area> <check> <expected> <actual>
  if [ "$4" = "$5" ]; then res=PASS; else res=FAIL; F=$((F + 1)); fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$res"
}
yn() { if sh -c "$1" >/dev/null 2>&1; then echo yes; else echo no; fi; }
printf 'id\tarea\tcheck\texpected\tactual\tresult\n'

# --- integrity: the restored system is clean
r INT-01 Integrity "OS package files unmodified (dpkg -V, non-config; Wazuh agent state excluded)" 0 "$(dpkg -V 2>/dev/null | awk '$2 != "c"' | grep -vc ' /var/ossec/')"
r INT-01b Integrity "Wazuh agent binaries unmodified (dpkg -V, /var/ossec/bin)" 0 "$(dpkg -V wazuh-agent 2>/dev/null | grep -c ' /var/ossec/bin/')"
r INT-02 Integrity "staged record / uploader folder absent" no "$(yn 'test -e /home/test.nurse/.cache/.sync')"
r INT-03 Integrity "no user crontabs in /var/spool/cron/crontabs" 0 "$(ls /var/spool/cron/crontabs 2>/dev/null | wc -l)"
r INT-04 Integrity "no syncd.py process" 0 "$(pgrep -fc '^python3 .*[s]yncd')"
r INT-05 Integrity "no SUID/SGID files in user-writable paths" 0 "$(find /home /tmp /var/tmp /dev/shm -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | wc -l)"
# --- identity and access (root cause)
r IAM-01 Identity "test.nurse NOT in clinical (mover rule)" no "$(yn 'id -nG test.nurse | tr " " "\n" | grep -qx clinical')"
r IAM-02 Identity "test.nurse locked + expired (pending HR)" "L 1970-01-02" "$(passwd -S test.nurse | awk '{print $2}') $(chage -l test.nurse | awk -F': ' '/Account expires/{print $2}' | xargs -I{} date -d '{}' +%F)"
r IAM-03 Identity "test.billing (leaver) locked + expired" "L 1970-01-02" "$(passwd -S test.billing | awk '{print $2}') $(chage -l test.billing | awk -F': ' '/Account expires/{print $2}' | xargs -I{} date -d '{}' +%F)"
r IAM-04 Identity "no SSH keys on disabled accounts" 0 "$(ls /home/test.nurse/.ssh/authorized_keys /home/test.billing/.ssh/authorized_keys 2>/dev/null | wc -l)"
r IAM-05 Identity "sudo group = it_admin only" it_admin "$(getent group sudo | cut -d: -f4)"
su -s /bin/sh test.clinician -c 'ehr-view PT-1001' >/dev/null 2>&1; rc=$?
r IAM-06 Identity "clinician can still view a record (no over-correction)" 0 "$rc"
setpriv --reuid=test.nurse --regid=test.nurse --init-groups /usr/local/bin/ehr-view PT-1003 >/dev/null 2>&1; rc=$?
r IAM-07 Identity "billing role is denied clinical record PT-1003" 1 "$rc"
r IAM-08 Identity "users other than root cannot use cron" root "$(cat /etc/cron.allow 2>/dev/null | paste -sd,)"
# --- services
for s in ssh cron ehr-portal auditd rsyslog ir-firewall wazuh-agent; do
  r "SVC-$s" Services "$s active + enabled at boot" "active enabled" "$(systemctl is-active $s) $(systemctl is-enabled $s 2>/dev/null)"
done
# --- network configuration
IF0=$(ip -o link | awk -F': ' '/52:54:00:0a:00:10/{print $2}'); IF1=$(ip -o link | awk -F': ' '/52:54:00:0a:00:50/{print $2}')
r NET-01 Network "clinical NIC $IF0 up with 10.0.2.15/24" "UP 10.0.2.15/24" "$(ip -br addr show $IF0 | awk '{print $2, $3}')"
r NET-02 Network "default route via clinical NAT gateway" "10.0.2.2 $IF0" "$(ip route show default | awk '{print $3, $5}' | head -1)"
r NET-03 Network "quarantine NIC $IF1 has no address" "" "$(ip -br -4 addr show $IF1 | awk '{print $3}')"
r NET-04 Network "firewall policies INPUT/FORWARD/OUTPUT = DROP" 3 "$(iptables -S | grep -cE '^-P (INPUT|FORWARD|OUTPUT) DROP')"
r NET-05 Network "egress to IOC 10.78.99.66:8080 blocked" 000 "$(curl -s -m 5 -o /dev/null -w '%{http_code}' http://10.78.99.66:8080/)"
r NET-06 Network "egress HTTP for updates allowed" 200 "$(curl -s -m 10 -o /dev/null -w '%{http_code}' http://deb.debian.org/debian/)"
r NET-07 Network "DNS resolution works" yes "$(yn 'getent hosts deb.debian.org')"
r NET-08 Network "clock synchronised by NTP" yes "$(timedatectl show -p NTPSynchronized --value)"
# --- monitoring still sees what matters
r MON-01 Monitoring "auditd incident watches loaded (5 keys)" 5 "$(auditctl -l | grep -oE '(-k |key=)(ehr-read|cron-persist|identity|user-exec|sudoers)' | sed 's/.* //; s/key=//' | sort -u | wc -l | tr -d ' ')"
r MON-02 Monitoring "EHR audit logged the clinician view (IAM-06)" yes "$(yn 'tail -5 /var/log/ehr-audit.log | grep -q "user=test.clinician action=VIEW patient=PT-1001 decision=ALLOW"')"
r MON-03 Monitoring "EHR audit logged the billing denial (IAM-07)" yes "$(yn 'tail -5 /var/log/ehr-audit.log | grep -q "user=test.nurse action=VIEW patient=PT-1003 decision=DENY"')"
r MON-04 Monitoring "firewall logged the IOC block (NET-05)" yes "$(sleep 1; yn 'dmesg | tail -20 | grep -q IOC-BLOCK')"
r MON-05 Monitoring "Wazuh agent connected to the manager" connected "$(grep -oE "status='[a-z]+'" /var/ossec/var/run/wazuh-agentd.state | cut -d"'" -f2)"
exit $F
