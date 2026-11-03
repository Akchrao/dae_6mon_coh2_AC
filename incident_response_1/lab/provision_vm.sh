#!/bin/sh
# provision_vm.sh - runs INSIDE parrot-vm as root (sent over the guest agent by run_lab.sh).
# Recreates the Care Access Navigator JML state from capstone_next_steps/jml-evidence/JML-LOG.csv
# on the Linux host, plus the EHR services and the audit trail used by Tasks 1-6.
# The public key for the macOS host is passed in $MAC_PUB. Patient records are SYNTHETIC.
set -e
# network: cloud-init pinned the golden build's NIC by MAC. Re-key to the lab adapters:
#   52:54:00:0a:00:10 = adapter 1 (clinical, DHCP from the hypervisor NAT)
#   52:54:00:0a:00:50 = adapter 2 (quarantine) - deliberately left unconfigured until containment
echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
rm -f /etc/netplan/50-cloud-init.yaml
cat > /etc/netplan/60-ir-lab.yaml <<'EOF'
network:
  version: 2
  ethernets:
    clinical:
      match: {macaddress: "52:54:00:0a:00:10"}
      dhcp4: true
EOF
chmod 600 /etc/netplan/60-ir-lab.yaml; netplan apply; sleep 3
groupadd -f clinical; groupadd -f billing; groupadd -f disabled-users
id it_admin >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo -c "IT Administrator (lab)" it_admin
echo "it_admin ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/it_admin; chmod 440 /etc/sudoers.d/it_admin
# joiner REQ-2026-0101: Sathya Hasi -> Clinician
id test.clinician >/dev/null 2>&1 || useradd -m -s /bin/bash -G clinical -c "Sathya Hasi (Physician)" test.clinician
# mover CHG-2026-0201: Tara Jones Nurse -> Billing. Billing added; clinical NOT removed (the IR1-2026-005 root cause)
id test.nurse >/dev/null 2>&1 || useradd -m -s /bin/bash -G clinical -c "Tara Jones (RN)" test.nurse
usermod -aG billing -c "Tara Jones (Billing Specialist)" test.nurse
# leaver TERM-2026-0301: Jeevan Smith - locked, expired, in DenyGroups
id test.billing >/dev/null 2>&1 || useradd -m -s /bin/bash -G billing -c "Jeevan Smith (Billing Specialist)" test.billing
usermod -L -e 1 -aG disabled-users test.billing
for u in test.clinician test.nurse test.billing; do
  install -d -m 700 -o $u -g $u /home/$u/.ssh
  echo "$MAC_PUB" > /home/$u/.ssh/authorized_keys; chown $u:$u /home/$u/.ssh/authorized_keys; chmod 600 /home/$u/.ssh/authorized_keys
done

# synthetic EHR records + viewer (same stub as Task 2)
mkdir -p /srv/ehr/clinical /srv/ehr/portal
printf "SYNTHETIC RECORD PT-1001\nPatient: Test Patient One\nDOB: 1961-04-02 (synthetic)\nDx: hypertension (synthetic)\n" > /srv/ehr/clinical/PT-1001.txt
printf "SYNTHETIC RECORD PT-1003\nPatient: Test Patient Three\nDOB: 1979-11-23 (synthetic)\nMRN: SYN-0003\nDx: type 2 diabetes (synthetic)\n" > /srv/ehr/clinical/PT-1003.txt
chgrp -R clinical /srv/ehr/clinical; chmod 750 /srv/ehr/clinical; chmod 640 /srv/ehr/clinical/*
echo "Care Access Navigator EHR portal (lab) - clinic schedule service" > /srv/ehr/portal/index.html
cat > /usr/local/bin/ehr-view <<'EOF'
#!/bin/sh
# ehr-view <patient-id> - EHR record viewer stub. clinical group may view; every view is audited (local5).
U=$(id -un); P="$1"; F="/srv/ehr/clinical/$P.txt"
if id -nG "$U" | tr ' ' '\n' | grep -qx clinical && [ -r "$F" ]; then
  logger -p local5.info -t ehr-audit "user=$U action=VIEW patient=$P decision=ALLOW basis=group:clinical"
  cat "$F"
else
  logger -p local5.notice -t ehr-audit "user=$U action=VIEW patient=$P decision=DENY basis=no-clinical-role"
  echo "ehr-view: access denied" >&2; exit 1
fi
EOF
chmod 755 /usr/local/bin/ehr-view

# EHR portal service hosted on this machine (shut down during containment)
cat > /etc/systemd/system/ehr-portal.service <<'EOF'
[Unit]
Description=Care Access Navigator EHR portal (lab)
After=network.target
[Service]
ExecStart=/usr/bin/python3 -m http.server 8080 --directory /srv/ehr/portal
User=nobody
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

# logging: EHR audit trail to its own file; verbose sshd; deprovisioned group denied
echo 'local5.*  /var/log/ehr-audit.log' > /etc/rsyslog.d/50-ehr.conf
printf 'LogLevel VERBOSE\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nDenyGroups disabled-users\n' > /etc/ssh/sshd_config.d/ir-lab.conf
# auditd: record reads of patient files, identity-file changes, and every command run by a real user
cat > /etc/audit/rules.d/ir-lab.rules <<'EOF'
-w /srv/ehr/clinical -p r -k ehr-read
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /var/spool/cron/crontabs -p wa -k cron-persist
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k user-exec
EOF
augenrules --load >/dev/null 2>&1 || true
systemctl restart rsyslog ssh
systemctl daemon-reload; systemctl enable --now ehr-portal >/dev/null 2>&1
echo "provisioned $(date -u +%FT%TZ)"
