#!/bin/sh
# recover_harden.sh - runs INSIDE parrot-vm as root, over the guest agent, right after the clean snapshot is restored.
# The baseline snapshot is clean (no uploader, no crontab, no staged file) but still carries the conditions that made
# IR1-2026-005 possible. This script removes them (root-cause fixes) and restores normal service.
set -e
echo "== R2.1 identity: apply the JML register correctly (CHG-2026-0201 mover, TERM-2026-0301 leaver)"
gpasswd -d test.nurse clinical 2>/dev/null || true                     # mover keeps billing only (IR1-2026-002)
gpasswd -d test.clinician sudo 2>/dev/null || true                     # no sudo without a change record (IR1-2026-003)
usermod -L -e 1 test.nurse                                             # stays disabled pending HR review (decision IR1-2026-005-D3)
for u in test.nurse test.billing; do                                   # no standing SSH keys for disabled accounts (IR1-2026-001)
  [ -f /home/$u/.ssh/authorized_keys ] && mv /home/$u/.ssh/authorized_keys /root/ir-recovery-removed-$u.authorized_keys || true
done
id test.nurse; id test.billing; passwd -S test.nurse; passwd -S test.billing

echo "== R2.2 persistence vector: only root may use cron (users cannot create crontabs)"
echo root > /etc/cron.allow; chmod 600 /etc/cron.allow
ls -la /var/spool/cron/crontabs/

echo "== R2.3 host firewall baseline (persistent): least-privilege inbound, egress allow-list"
mkdir -p /etc/iptables
cat > /etc/iptables/rules.v4 <<'EOF'
# Care Access Navigator - parrot-vm host firewall baseline (post-incident IR1-2026-002)
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:IOC-BLOCK - [0:0]
-A IOC-BLOCK -m limit --limit 20/min -j LOG --log-prefix "IOC-BLOCK " --log-uid
-A IOC-BLOCK -j DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -s 10.78.50.0/24 -j ACCEPT
-A INPUT -p tcp --dport 8080 -s 10.78.10.0/24 -j ACCEPT
-A INPUT -m limit --limit 20/min -j LOG --log-prefix "FW-DENY-IN "
-A OUTPUT -d 10.78.99.66/32 -j IOC-BLOCK
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -p udp --dport 53 -j ACCEPT
-A OUTPUT -p tcp --dport 53 -j ACCEPT
-A OUTPUT -p udp --dport 123 -j ACCEPT
-A OUTPUT -p udp --dport 67:68 -j ACCEPT
-A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
-A OUTPUT -d 10.78.50.20/32 -p tcp -m multiport --dports 1514,1515 -j ACCEPT
-A OUTPUT -m limit --limit 20/min -j LOG --log-prefix "FW-DENY-OUT " --log-uid
COMMIT
EOF
cat > /etc/systemd/system/ir-firewall.service <<'EOF'
[Unit]
Description=Care Access Navigator host firewall baseline (iptables-restore)
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now ir-firewall.service; systemctl is-active ir-firewall.service

echo "== R2.4 services back to normal"
systemctl unmask cron ehr-portal 2>/dev/null || true
systemctl enable --now cron ehr-portal auditd rsyslog ssh >/dev/null 2>&1
rm -f /etc/ssh/sshd_config.d/00-ir-containment.conf; systemctl reload ssh
systemctl is-active cron ehr-portal auditd rsyslog ssh | paste -sd' '

echo "== R2.5 audit: keep the incident watches, add one for privilege grants (sudoers)"
grep -q 'k sudoers' /etc/audit/rules.d/ir-lab.rules || echo '-w /etc/sudoers.d -p wa -k sudoers' >> /etc/audit/rules.d/ir-lab.rules
augenrules --load >/dev/null 2>&1; auditctl -l
echo "recovered $(date -u +%FT%TZ)"
