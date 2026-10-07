#!/usr/bin/env bash
# CAN VM hardening: automated patching, host firewall, secure SSH, brute-force protection.
# Usage: sudo ADMIN_IP=<your.public.ip> ./harden.sh
set -euo pipefail
ADMIN_IP="${ADMIN_IP:?set ADMIN_IP to the only address allowed to SSH in}"
ADMIN_USER="${ADMIN_USER:-canadmin}"
export DEBIAN_FRONTEND=noninteractive

echo "[1/5] Patching now + installing security tooling"
apt-get update -q
apt-get -y -q upgrade
apt-get -y -q install unattended-upgrades apt-listchanges ufw fail2ban

echo "[2/5] Automated security patching (unattended-upgrades)"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CFG'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
CFG
cat > /etc/apt/apt.conf.d/52unattended-upgrades-can <<'CFG'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
Unattended-Upgrade::SyslogEnable "true";
CFG
systemctl enable --now unattended-upgrades

echo "[3/5] Host firewall (ufw): deny all inbound except SSH from ${ADMIN_IP}"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw limit from "${ADMIN_IP}" to any port 22 proto tcp comment 'SSH from admin IP (rate-limited)'
ufw logging medium
ufw --force enable

echo "[4/5] SSH hardening"
cat > /etc/ssh/sshd_config.d/00-can-hardening.conf <<CFG
# Loaded before cloud-init's 50-cloudimg-settings.conf, so these values win
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers ${ADMIN_USER}
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
LogLevel VERBOSE
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
Banner /etc/issue.net
CFG
cat > /etc/issue.net <<'CFG'
Authorized access only. Care Access Navigator system - activity is logged and monitored.
CFG
sshd -t
systemctl reload ssh

echo "[5/5] fail2ban: ban IPs after repeated SSH failures"
cat > /etc/fail2ban/jail.d/sshd-can.local <<'CFG'
[sshd]
enabled  = true
backend  = systemd
maxretry = 3
findtime = 10m
bantime  = 1h
CFG
systemctl enable --now fail2ban
systemctl restart fail2ban

echo "Hardening complete."
