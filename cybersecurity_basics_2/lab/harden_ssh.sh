#!/bin/sh
# CB2: resolve the SSH brute-force alert on hrmc-linux-srv01 (run inside the container)
set -e
passwd -l tjones                                   # lock the compromised account pending review
usermod -s /usr/sbin/nologin tjones
cat > /etc/ssh/sshd_config.d/10-hrmc-hardening.conf <<CONF
# HRMC SSH hardening (POL-SEC-01 sections 2 and 4; procedure PROC-SEC-03)
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30
Banner /etc/issue.net
CONF
cp /tmp/system_use_banner.txt /etc/issue.net
sshd -t                                            # validate config before applying
kill -HUP "$(cat /run/sshd.pid)"
echo "ssh hardened"
