#!/bin/sh
rsyslogd
/usr/sbin/sshd
/var/ossec/bin/wazuh-control start
exec tail -F /var/ossec/logs/ossec.log
