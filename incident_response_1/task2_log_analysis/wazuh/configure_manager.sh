#!/bin/sh
# Runs INSIDE the wazuh-manager container (copied to /tmp/task2 by run_lab.sh).
# Installs the Task 2 decoders, rules, CDB lists and inputs, then restarts the manager.
set -e
W=/var/ossec
cp /tmp/task2/local_decoder.xml $W/etc/decoders/local_decoder.xml
cp /tmp/task2/local_rules.xml   $W/etc/rules/local_rules.xml
cp /tmp/task2/lists/*           $W/etc/lists/
cat /tmp/task2/ossec-task2.conf >> $W/etc/ossec.conf
# register the CDB lists inside the existing <ruleset> block (a second <ruleset> block would replace it)
sed -i '0,/<list>etc\/lists\/audit-keys<\/list>/s##<list>etc/lists/audit-keys</list>\n    <list>etc/lists/jml-leavers</list>\n    <list>etc/lists/jml-movers</list>\n    <list>etc/lists/rbac-no-root</list>#' $W/etc/ossec.conf
# the manager's own CIS/SCA and rootcheck scans are not part of this lab - switch them off (alert noise)
sed -i '/<sca>/,/<\/sca>/s#<enabled>yes</enabled>#<enabled>no</enabled>#' $W/etc/ossec.conf
sed -i '/<rootcheck>/,/<\/rootcheck>/s#<disabled>no</disabled>#<disabled>yes</disabled>#' $W/etc/ossec.conf
# macOS log files must exist before logcollector starts; content is appended later
mkdir -p $W/logs/macos
touch $W/logs/macos/install.log $W/logs/macos/ssh_client.log
chown -R wazuh:wazuh $W/etc/lists $W/etc/rules $W/etc/decoders $W/logs/macos
$W/bin/wazuh-control restart >/tmp/restart.log 2>&1 || { tail -20 /tmp/restart.log; exit 1; }
grep -n 'lists/jml\|lists/rbac' $W/etc/ossec.conf
$W/bin/wazuh-control status | grep -E 'analysisd|remoted|logcollector'
