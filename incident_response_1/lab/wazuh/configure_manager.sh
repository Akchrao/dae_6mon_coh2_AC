#!/bin/sh
# Runs INSIDE the wazuh-manager container (lab/wazuh copied to /tmp/w).
#   configure_manager.sh core   - Task 1: decoders, CDB lists, the 3 core rules, macOS inputs
#   configure_manager.sh task2  - Task 2: adds the analysis rules, restarts
set -e
W=/var/ossec
if [ "$1" = core ]; then
  cp /tmp/w/local_decoder.xml $W/etc/decoders/local_decoder.xml
  cp /tmp/w/can_ir1_core_rules.xml $W/etc/rules/
  cp /tmp/w/lists/* $W/etc/lists/
  cat /tmp/w/manager.conf >> $W/etc/ossec.conf
  # register the CDB lists inside the existing <ruleset> block (a second <ruleset> block would replace it)
  sed -i '0,/<list>etc\/lists\/audit-keys<\/list>/s##<list>etc/lists/audit-keys</list>\n    <list>etc/lists/jml-leavers</list>\n    <list>etc/lists/jml-movers</list>\n    <list>etc/lists/rbac-no-root</list>#' $W/etc/ossec.conf
  # the manager's own CIS/SCA and rootcheck scans are not part of this lab (alert noise)
  sed -i '/<sca>/,/<\/sca>/s#<enabled>yes</enabled>#<enabled>no</enabled>#' $W/etc/ossec.conf
  sed -i '/<rootcheck>/,/<\/rootcheck>/s#<disabled>no</disabled>#<disabled>yes</disabled>#' $W/etc/ossec.conf
  mkdir -p $W/logs/macos; touch $W/logs/macos/install.log $W/logs/macos/ssh_client.log
elif [ "$1" = task2 ]; then
  cp /tmp/w/can_ir1_task2_rules.xml $W/etc/rules/
fi
chown -R wazuh:wazuh $W/etc/lists $W/etc/rules $W/etc/decoders $W/logs/macos
$W/bin/wazuh-control restart >/tmp/restart.log 2>&1 || { tail -20 /tmp/restart.log; exit 1; }
ls $W/etc/rules/; grep -c '<rule id' $W/etc/rules/can_ir1_*.xml
$W/bin/wazuh-control status | grep -E 'analysisd|remoted|authd|logcollector'
