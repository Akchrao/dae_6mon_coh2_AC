#!/usr/bin/env bash
# Records cli_walkthrough.txt: the irtrack workflow on a scratch database, then the real register.
cd "$(dirname "$0")"; D=$(mktemp -d)/demo.db
{ echo "# irtrack CLI walk-through on a scratch database (IRTRACK_DB=demo.db) - the real register is incidents.db"
  run() { echo; echo "\$ irtrack.py $*"; IRTRACK_DB="$D" python3 -I irtrack.py "$@" 2>&1 | sed "s#$D#demo.db#"; }
  run init
  run new IR1-2026-099 --title "DEMO: unapproved sudo grant" --type "Unauthorized privilege escalation" --severity SEV-2 \
      --detected 2026-11-03T20:00:00Z --source "Wazuh 100230" --handler "A. Chennamaneni" --summary "walk-through only"
  run status IR1-2026-099 Triage --at 2026-11-03T20:05:00Z --note "validated on host"
  run action IR1-2026-099 --at 2026-11-03T20:06:00Z --phase Containment --by "A. Chennamaneni" --what "gpasswd -d test.clinician sudo" --result removed
  run status IR1-2026-099 Contained --at 2026-11-03T20:07:00Z
  run status IR1-2026-099 New --at 2026-11-03T20:08:00Z
  run list
  echo; echo "# the real register"; echo "\$ irtrack.py list"; python3 -I irtrack.py list
  echo; echo "\$ irtrack.py export incidents_register.csv"; python3 -I irtrack.py export incidents_register.csv
} > cli_walkthrough.txt
