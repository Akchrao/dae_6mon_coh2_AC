#!/usr/bin/env bash
# TEST-ONLY: rebuild a replica of Akhila's realm state as captured in E-AC-01/E-AC-02 (2026-10-13)
set -e
K="$KCADM"
$K config credentials --server http://localhost:8080 --realm master --user admin --password 'LabAdmin!2026' >/dev/null
R=care-access-navigator
$K create realms -s realm=$R -s enabled=true -s 'passwordPolicy=length(10) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and passwordHistory(3)' -s bruteForceProtected=false -s failureFactor=30 -s eventsEnabled=true -s adminEventsEnabled=true
for r in clinician nurse billing hr it-support security-analyst vendor; do $K create roles -r $R -s name=$r; done
mk(){ $K create clients -r $R -s clientId=$1 -s enabled=true -s publicClient=false -s fullScopeAllowed=false -s directAccessGrantsEnabled=true -s 'redirectUris=["http://localhost:9000/*"]' -s secret=$1-secret >/dev/null; }
for c in billing-app ehr-simulator patient-portal hr-app; do mk $c; done
scope(){ cid=$($K get clients -r $R -q clientId=$1 --fields id --format csv --noquotes); shift; for role in "$@"; do $K add-roles -r $R --cid $cid --rolename $role >/dev/null 2>&1 || true; rid=$($K get roles/$role -r $R --fields id --format csv --noquotes); $K create clients/$cid/scope-mappings/realm -r $R -b "[{\"id\":\"$rid\",\"name\":\"$role\"}]"; done; }
scope billing-app billing; scope ehr-simulator nurse clinician; scope patient-portal nurse clinician; scope hr-app hr it-support
u(){ $K create users -r $R -s username=$1 -s enabled=true -s firstName=Test -s lastName=$1 -s email=$1@hrmc.example >/dev/null; $K set-password -r $R --username $1 --new-password 'Synthetic!Pass1'; $K add-roles -r $R --uusername $1 --rolename $2; }
u test.billing1 billing; u test.clinician1 clinician; u test.hr1 hr; u test.itsupport1 it-support; u test.nurse1 nurse; u test.secanalyst1 security-analyst; u test.vendor1 vendor
$K create authentication/flows/browser/copy -r $R -s newName=browser-mfa-privileged
echo replica ready
