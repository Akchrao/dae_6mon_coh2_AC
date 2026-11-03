#!/usr/bin/env bash
# =============================================================================
# Care Access Navigator - Incident Response 1: run Tasks 1-6 as ONE continuous exercise on ONE lab
# -----------------------------------------------------------------------------
#   Task 1  build the lab, deploy the Wazuh agent, test the 3 custom rules, prove log collection, baseline snapshot
#   Task 2  (scenario) the JML people act from the Mac; wait for Wazuh's SEV-1 alert (rule 100221)
#   Task 3  containment starts at that alert (IR1-2026-002), and also contains IR1-2026-001 / -003 on the host
#   Task 2  (analysis) Parrot + macOS log analysis, leaver-login investigation, severity classification
#   Task 4  live response, Volatility, disk acquisition, chain of custody, super-timeline
#   Task 6  evidence gate, restore, root-cause fixes, validation x2 (reboot between)
#   Task 5  tracker loaded from all of the above; documents built from the evidence
# The Mac is kept awake for the whole run (caffeinate, no admin rights). About 45 minutes.
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lab_common.sh"
LOG="$VMLAB/run_all.log"
step() { echo; echo "========== $1  $(now)"; }
# start from clean evidence folders so nothing from an earlier run can mix in
for t in task1_environment_setup task2_log_analysis task3_containment task4_evidence_management task6_post_incident; do
  rm -rf "$IR/$t/evidence"; mkdir -p "$IR/$t/evidence"
done
chmod -R u+w "$BIG" 2>/dev/null; rm -rf "$BIG"; mkdir -p "$BIG"
{
  step "Task 1"; bash "$IR/task1_environment_setup/run_task1.sh" || exit 1
  step "Task 2 scenario"; bash "$IR/task2_log_analysis/run_task2.sh" scenario || exit 1
  step "Task 3"; bash "$IR/task3_containment/run_task3.sh" || exit 1
  step "Task 2 analysis"; bash "$IR/task2_log_analysis/run_task2.sh" analysis || exit 1
  step "Task 4"; bash "$IR/task4_evidence_management/run_task4.sh" || exit 1
  step "Task 6"; bash "$IR/task6_post_incident/run_task6.sh" || exit 1
  step "Task 5 tracker"; python3 -I "$IR/task5_ir_documentation/tracker/load_cases.py"
  step "done"
} 2>&1 | tee "$LOG"
