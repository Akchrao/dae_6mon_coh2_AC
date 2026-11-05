# Incident Response 1 — Task 6: Post-Incident Procedures

**Deliverable:** `Care_Access_Navigator_IR1_Task6_Post_Incident.pdf`

Recovery of the lab after all three incidents:

1. **Evidence gate:** all Task 1–4 evidence re-verified before anything was changed.
2. **Golden image:** its hash was verified.
3. **Restore:** the VM was returned to the `baseline-clean` snapshot.
4. **Root-cause fixes:** JML groups corrected (`lab/recover_harden.sh`), keys removed from disabled accounts, sudo cleaned, `cron.allow` set, a persistent firewall with an egress allow-list installed, and monitoring kept.
5. **Validation:** `lab/validate_recovery.sh`, 34 checks plus 6 network probes. **34/34 and 6/6, both before and after a reboot.**
6. **Write-up:** the report also covers the root cause, contributing factors and a 12-item improvement plan.

## Reproduce

This task runs as part of the shared IR1 exercise (see `../lab/README.md`):

```
bash lab/run_all.sh        # from incident_response_1/
```

Rebuild the PDF from `incident_response_1/`:

```
docker run --rm -v "$PWD":/ir -w /ir/task6_post_incident/pdf-build python:3.11-slim-bookworm \
  sh -c "pip install -q reportlab==4.2.5 && python build_task6.py"
```
