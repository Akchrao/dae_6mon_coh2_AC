#!/usr/bin/env python3
"""load_cases.py - loads the Incident Response 1 cases into the tracker from the evidence of Tasks 1-6.
Rebuilds incidents.db from scratch, so the tracker always matches the evidence. Every time stamp comes from the
evidence: detection = the first Wazuh alert for the incident (Task 2), containment = Task 3, recovery = Task 6.
Uses irtrack's own API (the same functions the CLI calls). Run:  python3 load_cases.py"""
import csv, datetime as dt, hashlib, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import irtrack as t

HERE = os.path.dirname(os.path.abspath(__file__))
IR = os.path.dirname(os.path.dirname(HERE)); REPO = os.path.dirname(os.path.dirname(IR))   # incident_response_1 -> repo root
E2, E3, E4, E6 = (os.path.join(IR, d, "evidence") for d in
                  ("task2_log_analysis", "task3_containment", "task4_evidence_management", "task6_post_incident"))
rows = lambda p: list(csv.DictReader(open(p)))
mk = lambda p, k="phase": {r[k]: r["utc"] for r in rows(p)}
m2, m3 = mk(os.path.join(E2, "markers.csv")), mk(os.path.join(E3, "markers.csv"))
s4, s6 = mk(os.path.join(E4, "steps.csv"), "step"), mk(os.path.join(E6, "steps.csv"), "step")
NOW = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
AN = "A. Chennamaneni (IR analyst)"
alerts = [json.loads(l) for l in open(os.path.join(E2, "wazuh", "alerts.json"))]
z = lambda s: s[:19] + "Z"


def first_alert(*ids):
    ts = sorted(a["timestamp"] for a in alerts if a["rule"]["id"] in ids)
    return z(ts[0]) if ts else None


ups = [json.loads(l) for l in open(os.path.join(E3, "exfil-sink", "uploads.jsonl"))]
v1 = [l.split("\t") for l in open(os.path.join(E6, "validation", "checklist_run1.tsv")).read().splitlines()[1:]]
v2 = [l.split("\t") for l in open(os.path.join(E6, "validation", "checklist_run2.tsv")).read().splitlines()[1:]]
ok = lambda v: f"{sum(1 for r in v if r[-1] == 'PASS')}/{len(v)}"
det = {"IR1-2026-001": first_alert("100210"), "IR1-2026-002": m3["detection"], "IR1-2026-003": first_alert("100230", "100231")}

if os.path.exists(t.DB):
    os.remove(t.DB)
t.db().close()

# ------------------------------------------------------------------ IR1-2026-002 (SEV-1, carried through Tasks 3-6)
I = "IR1-2026-002"
t.new(I, "Mover Tara Jones used stale clinical access to take patient record PT-1003 off the host",
      "Unauthorized ePHI access / data exfiltration (insider)", "SEV-1", det[I],
      "Wazuh rule 100221 (agent on parrot-vm) + host triage", AN,
      f"Tara Jones (test.nurse) moved Nurse -> Billing (CHG-2026-0201), but the host kept her clinical group. She read synthetic "
      f"record PT-1003, staged a copy, started an uploader (syncd.py) posting it to 10.78.99.66:8080 every 5 s, and added a cron job "
      f"to restart it. Wazuh raised rule 100221 within seconds and containment started at the alert. {len(ups)} uploads reached the "
      f"drop site before egress was blocked. Evidence preserved with chain of custody; host restored from the clean snapshot, root "
      f"cause fixed and validated ({ok(v1)} and {ok(v2)} checks, before and after a reboot).",
      "parrot-vm; EHR record PT-1003 (synthetic); account test.nurse")
t.status(I, "Triage", m3["triage"], "SEV-1 confirmed on the host: disclosure in progress")
t.status(I, "Contained", m3["contained"], "egress blocked, host isolated (SIEM kept), account locked; verified by probe matrix")
t.status(I, "Eradicated", s6["r2_restore"], "restored to pre-incident snapshot baseline-clean; artifacts gone (INT-02..04)")
t.status(I, "Recovered", s6["r7_snapshot"], f"root cause fixed; checklist {ok(v1)} / {ok(v2)}, probes 6/6 twice")
t.status(I, "Closed", NOW, "incident report and post-incident review complete (IR1 Tasks 5-6)")
names3 = {"triage": ("Triage", "Host triage: record read, SYNs to 10.78.99.66 every 5 s, process owned by test.nurse"),
          "c1_snapshot": ("Containment", "C1 live snapshot ir-pre-containment"),
          "c2_volatile": ("Evidence", "C2 tcpdump + volatile state to the case folder"),
          "c3_block": ("Containment", "C3 iptables chain IR-EGRESS-BLOCK drops all traffic to 10.78.99.66"),
          "c4_memory": ("Evidence", "C4 gcore of the uploader + full RAM image"),
          "c5_filesystem": ("Evidence", "C5 file artifacts stat'd, frozen, hashed, copied"),
          "c6_isolate": ("Containment", "C6 clinical cable out, quarantine adapter in, default-DROP, Wazuh kept via quarantine forward"),
          "c7_shutdown": ("Containment", "C7 kill uploader, mask cron, stop portal, lock account, remove clinical group, restrict sshd"),
          "c8_verify": ("Containment", "C8 probe matrix re-run"), "contained": ("Containment", "Snapshot ir-contained")}
for k, (ph, v) in names3.items():
    t.action(I, m3[k], ph, AN, v, "see task3 transcripts")
t.action(I, m2["analysis_done"], "Analysis", AN, "Log analysis + severity classification (Task 2)", "SEV-1 confirmed by the matrix")
for k, v in {"intake_verify": "Intake: Task 3 evidence re-hashed", "live_response": "Live response: 24 commands, RAM-only, hashed",
             "memory_analysis": "Volatility 3 on the RAM image; hash unchanged", "disk_seize": "Disk seized from snapshot ir-contained",
             "disk_image": "dc3dd image from a read-only source; hashes equal", "disk_examine": "Sleuth Kit: planted files recovered, hash-identical",
             "coc_timeline": "Chain of custody + super-timeline built"}.items():
    t.action(I, s4[k], "Evidence / analysis", AN, v, "see task4 transcripts")
for k, v in {"r0_gate": "Evidence gate: all items re-verified before recovery", "r1_record": "Snapshot pre-recovery; golden image hash verified",
             "r2_restore": "Restore snapshot baseline-clean; adapters to production wiring", "r3_system": "recover_harden.sh: JML fix, keys, cron.allow, firewall, services",
             "r5_validate": f"Validation run 1: {ok(v1)} checks, 6 probes", "r6_reboot": f"Reboot; validation run 2: {ok(v2)}",
             "r7_snapshot": "Snapshot recovered-validated (new baseline)"}.items():
    t.action(I, s6[k], "Eradication / recovery", AN, v, "see task6 transcripts")
for r in rows(os.path.join(E4, "timeline", "key_events.csv")):
    if r["utc"]:
        t.event(I, r["utc"], r["host"], r["source"], r["milestone"])
for r in rows(os.path.join(E4, "coc", "evidence_register.csv")):
    t.evidence(I, r["item"], r["description"], r["sha256_at_acquisition"], r["stored_at"])
for n, f in (("E14", "checklist_run1.tsv"), ("E15", "checklist_run2.tsv")):
    p = os.path.join(E6, "validation", f)
    t.evidence(I, n, f"Recovery validation checklist ({f})", hashlib.sha256(open(p, "rb").read()).hexdigest(),
               "repo:incident_response_1/task6_post_incident/evidence/validation/" + f)

# ------------------------------------------------------------------ IR1-2026-001 (SEV-3) and IR1-2026-003 (SEV-2)
for i, title, typ, sev, src, summ, assets, c7, fix, chk in [
    ("IR1-2026-001", "Leaver Jeevan Smith (test.billing) attempted SSH twice; his key was still on the host",
     "Unauthorized access attempt (leaver account)", "SEV-3", "Wazuh rules 100210/100211 (agent on parrot-vm)",
     "Both attempts were blocked by sshd DenyGroups, but the leaver's SSH key had never been removed from the host. "
     "Investigated in Task 2 (macOS client <-> packet capture <-> sshd <-> Wazuh). Key removed during containment (C7).",
     "parrot-vm; account test.billing", "C7: leaver's authorized_keys moved to /root/ir-quarantine", "IAM-03/IAM-04",
     "R2.1 keys removed from disabled accounts"),
    ("IR1-2026-003", "it_admin added joiner Sathya Hasi (test.clinician) to sudo with no change record; she then used root",
     "Unauthorized privilege escalation", "SEV-2", "Wazuh rules 100230/100231 (agent on parrot-vm)",
     "it_admin granted sudo with no change ticket and the clinician ran a command as root (RBAC/SoD violation). "
     "Grant removed during containment (C7); sudoers changes are now audited.",
     "parrot-vm; account test.clinician", "C7: gpasswd -d test.clinician sudo", "IAM-05/MON-01",
     "R2.1 sudo group = it_admin only; R2.5 sudoers audit rule")]:
    t.new(i, title, typ, sev, det[i], src, AN, summ, assets)
    t.status(i, "Triage", m3["triage"], f"{sev} queued behind the SEV-1 (playbook: highest severity first)")
    t.action(i, m3["c7_shutdown"], "Containment", AN, c7, "see task3 transcripts/08")
    t.status(i, "Contained", m3["c7_shutdown"], c7)
    t.action(i, m2["analysis_done"], "Analysis", AN, "Investigated and classified with the severity matrix (Task 2)", sev)
    t.action(i, s6["r3_system"], "Eradication / recovery", AN, fix, f"{chk} PASS")
    t.status(i, "Eradicated", s6["r3_system"], fix)
    t.status(i, "Recovered", s6["r7_snapshot"], f"{chk} validated twice")
    t.status(i, "Closed", NOW, "lessons folded into playbook CAN-IR-PB-02")

# ------------------------------------------------------------------ cross-course record carried over from the project register
reg = os.path.join(REPO, "Care_Access_Navigator", "08_Reporting", "02_Dashboards", "Tableau_Dataset", "incidents.csv")
for r in rows(reg) if os.path.exists(reg) else []:
    if r["incident_id"].startswith("INC-"):
        t.new(r["incident_id"], r["title"], "Cloud misconfiguration / attack", r["severity"].split()[0], r["detected_utc"].replace(" ", "T") + ":00Z",
              "Azure Monitor / Defender for Cloud", AN, "Carried over from the Cloud Security 1 register (cloud_security_1 evidence).",
              "Azure rg-cloudsec1-can", environment=r["environment"], course=r["course"])
        t.status(r["incident_id"], "Closed", r["detected_utc"].replace(" ", "T") + ":00Z", r["status"])

t.export(os.path.join(HERE, "incidents_register.csv"))
open(os.path.join(HERE, f"{I}_record.md"), "w").write(t.report(I))
print(f"loaded {t.db().execute('select count(*) from incident').fetchone()[0]} incidents into {os.path.basename(t.DB)}")
