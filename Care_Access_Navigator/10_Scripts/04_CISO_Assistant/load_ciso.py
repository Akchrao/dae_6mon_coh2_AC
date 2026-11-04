"""Load the Care Access Navigator GRC registers into CISO Assistant (idempotent; safe to rerun).

Run after build_payload.py, from the ciso-assistant-community folder:
    docker exec -i backend sh -c 'cd /code && uv run python manage.py shell' < load_ciso.py

Records are matched by ref_id (or name for evidence), so a rerun updates instead of duplicating.
"""
import json
import os
from datetime import date

from django.core.files import File
from django.db import transaction

from core.models import (AppliedControl, Asset, ComplianceAssessment, Evidence, EvidenceRevision, Finding,
                         FindingsAssessment, Framework, LoadedLibrary, Perimeter, RequirementAssessment,
                         RequirementNode, RiskAssessment, RiskScenario, SecurityException, StoredLibrary)
from iam.models import Folder, User

D = "/code/db/import_tmp"
P = json.load(open(os.path.join(D, "payload.json")))
TODAY = P["iso_date"]

user = User.objects.get(email="akchrao@gmail.com")
actor = AppliedControl.objects.get(ref_id="CAN-CTRL-JML-001").owner.first()  # the user's Actor record
dom = Folder.objects.get(name="Care Access Navigator - IAM & GRC")
perim = Perimeter.objects.get(ref_id="CAN-EHR-001")
ra = RiskAssessment.objects.get(ref_id="CAN-RA-001")
hipaa = ComplianceAssessment.objects.get(ref_id="CAN-AUD-HIPAA-001")
log = []


def d(s):
    return date.fromisoformat(s) if s and s[:4].isdigit() else None


def upsert(model, key, defaults, **extra):
    obj, created = model.objects.update_or_create(**key, defaults={**defaults, **extra})
    return obj, created


with transaction.atomic():
    # ---------------------------------------------------------------- assets
    assets = {}
    for ref, name, typ, desc in P["assets"]:
        if ref == "CAN-AST-001":
            a = Asset.objects.get(ref_id=ref)
        else:
            a, _ = upsert(Asset, {"ref_id": ref}, {"name": name, "type": typ, "description": desc, "folder": dom})
        assets[ref] = a
    primary = assets["CAN-AST-000"]
    for ref, a in assets.items():
        if a.type == "SP":
            a.parent_assets.add(primary)
        a.owner.add(actor)
    log.append(f"assets: {len(assets)}")

    # ---------------------------------------------------------------- applied controls (W9 Mon inventory)
    IMPL = {"Implemented": "active", "Partially implemented": "in_progress", "Not implemented": "to_do"}
    CSF = {"GV": "govern", "ID": "identify", "PR": "protect", "DE": "detect", "RS": "respond", "RC": "recover"}
    CAT = {"GRC": "process", "Incident response": "process", "IAM / GRC": "process", "Third-party access": "process"}
    ctl = {}
    ctl_impl = {}
    for (cid, objective, area, hip, csf, sp, iso, pci, risks, ev, test, result, impl, gap) in P["controls"]:
        desc = (f"{objective}\n\nArea: {area}\nHIPAA: {hip}\nNIST CSF 2.0: {csf}\nNIST SP 800-53 r5: {sp}\n"
                f"ISO 27001:2022: {iso}\nPCI DSS 4.0.1: {pci}\nRisks: {risks}\nEvidence: {ev}\n"
                f"Test: {test}\nTest result (2026-11-03): {result}")
        obs = f"Implementation: {impl}." + ("" if gap == "-" else f" Gap / follow-up: {gap}")
        c, _ = upsert(AppliedControl, {"ref_id": cid},
                      {"name": objective, "description": desc, "observation": obs, "folder": dom,
                       "status": IMPL[impl], "category": CAT.get(area, "technical"),
                       "csf_function": CSF[csf.split(".")[0]]})
        c.owner.add(actor)
        ctl[cid] = c
        ctl_impl[cid] = impl
    # existing JML controls: keep, refresh status of JML-002 with what TC-04 actually proved
    jml1 = AppliedControl.objects.get(ref_id="CAN-CTRL-JML-001")
    jml2 = AppliedControl.objects.get(ref_id="CAN-CTRL-JML-002")
    jml1.status = "active"
    jml1.csf_function = "protect"
    jml1.save()
    jml2.status = "in_progress"
    jml2.csf_function = "protect"
    jml2.observation = (
        "Progress 2026-11-03 (EV-14): the scripted leaver step (can_iam.py leaver) disables the Keycloak account, "
        "logs out every session and removes roles; TC-04 PASS covers validation tests 2 (session revocation), "
        "3 (access denied) and 4 (audit logging). Test 5 (detect accounts still enabled or holding access after "
        "termination) is partly met by the access-review flag DISABLED_BUT_HAS_ACCESS (TC-09, fixed by CA-09). "
        "Test 1 (an Entra ID termination disables the Keycloak copy automatically) is NOT done: for federated users "
        "the script only reports that Entra must also be blocked. Control stays In progress until Test 1 passes.")
    jml2.save()
    ctl["CAN-CTRL-JML-001"], ctl["CAN-CTRL-JML-002"] = jml1, jml2
    ctl_impl["CAN-CTRL-JML-001"], ctl_impl["CAN-CTRL-JML-002"] = "Implemented", "Partially implemented"
    log.append(f"applied controls: {len(ctl)}")

    # ---------------------------------------------------------------- evidence (W10 Mon repository)
    evd = {}
    ev_by_ctl = {}
    for e in P["evidence"]:
        if "existing" in e:
            ob = Evidence.objects.get(name=e["existing"])
        else:
            ob, _ = upsert(Evidence, {"name": e["name"], "folder": dom},
                           {"description": f"{e['desc']}\nRepository path: {e['path']}\nSHA-256: {e['sha256']}",
                            "status": "in_review"})
            if not ob.revisions.filter(attachment_hash=e["sha256"]).exists():
                with open(os.path.join(D, e["file"]), "rb") as fh:
                    EvidenceRevision.objects.create(evidence=ob, folder=dom, version=ob.revisions.count() + 1,
                                                    attachment=File(fh, name=e["file"]),
                                                    observation=f"Imported from {e['path']} on {TODAY}")
        ob.owner.add(actor)
        evd[e["name"]] = ob
        for c in e["controls"]:
            ctl[c].evidences.add(ob)
            ev_by_ctl.setdefault(c, set()).add(ob)
    jml_ev = Evidence.objects.get(name="Jeevan Smith -Leaver Access Revocation Evidence")
    ev_by_ctl.setdefault("CAN-CTRL-JML-001", set()).add(jml_ev)
    e2e = [o for n, o in evd.items() if n.startswith("EV-14 - End-to-end run results")]
    jml2.evidences.add(*e2e)
    ev_by_ctl.setdefault("CAN-CTRL-JML-002", set()).update(e2e)
    log.append(f"evidence: {len(evd)} (files {sum(1 for e in P['evidence'] if 'file' in e)})")

    # ---------------------------------------------------------------- exceptions (W10 Wed register)
    exc = {}
    for (xid, cid, what, why, comp, risk, req, appr, approved, expires, status) in P["exceptions"]:
        st = P["ex_status"].get(status, "approved" if approved not in ("-", "") else "in_review")
        desc = (f"{what}\n\nBusiness justification: {why}\nCompensating controls: {comp}\nControl: {cid}  Risk: {risk}"
                f"\nRequested by: {req}  Approved by: {appr}  Approved on: {approved}")
        x, _ = upsert(SecurityException, {"ref_id": xid},
                      {"name": f"{xid} {what[:80]}", "description": desc, "observation": f"Register status: {status}",
                       "status": st, "severity": P["ex_severity"][xid], "expiration_date": d(expires), "folder": dom,
                       "approver": user if st == "approved" else None})
        x.owners.add(actor)
        exc[xid] = x
        if cid in ctl:
            ctl[cid].security_exceptions.add(x)
    log.append(f"exceptions: {len(exc)}")

    # ---------------------------------------------------------------- risk scenarios (W8 register + scoring)
    TREAT = "mitigate"
    for r in P["risks"]:
        ref = r["ref"]
        li, im = r["inherent"]
        rl, ri = r["residual"]
        just = (f"Owner: {r['owner']}. Source: {r['source']}. Frameworks: {r['framework']}. Treatment status "
                f"(register 2026-11-03): {r['status']} - {r['evidence']}. Register residual score {r['residual_score']} "
                f"({r['residual_rating']}) entered as likelihood {rl} x impact {ri}.")
        if ref == "R02":
            s = RiskScenario.objects.get(risk_assessment=ra, ref_id__in=["R.02", "R02"])
            s.ref_id = "R02"
            s.inherent_proba, s.inherent_impact = li - 1, im - 1
            # current (3x5 High) and target (1x5) kept from the 2026-11-03 CISO analysis: Entra-triggered
            # deprovisioning (CAN-CTRL-JML-002 test 1) is still open, so the register's residual is a target.
            s.justification = just + (" CISO current level stays 3x5 because CAN-CTRL-JML-002 test 1 (automatic "
                                      "Entra-to-Keycloak disable) is not done; the register residual is the target.")
            s.save()
        else:
            s, _ = upsert(RiskScenario, {"risk_assessment": ra, "ref_id": ref},
                          {"name": r["name"], "treatment": TREAT,
                           "description": f"{r['name']}. Treatment: {r['treatment']}.",
                           "existing_controls": r["evidence"], "justification": just,
                           "inherent_proba": li - 1, "inherent_impact": im - 1,
                           "current_proba": rl - 1, "current_impact": ri - 1,
                           "residual_proba": rl - 1, "residual_impact": ri - 1})
        s.owner.add(actor)
        s.assets.add(*[assets[a] for a in r["assets"]])
        for (cid, *_rest) in P["controls"]:
            rk = _rest[7]
            hit = ref in rk or (rk.startswith("R01-R05"))
            if hit:
                (s.existing_applied_controls if ctl[cid].status == "active" else s.applied_controls).add(ctl[cid])
    for xid, x in exc.items():
        risk = next(e[5] for e in P["exceptions"] if e[0] == xid)
        if risk.startswith("R"):
            RiskScenario.objects.get(risk_assessment=ra, ref_id=risk).security_exceptions.add(x)
    ra.name = "Healthcare IAM Risk Assessment (R01-R05)"
    ra.version = "2.0"
    ra.authors.add(actor)
    ra.description = ("IAM risk register for Care Access Navigator (HRMC, synthetic data): R01-R05 from the Risk "
                      "Management 1 register, scored on the 5x5 ISO 27005 matrix (inherent, current, residual), linked "
                      "to assets, applied controls and exceptions. v1.0 (2026-11-03) covered R02 only; its exports are "
                      "kept in the repository. Educational simulation; not a certification.")
    ra.save()
    log.append(f"risk scenarios: {RiskScenario.objects.filter(risk_assessment=ra).count()}")

    # ---------------------------------------------------------------- HIPAA requirement assessments (W9 Tue + Thu)
    RANK = {"Implemented": 0, "Partially implemented": 1, "Not implemented": 2}
    RES = ["compliant", "partially_compliant", "non_compliant"]
    fw = hipaa.framework
    for node, label, cids in P["hipaa"]:
        rn = RequirementNode.objects.get(urn=f"urn:intuitem:risk:req_node:nist-sp-800-66-rev2:{node}")
        rq = RequirementAssessment.objects.get(compliance_assessment=hipaa, requirement=rn)
        worst = max(RANK[ctl_impl[c]] for c in cids)
        result, why = RES[worst], None
        if node in P["hipaa_override"]:
            result, why = P["hipaa_override"][node]
        summary = "; ".join(f"{c} ({ctl_impl[c]})" for c in cids)
        text = f"[{TODAY}] {label}. Controls: {summary}." + (f" {why}" if why else "")
        if node == "node48" and rq.observation and "Jeevan" in rq.observation and TODAY not in rq.observation:
            text = rq.observation + "\n\n" + text  # keep the original 2026-11-03 audit note
        elif node == "node48" and rq.observation and TODAY in rq.observation:
            text = rq.observation.split(f"\n\n[{TODAY}]")[0] + "\n\n" + text
        rq.result, rq.status, rq.observation = result, "done", text
        rq.save()
        rq.applied_controls.add(*[ctl[c] for c in cids])
        for c in cids:
            rq.evidences.add(*ev_by_ctl.get(c, []))
        for xid in P["hipaa_exceptions"].get(node, []):
            rq.security_exceptions.add(exc[xid])
    hipaa.name = "Healthcare IAM - HIPAA Security Rule Access Controls Audit"
    hipaa.version = "2.0"
    hipaa.authors.add(actor)
    hipaa.save()
    log.append(f"HIPAA requirements assessed: {RequirementAssessment.objects.filter(compliance_assessment=hipaa).exclude(result='not_assessed').count()}")

    # ---------------------------------------------------------------- NIST CSF 2.0 mapping (W9 Wed)
    sl = StoredLibrary.objects.filter(urn="urn:intuitem:risk:library:nist-csf-2.0").order_by("-version").first()
    if not LoadedLibrary.objects.filter(urn=sl.urn).exists():
        err = sl.load()
        if err:
            raise SystemExit(f"CSF load failed: {err}")
    csf_fw = Framework.objects.get(urn="urn:intuitem:risk:framework:nist-csf-2.0")
    csf, created = ComplianceAssessment.objects.get_or_create(
        ref_id="CAN-AUD-CSF-001",
        defaults=dict(name="Healthcare IAM - NIST CSF 2.0 Control Mapping", framework=csf_fw, perimeter=perim,
                      folder=perim.folder, version="1.0", status="in_progress",
                      description="Project controls mapped to NIST CSF 2.0 subcategories. Result per subcategory = "
                                  "weakest implementation of the mapped controls. Only mapped subcategories are "
                                  "assessed; the rest are out of the capstone scope."))
    if created or not csf.requirement_assessments.exists():
        csf.create_requirement_assessments()
    csf.authors.add(actor)
    sub = {}
    for (cid, *rest) in P["controls"]:
        for code in [x.strip() for x in rest[3].split(",")]:
            sub.setdefault(code, []).append(cid)
    done = 0
    for code, cids in sub.items():
        rq = RequirementAssessment.objects.filter(compliance_assessment=csf, requirement__ref_id=code).first()
        if not rq:
            log.append(f"  CSF {code} not found in framework")
            continue
        worst = max(RANK[ctl_impl[c]] for c in cids)
        rq.result, rq.status = RES[worst], "done"
        rq.observation = f"[{TODAY}] Controls: " + "; ".join(f"{c} ({ctl_impl[c]})" for c in cids)
        rq.save()
        rq.applied_controls.add(*[ctl[c] for c in cids])
        for c in cids:
            rq.evidences.add(*ev_by_ctl.get(c, []))
        done += 1
    log.append(f"CSF 2.0 subcategories assessed: {done}")

    # ---------------------------------------------------------------- corrective actions (W10 Thu) as findings
    fa, _ = upsert(FindingsAssessment, {"ref_id": "CAN-FA-001"},
                   {"name": "Corrective Action Tracker (W10)", "category": "self_identified", "status": "in_progress",
                    "perimeter": perim, "folder": perim.folder,
                    "description": "Findings from the Compliance 1 audit (F-01..F-06), the access reviews, the "
                                   "end-to-end tests and the board audit, each tracked to verification. "
                                   "Severities come from the Compliance 1 remediation tracker; others are unrated."})
    fa.authors.add(actor)
    f1 = Finding.objects.get(ref_id="CAN-FIND-001")
    f1.findings_assessment = fa
    f1.status = "in_progress"
    f1.observation = (f1.observation.split("\n\n[Update")[0] +
                      f"\n\n[Update {TODAY}] Scripted leaver step verified (TC-04, TC-09 after CA-09); Entra-triggered "
                      f"automatic disable still open - see CAN-CTRL-JML-002.")
    f1.save()
    for (aid, src, issue, action, owner, due, status, crit, vev, von) in P["actions"]:
        base = status.split(" (")[0]
        cid = P["ca_control_by_id"].get(aid) or P["ca_control"].get(src)
        obs = f"Owner role: {owner}. Register status: {status}. Verification criterion: {crit}."
        if vev and vev != "-":
            obs += f" Verification evidence: {vev}."
        if von:
            obs += f" Verified on {von}."
        f, _ = upsert(Finding, {"ref_id": aid, "findings_assessment": fa},
                      {"name": f"{aid} {issue}"[:200], "description": f"Source: {src}. {issue}", "recommendation": action,
                       "observation": obs, "status": P["ca_status"][base], "severity": P["f_severity"].get(src, -1),
                       "due_date": d(due), "folder": fa.folder})
        f.owner.add(actor)
        if cid:
            f.applied_controls.add(ctl[cid])
            if P["ca_status"][base] == "resolved":
                f.evidences.add(*ev_by_ctl.get(cid, []))
    log.append(f"findings: {Finding.objects.filter(findings_assessment=fa).count()}")
    if os.path.exists(os.path.join(D, "DRY_RUN")):
        print("\n".join(log))
        transaction.set_rollback(True)
        log = ["DRY RUN: rolled back (delete db/import_tmp/DRY_RUN to apply)"]

print("\n".join(log))
