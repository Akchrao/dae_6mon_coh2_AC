"""READ-ONLY sync: export the live GRC registers from CISO Assistant as JSON (stdout).

Run inside the CISO Assistant backend container:
  docker exec -i backend sh -c 'cd /code && uv run python manage.py shell' < ciso_sync_export.py > ../data/ciso_snapshot.json
Nothing is written to the CISO Assistant database.
"""
import json
from datetime import datetime, timezone
from core.models import AppliedControl, SecurityException, Finding, RiskScenario, RequirementAssessment, ComplianceAssessment

def s(v):
    return None if v is None else str(v)

out = {"exported_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "source": "CISO Assistant (live)"}
out["applied_controls"] = [{"ref_id": c.ref_id, "name": c.name, "status": s(c.status), "category": s(getattr(c, "category", None)),
                            "eta": s(getattr(c, "eta", None))} for c in AppliedControl.objects.all().order_by("ref_id")]
out["exceptions"] = [{"ref_id": x.ref_id, "name": x.name, "status": s(x.status), "expiration_date": s(getattr(x, "expiration_date", None)),
                      "severity": s(getattr(x, "severity", None))} for x in SecurityException.objects.all().order_by("ref_id")]
out["findings"] = [{"ref_id": f.ref_id, "name": f.name, "status": s(f.status), "severity": s(getattr(f, "severity", None)),
                    "eta": s(getattr(f, "eta", None)), "due_date": s(getattr(f, "due_date", None))} for f in Finding.objects.all().order_by("ref_id")]
out["risks"] = [{"ref_id": r.ref_id, "name": r.name, "current_level": s(r.current_level), "residual_level": s(r.residual_level),
                 "treatment": s(r.treatment)} for r in RiskScenario.objects.all().order_by("ref_id")]
out["compliance_assessments"] = []
for ca in ComplianceAssessment.objects.all():
    ras = RequirementAssessment.objects.filter(compliance_assessment=ca).exclude(result="not_assessed")
    res = {}
    for r in ras:
        res[r.result] = res.get(r.result, 0) + 1
    out["compliance_assessments"].append({"ref_id": ca.ref_id, "name": ca.name, "results": res})
print("CISO_SNAPSHOT_BEGIN")
print(json.dumps(out, indent=1))
print("CISO_SNAPSHOT_END")
