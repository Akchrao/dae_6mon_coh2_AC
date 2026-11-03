"""Week 11 Day 1 (+ Thursday validation): GRC dashboard KPIs, wireframe, Tableau build steps and expected values.
Reads the refreshed Tableau dataset (run build_tableau.py first).
Output: Care_Access_Navigator/08_Reporting/02_Dashboards/CAN_DOC_GRC_Dashboard_Design_v1.0.pdf"""
import csv, os
from collections import Counter
from html import escape as e

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors

import grc_data as g
from pdfstyle import P, bullets, note, table, kv, build, Spacer, PageBreak, inch, FULL_W, NAVY, AMBER, GREY_BG, MUTED

DS = os.path.join(g.CAN, "08_Reporting/02_Dashboards/Tableau_Dataset")
OUT = os.path.join(g.CAN, "08_Reporting/02_Dashboards/CAN_DOC_GRC_Dashboard_Design_v1.0.pdf")
TITLE = "GRC Dashboard Design"
rd = lambda n: list(csv.DictReader(open(os.path.join(DS, n), newline="")))
K = {r["kpi"]: r for r in rd("kpi_values.csv")}
REV, DET, TST, FND, RSK = (rd("access_review_AR-2026-Q4.csv"), rd("identity_detections.csv"), rd("control_tests.csv"),
                           rd("audit_findings.csv"), rd("risks.csv"))


def kv_(name):
    r = K[name]
    return f"{r['value']}{'%' if r['unit'] == '%' else ''}"


def wireframe():
    W, H = FULL_W, 5.3 * inch
    d = Drawing(W, H)
    d.add(Rect(0, 0, W, H, fillColor=colors.white, strokeColor=colors.HexColor("#CCCCCC")))
    d.add(Rect(0, H - 0.42 * inch, W, 0.42 * inch, fillColor=NAVY, strokeColor=None))
    d.add(String(8, H - 0.28 * inch, "HRMC Care Access Navigator - IAM & GRC Posture   [Filter: department] [Filter: severity]",
                 fontName="Helvetica-Bold", fontSize=8.5, fillColor=colors.white))
    tiles = [("Priv. MFA enforced", kv_("Privileged MFA enforcement")),
             ("Access review done", kv_("Access review completion")),
             ("Open High findings", kv_("Open High audit findings")),
             ("Control pass rate", kv_("Control test pass rate (11/03)")),
             ("Open exceptions", kv_("Open exceptions")),
             ("Residual High risks", kv_("Residual High risks"))]
    tw = (W - 7 * 6) / 6
    for i, (lab, val) in enumerate(tiles):
        x = 6 + i * (tw + 6)
        d.add(Rect(x, H - 1.25 * inch, tw, 0.7 * inch, fillColor=GREY_BG, strokeColor=colors.HexColor("#CCCCCC")))
        d.add(String(x + 5, H - 0.75 * inch, lab, fontName="Helvetica", fontSize=6.3, fillColor=MUTED))
        d.add(String(x + 5, H - 1.08 * inch, val, fontName="Helvetica-Bold", fontSize=14, fillColor=NAVY))
    boxes = [("1  Risk heat map (inherent vs residual)  - risks.csv", 0, 2), ("2  Audit findings: target-date Gantt by status - audit_findings.csv", 1, 2),
             ("3  Control test pass rate: 10/13 audit vs 11/03 - control_tests.csv", 0, 1),
             ("4  Identity detections by rule over time - identity_detections.csv", 1, 1),
             ("5  Access review flags by flag type - access_review_AR-2026-Q4.csv", 0, 0),
             ("6  Exceptions by expiry + corrective actions by status", 1, 0)]
    bw, bh = (W - 18) / 2, 1.2 * inch
    for lab, col, row in boxes:
        x, y = 6 + col * (bw + 6), 6 + row * (bh + 6)
        d.add(Rect(x, y, bw, bh, fillColor=colors.white, strokeColor=AMBER, strokeWidth=1))
        d.add(String(x + 6, y + bh - 14, lab, fontName="Helvetica-Bold", fontSize=6.6, fillColor=NAVY))
    return d


s = [P(TITLE, "title"), Spacer(1, 4), P(f"Week 11 &middot; {g.PROJECT} &middot; {g.ORG}", "subtitle"),
     P("KPIs, reporting design, wireframe, Tableau build steps and the values a correct dashboard must show", "subsub"),
     Spacer(1, 10)]
s += kv([("Author", g.AUTHOR), ("Date", g.DATE), ("Version", "v1.0"),
         ("Audience", "HRMC Security Officer and department managers (monthly); IAM and GRC analysts (weekly)"),
         ("Data", "08_Reporting/02_Dashboards/Tableau_Dataset/ (10 CSV files, refreshed 11/03 from live evidence by "
                  "10_Scripts/03_GRC_Build/build_tableau.py)"),
         ("Tool", "Tableau Public (free). Workbooks publish publicly, which is acceptable only because every row is synthetic.")])
s += [P("Board items covered", "h2")]
s += table([["Day", "Board item", "Where"],
            ["Mon", "Define dashboard KPIs and reporting design", "Sections 1-2 (KPIs, wireframe)"],
            ["Tue", "Build IAM metrics dataset", "access_review_AR-2026-Q4.csv, identity_detections.csv (live)"],
            ["Wed", "Build GRC and incident metrics dataset", "controls, control_tests, audit_findings, exceptions, "
                                                             "corrective_actions, risks, incidents, kpi_values"],
            ["Thu", "Build and validate integrated Tableau dashboard",
             "Section 3 build steps; Section 4 validation values (built in the Tableau app)"]],
           [0.5 * inch, 2.4 * inch, 3.6 * inch])

s += [PageBreak(), P("1. KPIs (measured 11/03/2026)", "h1")]
s += table([["KPI", "Formula", "Value", "Target", "Note"]] +
           [[e(r["kpi"]), e(r["formula"]), f"<b>{r['value']}{'%' if r['unit'] == '%' else ''}</b>"
             + (f" ({r['numerator']}/{r['denominator']})" if r["denominator"] else ""), e(r["target"]), e(r["note"])]
            for r in K.values()],
           [1.35 * inch, 1.9 * inch, 0.85 * inch, 0.8 * inch, 1.6 * inch])
s += note("Red is shown on purpose. MFA enrolment and access-review completion are 0% because privileged users enrol "
          "at their next sign-in and the reviewer has not signed yet. The dashboard reports the real state, and the "
          "corrective-action tracker shows who closes each gap and by when.", "Honest metrics")

s += [PageBreak(), P("2. Wireframe", "h1"), P("One dashboard, 1200 x 900. KPI tiles across the top, six views below. "
      "Department and severity filters apply to the views that carry those fields."), wireframe(), Spacer(1, 10)]
s += bullets(["Colour: navy for neutral, green at or above target, amber within 10 points, red below (same thresholds as "
              "the Compliance 1 KPI monitor).",
              "Every tile links to its view (dashboard action), so a manager can go from a red number to the rows behind it.",
              "Tooltips show the evidence ID (EV-13, EV-14, EV-15) so each number can be traced."])

s += [PageBreak(), P("3. Tableau build steps", "h1")]
steps = [
    ("Connect", "Tableau Public &rarr; Connect &rarr; Text file &rarr; open Tableau_Dataset/risks.csv; then add every other "
                "CSV from the same folder as its own data source (they are not joined)."),
    ("Sheet 1 Risk heat map", "risks.csv: Columns = inherent_likelihood, Rows = inherent_impact, Marks = Square, Colour "
                              "= inherent_score, Label = risk_id. Duplicate it for residual_score."),
    ("Sheet 2 Findings Gantt", "audit_findings.csv: Rows = finding_id, Columns = DAY(target_date), Marks = Gantt Bar, "
                               "Colour = status, Label = rating."),
    ("Sheet 3 Control pass rate", "control_tests.csv: Columns = audit_id, Rows = SUM([result]='PASS')/COUNT(result) as a "
                                  "calculated field 'Pass rate', Marks = Bar, Label = value."),
    ("Sheet 4 Detections", "identity_detections.csv: Columns = DAY(time_utc), Rows = CNT(rule_id), Colour = rule_id, "
                           "Filter = severity."),
    ("Sheet 5 Access review", "access_review_AR-2026-Q4.csv: split flags with SPLIT or a custom split on ';' (Data "
                              "pane &rarr; Transform &rarr; Custom Split), Rows = flag, Columns = CNT(username), Colour = risk."),
    ("Sheet 6 Remediation", "corrective_actions.csv: Rows = status, Columns = CNT(action_id); exceptions.csv: Rows = "
                            "exception_id, Columns = expires."),
    ("KPI tiles", "kpi_values.csv: one Text sheet per KPI with a filter on kpi, showing value; colour by a calculated RAG "
                  "field comparing value with target."),
    ("Dashboard", "New Dashboard, size 1200 x 900, place tiles in a horizontal container, then the six sheets in a "
                  "2 x 3 grid; add filter actions from each tile."),
    ("Publish", "File &rarr; Save to Tableau Public. Put the public link in 09_Portfolio and the README."),
]
s += table([["Step", "What to do"]] + [[a, b] for a, b in steps], [1.5 * inch, 5.0 * inch])

s += [PageBreak(), P("4. Validation: values the finished dashboard must show", "h1"),
      P("Compare each view with these counts, computed from the same files. A mismatch means a filter, join or "
        "calculated field is wrong.")]
flags = Counter(f for r in REV for f in r["flags"].split(";") if f)
s += table([["View", "Expected"],
            ["Risk heat map", f"{len(RSK)} risks; residual High = {sum(r['residual_rating'] == 'High' for r in RSK)} "
                              f"({', '.join(r['risk_id'] for r in RSK if r['residual_rating'] == 'High')})"],
            ["Findings", "; ".join(f"{k}: {v}" for k, v in Counter(r["status"] for r in FND).items())],
            ["Control pass rate", "; ".join(f"{a}: {sum(r['result'] == 'PASS' for r in TST if r['audit_id'] == a)}/"
                                            f"{sum(1 for r in TST if r['audit_id'] == a)}"
                                            for a in dict.fromkeys(r["audit_id"] for r in TST))],
            ["Detections", "; ".join(f"{k}: {v}" for k, v in sorted(Counter(r["rule_id"] for r in DET).items()))],
            ["Access review", f"{len(REV)} accounts; " + "; ".join(f"{k}: {v}" for k, v in flags.most_common())],
            ["Remediation", "; ".join(f"{k}: {v}" for k, v in Counter(a[6].split(' (')[0] for a in g.ACTIONS).items())]],
           [1.3 * inch, 5.2 * inch])
s += note("Week 11 Thursday is complete when the published dashboard shows these values and a screenshot of it is "
          "saved as 06_Evidence/01_Screenshots/EV-16_Tableau_GRC_Dashboard_YYYYMMDD.png.", "Done when")
build(OUT, s, TITLE, f"{g.PROJECT} | GRC Dashboard Design | v1.0")
