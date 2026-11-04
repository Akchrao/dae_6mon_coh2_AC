"""Build the Weeks 4-10 GRC workbooks from grc_data.py and the live access review.

Outputs (Care_Access_Navigator/):
  07_GRC/02_Controls/CAN_DOC_Control_Catalog_and_Mapping_v1.0.xlsx    (W5 D1-D3, W9 D1-D4)
  07_GRC/04_Remediation/CAN_DOC_Exceptions_and_Corrective_Actions_v1.0.xlsx  (W10 D3-D4)
  06_Evidence/CAN_DOC_Evidence_Index_v1.0.xlsx                        (W10 D1)
  06_Evidence/05_Access_Reviews/CAN_DOC_Access_Review_AR-2026-Q4_v1.0.xlsx    (W4 D4, sign-off sheet)
Run with a Python that has openpyxl.
"""
import os, re, sys
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.datavalidation import DataValidation

import grc_data as g

NAVY, GREY, CREAM = "1B2A4A", "F3F4F6", "FFF4DE"
FILL = {"PASS": "D8F0E0", "Verified": "D8F0E0", "Enforced": "D8F0E0", "Implemented": "D8F0E0", "Approved": "FFF4DE",
        "FAIL": "F8D7D3", "Open": "F8D7D3", "Not implemented": "F8D7D3", "Gap": "F8D7D3",
        "Partially": "FFF4DE", "In progress": "FFF4DE", "EXCEPTION": "FFF4DE", "Exception": "FFF4DE",
        "Pending": "FFF4DE", "Verify": "FFF4DE", "Rotate": "FFF4DE", "Improve": "FFF4DE", "High": "F8D7D3",
        "Medium": "FFF4DE", "Low": "D8F0E0"}
thin = Side(style="thin", color="CCCCCC")


def sheet(wb, title, header, rows, widths, status_cols=(), note=None):
    ws = wb.create_sheet(title)
    r0 = 1
    if note:
        ws.cell(1, 1, note).font = Font(italic=True, color="555555")
        ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=len(header))
        ws.row_dimensions[1].height = 30
        ws.cell(1, 1).alignment = Alignment(wrap_text=True, vertical="top")
        r0 = 2
    for c, h in enumerate(header, 1):
        cell = ws.cell(r0, c, h)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=NAVY)
        cell.alignment = Alignment(wrap_text=True, vertical="center")
    for i, row in enumerate(rows, r0 + 1):
        for c, v in enumerate(row, 1):
            cell = ws.cell(i, c, v)
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            cell.border = Border(top=thin, bottom=thin, left=thin, right=thin)
            if c - 1 in status_cols and isinstance(v, str):
                key = next((k for k in FILL if v.startswith(k)), None)
                if key:
                    cell.fill = PatternFill("solid", fgColor=FILL[key])
    for c, w in enumerate(widths, 1):
        ws.column_dimensions[ws.cell(r0, c).column_letter].width = w
    ws.freeze_panes = ws.cell(r0 + 1, 2)
    ws.auto_filter.ref = f"A{r0}:{ws.cell(r0, len(header)).column_letter}{r0 + len(rows)}"
    return ws


def cover(wb, title, purpose, rows):
    ws = wb.active
    ws.title = "About"
    ws["A1"] = title; ws["A1"].font = Font(bold=True, size=16, color=NAVY)
    ws["A2"] = f"{g.PROJECT} - {g.ORG}"; ws["A2"].font = Font(italic=True, color="555555")
    ws["A4"] = purpose; ws["A4"].alignment = Alignment(wrap_text=True, vertical="top")
    ws.merge_cells("A4:D4"); ws.row_dimensions[4].height = 75
    r = 6
    for k, v in [("Version", "v1.0"), ("Date", g.DATE), ("Author", g.AUTHOR), ("Data", "Synthetic identities only")] + rows:
        ws.cell(r, 1, k).font = Font(bold=True, color=NAVY)
        ws.cell(r, 2, v).alignment = Alignment(wrap_text=True)
        r += 1
    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 90


def save(wb, rel):
    out = os.path.join(g.CAN, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    wb.save(out)
    print("wrote", out)


def main():
    # ------------------------------------------------------------------ 1 control catalog + W5 registers
    wb = Workbook()
    impl = {}
    for c in g.CONTROLS:
        impl[c[12]] = impl.get(c[12], 0) + 1
    cover(wb, "Control Catalog and Compliance Mapping",
          "Week 9: one catalog of the project's controls mapped to the HIPAA Security Rule, NIST CSF 2.0, NIST SP 800-53 "
          "Rev. 5, ISO/IEC 27001:2022 Annex A and PCI DSS v4.0.1, with the latest test result and the gap assessment. "
          "Week 5: authentication baseline, privileged access matrix and service/vendor identity register. Mappings show "
          "which requirement each control supports; no certification is claimed.",
          [("Controls", str(len(g.CONTROLS))), ("Implementation",
                                                  "; ".join(f"{k}: {v}" for k, v in sorted(impl.items())))])
    sheet(wb, "Control_Catalog",
          ["Control ID", "Control objective", "Area", "HIPAA Security Rule (45 CFR)", "NIST CSF 2.0", "NIST SP 800-53 r5",
           "ISO/IEC 27001:2022", "PCI DSS v4.0.1", "Risks", "Evidence", "Test", "Result (11/03/2026)", "Implementation",
           "Gap / follow-up"],
          g.CONTROLS, [9, 38, 16, 22, 14, 18, 15, 13, 9, 28, 18, 16, 18, 40], status_cols=(11, 12))
    sheet(wb, "Gap_Assessment",
          ["Control ID", "Objective", "Implementation", "Result", "Gap", "Exception", "Corrective action"],
          [(c[0], c[1], c[12], c[11], c[13],
            ", ".join(e[0] for e in g.EXCEPTIONS if e[1] == c[0]) or "-",
            ", ".join(sorted(set(re.findall(r"CA-\d+", c[13] + c[11]))
                             | {a[0] for a in g.ACTIONS for e in g.EXCEPTIONS if e[1] == c[0] and a[1] == e[0]})) or "-")
           for c in g.CONTROLS],
          [9, 40, 20, 18, 50, 12, 18], status_cols=(2, 3),
          note="Week 9 Day 4: every control that is not fully implemented and passing has a documented gap and either an "
               "approved exception or a corrective action.")
    sheet(wb, "Auth_Baseline",
          ["ID", "Control", "Standard", "Before (live, 11/03 baseline)", "After (11/03 hardening)", "How verified",
           "Requirement", "Status"],
          g.AUTH_BASELINE, [9, 26, 40, 38, 38, 38, 26, 18], status_cols=(7,),
          note="Week 5 Day 1: authentication control baseline for realm care-access-navigator. Before/after values come "
               "from the can_iam.py audit log (EV-13).")
    sheet(wb, "Privileged_Access",
          ["ID", "Account / role", "System", "Privilege", "Holders (11/03)", "Business justification", "Approval",
           "MFA", "Other safeguards", "Monitoring", "Review", "Status"],
          g.PRIVILEGED, [7, 26, 20, 28, 22, 24, 20, 20, 32, 30, 12, 16], status_cols=(11,),
          note="Week 5 Day 2: privileged access matrix. Process: " +
               " -> ".join(f"{k}: {v}" for k, v in g.PAM_PROCESS))
    sheet(wb, "Service_Vendor_IDs",
          ["ID", "Identity", "Type", "System", "Owner / sponsor", "Credential", "Expiry / rotation", "Controls",
           "Review", "Status"],
          g.SERVICE_VENDOR, [7, 30, 20, 20, 20, 26, 24, 34, 12, 30], status_cols=(9,),
          note="Week 5 Day 3: service and vendor identity register. Rules: " + " ".join(g.VENDOR_RULES))
    save(wb, "07_GRC/02_Controls/CAN_DOC_Control_Catalog_and_Mapping_v1.0.xlsx")

    # ------------------------------------------------------------------ 2 exceptions + corrective actions
    wb = Workbook()
    ver = sum(1 for a in g.ACTIONS if a[6].startswith("Verified"))
    cover(wb, "Exception Register and Corrective Action Tracker",
          "Week 10 Days 3-4: approved and pending exceptions with business justification, compensating controls and "
          "expiry, and every corrective action (audit findings F-01..F-06, end-to-end test results, access review, "
          "board audit) tracked to a verification criterion and evidence. An action is closed only when it is Verified.",
          [("Exceptions", f"{len(g.EXCEPTIONS)} ({sum(1 for e in g.EXCEPTIONS if e[10] == 'Approved')} approved)"),
           ("Corrective actions", f"{len(g.ACTIONS)} ({ver} verified, {len(g.ACTIONS) - ver} open / in progress)")])
    sheet(wb, "Exceptions",
          ["Exception ID", "Control", "Exception", "Business justification", "Compensating controls", "Risk",
           "Requested by", "Approved by", "Approved", "Expires", "Status"],
          g.EXCEPTIONS, [11, 9, 40, 40, 44, 8, 14, 18, 12, 12, 30], status_cols=(10,))
    sheet(wb, "Corrective_Actions",
          ["Action ID", "Source", "Issue", "Action", "Owner", "Due", "Status", "Verification criterion",
           "Verification evidence", "Verified on"],
          g.ACTIONS, [10, 13, 40, 44, 18, 12, 16, 34, 34, 12], status_cols=(6,))
    save(wb, "07_GRC/04_Remediation/CAN_DOC_Exceptions_and_Corrective_Actions_v1.0.xlsx")

    # ------------------------------------------------------------------ 3 evidence index
    wb = Workbook()
    rows, missing = [], 0
    for ctl, eid, desc, rel in g.EVIDENCE:
        h = g.sha256(rel)
        missing += h is None
        rows.append((ctl, eid, desc, rel, h or "MISSING (built later in this run or not yet created)"))
    cover(wb, "Evidence Index",
          "Week 10 Day 1: evidence organised by control. Each item has its repository path and SHA-256 hash computed when "
          "this index was built, so a reviewer can confirm nothing changed afterwards (shasum -a 256 <path>).",
          [("Items", str(len(rows))), ("Controls covered", str(len({r[0] for r in rows})))])
    sheet(wb, "Evidence_by_Control", ["Control", "Evidence ID", "Description", "Path (repository root)", "SHA-256"],
          rows, [9, 11, 44, 70, 68])
    save(wb, "06_Evidence/CAN_DOC_Evidence_Index_v1.0.xlsx")
    if missing:
        print(f"  note: {missing} evidence item(s) not found yet")

    # ------------------------------------------------------------------ 4 access review sign-off sheet
    rev = os.path.join(g.CAN, "06_Evidence/05_Access_Reviews/EV-15_Access_Review_AR-2026-Q4_20261103/access_review_AR-2026-Q4.csv")
    if os.path.isfile(rev):
        def recommend(r):
            f = r["flags"]
            if "DISABLED_BUT_HAS_ACCESS" in f: return "Revoke remaining access"
            if "ACCESS_PAST_END_DATE" in f: return "Revoke (past end date)"
            if "VENDOR_NO_END_DATE" in f: return "Modify: sponsor sets end date (CA-08)"
            if "MULTIPLE_ROLES_SOD_CHECK" in f: return "Modify: keep one role"
            if "NO_ROLE" in f and r["enabled"] == "True": return "Keep (no app access) or disable"
            if "PRIVILEGED_NO_MFA_ENROLLED" in f: return "Keep: OTP enrolment forced at next sign-in (CA-13)"
            if "STALE_NO_LOGIN_90D" in f: return "Keep (test account) or disable"
            if r["enabled"] == "False": return "Keep disabled (retained for audit)"
            return "Keep"
        data = g.review_rows(rev)
        wb = Workbook()
        cover(wb, "Quarterly Access Review AR-2026-Q4",
              "Week 4 Day 4: every account in realm care-access-navigator with its groups, roles, MFA status, last sign-in "
              "and automatic risk flags (can_iam.py review). The analyst's recommendation is filled in; the reviewer "
              "(manager / application owner) chooses Keep, Modify or Revoke for every row and signs below. Revoke and "
              "Modify decisions become corrective actions.",
              [("Accounts", str(len(data))), ("Flagged", str(sum(1 for r in data if r["flags"]))),
               ("Source", os.path.relpath(rev, g.REPO)),
               ("Reviewer sign-off", "Name: ____________________   Role: ____________________   Date: ___________"),
               ("Instructions", "Fill columns Reviewer decision / Reviewer / Decision date on the Review sheet, then sign.")])
        cols = ["username", "enabled", "source", "groups", "effective_roles", "mfa_enrolled", "last_login",
                "access_end_date", "flags", "risk"]
        ws = sheet(wb, "Review",
                   ["Username", "Enabled", "Source", "Groups", "Roles", "MFA enrolled", "Last sign-in", "End date", "Flags",
                    "Risk", "Analyst recommendation", "Reviewer decision", "Reviewer", "Decision date"],
                   [[r[c] for c in cols] + [recommend(r), "", "", ""] for r in data],
                   [42, 9, 9, 16, 16, 10, 12, 11, 40, 8, 38, 16, 16, 13], status_cols=(9,))
        dv = DataValidation(type="list", formula1='"Keep,Modify,Revoke"', allow_blank=True)
        ws.add_data_validation(dv)
        dv.add(f"L2:L{len(data) + 1}")
        for i in range(2, len(data) + 2):
            for c in (12, 13, 14):
                ws.cell(i, c).fill = PatternFill("solid", fgColor=CREAM)
        save(wb, "06_Evidence/05_Access_Reviews/CAN_DOC_Access_Review_AR-2026-Q4_v1.0.xlsx")
    else:
        print("  skip access review workbook: run can_iam.py review --review-id AR-2026-Q4 first", file=sys.stderr)


if __name__ == "__main__":
    main()
