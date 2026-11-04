"""CA-14: bring the Project Design Documentation from v1.2 (status 10/13) to v1.3 (verified status 11/04).

Edits word/document.xml in place so the original formatting is kept: whole paragraphs are matched by their
opening words, and section 12/13/14 table rows by their first cell. Prints every change and fails if an expected
paragraph or row is not found. Usage: python3 update_design_doc.py <in.docx> <out.docx>"""
import re, shutil, sys, tempfile, zipfile
from html import escape

SRC, DST = sys.argv[1], sys.argv[2]
plain = lambda s: (re.sub(r"<[^>]+>", "", s).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                   .replace("&quot;", '"'))

PARAS = {  # paragraph starts with -> replacement text
    "Last updated:": "Last updated: Nov 4th, 2026",
    "Version: v1.2": "Version: v1.3",
    "Date: 10/13/2026": "Date: 11/04/2026",
    "Change Log:": "Change Log: v1.3 (11/04/2026): Section 14 status refreshed with evidence from the Week 5 live hardening "
                   "and the Week 12 end-to-end run (EV-13, EV-14, EV-15); Section 13.1 audit-finding status updated; "
                   "repository paths updated to the semester layout. v1.2 (10/13/2026): integrated the Compliance 1 and "
                   "Incident Response 1 course rubrics into the capstone (Sections 12–13); recorded the tools and frameworks "
                   "actually implemented to date (Azure, Microsoft Entra ID OIDC federation, Defender for Cloud, Azure Policy, "
                   "PCI DSS v4.0.1); added SAML federation, IAM automation (JML) and proof-of-detection / proof-of-prevention "
                   "success criteria; added an implementation-status snapshot (Section 14). v1.1 (08/11/2026): revised tool "
                   "stack and architecture diagram to use Tableau and practical 12-week simulation/equivalent components.",
    "In plain terms: every course": "In plain terms: every course has been answered with work on the same hospital scenario, "
                   "which is why the project tells one connected story (threat → network/cloud design → identity controls → "
                   "risk → compliance → incident response). Weeks 4, 5 and 9–12 were completed on 11/03/2026 by executing "
                   "those identity controls on the live lab and turning the results into registers, a dashboard dataset and "
                   "the demo (Section 14).",
    "Carry-forward into the capstone:": "Carry-forward into the capstone: audit findings F-01 (MFA not enforced), F-02 "
                   "(lockout disabled) and F-04 (password standard) were closed on 11/03/2026 with can_iam.py and verified "
                   "with before/after tests (evidence EV-13). F-05 (no completed access review) is in progress: review "
                   "AR-2026-Q4 was run on the live realm and awaits reviewer sign-off. F-03 (12-month log retention) and "
                   "F-06 (IdP over HTTP) are approved exceptions EX-02 and EX-05 with compensating controls and expiry dates.",
    "Verified against system-generated evidence": "Verified on 11/03–11/04/2026 against system-generated evidence: the "
                   "can_iam.py audit logs (EV-13 Week 5 hardening, EV-14 end-to-end tests, EV-15 access review), Keycloak "
                   "admin API reads and the Tableau dataset built from them. The Portfolio Index & Lessons Learned "
                   "(09_Portfolio/01_Documents) lists every deliverable and the open items.",
    "Evidence (compliance_1/)": "Evidence (Semester_5/Compliance_1/)",
}
HEADINGS = {"14. Implementation Status Snapshot (10/13/2026)": "14. Implementation Status Snapshot (11/04/2026)"}
NOTE_OLD, NOTE_NEW = "Evidence: incident_response_1/ in the repository.", "Evidence: Semester_5/Incident_Response_1/ in the repository."

ROWS = {  # first cell -> {column index: new text}
    "Compliance 1": {3: "Complete (5 tasks); F-01, F-02, F-04 closed 11/03; F-05 in progress; F-03, F-06 approved exceptions"},
    "3. Compliance Auditing Basics: audit plan, evidence for three controls, assessment + gap analysis, prioritized remediation plan":
        {3: "Complete; F-01, F-02, F-04 closed (verified 11/03); F-05 in progress; F-03, F-06 exceptions"},
    "Users / roles": {1: "Keycloak: 12 local test users (5 added for Week 5/12 tests) + 4 Entra-federated; 7 job roles. "
                         "Entra ID: 3 users, 7 app roles, assignment required", 2: "Done"},
    "Groups / security groups": {1: "7 Keycloak job-function groups; local users get roles only through their group "
                                    "(migrated 11/03). Entra uses app roles (group-to-app assignment needs Entra ID P1)",
                                 2: "Done"},
    "Applications": {1: "4 OIDC clients (fullScopeAllowed=false) each behind a per-app sign-in gate since 11/03; no running "
                        "app front-end", 2: "Done"},
    "RBAC / least privilege": {1: "One role per user through one group; app gates enforce the role-to-app matrix "
                                  "(TC-01, TC-02 pass)", 2: "Done"},
    "MFA": {1: "browser-mfa-privileged bound realm-wide 11/03: OTP required for Billing, IT-Support, Security-Analysts "
               "(F-01 closed). Entra users: Security defaults not yet evidenced (EX-01)", 2: "Done (Entra: exception)"},
    "Lockout / password": {1: "Lockout after 10 failures for 30 min; 12 characters, history 4 (F-02, F-04 closed, "
                              "verified 11/03)", 2: "Done"},
    "Federation": {1: "OIDC Keycloak↔Entra working; SAML 2.0 shown with can_iam.py saml-demo on the replica realm only",
                   2: "Partial"},
    "JML automation": {1: "Entra + Keycloak JML cycle 10/19 (JML-01..15); can_iam.py joiner/mover/leaver run on the live "
                          "realm (TC-01, TC-03, TC-04 pass)", 2: "Done"},
    "Access review": {1: "AR-2026-Q4 run on the live realm 11/03 (16 accounts, 10 flagged); leftover leaver role removed "
                         "(CA-09); reviewer sign-off pending (F-05)", 2: "Partial"},
    "Monitoring / detection": {1: "CAN-ID-001..007 identity rules on live Keycloak events (TC-05..07 pass); Wazuh 4.9.2 "
                                  "in the IR lab; Azure alerts. No continuously running SIEM for Keycloak", 2: "Partial"},
    "Log retention": {1: "90 days (Keycloak events, Azure Activity Log); 12 months not met: approved exception EX-02 "
                         "to 01/31/2027 (F-03)", 2: "Gap (exception)"},
    "Incident playbook": {1: "Cloud IR playbook (INC-20261008-01) + host playbook CAN-IR-PB-02 used for "
                             "IR1-2026-001/002/003", 2: "Done"},
    "Risk register / compliance": {1: "R01–R05 with treatment status; 16-control catalog mapped to HIPAA, CSF 2.0, "
                                      "SP 800-53, ISO 27001, PCI DSS; 7 exceptions, 17 corrective actions", 2: "Done"},
    "Simulated attack + PoD/PoP": {1: "Cloud, IR lab and identity layer: end-to-end run TC-01..TC-10, 10/10 pass "
                                      "(TC-05 after fix CA-10)", 2: "Done"},
    "Dashboard": {1: "Tableau dataset refreshed from live evidence; dashboard design with wireframe and validation values "
                     "(11/03); Tableau workbook build pending", 2: "Partial"},
}


def set_text(block, tag, new):
    ts = list(re.finditer(rf"<{tag}(?: [^>]*)?>(.*?)</{tag}>", block, re.S))
    if not ts:
        raise SystemExit(f"no <{tag}> in block: {plain(block)[:60]!r}")
    label = plain(ts[0].group(1))
    if len(ts) > 1 and label.strip() and new.startswith(label) and len(label) < len(new):
        # keep a separately formatted label run ("Version:", "Change Log:") and put the value after it
        head = block[:ts[1].start()]
        return head + set_text(block[ts[1].start():], tag, new[len(label):])
    for m in reversed(ts):
        val = escape(new, quote=False) if m is ts[0] else ""
        open_tag = re.match(rf"<{tag}(?: [^>]*)?>", m.group(0)).group(0)
        if tag == "w:t" and m is ts[0] and "xml:space" not in open_tag:
            open_tag = '<w:t xml:space="preserve">'
        block = block[:m.start()] + open_tag + val + f"</{tag}>" + block[m.end():]
    return block


def edit(x):
    seen = set()

    def row(m):
        r = m.group(0)
        cells = list(re.finditer(r"<w:tc(?: [^>]*)?>.*?</w:tc>", r, re.S))
        if not cells:
            return r
        key = plain(cells[0].group(0)).strip()
        if key not in ROWS:
            return r
        seen.add(key)
        for i in sorted(ROWS[key], reverse=True):
            c = cells[i]
            print(f"  row {key[:28]!r} col {i}: {plain(c.group(0))[:50]!r} -> {ROWS[key][i][:50]!r}")
            r = r[:c.start()] + set_text(c.group(0), "w:t", ROWS[key][i]) + r[c.end():]
        return r
    x = re.sub(r"<w:tr[ >].*?</w:tr>", row, x, flags=re.S)

    def para(m):
        p = m.group(0); t = plain(p).strip()
        for start, new in PARAS.items():
            if t.startswith(start):
                seen.add(start); print(f"  para {t[:50]!r} -> {new[:50]!r}")
                return set_text(p, "w:t", new)
        if t in HEADINGS:
            seen.add(t); print(f"  heading {t!r}")
            return set_text(p, "w:t", HEADINGS[t])
        if NOTE_OLD in t:
            seen.add(NOTE_OLD); print("  substitution note path")
            return set_text(p, "w:t", t.replace(NOTE_OLD, NOTE_NEW))
        return p
    x = re.sub(r"<w:p[ >].*?</w:p>", para, x, flags=re.S)
    missing = (set(ROWS) | set(PARAS) | set(HEADINGS) | {NOTE_OLD}) - seen
    if missing:
        raise SystemExit(f"not found: {sorted(missing)}")
    return x


tmp = tempfile.mktemp(suffix=".docx")
with zipfile.ZipFile(SRC) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename == "word/document.xml":
            data = edit(data.decode("utf-8")).encode("utf-8")
        zout.writestr(item, data)
shutil.move(tmp, DST)
print("wrote", DST)
