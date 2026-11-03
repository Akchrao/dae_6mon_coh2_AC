"""Week 5 package: authentication baseline, privileged access matrix, service/vendor identities, control tests.
Output: Care_Access_Navigator/07_GRC/02_Controls/CAN_DOC_Authentication_and_Privileged_Access_v1.0.pdf
All before/after results are read from the EV-13 audit log (grc_data.live())."""
import json, os
from html import escape as e

import grc_data as g
from pdfstyle import P, bullets, note, code, table, kv, ok, bad, build, step, Spacer, PageBreak, inch, FULL_W

L = g.live()
OUT = os.path.join(g.CAN, "07_GRC/02_Controls/CAN_DOC_Authentication_and_Privileged_Access_v1.0.pdf")
TITLE = "Authentication & Privileged Access"


def res(t):
    if t.startswith(("LOGGED_IN", "PASS")):
        return ok(e(t))
    if t.startswith(("DENIED", "MFA_REQUIRED", "REJECTED")):
        return f"<font color='#1B2A4A'><b>{e(t)}</b></font>"
    return bad(e(t))


s = []
s += [P(TITLE, "title"), Spacer(1, 4), P(f"Week 5 &middot; {g.PROJECT} &middot; {g.ORG}", "subtitle"),
      P("Week 5 deliverables: authentication control baseline, privileged access matrix, service and vendor identity "
        "register, and control testing on the live Keycloak lab", "subsub"), Spacer(1, 10)]
s += kv([("Author", g.AUTHOR), ("Date", g.DATE), ("Version", "v1.0"),
         ("System", "Keycloak 26.0 realm care-access-navigator (Docker, localhost) brokered to Microsoft Entra ID"),
         ("Hardened at", L["harden_ts"] + " (UTC) with can_iam.py harden --migrate and app-gate"),
         ("Evidence", "06_Evidence/04_Test_Results/EV-13_Auth_Hardening_Live_20261103/ (SHA-256 indexed)"),
         ("Data", "Synthetic identities only; no ePHI")])
s += [P("Board items covered", "h2")]
s += table([["Day", "Board item", "Deliverable in this document", "Status"],
            ["Mon", "Document authentication control baseline", "Section 1 (10 controls, before/after)", ok("Done")],
            ["Tue", "Build privileged access matrix", "Section 3 (10 privileged accounts/roles + process)", ok("Done")],
            ["Wed", "Define service and vendor identity controls", "Section 4 (10 identities + 5 rules)", ok("Done")],
            ["Thu", "Test authentication and privileged-access controls", "Section 2 (live before/after tests)",
             ok("Done")]], [0.5 * inch, 2.1 * inch, 2.9 * inch, 1.0 * inch])
s += note("Audit findings F-01 (MFA), F-02 (lockout) and F-04 (password standard) from the Compliance 1 internal audit "
          "CAN-IA-2026-01 were open until this week. They are now fixed on the live lab and verified (corrective "
          "actions CA-01, CA-02, CA-04). F-02 and F-04 closed after their 10/23 target date.", "Result")

# ---------------------------------------------------------------- 1 baseline
s += [PageBreak(), P("1. Authentication control baseline", "h1"),
      P("The baseline states the standard for each authentication control, the value found on the live realm before "
        "the change, the value after, and how it was proven. Values come from the can_iam.py audit log, not from "
        "memory.")]
s += table([["ID", "Control and standard", "Before", "After / verified by", "Status"]] +
           [[a[0], f"<b>{e(a[1])}</b><br/>{e(a[2])}<br/><font size=7.5 color='#555555'>{e(a[6])}</font>", e(a[3]),
             f"{e(a[4])}<br/><i>{e(a[5])}</i>", ok(a[7]) if a[7] == "Enforced" else e(a[7])]
            for a in g.AUTH_BASELINE],
           [0.7 * inch, 1.85 * inch, 1.4 * inch, 1.7 * inch, 0.85 * inch])
rb, ra = L["realm"]["before"], L["realm"]["after"]
s += code("\n".join(f"{k:22} {str(rb.get(k)):60} -> {ra.get(k)}" for k in rb),
          title="Realm settings before -> after (audit log harden.realm_settings)", width=118)

# ---------------------------------------------------------------- 2 tests
s += [PageBreak(), P("2. Control tests: before and after (Week 5 Day 4)", "h1"),
      P("Two verification identities were created for the test so that no existing account's password had to be "
        "changed: <b>test.billing2</b> (group Billing, privileged) and <b>test.clinician2</b> (group Clinicians). "
        "Their password is kept in the lab's local .env file, which is not in git. Each sign-in walks the real "
        "browser login flow of the application and reports what Keycloak asked for.")]
pair = {}
for r in L["before"]:
    pair.setdefault((r["user"], r["client"]), [None, None])[0] = r["result"]
for r in L["after"]:
    pair.setdefault((r["user"], r["client"]), [None, None])[1] = r["result"]
expect = {("test.billing2", "billing-app"): "MFA prompt", ("test.billing2", "ehr-simulator"): "Denied",
          ("test.clinician2", "ehr-simulator"): "Allowed", ("test.clinician2", "patient-portal"): "Allowed",
          ("test.clinician2", "billing-app"): "Denied", ("test.clinician2", "hr-app"): "Denied"}
s += table([["User", "Application", "Expected after", "Before (baseline)", "After (hardened)"]] +
           [[u, c, expect.get((u, c), "-"), res(b) if b else "not run", res(a) if a else "not run"]
            for (u, c), (b, a) in sorted(pair.items())],
           [1.1 * inch, 1.1 * inch, 0.95 * inch, 1.65 * inch, 1.7 * inch])
lb, la = L["lock_before"], L["lock_after"]
pw_rows = [[p["test"], res(p["result"])] for p in L["pw"]]
s += table([["Test", "Before", "After"],
            ["11 wrong passwords on test.vendor1 (lockout)", res(lb["result"]), res(la["result"])],
            ["Brute-force status after the test", e(f"numFailures={lb['keycloak_status']['numFailures']}, "
                                                    f"locked={lb['keycloak_status']['disabled']}"),
             e(f"numFailures={la['keycloak_status']['numFailures']}, locked={la['keycloak_status']['disabled']}")]],
           [2.5 * inch, 2.0 * inch, 2.0 * inch])
s += table([["Password policy test (after)", "Result"]] + pw_rows, [3.0 * inch, 3.5 * inch])
s += note("The lockout test unlocks test.vendor1 afterwards (--unlock) so the account is not left locked. The "
          "Keycloak events from these tests also produced live detections: CAN-ID-001 brute force, CAN-ID-003 login "
          "while locked and CAN-ID-004 unauthorized app access (identity_detections.csv).", "Note")
s += [P("What the hardening changed", "h2")]
s += bullets([
    f"MFA flow <b>{e(L['mfa']['flow'])}</b> bound realm-wide and to {e(', '.join(L['mfa']['bound_clients']))}; "
    "the OTP step now depends on realm role <b>mfa-required</b>, held by groups Billing, IT-Support and "
    "Security-Analysts.",
    "The hand-built flow had two problems, both fixed: its OTP sub-flow used 'user configured' (people who never set "
    "up OTP skipped MFA), and an IT-Support role condition sat outside the sub-flow, where Keycloak ignores it "
    f"(removed; config {e(json.dumps(L['misplaced'][0]['config']) if L['misplaced'] else '-')}).",
    f"{len(L['migrated'])} local users moved from a direct role to their job-function group; "
    f"{len(L['skipped'])} Entra users left alone (their role comes from Entra with sync mode FORCE).",
    f"{len(L['gate'])} application gates bound: " +
    "; ".join(f"{e(x['app'])} &larr; {e(', '.join(x['allowed_roles']))}" for x in L["gate"]) + ".",
])
s += [P("Rollback", "h2"),
      P("A partial realm export was taken before any change: <font name='Courier'>03_IAM_Lab/01_Keycloak/"
        "02_Realm_Exports/CAN_KC_Realm_Export_Before_W5_Hardening_20261103_v1.json</font> (client secrets masked by "
        "Keycloak). To undo MFA quickly: Authentication &rarr; browser &rarr; Bind flow (browser).")]

# ---------------------------------------------------------------- 3 PAM
s += [PageBreak(), P("3. Privileged access matrix (Week 5 Day 2)", "h1"),
      P("Every account or role that can change security settings, read cardholder data or administer a platform "
        "used by the project. Billing is treated as privileged because it handles card payments (PCI DSS scope).")]
s += table([["ID", "Account / role (system)", "Holders", "MFA", "Monitoring", "Status"]] +
           [[p[0], f"<b>{e(p[1])}</b><br/>{e(p[2])}<br/><font size=7.5 color='#555555'>{e(p[3])}</font>", e(p[4]),
             e(p[7]), e(p[9]), e(p[11])] for p in g.PRIVILEGED],
           [0.5 * inch, 1.9 * inch, 1.1 * inch, 0.9 * inch, 1.3 * inch, 0.8 * inch])
s += [P("Privileged access lifecycle", "h2")]
s += table([["Step", "Rule"]] + [[k, e(v)] for k, v in g.PAM_PROCESS], [1.1 * inch, 5.4 * inch])

# ---------------------------------------------------------------- 4 service / vendor
s += [PageBreak(), P("4. Service and vendor identity register (Week 5 Day 3)", "h1")]
s += table([["ID", "Identity", "Owner", "Credential / expiry", "Status"]] +
           [[v[0], f"<b>{e(v[1])}</b><br/>{e(v[2])}, {e(v[3])}", e(v[4]), f"{e(v[5])}<br/><i>{e(v[6])}</i>", e(v[9])]
            for v in g.SERVICE_VENDOR],
           [0.5 * inch, 2.0 * inch, 1.1 * inch, 1.6 * inch, 1.3 * inch])
s += [P("Vendor and service-account rules", "h2")] + bullets([e(r) for r in g.VENDOR_RULES])

# ---------------------------------------------------------------- 5 exceptions / follow-up
s += [P("5. Exceptions and follow-up actions raised this week", "h1")]
s += table([["ID", "Exception", "Compensating controls", "Expires"]] +
           [[x[0], e(x[2]), e(x[4]), x[9]] for x in g.EXCEPTIONS if x[0] in ("EX-01", "EX-03", "EX-04", "EX-05")],
           [0.6 * inch, 2.4 * inch, 2.7 * inch, 0.8 * inch])
s += table([["ID", "Action", "Owner", "Due"]] +
           [[a[0], e(a[3]), e(a[4]), a[5]] for a in g.ACTIONS if a[0] in ("CA-11", "CA-12", "CA-13", "CA-15", "CA-16", "CA-17")],
           [0.6 * inch, 3.9 * inch, 1.2 * inch, 0.8 * inch])
s += note("Only the account owner can turn on Entra ID Security defaults (EX-01) and sign the access review (CA-05). "
          "Both are listed in the corrective-action tracker with steps.", "Open items")

build(OUT, s, TITLE, f"{g.PROJECT} | Week 5 Authentication & Privileged Access | v1.0")
