"""Care Access Navigator — Joiner/Mover/Leaver (JML) evidence write-up."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.dirname(HERE)                                   # capstone_next_steps/jml-evidence
REPO = os.path.dirname(os.path.dirname(EV))
sys.path.insert(0, os.path.join(REPO, "compliance_1", "pdf-build"))
from style import *  # noqa: F401,F403  (shared house style)
from reportlab.platypus import CondPageBreak
from PIL import Image as PILImage

OUT = os.path.join(EV, "Care_Access_Navigator_JML_Lifecycle_Evidence.pdf")
FOOT = "Care Access Navigator — Joiner / Mover / Leaver Lifecycle Evidence"
CACHE = os.path.join(HERE, ".cache")
os.makedirs(CACHE, exist_ok=True)


def shot(fname, caption, max_h=3.9 * inch):
    src = os.path.join(EV, fname)
    out = os.path.join(CACHE, fname.rsplit(".", 1)[0] + ".jpg")
    im = PILImage.open(src).convert("RGB")
    if im.width > 1800:
        im = im.resize((1800, round(im.height * 1800 / im.width)), PILImage.LANCZOS)
    im.save(out, quality=85, optimize=True)
    return figure(fname, caption, max_h=max_h, path=out)


def ev(fname, title=None, keep=None):
    txt = open(os.path.join(EV, fname)).read()
    if keep:
        txt = keep(txt)
    return code(txt, title or fname)


def compact_audit(t):
    import re
    out = []
    for l in t.splitlines():
        if "Validate user authentication" in l:
            continue
        m = re.match(r"(\d{4}-\d\d-\d\d )(\d\d:\d\d:\d\d)\s+(.*?)\s{2,}(\w+)\s+target=(.*?)\s+by=(.*)$", l)
        if m:
            tgt = m.group(5).replace("care-access-navigator-keycloak-broker, ", "app: ").replace("@chakhilaraogmail.onmicrosoft.com", "").replace("@chakhilaraogmai", "")
            out.append("%s  %-36s %s" % (m.group(2), m.group(3)[:36], tgt[:40]))
        else:
            out.append(l.replace("@chakhilaraogmail.onmicrosoft.com", ""))
    return "\n".join(out)


s = []
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("Identity Lifecycle — Joiner / Mover / Leaver (JML) Evidence", "subtitle"),
      P("Microsoft Entra ID as the source of truth, federated into Keycloak (OIDC) for the Care Access Navigator "
        "applications", "subsub"), Spacer(1, 12)]
s += kv([("Prepared by:", "Akhila Chennamaneni, GRC / IAM Analyst"),
         ("Organization:", "HealthLine Regional Medical Center — Care Access Navigator (CAN)"),
         ("Systems:", "Microsoft Entra ID (tenant chakhilaraogmail.onmicrosoft.com), enterprise app "
                      "care-access-navigator-keycloak-broker; Keycloak 26 realm care-access-navigator"),
         ("Executed:", "October 19, 2026 (all times UTC)"), ("Cost:", "$0 — Entra ID Free tier; Keycloak local")])
s += [P("Purpose", "h1"),
      P("This document proves that HealthLine's access lifecycle works end to end: a new workforce member receives "
        "exactly the access their job needs on day one (<b>Joiner</b>), a transfer removes old access before granting "
        "new access (<b>Mover</b>), and a departing employee loses all access the same day (<b>Leaver</b>). Each step "
        "was executed live and is evidenced three ways: administrator screenshots, read-only system extracts "
        "(Microsoft Graph and the Keycloak admin API), and the Entra ID audit log.")]

s += [P("How identity flows in Care Access Navigator", "h2")]
s += code("""  Person signs in --> Microsoft Entra ID ---------------------> Keycloak (realm care-access-navigator) --> CAN apps
                     - workforce directory (source of truth)    - auto-creates entra-id.<login> account     ehr-simulator
                     - app role on enterprise app                - maps Entra role -> realm role (sync FORCE) patient-portal
                       (Clinician, Nurse, Billing, ...)          - password/lockout/MFA rules, event logs    billing-app
                     - "assignment required" = only assigned                                                 hr-app
                       people can sign in""", "Federation model (OIDC)")
s += table([
    ["Requirement", "Why", "Reference"],
    ["Access granted by role, least privilege", "Staff see only the ePHI their job needs", "HIPAA §164.308(a)(4); "
     "PCI DSS 7.2"],
    ["Access changed promptly on transfer", "Prevents privilege creep", "HIPAA §164.308(a)(4)(ii)(C)"],
    ["Access removed at termination", "Departed staff must not reach ePHI or card data", "HIPAA §164.308(a)(3)"
     "(ii)(C); PCI DSS 8.2.5"],
    ["Changes logged and retained", "Prove who changed what, when", "HIPAA §164.312(b); PCI DSS 10.2"],
], [2.1 * inch, 2.2 * inch, 2.2 * inch])

s += [CondPageBreak(2.2 * inch), P("Cast and tickets", "h2")]
s += table([
    ["Stage", "Ticket", "Person (display name)", "Login (UPN)", "Change", "Approver"],
    ["Joiner", "REQ-2026-0101", "Sathya Hasi — Physician", "test.clinician", "New account → Clinician",
     "Clinical Ops Manager"],
    ["Mover", "CHG-2026-0201", "Tara Jones — RN → Billing Specialist", "test.nurse", "Nurse → Billing",
     "Billing Manager"],
    ["Leaver", "TERM-2026-0301", "Jeevan Smith — Billing Specialist", "test.billing", "Disable, remove access",
     "Billing Manager + HR"],
], [0.6 * inch, 1.2 * inch, 1.5 * inch, 0.9 * inch, 1.2 * inch, 1.1 * inch])
s += note("Display names were changed from 'Test Nurse' / 'Test Billing' to realistic names before the cycle "
          "(audit log 16:08 and 16:10 UTC). Logins and roles were unchanged, so the rename has no security effect.",
          "Preparation")

# ---------------------------------------------------------------- before
s += [PageBreak(), P("1. Baseline (before)", "h1")]
s += shot("JML-01-before-users.png", "Entra ID users before the cycle: 3 users.")
s += shot("JML-02-before-app-roles.png", "Enterprise app care-access-navigator-keycloak-broker — assigned users "
          "before the cycle.")
s += ev("JML-02b-before-app-roles.txt", "System extract: role assigned to each user (portal list does not show the "
        "role column)")

# ---------------------------------------------------------------- joiner
s += [PageBreak(), P("2. Joiner — Sathya Hasi (REQ-2026-0101)", "h1")]
s += table([
    ["#", "Action", "System", "Time (UTC)"],
    ["1", "Create user test.clinician, Physician / Internal Medicine, temporary password", "Entra ID", "16:23"],
    ["2", "Assign app role Clinician on the enterprise app", "Entra ID", "16:46"],
    ["3", "First sign-in through entra-id; password changed; security info registered", "Entra ID", "16:53–16:57"],
    ["4", "Keycloak auto-creates entra-id.test.clinician with realm role clinician (REGISTER + LOGIN)", "Keycloak",
     "17:10"],
], [0.3 * inch, 4.2 * inch, 0.9 * inch, 1.1 * inch])
s += shot("JML-03-joiner-role-assigned.png", "Clinician app role assigned to Sathya Hasi.")
s += shot("JML-04-joiner-first-login.png", "Sathya Hasi's first sign-in lands on the Keycloak account page.")
s += ev("JML-05-after-joiner.txt", "System extract after the joiner (Entra + Keycloak + Keycloak events)")
s += note("No Keycloak account was created by hand. Keycloak provisioned it just-in-time at first sign-in and gave it "
          "only the clinician role, which reaches ehr-simulator and patient-portal but not billing-app or hr-app.",
          "Finding")

# ---------------------------------------------------------------- mover
s += [PageBreak(), P("3. Mover — Tara Jones (CHG-2026-0201)", "h1")]
s += table([
    ["#", "Action", "System", "Time (UTC)"],
    ["1", "Remove app role Nurse (old access removed first)", "Entra ID", "17:21"],
    ["2", "Assign app role Billing", "Entra ID", "17:23"],
    ["3", "Revoke sign-in sessions (old tokens invalid)", "Entra ID", "17:26"],
    ["4", "Job title Registered Nurse → Billing Specialist; dept Med-Surg 4W → Patient Financial Services",
     "Entra ID", "17:27"],
    ["5", "Next sign-in: Keycloak re-syncs roles → billing only; name updated to Tara Jones", "Keycloak", "17:41"],
], [0.3 * inch, 4.2 * inch, 0.9 * inch, 1.1 * inch])
s += shot("JML-06-mover-old-role-removed.png", "Nurse assignment removed for Tara Jones.")
s += shot("JML-07-mover-new-role.png", "Billing assignment added for Tara Jones.")
s += shot("JML-08-mover-keycloak-role.png", "Keycloak role mapping after the move: billing, no nurse.")
s += ev("JML-09-after-mover.txt", "System extract after the mover")
s += note("Keycloak removed the old nurse role by itself. The identity-provider role mappers use sync mode FORCE, "
          "so roles are recalculated from the Entra token at every sign-in. Access is replaced, not accumulated "
          "— this is the control that prevents privilege creep.", "Finding")

# ---------------------------------------------------------------- leaver
s += [PageBreak(), P("4. Leaver — Jeevan Smith (TERM-2026-0301)", "h1")]
s += table([
    ["#", "Action", "System", "Time (UTC)"],
    ["1", "Disable account (block sign-in)", "Entra ID", "18:13"],
    ["2", "Revoke sign-in sessions", "Entra ID", "18:15"],
    ["3", "Remove app role Billing from the enterprise app", "Entra ID", "18:17"],
    ["4", "Disable the Keycloak copy entra-id.test.billing (retained, not deleted); no active sessions", "Keycloak",
     "~18:28"],
    ["5", "Verification: sign-in attempt refused — 'Your account has been locked'", "Entra ID", "after 18:17"],
], [0.3 * inch, 4.2 * inch, 0.9 * inch, 1.1 * inch])
s += shot("JML-10-leaver-disabled.png", "Jeevan Smith's Entra account disabled.")
s += shot("JML-11-leaver-access-removed.png", "Billing assignment removed — Jeevan no longer listed.")
s += shot("JML-12-leaver-keycloak-disabled.png", "Keycloak copy entra-id.test.billing set to Disabled.")
s += shot("JML-13-leaver-login-refused.png", "Proof of removal: Microsoft refuses Jeevan's sign-in.")
s += note("A first attempt left the Keycloak copy enabled (screenshot showed the switch still on). It was caught in "
          "verification and corrected; the Keycloak admin API then returned enabled = false. Verification after every "
          "change is part of the procedure for this reason.", "Issue found and fixed")
s += ev("JML-14-after-leaver.txt", "System extract after the leaver",
        keep=lambda t: t.split("Keycloak — admin events")[0].rstrip()
        + "\n\nKeycloak re-check after the fix: entra-id.test.billing enabled = false")

# ---------------------------------------------------------------- audit
s += [PageBreak(), P("5. Independent Evidence — Entra ID Audit Log", "h1"),
      P("The audit log records every administrative change with time, actor and before/after values. It was exported "
        "the same day because the Entra ID Free tier keeps audit data for only 7 days. Routine 'Validate user "
        "authentication' entries (admin portal sign-ins) are omitted below for readability; the full export is in "
        "JML-15-entra-audit-log.txt.")]
s += ev("JML-15-entra-audit-log.txt", "JML-15 (filtered)",
        keep=compact_audit)

# ---------------------------------------------------------------- log + findings
s += [CondPageBreak(3 * inch), P("6. JML Change Log", "h1")]
s += table([
    ["Ticket", "Type", "Person", "Before", "After", "Entra time", "Keycloak time"],
    ["REQ-2026-0101", "Joiner", "Sathya Hasi", "No account", "Clinician", "16:23 / 16:46", "17:10"],
    ["CHG-2026-0201", "Mover", "Tara Jones", "Nurse", "Billing (nurse removed)", "17:21 / 17:23 / 17:26", "17:41"],
    ["TERM-2026-0301", "Leaver", "Jeevan Smith", "Billing, enabled", "Disabled, no role", "18:13 / 18:15 / 18:17",
     "~18:28"],
], [1.2 * inch, 0.55 * inch, 0.85 * inch, 0.9 * inch, 1.15 * inch, 1.1 * inch, 0.75 * inch])
s += [P("Machine-readable copy: JML-LOG.csv. All files are fingerprinted in EVIDENCE-INDEX-SHA256.txt.", "caption")]

s += [P("7. Key Findings and Lessons Learned", "h1")]
s += table([
    ["#", "Observation", "Implication / recommendation"],
    ["1", "Joiner provisioning is automatic: assigning one Entra app role was enough to create a correctly scoped "
     "Keycloak account at first sign-in.", "Single point of control (Entra). No duplicate accounts to maintain."],
    ["2", "Mover: Keycloak replaced nurse with billing on the next sign-in (sync FORCE).", "Privilege creep "
     "prevented by design. Revoking Entra sessions forces that next sign-in."],
    ["3", "Leaver: Entra blocks sign-in immediately, but Keycloak is not notified — its copy stays enabled until "
     "an admin disables it.", "<b>Known limitation.</b> Keep the manual Keycloak step in the procedure; future "
     "improvement: SCIM/automated deprovisioning or a scheduled reconciliation script."],
    ["4", "An existing Keycloak session would survive Entra revocation until it expires (30-min idle).",
     "Always sign out Keycloak sessions for leavers; consider shorter session lifetimes for privileged roles."],
    ["5", "Accounts are disabled, not deleted.", "Preserves audit trail (HIPAA 6-year documentation retention)."],
    ["6", "Assigning Entra groups to the app requires a paid licence (P1/P2).", "Users are assigned individually "
     "on the Free tier; group-based assignment is the scalable option if licensed."],
    ["7", "Keycloak shows the old name 'Test Billing' for the leaver.", "Expected: names re-sync only at sign-in, and "
     "a leaver never signs in again."],
    ["8", "Entra Free keeps audit logs 7 days.", "Export audit logs promptly or stream them to a log store "
     "(Compliance finding F-03)."],
], [0.3 * inch, 3.0 * inch, 3.2 * inch])
s += [KeepTogether([P("Conclusion", "h2"),
      P("All three lifecycle events completed successfully and were independently verified in Entra ID, Keycloak and "
        "the audit log. The design gives least-privilege access on day one, replaces rather than accumulates access "
        "on transfer, and removes access on termination — with one documented manual control (disabling the "
        "Keycloak copy) until automated deprovisioning is introduced.")])]

build(OUT, s, "CAN JML Lifecycle Evidence", FOOT)
