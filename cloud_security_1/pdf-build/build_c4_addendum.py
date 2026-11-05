"""Append a dated addendum to the Criterion 4 IAM evidence PDF.

The original 11 pages are kept unchanged; addendum pages (same style) are
appended and supersede the 'Known limitation' on page 11.
"""
import os

from pypdf import PdfReader, PdfWriter

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "build_pdf.py"), encoding="utf-8").read()
exec(src.split("\ns = []\n")[0])  # shared style helpers only (P, step, figure, code, table, note, ...)

ORIGINAL = os.path.join(HERE, "data", "Criterion_4_IAM_original_2026-09-30.pdf")  # pristine Sept 30 version
FINAL = os.path.join(SHOTS, "Care_Access_Navigator_CloudSec1_Criterion_4_IAM_Implementation.pdf")
ADDENDUM = os.path.join(HERE, ".cache", "c4-addendum.pdf")
ORIG_PAGES = len(PdfReader(ORIGINAL).pages)


def shot(filename, key, caption, max_h=4.4 * inch):
    """Embed an existing screenshot from cloud_security_1/ (downscaled)."""
    out = os.path.join(IMG, key + ".jpg")
    im = PILImage.open(os.path.join(SHOTS, filename)).convert("RGB")
    if im.width > 1800:
        im = im.resize((1800, round(im.height * 1800 / im.width)), PILImage.LANCZOS)
    im.save(out, quality=85, optimize=True)
    return figure(key, caption, max_h=max_h, path=out)


def addendum_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(inch, 0.55 * inch,
                      "Care Access Navigator — CloudSec1 Criterion 4: IAM — Addendum (October 6, 2026)")
    canvas.drawRightString(letter[0] - inch, 0.55 * inch, f"Page {ORIG_PAGES + doc.page}")
    canvas.setStrokeColor(GREY_LINE)
    canvas.line(inch, 0.7 * inch, letter[0] - inch, 0.7 * inch)
    canvas.restoreState()


fig_no[0] = 10  # original document ends at Figure 10
entra = open(os.path.join(HERE, "data", "c4-entra.txt")).read()
keycloak = open(os.path.join(HERE, "data", "c4-keycloak.txt")).read()
mappers, rest = keycloak.split("\n\n", 1)

a = []
a += [P("Addendum — Role-Differentiated Federation", "title"), Spacer(1, 4),
      P("Update of October 6, 2026: the planned enhancement on page 11 is now implemented and verified", "subtitle"),
      P("This addendum supersedes the “Known limitation” and “Planned enhancement” in the "
        "Implementation Status on page 11. Pages 1–11 are preserved unchanged as the record of the "
        "September 30 build.", "subsub"), Spacer(1, 12)]

a += [P("Summary", "h1"),
      P("On September 30, every user who signed in through Entra ID received the <b>security-analyst</b> role from "
        "a Hardcoded Role mapper, regardless of who they were. On October 6 this was replaced with "
        "<b>role-differentiated federation</b>: each person's CAN role is now assigned in Entra ID and carried to "
        "Keycloak in the token's <font name='Courier'>roles</font> claim, where it is mapped to the matching "
        "Keycloak realm role. Two new Entra ID test identities — a Billing user and a Nurse user — signed "
        "in end-to-end and each received <b>only</b> their own role.")]
a += table([
    ["", "September 30 (pages 1–11)", "October 6 (this addendum)"],
    ["How the CAN role is decided", "Hardcoded: everyone gets security-analyst",
     "Per user, from the Entra ID app role assigned to them"],
    ["Billing user receives", "security-analyst (wrong)", "<b>billing</b> only"],
    ["Nurse user receives", "security-analyst (wrong)", "<b>nurse</b> only"],
    ["Who can sign in", "Assigned users", "Assigned users only (assignment required = true)"],
    ["Federated username", "<font name='Courier'>entra-id.</font> (claim missing)",
     "<font name='Courier'>entra-id.&lt;UPN&gt;</font>, unique per person"],
], [1.75 * inch, 2.25 * inch, 2.5 * inch])

a += [P("Approach: App Roles instead of Group Claims", "h2"),
      P("Page 11 planned to use Entra ID <i>group</i> claims. Assigning groups to an enterprise application requires "
        "a Microsoft Entra ID P1/P2 licence, and this tenant is on the Free tier (no subscribed SKUs). "
        "<b>App roles</b> achieve the same result on the Free tier: the seven CAN roles are defined on the app "
        "registration, a role is assigned to each user on the enterprise application, and Entra ID emits it in the "
        "<font name='Courier'>roles</font> claim of the ID token. This is also the more direct model — the "
        "role is attached to the person's access to this specific application, not inferred from general "
        "directory groups.")]

a += [PageBreak(), P("Issues Found During the Audit", "h1"),
      P("Before adding the new users, the existing federation was audited from both sides (Entra ID and Keycloak). "
        "Three defects were found in the September 30 configuration:")]
a += table([
    ["#", "Defect", "Impact", "Fix"],
    ["1", "Two Hardcoded Role mappers (<font name='Courier'>role-mapper</font>, "
          "<font name='Courier'>security-analyst</font>) granted security-analyst to every Entra ID login",
     "<b>Least-privilege violation</b> — a nurse or billing clerk would receive security-analyst access",
     "Both mappers deleted (backed up first)"],
    ["2", "No Claim-to-Role mappers read the Entra ID <font name='Courier'>roles</font> claim",
     "Roles assigned in Entra ID were silently ignored", "Seven Claim-to-Role mappers added, one per CAN role"],
    ["3", "Keycloak requested only the <font name='Courier'>openid</font> scope, so "
          "<font name='Courier'>preferred_username</font>/<font name='Courier'>email</font> were absent",
     "Username template produced <font name='Courier'>entra-id.</font> for everyone — all federated people "
     "would collapse into one Keycloak account",
     "Scopes set to <font name='Courier'>openid profile email</font>; the broken account was deleted"],
], [0.3 * inch, 2.15 * inch, 2.15 * inch, 1.9 * inch])
a += note("The federated account shown in Figures 9–10 (username <font name='Courier'>entra-id.</font>) was "
          "a symptom of defect 3. It was exported to a backup and deleted; the administrator's next sign-in "
          "created a correctly named account, <font name='Courier'>entra-id.ch.akhilarao@gmail.com</font>.",
          "Note on pages 9–10")

a += step(9, "Assign CAN roles in Entra ID")
a += [P("The app registration <b>care-access-navigator-keycloak-broker</b> defines the seven CAN app roles "
        "(Billing, Clinician, HR, IT-Support, Nurse, Security-Analyst, Vendor). Two test identities were created "
        "and each was assigned exactly one role on the enterprise application. <b>Assignment required</b> is "
        "enabled, so a user with no assignment cannot sign in at all.")]
a += code(entra, "Entra ID enterprise application — role assignments (Microsoft Graph)")
a += shot("Test Billing.png", "c4billing", "Entra ID user Test Billing (test.billing@chakhilaraogmail.onmicrosoft"
          ".com) — member account assigned to the broker application.", max_h=3.9 * inch)
a += shot("Test Nurse.png", "c4nurse", "Entra ID user Test Nurse (test.nurse@chakhilaraogmail.onmicrosoft.com) "
          "— member account assigned to the broker application.", max_h=3.9 * inch)

a += step(10, "Map the Entra ID roles claim to Keycloak realm roles")
a += [P("On the <b>entra-id</b> identity provider, seven <b>Claim to Role</b> mappers translate each value of "
        "the <font name='Courier'>roles</font> claim into the matching realm role. All use sync mode "
        "<b>Force</b>, so a role change in Entra ID takes effect at the user's next sign-in, and removing a role "
        "in Entra ID removes it in Keycloak. The provider now requests "
        "<font name='Courier'>openid profile email</font> and sends "
        "<font name='Courier'>prompt=select_account</font>, so Microsoft always asks which account to use "
        "instead of silently reusing the administrator's session.")]
a += code(mappers + "\n\n" + rest.split("\n\n")[0], "Keycloak — entra-id identity provider configuration")

a += step(11, "End-to-end verification")
a += [P("Each test user signed in through the <b>entra-id</b> button in a private browser window, set a new "
        "password at Microsoft's first-sign-in prompt, and was returned to Keycloak. Keycloak's event log "
        "recorded <font name='Courier'>IDENTITY_PROVIDER_FIRST_LOGIN → REGISTER → LOGIN</font> for "
        "<font name='Courier'>entra-id.test.billing@…</font> (13:30 EDT) and "
        "<font name='Courier'>entra-id.test.nurse@…</font> (13:36 EDT) with no errors. The resulting "
        "accounts hold only their own role:")]
a += code(rest.split("\n\n", 1)[1], "Keycloak — federated users and their realm roles")
a += table([
    ["Test", "Expected", "Result"],
    ["Billing user signs in via Entra ID", "Keycloak role billing only", ok() + " — billing"],
    ["Nurse user signs in via Entra ID", "Keycloak role nurse only", ok() + " — nurse"],
    ["Either user receives security-analyst", "No", ok() + " — not assigned"],
    ["Administrator (Default Access, no CAN role)", "No CAN role", ok() + " — none"],
    ["billing-app role scope (config; fullScopeAllowed = false)", "billing", ok() + " — billing"],
    ["ehr-simulator / patient-portal role scope (config)", "nurse, clinician", ok() + " — nurse, clinician"],
], [2.6 * inch, 1.6 * inch, 2.3 * inch])
a += note("Keycloak's seven local test accounts (test.billing1 … test.vendor1) had no realm roles assigned. "
          "Each was given the role matching its name, so local and federated test identities now behave the same.",
          "Also corrected")

a += [P("Updated Implementation Status", "h1"),
      P("<b>Implemented &amp; verified:</b> OIDC federation (Keycloak ↔ Entra ID); profile attribute sync; "
        "<b>role-differentiated</b> RBAC — each federated identity receives exactly the CAN role assigned to "
        "it in Entra ID, for all seven roles, with Force sync; enterprise application assignment required; "
        "account picker enforced at sign-in.")]
a += table([
    ["Control area", "HIPAA Security Rule", "NIST CSF 2.0", "Addendum evidence"],
    ["Role-based least privilege", "§164.308(a)(4) Information access management",
     "PR.AA-05 (access permissions managed)", f"Steps 9–11, {figs('c4billing', 'c4nurse')}"],
    ["Unique user identification", "§164.312(a)(2)(i) Unique user identification",
     "PR.AA-01 (identities managed)", "Defect 3 fix; per-person usernames"],
    ["Access review / correction", "§164.308(a)(1)(ii)(D) Information system activity review",
     "ID.IM-02 (improvements identified)", "Issues found during the audit"],
], [1.5 * inch, 1.9 * inch, 1.55 * inch, 1.55 * inch])

doc = SimpleDocTemplate(ADDENDUM, pagesize=letter, leftMargin=inch, rightMargin=inch, topMargin=0.85 * inch,
                        bottomMargin=0.95 * inch)
doc.build(a, onFirstPage=addendum_footer, onLaterPages=addendum_footer)

w = PdfWriter()
for path in (ORIGINAL, ADDENDUM):
    for page in PdfReader(path).pages:
        w.add_page(page)
w.add_metadata({"/Title": "CAN CloudSec1 Criterion 4 - IAM Implementation Evidence (with Oct 6 addendum)",
                "/Author": "Akhila Chennamaneni"})
with open(FINAL, "wb") as f:
    w.write(f)
print(f"wrote {FINAL}: {ORIG_PAGES} original + {len(PdfReader(ADDENDUM).pages)} addendum pages")
