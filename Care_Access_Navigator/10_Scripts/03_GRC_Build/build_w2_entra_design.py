"""Week 2 Day 3 (board item W2 Wed): Entra ID identity governance design.
Output: Care_Access_Navigator/03_IAM_Lab/CAN_DOC_Entra_ID_Identity_Governance_Design_v1.0.pdf
Facts come from the realm export (IdP mappers), the JML evidence (JML-LOG.csv, JML-15 Entra audit log), grc_data.py
and the screenshots EV-02..EV-06, EV-17. Run with the pdf-build venv (reportlab):  python build_w2_entra_design.py
"""
import json, os

import grc_data as g
from pdfstyle import P, bullets, note, table, kv, ok, build, Spacer, PageBreak, inch

OUT = os.path.join(g.CAN, "03_IAM_Lab/CAN_DOC_Entra_ID_Identity_Governance_Design_v1.0.pdf")
TITLE = "Entra ID Identity Governance Design"
REALM = os.path.join(g.CAN, "03_IAM_Lab/01_Keycloak/02_Realm_Exports/CAN_KC_Realm_Export_Before_W5_Hardening_20261103_v1.json")

realm = json.load(open(REALM))
groups = {gr["realmRoles"][0]: gr["name"] for gr in realm["groups"] if gr.get("realmRoles")}
mappers = [m for m in realm["identityProviderMappers"] if m["identityProviderMapper"] == "oidc-role-idp-mapper"]
APPS = {"clinician": "EHR simulator, Patient Portal", "nurse": "EHR simulator, Patient Portal", "billing": "Billing app",
        "hr": "HR app", "it-support": "HR app (account support)", "security-analyst": "None (security events only)",
        "vendor": "None by default (per request, time-boxed)"}

s = [P(TITLE, "title"), Spacer(1, 4), P(f"Week 2 &middot; {g.PROJECT} &middot; {g.ORG}", "subtitle"),
     P("Board item W2 Wed: create/document the Entra ID tenant configuration available to the project, define groups "
       "and the identity governance approach", "subsub"), Spacer(1, 10)]
s += kv([("Author", g.AUTHOR), ("Date", "November 5, 2026"), ("Version", "v1.0"),
         ("Tenant", "Microsoft Entra ID, free tier, directory 'Default Directory' (tenant ID withheld)"),
         ("Integration", "OIDC app registration care-access-navigator-keycloak-broker -> Keycloak identity provider "
                         "'entra-id' in realm care-access-navigator"),
         ("Evidence", "EV-02..EV-06 (tenant, broker, federated user, application), EV-17 (Security defaults), "
                      "06_Evidence/07_JML_Lifecycle (JML-LOG.csv, JML-15 Entra audit log)"),
         ("Data", "Synthetic identities only; no ePHI")])
s += note("Entra ID is the workforce identity source; Keycloak is the broker and authorization layer that the "
          "applications trust. Entra decides <b>who</b> the person is and which <b>job role</b> they hold; Keycloak turns "
          "that role into application access. This document records what is built (with evidence) and the group design "
          "and governance rules the project follows.", "Summary")

# ---------------------------------------------------------------- 1 tenant
s += [P("1. Tenant configuration (as built)", "h1")]
s += table([["Setting", "Value", "Evidence"],
            ["Workforce accounts", "Cloud-only synthetic users (for example Sathya Hasi - Physician, Tara Jones - "
             "Billing Specialist, Jeevan Smith - leaver), department and job title set", "JML-LOG.csv; JML-15"],
            ["Broker application", "App registration care-access-navigator-keycloak-broker; user assignment required; "
             "client secret stored in the Keycloak identity provider (expiry to be recorded: CA-17)", "EV-04, EV-06; SV-06"],
            ["App roles", ", ".join(m["config"]["claim.value"] for m in mappers) + " (one per job function)",
             "Realm export, IdP mappers"],
            ["Role hand-off", "Keycloak mappers read the 'roles' claim and grant the matching realm role, sync mode "
             "FORCE (re-applied at every sign-in, so a change in Entra wins)", "Realm export"],
            ["Authentication", "Security defaults: <b>Enabled</b> - every user must register for MFA and is prompted when needed "
             "(always for administrators); legacy authentication blocked (exception EX-01 resolved 2026-11-05)", "EV-17"],
            ["Administrators", "One Global Administrator (tenant owner) (privileged access matrix PA-05)", "W5 PDF, PA-05"],
            ["Audit log", "Directory audit log, 7-day retention on the free tier; JML-cycle extract exported to the "
             "repository for permanence", "JML-15"]],
           [1.25 * inch, 3.75 * inch, 1.5 * inch])

# ---------------------------------------------------------------- 2 groups
s += [P("2. Group and role design", "h1"),
      P("One job function = one Entra app role = one Keycloak realm role = one Keycloak group. Access is never granted "
        "to an individual outside this chain.")]
rows = [["Entra app role", "Keycloak realm role", "Keycloak group", "Entra group (design)", "Applications"]]
for m in mappers:
    role = m["config"]["role"]
    rows.append([m["config"]["claim.value"], role, groups.get(role, "-"), "CAN-" + groups.get(role, role), APPS.get(role, "-")])
s += table(rows, [1.1 * inch, 1.1 * inch, 1.15 * inch, 1.65 * inch, 1.5 * inch])
s += bullets([
    "<b>Built:</b> the seven app roles, the seven Keycloak groups and the role mappers. In Entra, app roles are assigned "
    "<b>directly to users</b> on the broker application (JML-15: assignments on 2026-10-19).",
    "<b>Designed, not built:</b> Entra security groups CAN-&lt;group&gt; that each receive one app role on the broker "
    "application, so that adding a person to a group is the only joiner step. Assigning groups to an enterprise "
    "application requires Microsoft Entra ID P1; the lab tenant is on the free tier, so direct user assignment is used "
    "and recorded here as a design gap.",
    "<b>Separation of duties:</b> a person holds one job-function app role at a time; privileged roles (Billing, IT-Support, "
    "Security-Analyst) get MFA through Security defaults in Entra; local Keycloak accounts in those groups get the Keycloak OTP flow (W5)."])

# ---------------------------------------------------------------- 3 governance
s += [PageBreak(), P("3. Identity governance approach", "h1")]
s += table([["Process", "Rule", "Evidence"],
            ["Joiner", "Ticket (REQ-) approved by the line manager; create the Entra user with department and job title; "
             "assign exactly one app role; first sign-in creates the Keycloak copy with the mapped role",
             "REQ-2026-0101 (Sathya Hasi, Clinician)"],
            ["Mover", "Change ticket (CHG-) approved by the new manager; remove the old app role before adding the new one; "
             "revoke sessions; FORCE sync removes the old Keycloak role at next sign-in",
             "CHG-2026-0201 (Tara Jones, Nurse -> Billing)"],
            ["Leaver", "Termination ticket (TERM-) from HR; disable the Entra account, revoke sessions, remove the app role, "
             "then disable the Keycloak copy and remove its roles (can_iam.py leaver) - retained for audit",
             "TERM-2026-0301 (Jeevan Smith); TC-04, TC-09"],
            ["Access review", "Quarterly review of every account in the realm, including Entra-federated ones "
             "(source = entra-id); flags stale, privileged-without-MFA and disabled-but-has-access accounts; reviewer "
             "decision and sign-off per account", "AR-2026-Q4 (sign-off pending, CA-05)"],
            ["Authentication", "MFA for every Entra user through Security defaults; no legacy authentication",
             "EV-17"],
            ["Privileged access", "Single named Global Administrator; privilege only through job-function roles; "
             "reviewed quarterly", "PA-05; W5 privileged access matrix"],
            ["Logging", "Entra audit log exported after each JML cycle (7-day retention on the free tier); Keycloak "
             "keeps 90 days of login and admin events", "JML-15; AUTH-07"]],
           [1.1 * inch, 3.9 * inch, 1.5 * inch])

s += [P("4. Known gaps and next steps", "h1")]
s += table([["Gap", "Effect", "Tracked as"],
            ["Entra termination does not disable the Keycloak copy automatically", "Leaver depends on the operator "
             "running the Keycloak step", "CAN-FIND-001, CAN-CTRL-JML-002 (R02 High)"],
            ["Group-based app assignment needs Entra ID P1", "Roles are assigned per user instead of per group",
             "This design (section 2)"],
            ["Entra Access Reviews need an Entra ID Governance licence", "Reviews run from Keycloak with can_iam.py",
             "AR-01, CA-05"],
            ["Broker client secret expiry not recorded", "Federation could stop without warning", "CA-17"]],
           [2.3 * inch, 2.4 * inch, 1.8 * inch])
s += note("Week 2 Wednesday is covered: tenant configuration documented with evidence (section 1), groups and roles "
          "defined (section 2), governance approach defined and exercised in the October JML cycle (section 3).",
          "Board item")
build(OUT, s, TITLE, f"{g.PROJECT} - {TITLE} v1.0")
print("wrote", OUT)
