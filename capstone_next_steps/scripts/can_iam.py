#!/usr/bin/env python3
"""
can_iam.py — Care Access Navigator (HRMC) IAM automation for Keycloak
=====================================================================
Author : Akhila Chennamaneni (capstone) — starter built with Claude, 2026-10-13
Needs  : Python 3.8+ standard library only (no pip installs, no admin rights)
Target : Keycloak 26.x realm `care-access-navigator` (docker container care-access-keycloak)

Sub-commands
  harden      Fix audit findings F-01/F-02/F-04 + create RBAC groups (optionally migrate users)
  joiner      Onboard a new workforce identity into exactly one role group
  mover       Move an identity from one role group to another (old access removed first)
  leaver      Disable, sign out, strip groups/roles, and verify access is gone
  review      Export a quarterly access-review CSV with automatic risk flags
  app-gate    Per-app access gate: only approved job roles can sign in to each app
  verify      Prove controls work: MFA prompt, lockout, disabled-user denial, app denial
  detect      Simulated SIEM: identity detections over Keycloak events (brute force,
              disabled/locked login, unapproved app, privilege change, expired access)
              plus optional EHR access log (excessive patient-record access) -> CSV for Tableau
  saml-demo   Stand up a SAML 2.0 federation (partner realm -> HRMC realm) and prove SSO

Every action is written to evidence/can_iam_audit_log.jsonl (one JSON object per line,
UTC timestamp, actor, before/after) and evidence/EVIDENCE-INDEX-SHA256.txt is refreshed.

Environment variables (defaults in brackets)
  KC_URL       [http://localhost:8080]
  KC_REALM     [care-access-navigator]
  KC_ADMIN     admin user in the master realm   (from your .env KC_ADMIN_USERNAME)
  KC_ADMIN_PW  admin password                   (from your .env KC_ADMIN_PASSWORD)
  CAN_EVIDENCE [./evidence]

SYNTHETIC DATA ONLY — never point this at a realm that contains real people or ePHI.
"""
import argparse, csv, datetime as dt, hashlib, html, http.cookiejar, json, os, re, sys
import urllib.error, urllib.parse, urllib.request

KC_URL = os.environ.get("KC_URL", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("KC_REALM", "care-access-navigator")
EVID = os.environ.get("CAN_EVIDENCE", "./evidence")

# Business role -> Keycloak realm role -> RBAC group (one group per job function)
ROLE_GROUPS = {
    "clinician": "HRMC-Clinicians", "nurse": "HRMC-Nurses", "billing": "HRMC-Billing",
    "hr": "HRMC-HR", "it-support": "HRMC-IT-Support",
    "security-analyst": "HRMC-Security-Analysts", "vendor": "HRMC-Vendors",
}
PRIVILEGED = {"it-support", "security-analyst", "billing"}   # MFA required (policy 4.6 / PCI 8.4.2)
MFA_CLIENTS = ["billing-app", "hr-app"]                       # apps bound to the MFA flow
MFA_FLOW = "browser-mfa-privileged"


# ----------------------------------------------------------------- helpers
def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(action, **data):
    os.makedirs(EVID, exist_ok=True)
    rec = {"ts_utc": now(), "actor": os.environ.get("KC_ADMIN", "?"), "realm": REALM, "action": action, **data}
    with open(os.path.join(EVID, "can_iam_audit_log.jsonl"), "a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"[{rec['ts_utc']}] {action}: " + json.dumps(data)[:300])


def hash_index():
    lines = [f"EVIDENCE INDEX — can_iam.py (SHA-256, computed {now()})"]
    for name in sorted(os.listdir(EVID)):
        p = os.path.join(EVID, name)
        if os.path.isfile(p) and not name.startswith("EVIDENCE-INDEX"):
            h = hashlib.sha256(open(p, "rb").read()).hexdigest()
            lines.append(f"{h}  {os.path.getsize(p):>8} bytes  {name}")
    open(os.path.join(EVID, "EVIDENCE-INDEX-SHA256.txt"), "w").write("\n".join(lines) + "\n")


class KC:
    """Tiny Keycloak Admin REST client (stdlib only)."""

    def __init__(self):
        user, pw = os.environ.get("KC_ADMIN"), os.environ.get("KC_ADMIN_PW")
        if not user or not pw:
            sys.exit("Set KC_ADMIN and KC_ADMIN_PW (see your docker-compose .env)")
        body = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli",
                                       "username": user, "password": pw}).encode()
        tok = json.load(urllib.request.urlopen(
            f"{KC_URL}/realms/master/protocol/openid-connect/token", body))
        self.h = {"Authorization": "Bearer " + tok["access_token"], "Content-Type": "application/json"}
        self.base = f"{KC_URL}/admin/realms"

    def call(self, method, path, body=None, realm=REALM, ok404=False):
        url = f"{self.base}/{realm}{path}" if realm else f"{self.base}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self.h, method=method)
        try:
            r = urllib.request.urlopen(req)
            txt = r.read().decode()
            return json.loads(txt) if txt.strip().startswith(("{", "[")) else (txt or None)
        except urllib.error.HTTPError as e:
            if ok404 and e.code in (404, 409):
                return None
            sys.exit(f"HTTP {e.code} {method} {path}: {e.read().decode()[:300]}")

    get = lambda s, p, **k: s.call("GET", p, **k)
    put = lambda s, p, b, **k: s.call("PUT", p, b, **k)
    post = lambda s, p, b=None, **k: s.call("POST", p, b if b is not None else {}, **k)
    delete = lambda s, p, b=None, **k: s.call("DELETE", p, b, **k)

    # lookups
    def user(self, username):
        u = self.get(f"/users?exact=true&username={urllib.parse.quote(username)}")
        if not u:
            sys.exit(f"user {username} not found")
        return u[0]

    def group(self, name):
        g = [x for x in self.get(f"/groups?search={name}&exact=true") if x["name"] == name]
        return g[0] if g else None

    def role(self, name):
        return self.get(f"/roles/{name}")

    def user_groups(self, uid):
        return [g["name"] for g in self.get(f"/users/{uid}/groups")]

    def direct_roles(self, uid):
        return sorted(r["name"] for r in self.get(f"/users/{uid}/role-mappings/realm")
                      if r["name"] in ROLE_GROUPS)

    def effective_roles(self, uid):
        return sorted(r["name"] for r in self.get(f"/users/{uid}/role-mappings/realm/composite")
                      if r["name"] in ROLE_GROUPS)

    def federated(self, uid):
        # Entra ID users: roles arrive from the IdP mappers (FORCE sync), not from RBAC groups
        return [l["identityProvider"] for l in self.get(f"/users/{uid}/federated-identity")]

    def snapshot(self, username):
        u = self.user(username)
        return {"username": username, "enabled": u["enabled"], "groups": self.user_groups(u["id"]),
                "effective_roles": self.effective_roles(u["id"]),
                "sessions": len(self.get(f"/users/{u['id']}/sessions"))}


# ----------------------------------------------------------------- harden
def cmd_harden(kc, a):
    before = kc.get("")
    keys = ["bruteForceProtected", "failureFactor", "waitIncrementSeconds", "maxFailureWaitSeconds",
            "permanentLockout", "passwordPolicy"]
    snap_b = {k: before.get(k) for k in keys}

    # F-02 lockout after 10 failures for 30 min; F-04 12+ chars, history 4
    pol = "length(12) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and passwordHistory(4)"
    kc.put("", {"bruteForceProtected": True, "failureFactor": 10, "waitIncrementSeconds": 1800,
                "maxFailureWaitSeconds": 1800, "maxDeltaTimeSeconds": 43200, "permanentLockout": False,
                "passwordPolicy": pol, "eventsEnabled": True, "adminEventsEnabled": True,
                "adminEventsDetailsEnabled": True, "eventsExpiration": 7776000})
    after = kc.get("")
    log("harden.realm_settings", finding="F-02,F-04", before=snap_b, after={k: after.get(k) for k in keys})

    # F-01 MFA — role-based: anyone holding realm role `mfa-required` MUST pass OTP
    # (users who have not enrolled yet are forced to enrol on next login).
    if not kc.get("/roles/mfa-required", ok404=True):
        kc.post("/roles", {"name": "mfa-required",
                           "description": "Marker role: OTP enforced at login (policy 4.6, PCI 8.4.2)"})
    mfa_role = kc.role("mfa-required")
    flows = {f["alias"]: f for f in kc.get("/authentication/flows")}
    if MFA_FLOW not in flows:
        kc.post("/authentication/flows/browser/copy", {"newName": MFA_FLOW})
    fq = urllib.parse.quote(MFA_FLOW)
    ex = kc.get(f"/authentication/flows/{fq}/executions")
    otp_sub = next(e for e in ex if e.get("authenticationFlow") and "Conditional OTP" in e["displayName"])
    sub_alias = urllib.parse.quote(otp_sub["displayName"])
    sub_ex = kc.get(f"/authentication/flows/{sub_alias}/executions")
    if not any(e.get("providerId") == "conditional-user-role" for e in sub_ex):
        for e in sub_ex:   # replace "user configured" (lets un-enrolled users skip MFA) with "user role"
            if e.get("providerId") == "conditional-user-configured":
                kc.delete(f"/authentication/executions/{e['id']}")
        kc.post(f"/authentication/flows/{sub_alias}/executions/execution", {"provider": "conditional-user-role"})
        sub_ex = kc.get(f"/authentication/flows/{sub_alias}/executions")
        cond = next(e for e in sub_ex if e.get("providerId") == "conditional-user-role")
        kc.put(f"/authentication/flows/{sub_alias}/executions", {"id": cond["id"], "requirement": "REQUIRED"})
        kc.post(f"/authentication/executions/{cond['id']}/config",
                {"alias": "cond-mfa-required-role", "config": {"condUserRole": "mfa-required", "negate": "false"}})
        kc.post(f"/authentication/executions/{cond['id']}/raise-priority")   # condition before OTP form
    for e in kc.get(f"/authentication/flows/{sub_alias}/executions"):
        if e.get("providerId") == "auth-otp-form" and e["requirement"] != "REQUIRED":
            kc.put(f"/authentication/flows/{sub_alias}/executions", {"id": e["id"], "requirement": "REQUIRED"})
    # privileged / CDE groups carry the marker role
    for role in PRIVILEGED:
        g = kc.group(ROLE_GROUPS[role])
        if g:
            kc.post(f"/groups/{g['id']}/role-mappings/realm", [mfa_role])
    flow_id = next(f["id"] for f in kc.get("/authentication/flows") if f["alias"] == MFA_FLOW)
    kc.put("", {"browserFlow": MFA_FLOW})   # realm-wide: MFA follows the person, not just the app
    changes = [(e, e["requirement"]) for e in kc.get(f"/authentication/flows/{sub_alias}/executions")]
    bound = []
    for cid in MFA_CLIENTS:
        c = kc.get(f"/clients?clientId={cid}")
        if not c:
            print(f"  ! client {cid} not found, skipped"); continue
        c = c[0]
        ov = c.get("authenticationFlowBindingOverrides") or {}
        ov["browser"] = flow_id
        c["authenticationFlowBindingOverrides"] = ov
        kc.put(f"/clients/{c['id']}", c)
        bound.append(cid)
    log("harden.mfa", finding="F-01", flow=MFA_FLOW,
        executions={e["displayName"]: r for e, r in changes}, bound_clients=bound)

    # Keycloak 26 drops custom user attributes unless the user profile allows them.
    # ADMIN_EDIT = only admins/automation can set department, manager, access_end_date, tickets.
    prof = kc.get("/users/profile")
    if prof.get("unmanagedAttributePolicy") != "ADMIN_EDIT":
        prof["unmanagedAttributePolicy"] = "ADMIN_EDIT"
        kc.put("/users/profile", prof)
    log("harden.user_profile", unmanagedAttributePolicy="ADMIN_EDIT",
        why="store JML attributes (department, manager, access_end_date, tickets) on each identity")

    # RBAC groups — one per job function, each mapped to exactly one realm role
    for role, gname in ROLE_GROUPS.items():
        g = kc.group(gname)
        if not g:
            kc.post("/groups", {"name": gname, "attributes": {"owner": ["IAM Analyst"],
                                                              "description": [f"RBAC group for {role}"]}})
            g = kc.group(gname)
        r = kc.role(role)
        kc.post(f"/groups/{g['id']}/role-mappings/realm", [r])
    for role in PRIVILEGED:   # (re)apply marker role now that groups certainly exist
        kc.post(f"/groups/{kc.group(ROLE_GROUPS[role])['id']}/role-mappings/realm", [kc.role("mfa-required")])
    log("harden.groups", groups=ROLE_GROUPS, mfa_required_groups=sorted(ROLE_GROUPS[r] for r in PRIVILEGED))

    if a.migrate:
        # move direct role assignments onto the matching group, then remove the direct role
        for u in kc.get("/users?max=500"):
            if kc.federated(u["id"]):   # Entra re-applies the role at next sign-in; leave it alone
                log("harden.migrate_skip", username=u["username"], reason="federated identity (roles from IdP)")
                continue
            for role in kc.direct_roles(u["id"]):
                g = kc.group(ROLE_GROUPS[role])
                kc.put(f"/users/{u['id']}/groups/{g['id']}", {})
                kc.delete(f"/users/{u['id']}/role-mappings/realm", [kc.role(role)])
                log("harden.migrate_user", username=u["username"], role=role, group=g["name"])
    hash_index()


# ----------------------------------------------------------------- JML
def cmd_joiner(kc, a):
    role = a.role
    if role not in ROLE_GROUPS:
        sys.exit(f"role must be one of {list(ROLE_GROUPS)}")
    attrs = {"department": [a.department], "manager": [a.manager], "ticket": [a.ticket],
             "employment_type": ["vendor" if role == "vendor" else "employee"]}
    if a.end_date:
        attrs["access_end_date"] = [a.end_date]
    if role == "vendor" and not a.end_date:
        sys.exit("vendors must have --end-date (policy: no indefinite third-party access)")
    required = ["UPDATE_PASSWORD"] + (["CONFIGURE_TOTP"] if role in PRIVILEGED else [])
    kc.post("/users", {"username": a.username, "firstName": a.first, "lastName": a.last,
                       "email": a.email, "enabled": True, "emailVerified": True,
                       "attributes": attrs, "requiredActions": required,
                       "credentials": [{"type": "password", "value": a.temp_password, "temporary": True}]})
    u = kc.user(a.username)
    g = kc.group(ROLE_GROUPS[role])
    if not g:
        sys.exit("RBAC groups missing — run `harden` first")
    kc.put(f"/users/{u['id']}/groups/{g['id']}", {})
    log("JOINER", ticket=a.ticket, approved_by=a.manager, after=kc.snapshot(a.username),
        required_actions=required)
    hash_index()


def cmd_mover(kc, a):
    if a.new_role not in ROLE_GROUPS:
        sys.exit(f"role must be one of {list(ROLE_GROUPS)}")
    u = kc.user(a.username)
    if kc.federated(u["id"]):
        sys.exit(f"{a.username} is federated from {kc.federated(u['id'])}: change the app role in Entra ID "
                 "(Enterprise applications -> Users and groups); Keycloak re-syncs it at next sign-in")
    before = kc.snapshot(a.username)
    # 1) remove ALL old role groups + direct roles first, so access never accumulates
    for g in kc.get(f"/users/{u['id']}/groups"):
        if g["name"] in ROLE_GROUPS.values():
            kc.delete(f"/users/{u['id']}/groups/{g['id']}")
    dr = kc.direct_roles(u["id"])
    if dr:
        kc.delete(f"/users/{u['id']}/role-mappings/realm", [kc.role(r) for r in dr])
    # 2) grant the new, approved role group
    g = kc.group(ROLE_GROUPS[a.new_role])
    kc.put(f"/users/{u['id']}/groups/{g['id']}", {})
    if a.new_role in PRIVILEGED:
        u = kc.user(a.username)
        ra = set(u.get("requiredActions", [])) | {"CONFIGURE_TOTP"}
        if not any(c["type"] == "otp" for c in kc.get(f"/users/{u['id']}/credentials")):
            kc.put(f"/users/{u['id']}", {"requiredActions": sorted(ra)})
    kc.post(f"/users/{u['id']}/logout")   # force re-login so new token carries new roles only
    attrs = kc.user(a.username).get("attributes", {})
    attrs.update({"department": [a.department], "last_mover_ticket": [a.ticket]})
    kc.put(f"/users/{u['id']}", {"attributes": attrs})
    after = kc.snapshot(a.username)
    log("MOVER", ticket=a.ticket, approved_by=a.manager, before=before, after=after,
        removed=sorted(set(before["effective_roles"]) - set(after["effective_roles"])),
        added=sorted(set(after["effective_roles"]) - set(before["effective_roles"])))
    hash_index()


def cmd_leaver(kc, a):
    u = kc.user(a.username)
    before = kc.snapshot(a.username)
    kc.put(f"/users/{u['id']}", {"enabled": False})                      # 1 disable
    kc.post(f"/users/{u['id']}/logout")                                  # 2 kill sessions/tokens
    for g in kc.get(f"/users/{u['id']}/groups"):                         # 3 strip groups
        kc.delete(f"/users/{u['id']}/groups/{g['id']}")
    dr = kc.direct_roles(u["id"])                                        # 4 strip direct roles
    if dr:
        kc.delete(f"/users/{u['id']}/role-mappings/realm", [kc.role(r) for r in dr])
    attrs = kc.user(a.username).get("attributes", {})
    attrs.update({"termination_ticket": [a.ticket], "terminated_utc": [now()]})
    kc.put(f"/users/{u['id']}", {"attributes": attrs})
    after = kc.snapshot(a.username)
    ok = (not after["enabled"]) and not after["groups"] and not after["effective_roles"] and after["sessions"] == 0
    idp = kc.federated(u["id"])
    log("LEAVER", ticket=a.ticket, approved_by=a.manager, before=before, after=after,
        verification="PASS" if ok else "FAIL",
        **({"upstream_action_required": f"also block sign-in for this user in {','.join(idp)} (Entra ID)"} if idp else {}))
    if a.password:   # optional: prove login is refused
        res = browser_login("ehr-simulator", a.username, a.password, kc)
        log("LEAVER.verify_login", client="ehr-simulator", result=res)
    hash_index()


# ----------------------------------------------------------------- access review
def cmd_review(kc, a):
    today = dt.date.today()
    rows = []
    for u in kc.get("/users?max=1000&briefRepresentation=false"):
        uid = u["id"]
        groups, direct, eff = kc.user_groups(uid), kc.direct_roles(uid), kc.effective_roles(uid)
        attrs = u.get("attributes", {}) or {}
        end = (attrs.get("access_end_date") or [""])[0]
        idp = kc.federated(uid)
        has_otp = any(c["type"] == "otp" for c in kc.get(f"/users/{uid}/credentials"))
        ev = kc.get(f"/events?user={uid}&type=LOGIN&max=1") or []
        last = dt.datetime.fromtimestamp(ev[0]["time"] / 1000, dt.timezone.utc).date() if ev else None
        created = dt.datetime.fromtimestamp(u["createdTimestamp"] / 1000, dt.timezone.utc).date()
        flags = []
        if direct and not idp: flags.append("DIRECT_ROLE_NOT_VIA_GROUP")   # IdP-mapped roles are expected
        if not eff and u["enabled"]: flags.append("NO_ROLE")
        if len(eff) > 1: flags.append("MULTIPLE_ROLES_SOD_CHECK")
        if not u["enabled"] and (eff or groups): flags.append("DISABLED_BUT_HAS_ACCESS")
        if end and end < today.isoformat() and u["enabled"]: flags.append("ACCESS_PAST_END_DATE")
        if "vendor" in eff and not end: flags.append("VENDOR_NO_END_DATE")
        if set(eff) & PRIVILEGED and not has_otp: flags.append("PRIVILEGED_NO_MFA_ENROLLED")
        if u["enabled"] and (last is None and (today - created).days > 30 or last and (today - last).days > 90):
            flags.append("STALE_NO_LOGIN_90D")
        rows.append({"review_id": a.review_id, "username": u["username"], "enabled": u["enabled"],
                     "source": ",".join(idp) or "local", "groups": ";".join(groups),
                     "effective_roles": ";".join(eff), "direct_roles": ";".join(direct),
                     "department": (attrs.get("department") or [""])[0],
                     "manager": (attrs.get("manager") or [""])[0], "access_end_date": end,
                     "mfa_enrolled": has_otp, "created": created.isoformat(),
                     "last_login": last.isoformat() if last else "", "flags": ";".join(flags),
                     "risk": "High" if any(f in flags for f in ("DISABLED_BUT_HAS_ACCESS", "ACCESS_PAST_END_DATE",
                                                                  "PRIVILEGED_NO_MFA_ENROLLED")) else
                             ("Medium" if flags else "Low"),
                     "reviewer_decision": "", "reviewer": "", "decision_date": ""})
    os.makedirs(EVID, exist_ok=True)
    out = os.path.join(EVID, f"access_review_{a.review_id}.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    summary = {"accounts": len(rows), "flagged": sum(1 for r in rows if r["flags"]),
               "high": sum(1 for r in rows if r["risk"] == "High")}
    log("ACCESS_REVIEW.export", file=out, **summary)
    hash_index()


class LocalhostCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    """Browsers treat http://localhost as a secure context; Python does not. Send Keycloak's
    Secure cookies to localhost the way a browser would (lab use only)."""
    def return_ok_secure(self, cookie, request):
        return True


def new_jar():
    return http.cookiejar.CookieJar(policy=LocalhostCookiePolicy())


# ----------------------------------------------------------------- verification (browser simulation)
def browser_login(client_id, username, password, kc=None):
    """Walk the real browser login flow for an app and report what Keycloak asked for."""
    redirect = "http://localhost:9000/callback"
    if kc:
        c = kc.get(f"/clients?clientId={client_id}")[0]
        uris = [x for x in c.get("redirectUris", []) if x.startswith("http")]
        if uris:
            redirect = uris[0].replace("*", "callback")
    jar = new_jar()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)
    q = urllib.parse.urlencode({"client_id": client_id, "response_type": "code", "scope": "openid",
                                "redirect_uri": redirect})
    page = op.open(f"{KC_URL}/realms/{REALM}/protocol/openid-connect/auth?{q}").read().decode()
    action = html.unescape(re.search(r'action="([^"]+)"', page).group(1))
    data = urllib.parse.urlencode({"username": username, "password": password, "credentialId": ""}).encode()
    try:
        r = op.open(action, data)
        body = r.read().decode()
    except urllib.error.HTTPError as e:
        if e.code in (302, 303):
            loc = e.headers.get("Location", "")
            if "code=" in loc:
                return "LOGGED_IN (auth code issued)"
            if "required-action" in loc:   # Keycloak wants something before issuing a code
                try:
                    body = op.open(loc).read().decode()
                except urllib.error.HTTPError as e2:
                    body = e2.read().decode()
            else:
                return f"REDIRECT {loc[:80]}"
        else:
            body = e.read().decode()
    if re.search(r"Access denied", body):
        return "DENIED (role not approved for this app)"
    if re.search(r"Account is disabled|account is disabled", body):
        return "DENIED (account disabled)"
    if re.search(r"temporarily disabled|locked", body, re.I):
        return "DENIED (account temporarily locked)"
    if re.search(r"Invalid username or password", body):
        return "DENIED (invalid credentials)"
    if re.search(r'Mobile Authenticator|kc-totp-settings|kc-otp-login-form|name="otp"', body):
        return "MFA_REQUIRED (OTP setup/prompt shown)"
    if re.search(r'name="password-new"', body):
        return "PASSWORD_CHANGE_REQUIRED (first login)"
    return "UNKNOWN: " + re.sub(r"\s+", " ", re.sub("<[^>]+>", " ", body))[:160]


def cmd_verify(kc, a):
    results = []
    import time
    for client in a.clients:
        time.sleep(1.5)   # stay clear of Keycloak's quick-login brute-force check between test logins
        res = browser_login(client, a.username, a.password, kc)
        results.append({"client": client, "user": a.username, "result": res})
        log("VERIFY.login", client=client, user=a.username, result=res)
    if a.lockout_user:
        u = kc.user(a.lockout_user)
        for i in range(11):   # 1.5 s apart so Keycloak's "quick login" check is not what trips
            browser_login(a.clients[0], a.lockout_user, "Wrong-Password-%d!" % i, kc)
            time.sleep(1.5)
        st = kc.get(f"/attack-detection/brute-force/users/{u['id']}")
        log("VERIFY.lockout", user=a.lockout_user, bad_attempts=11, keycloak_status=st,
            result="PASS (locked after %s failures)" % st.get("numFailures") if st.get("disabled") else "FAIL (not locked)")
        if a.unlock:
            kc.delete(f"/attack-detection/brute-force/users/{u['id']}")
            log("VERIFY.lockout_cleared", user=a.lockout_user)
    hash_index()


# ----------------------------------------------------------------- SAML federation demo
def cmd_saml_demo(kc, a):
    """Partner realm (SP side) trusts HRMC realm (IdP side) over SAML 2.0."""
    partner = a.partner_realm
    if not kc.get("", realm=partner, ok404=True):
        kc.post("", {"realm": partner, "enabled": True, "displayName": "Partner Clinic (SAML SP)"}, realm="")
    sp_entity = f"{KC_URL}/realms/{partner}"
    acs = f"{KC_URL}/realms/{partner}/broker/hrmc-saml/endpoint"
    # 1) SAML client in HRMC realm representing the partner
    if not kc.get(f"/clients?clientId={urllib.parse.quote(sp_entity, safe='')}"):
        kc.post("/clients", {"clientId": sp_entity, "protocol": "saml", "enabled": True,
                             "redirectUris": [acs + "*"], "frontchannelLogout": True,
                             "attributes": {"saml_assertion_consumer_url_post": acs,
                                            "saml.client.signature": "false",
                                            "saml.authnstatement": "true",
                                            "saml_name_id_format": "username",
                                            "saml.force.name.id.format": "true"},
                             "protocolMappers": [{"name": "role list", "protocol": "saml",
                                                  "protocolMapper": "saml-role-list-mapper",
                                                  "config": {"single": "true", "attribute.name": "Role"}}]})
    # 2) SAML identity provider in partner realm pointing at HRMC IdP
    idp_sso = f"{KC_URL}/realms/{REALM}/protocol/saml"
    if not kc.get("/identity-provider/instances/hrmc-saml", realm=partner, ok404=True):
        kc.post("/identity-provider/instances", {
            "alias": "hrmc-saml", "displayName": "Sign in with HRMC (SAML)", "providerId": "saml",
            "enabled": True, "trustEmail": True,
            "config": {"singleSignOnServiceUrl": idp_sso, "singleLogoutServiceUrl": idp_sso,
                       "entityId": sp_entity, "idpEntityId": f"{KC_URL}/realms/{REALM}",
                       "nameIDPolicyFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                       "principalType": "SUBJECT", "postBindingResponse": "true",
                       "postBindingAuthnRequest": "true", "validateSignature": "false",
                       "syncMode": "FORCE"}}, realm=partner)
    md = urllib.request.urlopen(f"{KC_URL}/realms/{REALM}/protocol/saml/descriptor").read().decode()
    open(os.path.join(EVID, "hrmc_saml_idp_metadata.xml"), "w").write(md)
    log("SAML.configured", idp_realm=REALM, sp_realm=partner, sp_entity=sp_entity, acs=acs)

    # 3) prove SSO: partner account console -> HRMC login -> SAMLResponse -> partner session
    if a.username:
        jar = new_jar()
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        q = urllib.parse.urlencode({"client_id": "account-console", "response_type": "code",
                                    "scope": "openid", "kc_idp_hint": "hrmc-saml",
                                    "redirect_uri": f"{KC_URL}/realms/{partner}/account/",
                                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                                    "code_challenge_method": "S256"})
        p = op.open(f"{KC_URL}/realms/{partner}/protocol/openid-connect/auth?{q}").read().decode()
        steps = []
        for _ in range(6):
            if "SAMLRequest" in p or "SAMLResponse" in p:
                act = html.unescape(re.search(r'action="([^"]+)"', p).group(1))
                fields = dict(re.findall(r'name="(SAML\w+|RelayState)"\s+value="([^"]*)"', p))
                steps.append(("SAMLResponse" if "SAMLResponse" in fields else "SAMLRequest") + " -> " + act.split("/realms/")[1][:60])
                if "SAMLResponse" in fields:   # keep the signed assertion as evidence
                    import base64
                    xml = base64.b64decode(html.unescape(fields["SAMLResponse"])).decode(errors="replace")
                    open(os.path.join(EVID, "saml_response_captured.xml"), "w").write(xml)
                    steps.append("assertion attributes: " + ",".join(sorted(set(re.findall(r'Attribute Name="([^"]+)"', xml)))) +
                                 " | signed=" + str("SignatureValue" in xml))
                p = op.open(act, urllib.parse.urlencode({k: html.unescape(v) for k, v in fields.items()}).encode()).read().decode()
            elif "idp-review-profile" in p or "kc-update-profile-form" in p:
                act = html.unescape(re.search(r'action="([^"]+)"', p).group(1))
                steps.append("partner first-broker-login: profile reviewed")
                p = op.open(act, urllib.parse.urlencode({"username": a.username, "email": f"{a.username}@hrmc.example",
                                                         "firstName": "Test", "lastName": a.username}).encode()).read().decode()
            elif 'name="username"' in p or 'id="kc-form-login"' in p:
                act = html.unescape(re.search(r'action="([^"]+)"', p).group(1))
                steps.append("HRMC login form posted" if f"/realms/{REALM}/" in act else "partner form")
                p = op.open(act, urllib.parse.urlencode({"username": a.username, "password": a.password}).encode()).read().decode()
            else:
                break
        linked = kc.get(f"/users?username={a.username}&exact=true", realm=partner)
        fed = kc.get(f"/users/{linked[0]['id']}/federated-identity", realm=partner) if linked else []
        ok = bool(linked and fed)
        log("SAML.sso_test", user=a.username, steps=steps,
            partner_user_created=bool(linked), federated_link=fed,
            result="PASS (SAML SSO established)" if ok else "FAIL")
    hash_index()


# ----------------------------------------------------------------- identity detections (SIEM-lite)
def cmd_detect(kc, a):
    """Pull Keycloak login + admin events, run identity detection rules, write CSVs for
    Wazuh/Sentinel/Tableau. Proof of detection for the identity layer."""
    ev = kc.get(f"/events?max={a.max}") or []
    adm = kc.get(f"/admin-events?max={a.max}") or []
    ts = lambda ms: dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc)
    all_users = kc.get("/users?max=2000&briefRepresentation=false")
    users = {u["id"]: u["username"] for u in all_users}
    end_dates = {u["id"]: ((u.get("attributes") or {}).get("access_end_date") or [""])[0] for u in all_users}
    os.makedirs(EVID, exist_ok=True)
    with open(os.path.join(EVID, "keycloak_login_events.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time_utc", "type", "error", "username", "client", "ip"])
        for e in sorted(ev, key=lambda e: e["time"]):
            d = e.get("details") or {}
            w.writerow([ts(e["time"]).isoformat(), e["type"], e.get("error", ""),
                        users.get(e.get("userId"), d.get("username", "")), e.get("clientId", ""), e.get("ipAddress", "")])
    alerts = []

    def alert(rule, sev, when, who, detail):
        alerts.append({"rule_id": rule, "severity": sev, "time_utc": when.isoformat(), "subject": who, "detail": detail})

    # CAN-ID-001 brute force: >= 5 failed logins for one user within 10 minutes
    fails = {}
    for e in sorted((e for e in ev if e["type"] == "LOGIN_ERROR"), key=lambda e: e["time"]):
        who = users.get(e.get("userId")) or (e.get("details") or {}).get("username", "?")
        fails.setdefault(who, []).append(ts(e["time"]))
    for who, times in fails.items():
        for i in range(len(times)):
            win = [t for t in times[i:] if (t - times[i]).total_seconds() <= 600]
            if len(win) >= 5:
                alert("CAN-ID-001 brute force", "High", times[i], who, f"{len(win)} failed logins in 10 min")
                break
    for e in ev:
        who = users.get(e.get("userId")) or (e.get("details") or {}).get("username", "?")
        err = e.get("error", "")
        if err == "user_disabled":           # CAN-ID-002 disabled / terminated account used
            alert("CAN-ID-002 disabled-account login", "High", ts(e["time"]), who, f"client={e.get('clientId')}")
        if err == "user_temporarily_disabled":
            alert("CAN-ID-003 login while locked out", "Medium", ts(e["time"]), who, f"client={e.get('clientId')}")
        if err == "access_denied":           # CAN-ID-004 unapproved application
            alert("CAN-ID-004 unauthorized app access", "Medium", ts(e["time"]), who, f"client={e.get('clientId')}")
        end = end_dates.get(e.get("userId"))   # CAN-ID-006 sign-in after access_end_date (vendor/contract expired)
        if e["type"] == "LOGIN" and end and ts(e["time"]).date().isoformat() > end:
            alert("CAN-ID-006 expired access still in use", "High", ts(e["time"]), who,
                  f"access_end_date={end} client={e.get('clientId')}")
    gname = {g["id"]: g["name"] for g in kc.get("/groups?max=500")}
    priv_names = {ROLE_GROUPS[r] for r in PRIVILEGED} | PRIVILEGED | {"mfa-required"}
    for e in adm:                            # CAN-ID-005 privilege / membership change on a user
        rp = e.get("resourcePath", "")
        if not rp.startswith("users/") or not ("role-mappings" in rp or "/groups/" in rp):
            continue
        parts = rp.split("/")
        target = users.get(parts[1], parts[1])
        what = gname.get(parts[3], parts[3]) if parts[2] == "groups" else ",".join(
            r.get("name", "") for r in json.loads(e.get("representation") or "[]") if isinstance(r, dict))
        sev = "High" if any(n in what for n in priv_names) and e.get("operationType") == "CREATE" else "Medium"
        alert("CAN-ID-005 privilege change", sev, ts(e["time"]), target,
              f"{e.get('operationType')} {parts[2]}: {what} (by admin event)")
    if a.ehr_log:   # CAN-ID-007 excessive ePHI access: many distinct patients opened in a short window
        with open(a.ehr_log, newline="") as f:
            rows = sorted(csv.DictReader(f), key=lambda r: r["time_utc"])
        views = {}
        for r in rows:
            views.setdefault(r["username"], []).append((dt.datetime.fromisoformat(r["time_utc"].replace("Z", "+00:00")),
                                                        r["patient_id"]))
        for who, hits in views.items():
            for i in range(len(hits)):
                win = {pid for t, pid in hits[i:] if (t - hits[i][0]).total_seconds() <= 3600}
                if len(win) >= a.ehr_threshold:
                    alert("CAN-ID-007 excessive patient-record access", "High", hits[i][0], who,
                          f"{len(win)} distinct patient records in 60 min (threshold {a.ehr_threshold})")
                    break
    out = os.path.join(EVID, "identity_detections.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["rule_id", "severity", "time_utc", "subject", "detail"])
        w.writeheader(); w.writerows(sorted(alerts, key=lambda r: r["time_utc"]))
    summary = {}
    for r in alerts:
        summary[r["rule_id"]] = summary.get(r["rule_id"], 0) + 1
    log("DETECT.run", login_events=len(ev), admin_events=len(adm), ehr_log=a.ehr_log, alerts=summary, file=out)
    hash_index()


# ----------------------------------------------------------------- application access gate
APP_ACCESS = {   # which job roles may sign in to which app (mirrors the client role scopes in E-AC-01)
    "billing-app": ["billing"], "ehr-simulator": ["clinician", "nurse"],
    "patient-portal": ["clinician", "nurse"], "hr-app": ["hr", "it-support"],
}


def cmd_app_gate(kc, a):
    """Keycloak lets ANY realm user sign in to ANY app unless told otherwise. This adds a per-app
    gate: users without the app's access role see 'Access denied' at the identity provider."""
    if MFA_FLOW not in {f["alias"] for f in kc.get("/authentication/flows")}:
        sys.exit("run `harden` first (the gate flows are built on top of the MFA flow)")
    for app, roles in APP_ACCESS.items():
        c = kc.get(f"/clients?clientId={app}")
        if not c:
            print(f"  ! client {app} not found, skipped"); continue
        c = c[0]
        access_role = f"app-access-{app}"
        if not kc.get(f"/roles/{access_role}", ok404=True):
            kc.post("/roles", {"name": access_role, "description": f"May sign in to {app}"})
        for r in roles:   # grant the access role to each allowed job-function group ...
            kc.post(f"/groups/{kc.group(ROLE_GROUPS[r])['id']}/role-mappings/realm", [kc.role(access_role)])
            # ... and to the job role itself, so Entra users (role mapped directly by the IdP) pass the gate
            kc.post(f"/roles/{r}/composites", [kc.role(access_role)])
        gate = f"gate-{app}"
        if gate not in {f["alias"] for f in kc.get("/authentication/flows")}:
            kc.post(f"/authentication/flows/{urllib.parse.quote(MFA_FLOW)}/copy", {"newName": gate})
            ex = kc.get(f"/authentication/flows/{gate}/executions")
            forms = next(e for e in ex if e.get("authenticationFlow") and e["displayName"].endswith(" forms"))
            fa = urllib.parse.quote(forms["displayName"])
            deny_alias = f"{gate} deny-unauthorized"
            kc.post(f"/authentication/flows/{fa}/executions/flow",
                    {"alias": deny_alias, "type": "basic-flow", "provider": "registration-page-form",
                     "description": f"Deny users without {access_role}"})
            sub = next(e for e in kc.get(f"/authentication/flows/{fa}/executions") if e["displayName"] == deny_alias)
            kc.put(f"/authentication/flows/{fa}/executions", {"id": sub["id"], "requirement": "CONDITIONAL"})
            da = urllib.parse.quote(deny_alias)
            kc.post(f"/authentication/flows/{da}/executions/execution", {"provider": "conditional-user-role"})
            kc.post(f"/authentication/flows/{da}/executions/execution", {"provider": "deny-access-authenticator"})
            for e in kc.get(f"/authentication/flows/{da}/executions"):
                kc.put(f"/authentication/flows/{da}/executions", {"id": e["id"], "requirement": "REQUIRED"})
                if e["providerId"] == "conditional-user-role":
                    kc.post(f"/authentication/executions/{e['id']}/config",
                            {"alias": f"{gate}-not-{access_role}",
                             "config": {"condUserRole": access_role, "negate": "true"}})
                if e["providerId"] == "deny-access-authenticator":
                    kc.post(f"/authentication/executions/{e['id']}/config",
                            {"alias": f"{gate}-deny-msg",
                             "config": {"denyErrorMessage": f"Access denied: your role is not approved for {app}."}})
        flow_id = next(f["id"] for f in kc.get("/authentication/flows") if f["alias"] == gate)
        ov = c.get("authenticationFlowBindingOverrides") or {}
        ov["browser"] = flow_id
        c["authenticationFlowBindingOverrides"] = ov
        kc.put(f"/clients/{c['id']}", c)
        log("APP_GATE.bound", app=app, allowed_roles=roles, access_role=access_role, flow=gate)
    hash_index()


# ----------------------------------------------------------------- CLI
def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    s = p.add_subparsers(dest="cmd", required=True)
    h = s.add_parser("harden"); h.add_argument("--migrate", action="store_true",
                                               help="move direct role assignments into RBAC groups")
    j = s.add_parser("joiner")
    for f in ("username", "first", "last", "email", "role", "department", "manager", "ticket", "temp_password"):
        j.add_argument("--" + f.replace("_", "-"), required=True)
    j.add_argument("--end-date", help="YYYY-MM-DD (required for vendors)")
    m = s.add_parser("mover")
    for f in ("username", "new_role", "department", "manager", "ticket"):
        m.add_argument("--" + f.replace("_", "-"), required=True)
    l = s.add_parser("leaver")
    for f in ("username", "manager", "ticket"):
        l.add_argument("--" + f, required=True)
    l.add_argument("--password", help="old password, to prove login is now refused")
    r = s.add_parser("review"); r.add_argument("--review-id", default=dt.date.today().strftime("AR-%Y-Q%m"))
    v = s.add_parser("verify")
    v.add_argument("--username", required=True); v.add_argument("--password", required=True)
    v.add_argument("--clients", nargs="+", default=["billing-app", "ehr-simulator"])
    v.add_argument("--lockout-user"); v.add_argument("--unlock", action="store_true")
    dtc = s.add_parser("detect", help="run identity detection rules over Keycloak events")
    dtc.add_argument("--max", type=int, default=5000)
    dtc.add_argument("--ehr-log", help="EHR access log CSV (time_utc,username,role,patient_id,action,workstation)")
    dtc.add_argument("--ehr-threshold", type=int, default=15, help="distinct patients in 60 min that raise CAN-ID-007")
    s.add_parser("app-gate", help="deny sign-in to apps the user's role is not approved for")
    sd = s.add_parser("saml-demo"); sd.add_argument("--partner-realm", default="partner-clinic")
    sd.add_argument("--username"); sd.add_argument("--password")
    a = p.parse_args()
    kc = KC()
    {"harden": cmd_harden, "joiner": cmd_joiner, "mover": cmd_mover, "leaver": cmd_leaver,
     "review": cmd_review, "verify": cmd_verify, "saml-demo": cmd_saml_demo,
     "app-gate": cmd_app_gate, "detect": cmd_detect}[a.cmd](kc, a)


if __name__ == "__main__":
    main()
