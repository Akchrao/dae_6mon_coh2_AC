# Observability & Logging: Project Notes

This document tracks how the GRC tool used in the capstone (CISO Assistant v4.2.1, self-hosted with Docker at
`https://localhost:8443`) is checked for health, what it logs and how its state is monitored. Updated 2026-11-05.

---

## 1. Health Check Endpoint

**Have you implemented a health-check endpoint?**

-   [x] Yes (provided by CISO Assistant; used and verified, not written by me)
-   [ ] No
-   [ ] Not applicable to my project

**Your endpoint path:** `/api/health/`

```
# GET https://localhost:8443/api/health/   (2026-11-05, see evidence/health_check.txt)
{"status":"ok"}
HTTP 200
```

**Why is this useful?**

> Docker Compose uses it to decide when the backend is ready, so the frontend and the reverse proxy only start sending
> traffic to a backend that can answer; I use it to confirm the tool is up before a demo or before loading data.

---

## 2. Health Check Test

**Did you write a test for the health-check endpoint?**

-   [x] Yes (container health check plus a manual check; the test itself is the project's Compose configuration)
-   [ ] No

```
# docker-compose.yml - backend service (runs every 10 s, 30 retries, 150 s start period)
healthcheck:
  test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://backend:8000/api/health/', timeout=5)"]

# manual check (evidence/health_check.txt, evidence/docker_compose_ps.txt)
$ docker inspect -f '{{.State.Health.Status}}' backend
healthy
$ docker compose ps
backend   ...   Up 56 minutes (healthy)   8000/tcp
caddy     ...   Up 56 minutes             127.0.0.1:8443->8443/tcp
```

Used in practice: after moving the tool to a new folder on 2026-11-05 I waited for `healthy` and an HTTP 200 on the
login page before checking that the data (5 risks, 18 controls, 41 evidence items, 19 findings) had survived.

---

## 3. Log Event or Metric

**Name of log event or metric:** `request_finished` (application request log) and the **audit log entry**
(record history).

**What triggers this?**

-   `request_finished`: every HTTP request to the backend API (structlog middleware).
-   Audit log entry: every create, update or delete of a GRC record (risk, control, evidence, exception, finding ...).
    1,241 entries on 2026-11-05.

**Sample output format or log:**

```
# request log (docker logs backend)
2026-11-05T17:48:25.421046Z [info] request_finished [django_structlog.middlewares.request]
  code=200 ip=172.20.0.1 request='GET /api/risk-assessments/<id>/risk_assessment_csv/'
  request_id=8f0d6613-a52c-4d16-9f02-9e88b33bf110 user_id=95a5a246-fca7-41d4-ae55-2b8509263f48

# audit log entry (record history of exception EX-01)
2026-11-05T17:01:50Z  update  securityexception  EX-01
  status: approved -> resolved
  observation: "Open: turn on Security defaults and screenshot" -> "Resolved 2026-11-05: Security defaults enabled (EV-17)"
```

**Where is this implemented in your code?**

> In CISO Assistant itself: `django_structlog.middlewares.request` (request log, read with `docker logs backend`) and
> the `auditlog` app (record history, visible on each record's history in the UI). The changes above were made by my
> loader `Care_Access_Navigator/10_Scripts/04_CISO_Assistant/load_ciso.py`, which is why the audit entry has no user
> (actor) attached - changes made in the UI record the user.

---

## 4. Optional Monitoring Tools

**Did you use monitoring tools (e.g. Grafana, Prometheus, Kibana)?**

-   [x] Yes - CISO Assistant's built-in analytics dashboards (no Grafana / Prometheus; `EXPOSE_METRICS` is off)
-   [ ] No

**Tool name(s):** CISO Assistant Analytics (Summary, Risk, Compliance tabs), risk matrix view, audit donut chart.

**Screenshot or description of what the tool shows:**

```
Summary: 18 controls - 11 active, 6 in progress, 1 to do; NIST CSF function wheel (mostly Protect)
Risk matrix: R02 in High (3 x 5); R01, R03, R04 in Medium (2 x 5); R05 in Low (1 x 4)
Compliance: progress by framework - HIPAA (NIST SP 800-66 rev2) 16 % assessed, NIST CSF 2.0 14 % assessed
```

Screenshots: `EV-16_CISO_Dashboard_Analytics_20261104.png`,
`EV-16_CISO_Dashboard_Risk_Heatmap_20261104.png`, `EV-16_CISO_Dashboard_Compliance_20261105.png`.

---

## 5. Reflection & Learning

**What did you learn while implementing observability in your project?**

> _Draft from the project record - rewrite in your own words:_ The health check and the audit log turned out to be the
> two things I relied on most. The health check told me when it was safe to use the tool after a restart or a move, and
> the audit log shows exactly when and how a record changed (for example EX-01 going from approved to resolved), which
> is what an auditor would ask for.

**Anything you would do differently or improve in the future?**

> _Draft - rewrite in your own words:_ Stop the stack before copying the database (a live copy was corrupted during the
> Windows-to-Mac move), make scripted changes run under a named service user so the audit log records an actor, and
> turn on metrics export if the tool were used beyond a single-person lab.
