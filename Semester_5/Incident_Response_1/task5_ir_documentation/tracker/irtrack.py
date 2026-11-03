#!/usr/bin/env python3
"""
irtrack.py - Care Access Navigator incident tracking system (SQLite, standard library only)
==========================================================================================
One database file (incidents.db) holds every incident with its details, status history, response actions,
timeline of events and linked evidence. Status moves forward only:

    New -> Triage -> Contained -> Eradicated -> Recovered -> Closed

Commands
  irtrack.py init
  irtrack.py new <id> --title T --type T --severity SEV-n --detected UTC --source S --handler H --summary S [--assets A]
  irtrack.py status <id> <Status> --at UTC [--note N]
  irtrack.py action <id> --at UTC --phase P --by B --what W [--result R]
  irtrack.py event  <id> --at UTC --host H --source S --what W
  irtrack.py evidence <id> --item E01 --desc D --sha256 H --location L
  irtrack.py list                     one line per incident with SLA status
  irtrack.py show <id>                full record
  irtrack.py export <file.csv>        incident register (Tableau-ready)
  irtrack.py report <id>              Markdown incident record to stdout
Database path: $IRTRACK_DB or ./incidents.db
"""
import argparse, csv, datetime as dt, os, sqlite3, sys

DB = os.environ.get("IRTRACK_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "incidents.db"))
FLOW = ["New", "Triage", "Contained", "Eradicated", "Recovered", "Closed"]
SLA_START_MIN = {"SEV-1": 15, "SEV-2": 60, "SEV-3": 8 * 60, "SEV-4": 5 * 24 * 60}     # time to start response (playbook §0)
SCHEMA = """
CREATE TABLE IF NOT EXISTS incident (id TEXT PRIMARY KEY, title TEXT, type TEXT, severity TEXT, status TEXT,
    detected_utc TEXT, source TEXT, handler TEXT, assets TEXT, summary TEXT, environment TEXT, course TEXT);
CREATE TABLE IF NOT EXISTS status_history (incident TEXT, status TEXT, at_utc TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS action (incident TEXT, at_utc TEXT, phase TEXT, by_whom TEXT, what TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS event (incident TEXT, at_utc TEXT, host TEXT, source TEXT, what TEXT);
CREATE TABLE IF NOT EXISTS evidence (incident TEXT, item TEXT, description TEXT, sha256 TEXT, location TEXT);
"""


def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; c.executescript(SCHEMA); return c


def ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def mins(a, b):
    return (ts(b) - ts(a)).total_seconds() / 60 if a and b else None


def new(i, title, type, severity, detected, source, handler, summary, assets="", environment="IR lab (Parrot-equivalent)", course="Incident Response 1"):
    assert severity in SLA_START_MIN, "severity must be SEV-1..SEV-4"
    with db() as c:
        c.execute("INSERT INTO incident VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                  (i, title, type, severity, "New", detected, source, handler, assets, summary, environment, course))
        c.execute("INSERT INTO status_history VALUES (?,?,?,?)", (i, "New", detected, f"opened from {source}"))


def status(i, st, at, note=""):
    with db() as c:
        cur = c.execute("SELECT status FROM incident WHERE id=?", (i,)).fetchone()["status"]
        if FLOW.index(st) <= FLOW.index(cur):
            raise SystemExit(f"{i}: status can only move forward ({cur} -> {st} refused)")
        c.execute("UPDATE incident SET status=? WHERE id=?", (st, i))
        c.execute("INSERT INTO status_history VALUES (?,?,?,?)", (i, st, at, note))


def action(i, at, phase, by, what, result=""):
    with db() as c:
        c.execute("INSERT INTO action VALUES (?,?,?,?,?,?)", (i, at, phase, by, what, result))


def event(i, at, host, source, what):
    with db() as c:
        c.execute("INSERT INTO event VALUES (?,?,?,?,?)", (i, at, host, source, what))


def evidence(i, item, desc, sha, loc):
    with db() as c:
        c.execute("INSERT INTO evidence VALUES (?,?,?,?,?)", (i, item, desc, sha, loc))


def metrics(c, i):
    inc = c.execute("SELECT * FROM incident WHERE id=?", (i,)).fetchone()
    h = {r["status"]: r["at_utc"] for r in c.execute("SELECT * FROM status_history WHERE incident=?", (i,))}
    first_action = c.execute("SELECT min(at_utc) a FROM action WHERE incident=?", (i,)).fetchone()["a"]
    start = mins(inc["detected_utc"], first_action)
    sla = SLA_START_MIN[inc["severity"]]
    return {"time_to_respond_min": start, "sla_min": sla,
            "sla": "n/a" if start is None else ("MET" if start <= sla else "MISSED"),
            "time_to_contain_min": mins(inc["detected_utc"], h.get("Contained")),
            "time_to_recover_min": mins(inc["detected_utc"], h.get("Recovered")),
            "closed_utc": h.get("Closed", "")}


def f1(x):
    return "" if x is None else f"{x:.1f}"


def cmd_list():
    with db() as c:
        print(f"{'ID':16} {'SEV':6} {'STATUS':11} {'DETECTED':21} {'RESPOND(min)':>12} {'SLA':7} {'CONTAIN(min)':>12}  TITLE")
        for r in c.execute("SELECT * FROM incident ORDER BY detected_utc"):
            m = metrics(c, r["id"])
            print(f"{r['id']:16} {r['severity']:6} {r['status']:11} {r['detected_utc']:21} {f1(m['time_to_respond_min']):>12} "
                  f"{m['sla']:7} {f1(m['time_to_contain_min']):>12}  {r['title'][:60]}")


def report(i):
    with db() as c:
        r = c.execute("SELECT * FROM incident WHERE id=?", (i,)).fetchone()
        if not r:
            raise SystemExit(f"no incident {i}")
        m = metrics(c, i)
        out = [f"# Incident record {i}", "", f"**{r['title']}**", "",
               "| Field | Value |", "|---|---|"]
        for k in ("type", "severity", "status", "detected_utc", "source", "handler", "assets", "environment", "course"):
            out.append(f"| {k} | {r[k]} |")
        out += [f"| time to first response | {f1(m['time_to_respond_min'])} min (target {m['sla_min']} min: {m['sla']}) |",
                f"| time to contain | {f1(m['time_to_contain_min'])} min |", f"| time to recover | {f1(m['time_to_recover_min'])} min |",
                "", "## Summary", "", r["summary"], "", "## Status history", "", "| UTC | Status | Note |", "|---|---|---|"]
        out += [f"| {h['at_utc']} | {h['status']} | {h['note']} |" for h in c.execute("SELECT * FROM status_history WHERE incident=? ORDER BY at_utc", (i,))]
        out += ["", "## Response actions", "", "| UTC | Phase | By | Action | Result |", "|---|---|---|---|---|"]
        out += [f"| {a['at_utc']} | {a['phase']} | {a['by_whom']} | {a['what']} | {a['result']} |"
                for a in c.execute("SELECT * FROM action WHERE incident=? ORDER BY at_utc", (i,))]
        out += ["", "## Timeline of events", "", "| UTC | Host | Source | Event |", "|---|---|---|---|"]
        out += [f"| {e['at_utc']} | {e['host']} | {e['source']} | {e['what']} |"
                for e in c.execute("SELECT * FROM event WHERE incident=? ORDER BY at_utc", (i,))]
        out += ["", "## Evidence", "", "| Item | Description | SHA-256 | Location |", "|---|---|---|---|"]
        out += [f"| {e['item']} | {e['description']} | `{e['sha256'][:16]}...` | {e['location']} |"
                for e in c.execute("SELECT * FROM evidence WHERE incident=? ORDER BY item", (i,))]
        return "\n".join(out) + "\n"


def export(path):
    with db() as c, open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["incident_id", "title", "environment", "severity", "detected_utc", "status", "course", "type",
                    "time_to_respond_min", "response_sla", "time_to_contain_min", "time_to_recover_min", "closed_utc",
                    "actions", "events", "evidence_items"])
        for r in c.execute("SELECT * FROM incident ORDER BY detected_utc"):
            m = metrics(c, r["id"])
            n = lambda t: c.execute(f"SELECT count(*) FROM {t} WHERE incident=?", (r["id"],)).fetchone()[0]
            w.writerow([r["id"], r["title"], r["environment"], r["severity"], r["detected_utc"], r["status"], r["course"], r["type"],
                        f1(m["time_to_respond_min"]), m["sla"], f1(m["time_to_contain_min"]), f1(m["time_to_recover_min"]),
                        m["closed_utc"], n("action"), n("event"), n("evidence")])


def main():
    ap = argparse.ArgumentParser(description="Care Access Navigator incident tracker"); sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("init"); sp.add_parser("list")
    p = sp.add_parser("new"); p.add_argument("id")
    for a in ("title", "type", "severity", "detected", "source", "handler", "summary"):
        p.add_argument("--" + a, required=True)
    p.add_argument("--assets", default="")
    p = sp.add_parser("status"); p.add_argument("id"); p.add_argument("status", choices=FLOW); p.add_argument("--at", required=True); p.add_argument("--note", default="")
    p = sp.add_parser("action"); p.add_argument("id")
    for a in ("at", "phase", "by", "what"):
        p.add_argument("--" + a, required=True)
    p.add_argument("--result", default="")
    p = sp.add_parser("event"); p.add_argument("id")
    for a in ("at", "host", "source", "what"):
        p.add_argument("--" + a, required=True)
    p = sp.add_parser("evidence"); p.add_argument("id")
    for a in ("item", "desc", "sha256", "location"):
        p.add_argument("--" + a, required=True)
    p = sp.add_parser("show"); p.add_argument("id")
    p = sp.add_parser("report"); p.add_argument("id")
    p = sp.add_parser("export"); p.add_argument("file")
    a = ap.parse_args()
    if a.cmd == "init":
        db().close(); print(f"initialised {DB}")
    elif a.cmd == "new":
        new(a.id, a.title, a.type, a.severity, a.detected, a.source, a.handler, a.summary, a.assets)
    elif a.cmd == "status":
        status(a.id, a.status, a.at, a.note)
    elif a.cmd == "action":
        action(a.id, a.at, a.phase, a.by, a.what, a.result)
    elif a.cmd == "event":
        event(a.id, a.at, a.host, a.source, a.what)
    elif a.cmd == "evidence":
        evidence(a.id, a.item, a.desc, a.sha256, a.location)
    elif a.cmd == "list":
        cmd_list()
    elif a.cmd in ("show", "report"):
        sys.stdout.write(report(a.id))
    elif a.cmd == "export":
        export(a.file); print(f"exported {a.file}")


if __name__ == "__main__":
    main()
