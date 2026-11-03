#!/usr/bin/env python3
"""build_timeline.py - Care Access Navigator IR1 Task 4: super-timeline for case IR1-2026-002.
Merges, in UTC, every time-stamped source collected in Tasks 3 and 4:
  macOS   DAEDMAC1009 ssh_client.log (local time -05:00 -> UTC)
  Parrot  auth.log, ehr-audit.log, audit.log (auditd), kern.log (firewall)  - from the Task 3 artifacts tar
  disk    file-system MAC times from the dc3dd image (fls body file -> mactime)
  network hypervisor packet capture (HTTP POSTs to the IOC), drop-site upload log
  IR      responder actions (Task 3 markers, Task 4 steps)
Writes evidence/timeline/: supertimeline_IR1-2026-002.csv, key_events.csv, session_correlation.csv, source_counts.csv"""
import csv, datetime as dt, json, os, re, tarfile
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
T4 = os.path.dirname(HERE); T3 = os.path.join(os.path.dirname(T4), "task3_containment"); T2 = os.path.join(os.path.dirname(T4), "task2_log_analysis")
EV4, EV3 = os.path.join(T4, "evidence"), os.path.join(T3, "evidence")
OUT = os.path.join(EV4, "timeline")
UTC = dt.timezone.utc
ev = []   # (utc datetime, host, source, category, event, detail)


def add(t, host, src, cat, event, detail=""):
    ev.append((t.astimezone(UTC), host, src, cat, event, detail[:220]))


iso = lambda s: dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
tar = tarfile.open(os.path.join(EV3, "filesystem", "IR1-2026-002_artifacts.tar"))
log = lambda p: tar.extractfile("./" + p).read().decode(errors="replace").splitlines()

# ---- macOS: SSH client trail
mac_sessions = {}
for l in open(os.path.join(T2, "evidence", "macos", "ssh_client.log")):
    m = re.match(r"(\S+) (\S+) ssh\[(\d+)\]: (.*)", l.rstrip())
    if not m:
        continue
    t, host, pid, msg = iso(m[1]), m[2], m[3], m[4]
    s = mac_sessions.setdefault(pid, {"pid": pid})
    if "Connecting to" in msg:
        s["connect"] = t; add(t, f"{host} (macOS)", "ssh_client.log", "macOS", "SSH client connects to parrot-vm", msg)
    elif "Authenticating to" in msg:
        s["user"] = re.search(r"as '([^']+)'", msg)[1]
    elif "Server accepts key" in msg:
        s["fp"] = re.search(r"(SHA256:\S+)", msg)[1]
    elif msg.startswith("Authenticated to"):
        s["auth"] = t; add(t, f"{host} (macOS)", "ssh_client.log", "macOS", f"SSH session authenticated (publickey) as {s.get('user', '?')}", f"ssh pid {pid}; {msg}")
    elif "Exit status" in msg:
        s["exit"] = t

# ---- Parrot: auth.log
vm_sessions = []
auth_lines = log("var/log/auth.log")
img_auth = os.path.join(EV4, "disk", "image_auth.log")       # same log, recovered from the disk image after C7
if os.path.exists(img_auth):
    seen = set(auth_lines)
    auth_lines += [l for l in open(img_auth, errors="replace").read().splitlines() if l not in seen]
for l in auth_lines:
    m = re.match(r"(\S+) parrot-vm (\S+?)(?:\[\d+\])?: (.*)", l)
    if not m:
        continue
    t, prog, msg = iso(m[1]), m[2], m[3]
    if "Accepted publickey for" in msg:
        a = re.search(r"for (\S+) from (\S+) port (\d+) .*?(SHA256:\S+)", msg)
        vm_sessions.append({"t": t, "user": a[1], "src": a[2], "port": a[3], "fp": a[4]})
        add(t, "parrot-vm", "auth.log", "Parrot", f"sshd accepted publickey for {a[1]}", msg)
    elif "test.nurse" in msg and prog in ("usermod", "useradd", "gpasswd", "passwd"):
        add(t, "parrot-vm", "auth.log", "Parrot", f"account change: {prog}", msg)
    elif prog == "sudo" and "COMMAND=" in msg:
        add(t, "parrot-vm", "auth.log", "Responder", "sudo by responder", msg)

# ---- Parrot: EHR audit trail
for l in log("var/log/ehr-audit.log"):
    m = re.match(r"(\S+) parrot-vm ehr-audit: (.*)", l)
    if m:
        add(iso(m[1]), "parrot-vm", "ehr-audit.log", "Parrot", "EHR record viewed", m[2])

# ---- Parrot: auditd (enriched format; EXECVE args may be hex)
recs = {}
for l in log("var/log/audit/audit.log"):
    m = re.match(r"type=(\w+) msg=audit\((\d+\.\d+):(\d+)\): (.*)", l)
    if m:
        recs.setdefault((m[2], m[3]), {"t": float(m[2])})[m[1]] = m[4]   # serial restarts each boot: key on time + serial
noise = re.compile(r"systemd|generator|motd|run-parts|uname|/etc/update-motd|00-header|10-uname|env -i")
for seq, r in recs.items():
    sc = r.get("SYSCALL", "")
    key = re.search(r'key="([^"]+)"', sc)
    if not key or "auid=1003" not in sc:
        continue
    t = dt.datetime.fromtimestamp(r["t"], UTC)
    if key[1] == "user-exec":
        args = []
        for k, v in re.findall(r"a(\d+)=(\"[^\"]*\"|[0-9A-F]+)", r.get("EXECVE", "")):
            args.append(v.strip('"') if v.startswith('"') else bytes.fromhex(v).decode(errors="replace"))
        cmd = " ".join(args)
        if cmd and not noise.search(cmd):
            add(t, "parrot-vm", "audit.log", "Parrot", "command executed by test.nurse (auditd)", cmd)
    elif key[1] in ("ehr-read", "cron-persist", "identity"):
        exe = re.search(r'exe="([^"]+)"', sc)
        add(t, "parrot-vm", "audit.log", "Parrot", f"auditd watch hit: {key[1]}", f"exe={exe[1] if exe else '?'}")

# ---- Parrot: firewall drops (kern.log)
for l in log("var/log/kern.log"):
    if "IR-BLOCK" in l:
        m = re.match(r"(\S+) ", l); d = re.search(r"DST=(\S+).*DPT=(\d+).*UID=(\d+)", l)
        add(iso(m[1]), "parrot-vm", "kern.log", "Parrot", "firewall dropped upload attempt", f"DST={d[1]}:{d[2]} UID={d[3]}" if d else "")

# ---- disk: MAC times from the dc3dd image
mt = os.path.join(EV4, "disk", "mactime_incident.csv")
if os.path.exists(mt):
    last_date = ""
    for r in csv.DictReader(open(mt)):
        last_date = r["Date"] or last_date          # mactime leaves Date blank when it repeats the row above
        f = r.get("File Name", "")
        if not f:
            continue
        try:
            t = iso(last_date)
        except ValueError:
            continue
        if re.search(r"/home/test\.nurse/\.cache/\.sync/|crontabs/test\.nurse|ir-quarantine|00-ir-containment|/etc/group$", f):
            add(t, "parrot-vm (disk image)", "mactime", "File system", f"MAC times {r['Type']}", f.split(" (deleted")[0])

# ---- network: hypervisor capture + drop-site log
for l in open(os.path.join(EV3, "network", "ioc_posts_nic0.tsv")):
    if l.strip():
        add(dt.datetime.fromtimestamp(float(l.split("\t")[0]), UTC), "ir-hv (hypervisor)", "nic0 pcap", "Network",
            "HTTP POST to IOC 10.78.99.66:8080 on the wire", l.split("\t")[1].strip())
for l in open(os.path.join(EV3, "exfil-sink", "uploads.jsonl")):
    u = json.loads(l)
    add(iso(u["ts"]), "exfil-sink (lab)", "uploads.jsonl", "Network", "drop site received upload", f'{u["bytes"]} B "{u["first_line"]}" sha256={u["sha256"][:16]}')

# ---- SIEM: Wazuh alerts from the parrot-vm agent (IR1 rules, FIM, level >= 7)
for l in open(os.path.join(T2, "evidence", "wazuh", "alerts.json")):
    a = json.loads(l)
    if a.get("agent", {}).get("name") != "parrot-vm":
        continue
    r = a["rule"]
    if r["id"].startswith("1002") or "syscheck" in a or r["level"] >= 7:
        what = f'Wazuh rule {r["id"]} (L{r["level"]}): {r["description"]}'
        add(dt.datetime.strptime(a["timestamp"][:23], "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=UTC), "wazuh-manager", "alerts.json", "SIEM",
            what[:120], a.get("syscheck", {}).get("path", "") or a.get("full_log", "")[:150])

# ---- responder actions
names = {"triage": "triage on the host: disclosure in progress, SEV-1 confirmed", "detection": "Wazuh rule 100221 alert: SEV-1",
         "c1_snapshot": "C1 live snapshot", "c2_volatile": "C2 volatile collection", "c3_block": "C3 egress blocked",
         "c4_memory": "C4 memory preserved", "c5_filesystem": "C5 artifacts preserved", "c6_isolate": "C6 host isolated",
         "c7_shutdown": "C7 services/account shut down", "c8_verify": "C8 verification", "contained": "contained, snapshot ir-contained"}
for r in csv.DictReader(open(os.path.join(EV3, "markers.csv"))):
    add(iso(r["utc"]), "IR team", "task3 markers.csv", "Responder", names.get(r["phase"], r["phase"]), r["phase"])
for r in csv.DictReader(open(os.path.join(EV4, "steps.csv"))):
    add(iso(r["utc"]), "IR team", "task4 steps.csv", "Responder", f"Task 4: {r['step']}", r["step"])

RUN_START = iso(next(r["utc"] for r in csv.DictReader(open(os.path.join(T2, "evidence", "markers.csv"))) if r["phase"] == "scenario_start")) - dt.timedelta(minutes=2)
ev[:] = [e for e in ev if e[0] >= RUN_START]
ev.sort(key=lambda x: x[0])
os.makedirs(OUT, exist_ok=True)
fmt = lambda t: t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
with open(os.path.join(OUT, "supertimeline_IR1-2026-002.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["utc", "host", "source", "category", "event", "detail"])
    for e in ev:
        w.writerow([fmt(e[0]), *e[1:]])

# ---- cross-host session correlation: macOS client <-> Parrot sshd (time + key fingerprint)
corr = []
for s in sorted(mac_sessions.values(), key=lambda s: s.get("auth", dt.datetime.max.replace(tzinfo=UTC))):
    if "auth" not in s:
        continue
    best = min(vm_sessions, key=lambda v: abs((v["t"] - s["auth"]).total_seconds()))
    dtsec = (best["t"] - s["auth"]).total_seconds()
    corr.append([s["pid"], fmt(s["auth"].astimezone(UTC)), best["user"], f'{best["src"]}:{best["port"]}', fmt(best["t"]), f"{dtsec:+.2f}",
                 "MATCH" if s.get("fp") == best["fp"] else "DIFFERENT", best["fp"][:20] + "..."])
with open(os.path.join(OUT, "session_correlation.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["mac_ssh_pid", "mac_authenticated_utc", "vm_user", "vm_seen_from", "vm_accepted_utc",
                                   "delta_s", "key_fingerprint", "fingerprint"]); w.writerows(corr)

# ---- key events: first occurrence of each milestone
T_C7 = next(iso(r["utc"]) for r in csv.DictReader(open(os.path.join(EV3, "markers.csv"))) if r["phase"] == "c7_shutdown")
first = lambda pred: next((e for e in ev if pred(e)), None)
last = lambda pred: next((e for e in reversed(ev) if pred(e)), None)
K = [
    ("Tara's first SSH session from the Mac authenticated", first(lambda e: e[2] == "ssh_client.log" and e[4].endswith("as test.nurse"))),
    ("Parrot sshd accepts test.nurse (same key fingerprint)", first(lambda e: e[4] == "sshd accepted publickey for test.nurse")),
    ("PT-1003 viewed through stale clinical group", first(lambda e: e[2] == "ehr-audit.log" and "user=test.nurse" in e[5] and "PT-1003" in e[5])),
    ("auditd: patient file read", first(lambda e: "ehr-read" in e[4])),
    ("Staged copy written (file system)", first(lambda e: e[3] == "File system" and "pt1003.txt" in e[5])),
    ("Uploader script written (file system)", first(lambda e: e[3] == "File system" and "syncd.py" in e[5])),
    ("Uploader started (auditd)", first(lambda e: e[2] == "audit.log" and "syncd.py" in e[5] and "python3" in e[5])),
    ("Persistence: crontab written (auditd)", first(lambda e: "cron-persist" in e[4])),
    ("First upload received by drop site", first(lambda e: e[2] == "uploads.jsonl")),
    ("Wazuh alert 100221 (detection, SEV-1)", first(lambda e: e[2] == "alerts.json" and "100221" in e[4])),
    ("Triage confirms disclosure in progress", first(lambda e: e[5] == "triage")),
    ("Egress blocked (C3)", first(lambda e: e[5] == "c3_block")),
    ("Last upload received by drop site", last(lambda e: e[2] == "uploads.jsonl")),
    ("First firewall drop logged", first(lambda e: e[2] == "kern.log")),
    ("Memory preserved (C4)", first(lambda e: e[5] == "c4_memory")),
    ("Host isolated (C6)", first(lambda e: e[5] == "c6_isolate")),
    ("Account locked + clinical group removed", first(lambda e: e[2] == "auth.log" and e[4].startswith("account change") and e[0] >= T_C7)),
    ("Contained", first(lambda e: e[5] == "contained")),
]
with open(os.path.join(OUT, "key_events.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["milestone", "utc", "host", "source", "detail"])
    for name, e in K:
        w.writerow([name, fmt(e[0]) if e else "", e[1] if e else "", e[2] if e else "not found", e[5] if e else ""])
cnt = Counter((e[1].split(" ")[0], e[2]) for e in ev)
with open(os.path.join(OUT, "source_counts.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["host", "source", "events"]); w.writerows([[h, s, n] for (h, s), n in sorted(cnt.items())])
print(f"super-timeline: {len(ev)} events from {len(cnt)} host/source pairs; {fmt(ev[0][0])} -> {fmt(ev[-1][0])}")
print(f"session correlation: {sum(1 for c in corr if c[6] == 'MATCH')}/{len(corr)} macOS sessions matched to Parrot sshd by key fingerprint")
print(f"key events found: {sum(1 for _, e in K if e)}/{len(K)}")
