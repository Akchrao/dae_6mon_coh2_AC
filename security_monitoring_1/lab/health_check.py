#!/usr/bin/env python3
"""HRMC Wazuh health check (Security Monitoring 1, criterion 3).

Checks collection status, processing performance and storage utilization against thresholds and writes
outputs/health_check_<UTC>.json and outputs/health_check_latest.md. Exit code 0 = all OK, 1 = warning, 2 = critical.

  python3 lab/health_check.py
"""
import json, os, ssl, subprocess, sys, pathlib, shutil, urllib.request, base64, datetime as dt

OUT = pathlib.Path(__file__).resolve().parents[1] / "outputs"
OUT.mkdir(exist_ok=True)
MGR = "single-node-wazuh.manager-1"
IDX = "https://localhost:9200"
AUTH = base64.b64encode(os.environ.get("WAZUH_INDEXER_AUTH", "admin:SecretPassword").encode()).decode()  # lab default
CTX = ssl._create_unverified_context()  # lab self-signed certificate
TH = {"queue_usage_pct_warn": 70, "events_dropped_warn": 0, "source_silence_minutes_warn": 60,
      "disk_free_pct_warn": 15, "disk_free_gb_crit": 3, "index_status_ok": ("green", "yellow")}
now = dt.datetime.now(dt.timezone.utc)
checks = []


def add(area, name, value, status, threshold):
    checks.append({"area": area, "check": name, "value": value, "status": status, "threshold": threshold})


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def idx(path, body=None):
    req = urllib.request.Request(IDX + path, data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": "Basic " + AUTH, "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, context=CTX, timeout=20))


# --- collection status: agents, services, sources
agents = [l.strip() for l in sh(f"docker exec {MGR} /var/ossec/bin/agent_control -l").splitlines() if l.strip().startswith("ID:")]
for a in agents:
    ok = "Active" in a
    add("Collection", f"Agent {a.split(',')[1].split(':')[1].strip()}", a.split(",")[-1].strip(), "OK" if ok else "CRITICAL", "Active")
svc = sh(f"docker exec {MGR} /var/ossec/bin/wazuh-control status")
for s in ("wazuh-analysisd", "wazuh-remoted", "wazuh-logcollector", "wazuh-syscheckd", "wazuh-maild", "wazuh-db", "wazuh-modulesd"):
    run = f"{s} is running" in svc
    add("Collection", f"Service {s}", "running" if run else "NOT running", "OK" if run else "CRITICAL", "running")
try:
    lc = json.loads(sh(f"docker exec {MGR} cat /var/ossec/var/run/wazuh-logcollector.state"))
    for f in lc["global"]["files"]:
        if "/var/log/soc1/" in f["location"]:
            add("Collection", f"Log file {f['location'].split('/')[-1]}", f"{f['events']} events since start", "OK", "file monitored")
except Exception as e:
    add("Collection", "logcollector state", f"unreadable: {e}", "WARNING", "readable")
# last event per source (freshness)
try:
    r = idx("/wazuh-alerts-*/_search", {"size": 0, "aggs": {"src": {"terms": {"field": "data.src", "size": 20}, "aggs": {"last": {"max": {"field": "timestamp"}}}},
                                                          "agent": {"terms": {"field": "agent.name", "size": 20}, "aggs": {"last": {"max": {"field": "timestamp"}}}}}})
    for kind in ("src", "agent"):
        for b in r["aggregations"][kind]["buckets"]:
            last = dt.datetime.fromisoformat(b["last"]["value_as_string"].replace("Z", "+00:00"))
            mins = round((now - last).total_seconds() / 60)
            st = "OK" if mins <= TH["source_silence_minutes_warn"] else "WARNING"
            add("Collection", f"Last alert from {'source' if kind == 'src' else 'agent'} {b['key']}", f"{mins} min ago ({b['doc_count']} alerts)", st,
                f"<= {TH['source_silence_minutes_warn']} min (imported sources replay on demand)")
except Exception as e:
    add("Collection", "freshness query", f"failed: {e}", "WARNING", "query succeeds")

# --- processing performance
try:
    st = dict(l.split("=", 1) for l in sh(f"docker exec {MGR} cat /var/ossec/var/run/wazuh-analysisd.state").splitlines() if "=" in l and not l.startswith("#"))
    g = lambda k: float(st.get(k, "0").strip("'"))
    add("Processing", "Events decoded (total since start)", int(g("total_events_decoded")), "OK", "> 0")
    add("Processing", "Events per second (last interval)", g("events_edps"), "OK", "baseline in section 3.3")
    add("Processing", "Events dropped", int(g("events_dropped")), "OK" if g("events_dropped") <= TH["events_dropped_warn"] else "WARNING", "0")
    q = max(g("event_queue_usage"), g("alerts_queue_usage"), g("archives_queue_usage")) * 100
    add("Processing", "Highest analysisd queue usage", f"{q:.1f}%", "OK" if q < TH["queue_usage_pct_warn"] else "WARNING", f"< {TH['queue_usage_pct_warn']}%")
    add("Processing", "Alerts written", int(g("alerts_written")), "OK", "> 0")
except Exception as e:
    add("Processing", "analysisd state", f"unreadable: {e}", "WARNING", "readable")
try:
    rs = dict(l.split("=", 1) for l in sh(f"docker exec {MGR} cat /var/ossec/var/run/wazuh-remoted.state").splitlines() if "=" in l and not l.startswith("#"))
    disc = int(float(rs.get("discarded_count", "0").strip("'")))
    add("Processing", "Agent messages discarded (remoted)", disc, "OK" if disc == 0 else "WARNING", "0")
except Exception as e:
    add("Processing", "remoted state", f"unreadable: {e}", "WARNING", "readable")

# --- storage utilization
try:
    h = idx("/_cluster/health")
    add("Storage", "Indexer cluster health", h["status"], "OK" if h["status"] in TH["index_status_ok"] else "CRITICAL", "green/yellow (single node)")
    cat = json.load(urllib.request.urlopen(urllib.request.Request(IDX + "/_cat/indices/wazuh-alerts-*?format=json&bytes=b",
                                                                   headers={"Authorization": "Basic " + AUTH}), context=CTX))
    size = sum(int(i["store.size"]) for i in cat); docs = sum(int(i["docs.count"]) for i in cat)
    add("Storage", "Alert indices size", f"{size/1e6:.1f} MB, {docs} alerts in {len(cat)} daily indices", "OK", "trend tracked")
    fs = idx("/_nodes/stats/fs")
    n = list(fs["nodes"].values())[0]["fs"]["total"]
    pct = 100 * n["available_in_bytes"] / n["total_in_bytes"]
    add("Storage", "Indexer data disk free", f"{pct:.0f}% ({n['available_in_bytes']/1e9:.1f} GB)", "OK" if pct > TH["disk_free_pct_warn"] else "WARNING", f"> {TH['disk_free_pct_warn']}%")
except Exception as e:
    add("Storage", "indexer", f"unreachable: {e}", "CRITICAL", "reachable")
du = shutil.disk_usage(pathlib.Path.home())
free_gb = du.free / 1e9
add("Storage", "Host (Mac) disk free", f"{free_gb:.1f} GB ({100*du.free/du.total:.0f}%)",
    "CRITICAL" if free_gb < TH["disk_free_gb_crit"] else ("WARNING" if 100 * du.free / du.total < TH["disk_free_pct_warn"] else "OK"),
    f"warn < {TH['disk_free_pct_warn']}% free, critical < {TH['disk_free_gb_crit']} GB")
q = sh(f"docker exec {MGR} du -sm /var/ossec/queue").split()[0]
add("Storage", "Manager queue folder", f"{q} MB", "OK" if int(q) < 1000 else "WARNING", "< 1,000 MB")

worst = max((["OK", "WARNING", "CRITICAL"].index(c["status"]) for c in checks), default=0)
res = {"run_utc": now.isoformat(timespec="seconds"), "overall": ["OK", "WARNING", "CRITICAL"][worst], "thresholds": TH, "checks": checks}
json.dump(res, open(OUT / f"health_check_{now:%Y%m%dT%H%M%SZ}.json", "w"), indent=1)
md = [f"# Wazuh health check {res['run_utc']}: **{res['overall']}**\n", "| Area | Check | Value | Status | Threshold |", "|---|---|---|---|---|"]
md += [f"| {c['area']} | {c['check']} | {c['value']} | {c['status']} | {c['threshold']} |" for c in checks]
open(OUT / "health_check_latest.md", "w").write("\n".join(md) + "\n")
print("\n".join(md))
sys.exit(worst)
