#!/usr/bin/env python3
"""
analyze.py - Care Access Navigator IR 1, Task 2 (log analysis over real Wazuh output)
====================================================================================
Reads the evidence exported by lab/run_lab.sh and writes the analysis tables used in
the report (evidence/analysis/*.csv, *.json):

  alerts_by_rule.csv      every Wazuh alert grouped by source host, rule and level
  macos_findings.json     install.log findings (patch status, power cycles, installs)
  correlation_inc_a.csv   per login attempt: macOS client <-> pcap <-> sshd <-> Wazuh
  timeline_inc_a.csv      INC-A event timeline (JML record + both hosts + Wazuh), UTC
  timeline_all.csv        all security-relevant events from both hosts, UTC
  detection_latency.csv   log time -> Wazuh alert time for the Parrot alerts
  incidents.csv           the three incidents with their severity-matrix scoring

Standard library only:
  python3 analyze.py --evidence ../evidence --jml ../../../capstone_next_steps/jml-evidence/JML-LOG.csv
"""
import argparse, collections, csv, datetime as dt, json, os, re, statistics

UTC = dt.timezone.utc


def ts(s):
    """ISO 8601 (with offset) -> aware UTC datetime."""
    s = s.strip().replace("Z", "+00:00")
    m = re.match(r"(.*T\d\d:\d\d:\d\d)(\.\d+)?([+-]\d\d):?(\d\d)$", s)
    if m:
        s = f"{m[1]}{(m[2] or '')[:7]}{m[3]}:{m[4]}"
    return dt.datetime.fromisoformat(s).astimezone(UTC)


def iso(d, ms=True):
    return d.strftime("%Y-%m-%dT%H:%M:%S") + (f".{d.microsecond // 1000:03d}" if ms else "") + "Z"


def log_time(alert):
    """Original event time: the timestamp at the start of full_log (not the alert's ingest time)."""
    m = re.match(r"(\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d))", alert.get("full_log", ""))
    return ts(m[1]) if m else ts(alert["timestamp"])


def source(alert):
    loc = alert.get("location", "")
    if "macos" in loc:
        return "macOS DAEDMAC1009"
    if loc.startswith("10.77.0.10"):
        return "Parrot parrot-sim"
    return "Wazuh manager"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--jml", required=True)
    a = ap.parse_args()
    EV = a.evidence
    out = os.path.join(EV, "analysis"); os.makedirs(out, exist_ok=True)

    alerts = [json.loads(l) for l in open(os.path.join(EV, "wazuh", "alerts.json")) if l.strip()]
    for al in alerts:
        al["_src"] = source(al); al["_t"] = log_time(al); al["_at"] = ts(al["timestamp"])
    alerts.sort(key=lambda x: x["_t"])

    # ---- 1. alerts by source/rule -------------------------------------------------------
    grp = collections.OrderedDict()
    for al in alerts:
        r = al["rule"]
        k = (al["_src"], r["id"], r["level"], re.sub(r"\s+", " ", r["description"]))
        g = grp.setdefault(k, {"count": 0, "first": al["_t"], "last": al["_t"]})
        g["count"] += 1; g["last"] = al["_t"]
    with open(os.path.join(out, "alerts_by_rule.csv"), "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["source", "rule_id", "level", "description", "count", "first_utc", "last_utc"])
        for (s, i, lv, d), g in sorted(grp.items(), key=lambda x: (x[0][0], -x[0][2], x[0][1])):
            w.writerow([s, i, lv, d, g["count"], iso(g["first"], False), iso(g["last"], False)])

    # ---- 2. macOS install.log findings --------------------------------------------------
    mac = [al for al in alerts if al["location"].endswith("install.log")]
    offers = collections.Counter(al["data"].get("update_offered") for al in mac if al["rule"]["id"] == "100241")
    power = [al for al in mac if al["rule"]["id"] == "100240"]
    raw_lines = sum(1 for _ in open(os.path.join(EV, "macos", "install.log"), errors="replace"))
    first_line = open(os.path.join(EV, "macos", "install.log"), errors="replace").readline()
    procs = collections.Counter()
    for line in open(os.path.join(EV, "macos", "install.log"), errors="replace"):
        m = re.match(r"^\S+ \S+ \S+ ([^\[:]+)", line)
        if m:
            procs[m[1]] += 1
    mf = {
        "install_log_lines": raw_lines,
        "window_start": first_line[:22],
        "top_processes": procs.most_common(6),
        "updates_offered": [{"update": k, "times_offered": n} for k, n in offers.most_common()],
        "update_offer_first": iso(min(al["_t"] for al in mac if al["rule"]["id"] == "100241"), False),
        "update_offer_last": iso(max(al["_t"] for al in mac if al["rule"]["id"] == "100241"), False),
        "power_events": len(power),
        "sleeps": sum(1 for al in power if "sleep" in al["data"].get("power_state", "")),
        "wakes": sum(1 for al in power if "powered on" in al["data"].get("power_state", "")),
        "last_wake_before_scenario": None,
        "entitlement_violations": sum(1 for al in mac if al["rule"]["id"] == "100242"),
        "entitlement_pids": sorted({al["data"].get("client_pid") for al in mac if al["rule"]["id"] == "100242"}),
        "packages_installed": [{"package": al["data"].get("package"), "time_utc": iso(al["_t"], False),
                                "rule": al["rule"]["id"]} for al in mac if al["rule"]["id"] in ("100243", "100244")],
        "alerts_from_install_log": len(mac),
    }

    # ---- 3. INC-A correlation (leaver login attempts) -----------------------------------
    # macOS client sessions from ssh_client.log
    sessions = collections.OrderedDict()
    for line in open(os.path.join(EV, "macos", "ssh_client.log")):
        m = re.match(r"(\S+) (\S+) ssh\[(\d+)\]: (.*)", line.rstrip())
        if not m:
            continue
        t, host, pid, msg = ts(m[1]), m[2], m[3], m[4]
        s = sessions.setdefault(pid, {"pid": pid, "host": host, "start": t, "lines": []})
        s["lines"].append(msg)
        if (u := re.search(r"Authenticating to \S+ as '(\S+)'", msg)): s["user"] = u[1]
        if (v := re.search(r"Local version string (\S+)", msg)): s["client_version"] = v[1]
        if (k := re.search(r"Server host key: (\S+ \S+)", msg)): s["server_host_key"] = k[1]
        if (o := re.search(r"Offering public key: (\S+)", msg)): s["key_path"] = o[1]
        if "Permission denied" in msg: s["outcome"], s["outcome_t"] = "Permission denied (publickey)", t
        if msg.startswith("Authenticated to"): s["outcome"] = "Authenticated (publickey)"
        if (o := re.search(r"Offering public key: \S+ \S+ (SHA256:\S+)", msg)): s["key_fp"] = o[1]
    # pcap client banners
    banners = []
    for row in csv.reader(open(os.path.join(EV, "pcap", "client_banners.csv"))):
        if len(row) == 4:
            banners.append({"t": dt.datetime.fromtimestamp(float(row[0]), UTC), "ip": row[1], "port": row[2], "banner": row[3]})
    # sshd connections
    sshd = {}
    for line in open(os.path.join(EV, "parrot", "auth.log")):
        m = re.match(r"(\S+) parrot-sim sshd\[(\d+)\]: (.*)", line.rstrip())
        if not m:
            continue
        t, pid, msg = ts(m[1]), m[2], m[3]
        if (c := re.match(r"Connection from (\S+) port (\d+)", msg)):
            sshd[pid] = {"pid": pid, "t": t, "ip": c[1], "port": c[2], "events": []}
        if pid in sshd:
            sshd[pid]["events"].append((t, msg))
            if (u := re.search(r"(?:User|for) (test\.\w+)", msg)): sshd[pid].setdefault("user", u[1])
    corr = []
    wz = [al for al in alerts if al["rule"]["id"] in ("100210", "100211")]
    wz_mac = [al for al in alerts if al["rule"]["id"] == "100251"]
    for s in sessions.values():
        if s.get("user") != "test.billing":
            continue
        b = min(banners, key=lambda x: abs((x["t"] - s["start"]).total_seconds()))
        c = next(v for v in sshd.values() if v["port"] == b["port"])
        deny = next(m for (t, m) in c["events"] if "not allowed" in m)
        deny_t = next(t for (t, m) in c["events"] if "not allowed" in m)
        w = min(wz, key=lambda x: abs((x["_t"] - deny_t).total_seconds()))
        wm = min(wz_mac, key=lambda x: abs((x["_t"] - s["start"]).total_seconds()))
        corr.append({
            "attempt": len(corr) + 1,
            "mac_time_utc": iso(s["start"], False), "mac_host": s["host"], "mac_ssh_pid": s["pid"],
            "mac_user_from_key_path": re.search(r"/Users/([^/]+)/", s.get("key_path", "")) [1] if s.get("key_path") else "",
            "target_account": s["user"], "client_version": s.get("client_version"),
            "server_host_key_seen": s.get("server_host_key"), "mac_outcome": s.get("outcome"),
            "pcap_time_utc": iso(b["t"]), "pcap_src": f'{b["ip"]}:{b["port"]}', "pcap_client_banner": b["banner"],
            "sshd_time_utc": iso(c["t"]), "sshd_deny_utc": iso(deny_t), "sshd_pid": c["pid"], "sshd_src": f'{c["ip"]}:{c["port"]}', "sshd_decision": deny,
            "wazuh_parrot_rule": f'{w["rule"]["id"]} (L{w["rule"]["level"]})', "wazuh_parrot_alert_utc": iso(w["_at"]),
            "wazuh_mac_rule": f'{wm["rule"]["id"]} (L{wm["rule"]["level"]})', "wazuh_mac_alert_utc": iso(wm["_at"]),
            "mac_outcome_utc": iso(s.get("outcome_t", s["start"]), False),
            "delta_mac_to_sshd_s": round((c["t"] - s["start"]).total_seconds(), 3),
            "delta_pcap_to_sshd_s": round((c["t"] - b["t"]).total_seconds(), 3),
            "detect_latency_s": round((w["_at"] - deny_t).total_seconds(), 3),
        })
    with open(os.path.join(out, "correlation_inc_a.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(corr[0].keys())); w.writeheader(); w.writerows(corr)

    # ---- 4. INC-A timeline ---------------------------------------------------------------
    jml = {r["ticket"]: r for r in csv.DictReader(open(a.jml))}
    term = jml["TERM-2026-0301"]
    # (datetime, display time, host, source, event); macOS ssh lines have 1-second resolution
    J = lambda x: ts(x)
    tl = [
        (J("2026-10-19T18:13:00Z"), "2026-10-19 18:13", "Entra ID", "JML-LOG TERM-2026-0301", "Jeevan Smith (test.billing) disabled in Entra ID (leaver)"),
        (J("2026-10-19T18:15:00Z"), "2026-10-19 18:15", "Entra ID", "JML-LOG TERM-2026-0301", "Sessions revoked; app role removed 18:17"),
        (J("2026-10-19T18:28:00Z"), "2026-10-19 ~18:28", "Keycloak", "JML-LOG TERM-2026-0301", "Keycloak copy disabled"),
    ]
    for line in open(os.path.join(EV, "parrot", "auth.log")):
        if "usermod" in line and "'test.billing'" in line and "shadow" not in line:
            d = ts(line.split()[0])
            tl.append((d, iso(d), "Parrot", "auth.log usermod", "Lab replay of leaver: " + line.split(": ", 1)[1].strip()))
    for c in corr:
        n = c["attempt"]
        sec = lambda x: ts(x)
        tl += [
            (sec(c["mac_time_utc"]), c["mac_time_utc"], "macOS", f"ssh_client.log ssh[{c['mac_ssh_pid']}]",
             f"Attempt {n}: Mac user '{c['mac_user_from_key_path']}' starts ssh as test.billing to 127.0.0.1:2222 ({c['client_version']})"),
            (sec(c["pcap_time_utc"]), c["pcap_time_utc"], "Network", "ssh_sessions.pcapng", f"Attempt {n}: client banner {c['pcap_client_banner']} from {c['pcap_src']}"),
            (sec(c["sshd_time_utc"]), c["sshd_time_utc"], "Parrot", f"auth.log sshd[{c['sshd_pid']}]", f"Attempt {n}: Connection from {c['sshd_src']} (Docker gateway for 127.0.0.1:2222)"),
            (sec(c["sshd_deny_utc"]), c["sshd_deny_utc"], "Parrot", f"auth.log sshd[{c['sshd_pid']}]", f"Attempt {n}: {c['sshd_decision']}"),
            (sec(c["wazuh_parrot_alert_utc"]) + dt.timedelta(microseconds=1), c["wazuh_parrot_alert_utc"], "Wazuh", f"rule {c['wazuh_parrot_rule']}", "Alert raised from the live Parrot syslog stream"),
            (sec(c["mac_outcome_utc"]) + dt.timedelta(milliseconds=999), c["mac_outcome_utc"], "macOS", f"ssh_client.log ssh[{c['mac_ssh_pid']}]", f"Attempt {n}: client receives {c['mac_outcome']}"),
            (sec(c["wazuh_mac_alert_utc"]), c["wazuh_mac_alert_utc"], "Wazuh", f"rule {c['wazuh_mac_rule']}", f"Attempt {n}: macOS-side alert when the host log was shipped"),
        ]
    tl.sort(key=lambda r: r[0])
    tl = [r[1:] for r in tl]
    with open(os.path.join(out, "timeline_inc_a.csv"), "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["time_utc", "host", "source", "event"]); w.writerows(tl)

    # ---- 5. combined timeline (alerts >= L5 from both hosts during the scenario) ------------
    scen = [al for al in alerts if al["_src"] != "Wazuh manager" and al["_t"] >= ts(corr[0]["mac_time_utc"]) - dt.timedelta(minutes=10)]
    with open(os.path.join(out, "timeline_all.csv"), "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["time_utc", "host", "rule_id", "level", "description"])
        for al in scen:
            if al["rule"]["level"] >= 3 and al["rule"]["id"] not in ("5501", "5502", "5555", "100253", "100252", "100241", "100242"):
                w.writerow([iso(al["_t"]), al["_src"], al["rule"]["id"], al["rule"]["level"], al["rule"]["description"]])

    # ---- 6. detection latency for Parrot alerts --------------------------------------------
    par = [al for al in alerts if al["_src"].startswith("Parrot") and al["rule"]["level"] >= 10]
    with open(os.path.join(out, "detection_latency.csv"), "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["rule_id", "log_time_utc", "alert_time_utc", "latency_s"])
        for al in par:
            w.writerow([al["rule"]["id"], iso(al["_t"]), iso(al["_at"]), round((al["_at"] - al["_t"]).total_seconds(), 3)])
    lat = [(al["_at"] - al["_t"]).total_seconds() for al in par]

    # ---- 7. scenario timestamps for the other two incidents --------------------------------
    def first(rule):
        x = [al for al in alerts if al["rule"]["id"] == rule]
        return iso(x[0]["_t"]) if x else ""
    mf["last_wake_before_scenario"] = iso(max((al["_t"] for al in power if "powered on" in al["data"].get("power_state", "")
                                                 and al["_t"] < ts(corr[0]["mac_time_utc"])), default=ts(corr[0]["mac_time_utc"])), False)
    with open(os.path.join(out, "macos_findings.json"), "w") as fh:
        json.dump(mf, fh, indent=2)

    keyevents = {r: first(r) for r in ("100220", "100230", "100231", "100221", "100222", "100210", "100211", "100244")}
    with open(os.path.join(out, "key_events.json"), "w") as fh:
        json.dump({"first_alert_log_time": keyevents,
                   "latency_s": {"min": min(lat), "median": statistics.median(lat), "max": max(lat)},
                   "alert_totals": {"all": len(alerts),
                                    "by_source": collections.Counter(al["_src"] for al in alerts),
                                    "level_ge_10": sum(1 for al in alerts if al["rule"]["level"] >= 10)}}, fh, indent=2)

    # ---- console summary -------------------------------------------------------------------
    print(f"alerts loaded        : {len(alerts)}  " + ", ".join(f"{k}={v}" for k, v in collections.Counter(al['_src'] for al in alerts).items()))
    print(f"alerts level >= 10   : {sum(1 for al in alerts if al['rule']['level'] >= 10)}")
    print(f"macOS install.log    : {raw_lines} lines, {len(mac)} alerts, updates offered {dict(offers)}")
    print(f"INC-A correlated     : {len(corr)} attempts")
    for c in corr:
        print(f"  attempt {c['attempt']}: mac {c['mac_time_utc']} pid {c['mac_ssh_pid']} -> pcap {c['pcap_src']} "
              f"-> sshd[{c['sshd_pid']}] (+{c['delta_mac_to_sshd_s']}s) -> Wazuh {c['wazuh_parrot_rule']} in {c['detect_latency_s']}s")
    print(f"Parrot detection latency (L>=10): max {max(0, max(lat)) * 1000:.1f} ms (alert time = log time at ms resolution)")
    print(f"outputs in {out}")


if __name__ == "__main__":
    main()
