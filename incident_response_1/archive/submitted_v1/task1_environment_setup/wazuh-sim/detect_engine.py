#!/usr/bin/env python3
"""
detect_engine.py - Care Access Navigator IR 1, Task 1 (simulated SIEM)
=====================================================================
A small rule engine that loads the SAME local_rules.xml a Wazuh manager would use and
evaluates it against decoded log events, the way `wazuh-logtest` does. It supports the
subset of the Wazuh rule grammar this lab uses:

  <decoded_as>, <match>, <regex>, <level>, <description>
  <if_matched_sid> + <frequency>/<timeframe> + <same_source_ip>   (correlation rules)
  <mitre><id>                                                     (technique tagging)

Standard library only. Input is a syslog-format auth log (sshd / sudo lines). Output is a
JSON alert stream plus a CSV, written under ../evidence/.

  python3 detect_engine.py --rules local_rules.xml --log sample_auth.log --out ../evidence

SYNTHETIC DATA ONLY. The sample log represents a lab scenario; no live host is attacked.
"""
import argparse, csv, json, os, re, sys, datetime as dt
import xml.etree.ElementTree as ET

# ---- minimal syslog decoders (stand in for Wazuh's sshd / sudo decoders) -------------
SSHD_FAIL = re.compile(r"sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) "
                       r"from (?P<srcip>\d+\.\d+\.\d+\.\d+)")
SSHD_OK   = re.compile(r"sshd\[\d+\]:\s+Accepted password for (?P<user>\S+) "
                       r"from (?P<srcip>\d+\.\d+\.\d+\.\d+)")
SUDO      = re.compile(r"sudo:\s+(?P<user>\S+)\s+:.*?(?P<cmd>USER=root\s*;\s*COMMAND=\S+)")
SYSLOG_TS = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def decode(line, year=2026):
    """Return (program, {fields}) for a syslog line, or (None, None)."""
    m = SYSLOG_TS.match(line)
    when = None
    if m:
        when = dt.datetime(year, MONTHS[m["mon"]], int(m["day"]),
                           *map(int, m["time"].split(":")), tzinfo=dt.timezone.utc)
    if SSHD_FAIL.search(line):
        g = SSHD_FAIL.search(line).groupdict(); g.update(when=when, raw=line.rstrip()); return "sshd_fail", g
    if SSHD_OK.search(line):
        g = SSHD_OK.search(line).groupdict();   g.update(when=when, raw=line.rstrip()); return "sshd_ok", g
    if SUDO.search(line):
        g = SUDO.search(line).groupdict();       g.update(srcip="local", when=when, raw=line.rstrip()); return "sudo", g
    return None, None


# ---- rule loading --------------------------------------------------------------------
class Rule:
    def __init__(self, el):
        self.id = el.get("id"); self.level = int(el.get("level", "0"))
        self.frequency = int(el.get("frequency", "0")); self.timeframe = int(el.get("timeframe", "0"))
        self.decoded_as = (el.findtext("decoded_as") or "").strip()
        self.match = el.findtext("match"); self.regex = el.findtext("regex")
        self.desc = (el.findtext("description") or "").strip()
        self.if_matched_sid = el.findtext("if_matched_sid")
        self.same_source_ip = el.find("same_source_ip") is not None
        self.mitre = [m.text for m in el.findall("./mitre/id")]
        self.groups = (el.findtext("group") or "").strip()


def load_rules(path):
    root = ET.parse(path).getroot()
    return [Rule(e) for e in root.iter("rule")]


def fill(desc, f):   # expand $(user)/$(srcip) placeholders in a description
    return re.sub(r"\$\((\w+)\)", lambda m: str(f.get(m.group(1), m.group(0))), desc)


def atomic_hit(rule, prog, fields):
    """True if an atomic (non-correlation) rule matches this decoded event."""
    want = {"sshd": ("sshd_fail", "sshd_ok"), "sudo": ("sudo",)}.get(rule.decoded_as, ())
    if want and prog not in want:
        return False
    if rule.match and rule.match not in fields["raw"]:
        return False
    if rule.regex and not re.search(rule.regex, fields["raw"]):
        return False
    return bool(rule.match or rule.regex or rule.decoded_as)


def run(rules, events):
    by_id = {r.id: r for r in rules}
    fired = {}          # rule_id -> list of (when, srcip) it has fired on (for if_matched_sid)
    alerts = []

    def emit(rule, f):
        alerts.append({"time_utc": f["when"].isoformat() if f["when"] else "",
                       "rule_id": rule.id, "level": rule.level,
                       "severity": sev(rule.level), "srcip": f.get("srcip", ""),
                       "user": f.get("user", ""), "mitre": ",".join(rule.mitre),
                       "description": fill(rule.desc, f), "raw": f["raw"]})
        fired.setdefault(rule.id, []).append((f["when"], f.get("srcip")))

    for prog, f in events:
        # 1) atomic rules
        for r in rules:
            if r.if_matched_sid:
                continue
            if atomic_hit(r, prog, f):
                emit(r, f)
        # 2) correlation rules keyed on a child SID + frequency within timeframe (+ same srcip)
        for r in rules:
            if not r.if_matched_sid:
                continue
            base = by_id.get(r.if_matched_sid)
            # the correlation rule may itself require a match on THIS event (e.g. Accepted password)
            if r.decoded_as and not atomic_hit(r, prog, f):
                continue
            hits = fired.get(r.if_matched_sid, [])
            if r.same_source_ip:
                hits = [(w, ip) for (w, ip) in hits if ip == f.get("srcip")]
            if f["when"] and r.timeframe:
                lo = f["when"] - dt.timedelta(seconds=r.timeframe)
                hits = [(w, ip) for (w, ip) in hits if w and lo <= w <= f["when"]]
            need = r.frequency or 1
            already = any(ip == f.get("srcip") for (_, ip) in fired.get(r.id, []))
            if len(hits) >= need and not (r.frequency > 1 and already):
                emit(r, f)
    return alerts


def sev(level):
    return "Critical" if level >= 12 else "High" if level >= 10 else "Medium" if level >= 7 else "Low"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True); ap.add_argument("--log", required=True)
    ap.add_argument("--out", default="../evidence")
    a = ap.parse_args()
    rules = load_rules(a.rules)
    events = []
    for line in open(a.log):
        prog, f = decode(line)
        if prog:
            events.append((prog, f))
    alerts = run(rules, events)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "alerts.json"), "w") as fh:
        json.dump(alerts, fh, indent=2)
    with open(os.path.join(a.out, "alerts.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["time_utc", "rule_id", "level", "severity",
                                           "srcip", "user", "mitre", "description"])
        w.writeheader()
        for al in alerts:
            w.writerow({k: al[k] for k in w.fieldnames})
    print(f"rules loaded : {len(rules)}  ({', '.join(r.id for r in rules)})")
    print(f"events decoded: {len(events)} from {a.log}")
    print(f"alerts        : {len(alerts)}")
    for al in alerts:
        print(f"  [{al['severity']:8}] rule {al['rule_id']} L{al['level']:<2} "
              f"{al['srcip']:>12}  {al['description']}")
    if not alerts:
        sys.exit("no alerts - check rules/log")


if __name__ == "__main__":
    main()
