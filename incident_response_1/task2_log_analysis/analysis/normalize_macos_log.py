#!/usr/bin/env python3
"""Normalise macOS /var/log/install.log timestamps to ISO 8601 so Wazuh's pre-decoder reads them.

  2026-10-20 11:55:22-04 HOST prog[pid]: msg   ->   2026-10-20T11:55:22-04:00 HOST prog[pid]: msg

Only the timestamp is rewritten; hostname, program and message are untouched. Continuation
lines (multi-line entries) are kept as-is. Usage: normalize_macos_log.py <in> <out>"""
import re, sys

TS = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})([+-]\d{2})(\d{2})? ")
with open(sys.argv[1], errors="replace") as src, open(sys.argv[2], "w") as dst:
    for line in src:
        dst.write(TS.sub(lambda m: f"{m[1]}T{m[2]}{m[3]}:{m[4] or '00'} ", line, count=1))
