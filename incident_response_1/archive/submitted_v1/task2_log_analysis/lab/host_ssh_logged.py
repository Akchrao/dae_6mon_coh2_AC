#!/usr/bin/env python3
"""
host_ssh_logged.py - Care Access Navigator IR 1, Task 2 (runs on the macOS host)
================================================================================
The macOS unified log cannot be read on this host without admin rights ("log show" ->
"Could not open local log store: Operation not permitted"). To still have host-side
telemetry for every SSH session the Mac opens to the Parrot lab host, this wrapper runs
the real macOS OpenSSH client with -v and writes each debug line to a syslog-style file
stamped with the host's own clock, hostname and the ssh process ID:

  2026-10-20T12:30:01-04:00 DAEDMAC1009 ssh[4242]: debug1: Authenticating to 127.0.0.1:2222 as 'test.billing'

That file is shipped to the Wazuh manager (localfile, log_format syslog) and decoded by
the macos-ssh-client decoder in wazuh/local_decoder.xml.

  python3 host_ssh_logged.py <logfile> <ssh args...>

stdin is passed through to ssh (used to feed a sudo password without putting it on the
command line, where ssh -v would record it).
"""
import datetime, socket, subprocess, sys

log, args = sys.argv[1], sys.argv[2:]
host = socket.gethostname().split(".")[0]
p = subprocess.Popen(["ssh", "-v", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
with open(log, "a") as fh:
    for line in p.stderr:
        ts = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
        fh.write(f"{ts} {host} ssh[{p.pid}]: {line.rstrip()}\n")
out = p.stdout.read()
p.wait()
sys.stdout.write(out)
sys.exit(p.returncode)
