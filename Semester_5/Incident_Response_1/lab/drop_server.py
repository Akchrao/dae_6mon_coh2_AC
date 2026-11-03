#!/usr/bin/env python3
# exfil-sink - LAB-ONLY stand-in for the outside drop site (container on ir3-internet, 10.78.99.66).
# Logs every upload as one JSON line so the report can show exactly when exfiltration stopped.
import datetime, hashlib, json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = sys.argv[1] if len(sys.argv) > 1 else "/srv/drop/uploads.jsonl"


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        rec = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
               "src": self.client_address[0], "path": self.path, "ua": self.headers.get("User-Agent"),
               "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
               "first_line": body.split(b"\n", 1)[0].decode(errors="replace")}
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    def do_GET(self):                            # reachability probe for the verification matrix
        self.send_response(200); self.end_headers(); self.wfile.write(b"drop-site\n")

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
