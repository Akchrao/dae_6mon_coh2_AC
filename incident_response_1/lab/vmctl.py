#!/usr/bin/env python3
"""
vmctl.py - hypervisor-side control of parrot-vm (runs inside the ir-hypervisor container)
==========================================================================================
The lab's equivalent of VBoxManage. Talks to QEMU over its two control sockets:

  QMP (QEMU Machine Protocol, /vm/qmp.sock)  - hypervisor actions: link state, NIC hot-swap,
                                               memory dump, packet capture filters
  QGA (QEMU guest agent,  /vm/qga.sock)      - out-of-band commands inside the guest over a
                                               virtio-serial channel; keeps working after every
                                               network path to the VM has been cut

  vmctl.py qmp  <command> ['<json arguments>']     e.g. vmctl.py qmp set_link '{"name":"nic0","up":false}'
  vmctl.py hmp  '<monitor command>'                e.g. vmctl.py hmp 'savevm pre-containment'
  vmctl.py exec '<shell command>' [timeout_s]      run /bin/sh -c inside parrot-vm as root
  vmctl.py wait-agent [timeout_s]                  block until the guest agent answers

VirtualBox mapping (documented in the report):
  set_link off        = VBoxManage controlvm parrot-vm setlinkstate1 off
  netdev/device swap  = VBoxManage controlvm parrot-vm nic1 intnet quarantine
  dump-guest-memory   = VBoxManage debugvm parrot-vm dumpvmcore --filename=...
  savevm / loadvm     = VBoxManage snapshot parrot-vm take / restore
  guest-exec          = VBoxManage guestcontrol parrot-vm run ...
"""
import base64, json, socket, sys, time

QMP, QGA = "/vm/qmp.sock", "/vm/qga.sock"


def _conn(path, timeout=30):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    return s, s.makefile("rwb")


def _send(f, obj):
    f.write((json.dumps(obj) + "\n").encode()); f.flush()


def _reply(f):
    while True:                                  # skip asynchronous events
        line = f.readline()
        if not line:
            raise RuntimeError("socket closed")
        msg = json.loads(line)
        if "return" in msg or "error" in msg:
            return msg


def qmp(cmd, args=None):
    s, f = _conn(QMP)
    f.readline()                                 # greeting
    _send(f, {"execute": "qmp_capabilities"}); _reply(f)
    _send(f, {"execute": cmd, **({"arguments": args} if args else {})})
    r = _reply(f); s.close()
    return r


def qga(cmd, args=None, timeout=30):
    s, f = _conn(QGA, timeout)
    sync = int(time.time()) & 0xFFFFFF
    _send(f, {"execute": "guest-sync", "arguments": {"id": sync}})
    while _reply(f).get("return") != sync:
        pass
    _send(f, {"execute": cmd, **({"arguments": args} if args else {})})
    r = _reply(f); s.close()
    return r


def guest_exec(shell, timeout=120):
    r = qga("guest-exec", {"path": "/bin/sh", "arg": ["-c", shell], "capture-output": True})
    if "error" in r:
        raise RuntimeError(r["error"])
    pid, end = r["return"]["pid"], time.time() + timeout
    while time.time() < end:
        st = qga("guest-exec-status", {"pid": pid})["return"]
        if st.get("exited"):
            out = base64.b64decode(st.get("out-data", "")).decode(errors="replace")
            err = base64.b64decode(st.get("err-data", "")).decode(errors="replace")
            return st.get("exitcode", 0), out, err
        time.sleep(0.5)
    raise TimeoutError(f"guest-exec pid {pid} still running after {timeout}s")


def main(a):
    if a[0] == "qmp":
        r = qmp(a[1], json.loads(a[2]) if len(a) > 2 else None)
        print(json.dumps(r)); return 1 if "error" in r else 0
    if a[0] == "hmp":
        r = qmp("human-monitor-command", {"command-line": a[1]})
        print(r.get("return", json.dumps(r)).rstrip() or "(ok)"); return 1 if "error" in r else 0
    if a[0] == "exec":
        rc, out, err = guest_exec(a[1], int(a[2]) if len(a) > 2 else 120)
        sys.stdout.write(out); sys.stderr.write(err); return rc
    if a[0] == "wait-agent":
        end = time.time() + (int(a[1]) if len(a) > 1 else 300)
        while time.time() < end:
            try:
                if "return" in qga("guest-ping", timeout=5):
                    print("guest agent: up"); return 0
            except (OSError, RuntimeError, ValueError):
                pass
            time.sleep(3)
        print("guest agent: no answer"); return 1
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
