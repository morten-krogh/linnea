#!/usr/bin/env python3
# The upload capture file must be created on the filesystem spill_dir names.
#
# The config claims in doc_claims_test.py cover parsing and validation — that a
# missing directory is refused, that one without O_TMPFILE is refused. None of
# that would notice the two open() sites going back to a hardcoded "/tmp",
# which is the mistake worth catching: it is silent, and its only symptom is
# that uploads are held in RAM instead of on disk. So this asserts the runtime
# path, by finding the open descriptor while a body is still arriving.
#
# An O_TMPFILE has no directory entry, so it cannot be found by listing the
# directory — /proc/<pid>/fd is the only place it is visible, as
# "<dir>/#<inode> (deleted)".
#
# Usage: spill_dir_test.py <port> <spill_dir> <master_pid>
import os
import socket
import sys
import time

port, spill_dir, master = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
want = os.path.abspath(spill_dir)
BODY = 2 << 20                      # bigger than any buffer on the path


def workers():
    """The master's children, plus the master itself."""
    out = [master]
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % d) as f:
                # ppid is the 4th field, but the 2nd (comm) may contain spaces
                st = f.read()
            ppid = int(st[st.rindex(")") + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        if ppid == master:
            out.append(int(d))
    return out


def capture_open():
    """Any descriptor pointing into the spill directory."""
    for p in workers():
        try:
            fds = os.listdir("/proc/%d/fd" % p)
        except OSError:
            continue
        for fd in fds:
            try:
                t = os.readlink("/proc/%d/fd/%s" % (p, fd))
            except OSError:
                continue
            if t.startswith(want + "/"):
                return p, t
    return None, None


s = socket.create_connection(("127.0.0.1", port), timeout=20)
s.sendall(b"POST /api/echo HTTP/1.1\r\nHost: localhost\r\n"
          b"Content-Length: %d\r\nConnection: close\r\n\r\n" % BODY)

# Dribble the body: the capture file exists for as long as the body is
# arriving, and closing the descriptor is what releases it.
sent = 0
found = None
chunk = b"S" * 16384
deadline = time.time() + 15
while sent < BODY and time.time() < deadline:
    s.sendall(chunk[:min(len(chunk), BODY - sent)])
    sent += min(len(chunk), BODY - sent)
    if found is None:
        pid, target = capture_open()
        if target:
            found = target
            break
    time.sleep(0.02)

if found is None:
    # give it a moment in case the body outran the poll
    for _ in range(50):
        pid, target = capture_open()
        if target:
            found = target
            break
        time.sleep(0.02)

try:
    s.close()
except OSError:
    pass

if found is None:
    print("no capture file found under %s while a body was arriving" % want)
    sys.exit(1)
print("ok (%s)" % found)
