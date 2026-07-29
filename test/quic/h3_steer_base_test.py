#!/usr/bin/env python3
# Q118: a master handed a steering section in LINNEA_UPGRADE must stamp its
# workers' connection ids from the OTHER half of the index space (steer_base
# 64 when the drained generation used 0), so its connections can never collide
# with ones the draining workers still serve. And the inherited bpf fds are
# best-effort: bogus ones (here: a pipe) must cost only the steering, never
# the serving. This exercises the whole adopt path except the bpf syscalls
# themselves, which need CAP_BPF the test environment does not have.
# Usage: h3_steer_base_test.py <config> <port>
import os
import socket
import ssl
import subprocess
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

config, port = sys.argv[1], int(sys.argv[2])

# stand in for the previous master: the listener the new generation adopts
ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port))
ls.listen(64)
lfd = ls.fileno()

# an "old worker" pid that is safely signal-inert: our own unreaped zombie
zomb = subprocess.Popen(["true"])
time.sleep(0.2)

# two fds that exist but are not bpf objects, standing in for the map+program
pr, pw = os.pipe()
os.set_inheritable(pr, True)
os.set_inheritable(pw, True)

env = dict(os.environ)
env["LINNEA_UPGRADE"] = f"{lfd};{zomb.pid};{pr}:{pw}:0"
srv = subprocess.Popen(["bin/linnea", "--config", config],
                       pass_fds=[lfd, pr, pw], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.6)
assert srv.poll() is None, "server did not survive the steering handoff"

cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
cfg.verify_mode = ssl.CERT_NONE
cfg.server_name = "localhost"
conn = QuicConnection(configuration=cfg)
conn.connect(("127.0.0.1", port), now=0.0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)


def flush(t):
    for d, _ in conn.datagrams_to_send(now=t):
        s.sendto(d, ("127.0.0.1", port))


def vlq(n):
    return bytes([n]) if n < 64 else (0x4000 | n).to_bytes(2, "big")


try:
    flush(0.0)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ("127.0.0.1", port), now=0.1)
    flush(0.2)
    r, _ = s.recvfrom(4096)
    conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)
    assert conn._handshake_confirmed, "handshake not confirmed"

    scid0 = conn._peer_cid.cid[0]
    assert scid0 == 64, (
        f"connection id stamped {scid0}: the adopted generation must take the "
        f"other half of the steering index space (want 64)")

    # and a request still round-trips: the pipe fds failed every bpf call,
    # which must have cost nothing but the steering
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":path", b"/hello.txt"),
                               (b":scheme", b"https"), (b":authority", b"localhost")])
    conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields, end_stream=True)
    flush(0.4)
    got, fin = 0, False
    deadline = time.time() + 5
    while not fin and time.time() < deadline:
        try:
            r, _ = s.recvfrom(4096)
        except socket.timeout:
            break
        conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
        flush(0.6)
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                got += len(ev.data)
                if ev.end_stream:
                    fin = True
            ev = conn.next_event()
    assert fin and got > 0, f"no response over the adopted generation (got={got})"
    print("ok")
finally:
    srv.terminate()
    try:
        srv.wait(timeout=10)
    except subprocess.TimeoutExpired:
        srv.kill()
    zomb.wait()
