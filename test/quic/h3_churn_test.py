#!/usr/bin/env python3
# Connection churn: more connections, one after another, than the pool has slots
# (64). Each fetches a file and then closes cleanly, so the server sees a
# CONNECTION_CLOSE and hands the slot straight back. Without that, the pool
# would fill after 64 and every later connection would be refused — the idle
# sweep only reclaims after the idle window, far longer than this test runs.
# Usage: h3_churn_test.py <port> [count]
import socket
import ssl
import sys

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived


def vlq(n):
    if n < 64:
        return bytes([n])
    return (0x4000 | n).to_bytes(2, "big")


def fetch_and_close(port):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    conn.connect(("127.0.0.1", port), now=0.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)

    def flush(t):
        for d, _ in conn.datagrams_to_send(now=t):
            s.sendto(d, ("127.0.0.1", port))

    try:
        flush(0.0)
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ("127.0.0.1", port), now=0.1)
        flush(0.2)
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ("127.0.0.1", port), now=0.3)
        while conn.next_event() is not None:
            pass
        enc = pylsqpack.Encoder()
        enc.apply_settings(max_table_capacity=0, blocked_streams=0)
        _, fields = enc.encode(0, [(b":method", b"GET"),
                                   (b":path", b"/hello.txt"),
                                   (b":scheme", b"https"),
                                   (b":authority", b"h3.test")])
        conn.send_stream_data(0, vlq(1) + vlq(len(fields)) + fields,
                              end_stream=True)
        flush(0.4)
        r, _ = s.recvfrom(4096)
        conn.receive_datagram(r, ("127.0.0.1", port), now=0.5)
        got = b""
        ev = conn.next_event()
        while ev is not None:
            if isinstance(ev, StreamDataReceived) and ev.stream_id == 0:
                got += ev.data
            ev = conn.next_event()
        served = b"hello from linnea" in got
        conn.close()                       # CONNECTION_CLOSE frees the slot
        flush(0.6)
        return served
    except Exception:                      # noqa: BLE001 - counted as a failure
        return False
    finally:
        s.close()


port = int(sys.argv[1])
count = int(sys.argv[2]) if len(sys.argv) > 2 else 100
served = sum(1 for _ in range(count) if fetch_and_close(port))
if served != count:
    print(f"only {served}/{count} connections served", file=sys.stderr)
    sys.exit(1)
print("ok")
