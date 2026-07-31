#!/usr/bin/env python3
# The server must not name a protocol the client never offered (RFC 7301 3.2).
#
# linnea_quic_build_ee wrote "h3" into EncryptedExtensions unconditionally,
# without ever looking at the client's list. A client offering only hq-interop,
# or doq, or anything else was therefore told that h3 had been selected — which
# 3.2 forbids outright. linnea_quic_alpn_has had existed all along with no caller.
#
# RFC 9001 8.1 wants this refused with a no_application_protocol alert carried in
# a CONNECTION_CLOSE (QUIC error 0x0178). There is no path from a TLS-level
# failure to a CONNECTION_CLOSE in the handshake spaces yet — both close paths
# need 1-RTT keys that do not exist at that point — so the connection is dropped
# the way every other handshake refusal here is. Silent, but no longer a lie;
# the alert is tracked separately in the audit.
#
# Usage: h3_alpn_test.py <port>
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

PORT = int(sys.argv[1])


def try_alpn(protocols, budget=4.0):
    """Returns the ALPN the handshake settled on, or None if it never completed."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=protocols)
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.002
        return vt[0]

    negotiated = []
    conn.connect(("127.0.0.1", PORT), now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)

    def flush():
        try:
            for d, _ in conn.datagrams_to_send(now=clk()):
                s.sendto(d, ("127.0.0.1", PORT))
        except Exception:
            pass

    flush()
    dl = time.time() + budget
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            try:
                conn.handle_timer(now=clk())
            except Exception:
                break
        except Exception:
            break
        for ev in iter(conn.next_event, None):
            if type(ev).__name__ == "ProtocolNegotiated":
                negotiated.append(ev.alpn_protocol)
        flush()
    done = conn._handshake_confirmed
    s.close()
    return (negotiated[0] if negotiated else "<none>") if done else None


fails = 0

got = try_alpn(["h3"], budget=8.0)
if got == "h3":
    print("ok   a client offering h3 negotiates h3")
else:
    print(f"FAIL a client offering h3 got {got!r} — the baseline is broken")
    fails += 1

for offer in (["doq"], ["hq-interop"], ["spdy/3.1", "doq"]):
    got = try_alpn(offer)
    if got is None:
        print(f"ok   {offer} is refused rather than answered with h3")
    else:
        print(f"FAIL {offer} was told {got!r} was selected — the server named a "
              f"protocol the client never advertised")
        fails += 1

sys.exit(1 if fails else 0)
