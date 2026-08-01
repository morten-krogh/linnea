#!/usr/bin/env python3
# A handshake we refuse must SAY SO (RFC 9001 4.8): a TLS alert raised during the
# handshake becomes a QUIC connection error of 0x0100 + the alert description,
# carried in a CONNECTION_CLOSE.
#
# Every handshake-space refusal used to drop the connection and go silent,
# because the only close path ran through emit_1rtt and 1-RTT keys do not exist
# that early. The client had nothing to distinguish "refused" from "lost": it sat
# retransmitting its ClientHello until it gave up, then fell back to TCP with no
# diagnosis on either side. Initial keys come from the client's own DCID, so that
# space is writable however the handshake failed.
#
# Two refusals reach the wire here:
#   ALPN we do not speak   -> no_application_protocol (120) = 0x0178, named by
#                             RFC 9001 8.1 for exactly this case
#   no x25519 key share    -> handshake_failure (40) = 0x0128
#
# The second client genuinely cannot do x25519 (aioquic sends a key share for
# every group it supports, so dropping x25519 from the list drops its share too),
# which is the case where a HelloRetryRequest would NOT help and refusing is
# correct. A client that supports x25519 and merely guessed a different group
# first still deserves an HRR, and the QUIC path has none — it does not read
# supported_groups at all, so it cannot tell the two apart. Tracked separately;
# the TCP path got its HRR in Q159.
#
# Usage: h3_hs_close_test.py <port>
import socket
import ssl
import sys
import time

from aioquic import tls
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

PORT = int(sys.argv[1])

NO_APPLICATION_PROTOCOL = 0x0100 + 120
HANDSHAKE_FAILURE = 0x0100 + 40


def attempt(protocols, groups=None, budget=6.0):
    """-> (completed, close_error_code or None)"""
    vt = [0.0]

    def clk():
        vt[0] += 0.002
        return vt[0]

    # The TLS context is built inside connect(), not the constructor, so the
    # patch has to survive until after it -- restoring too early silently gives
    # you a perfectly ordinary client and a test that proves nothing.
    original = tls.Context.__init__
    if groups is not None:
        def patched(self, *a, **kw):
            original(self, *a, **kw)
            self._supported_groups = list(groups)

        tls.Context.__init__ = patched
    try:
        cfg = QuicConfiguration(is_client=True, alpn_protocols=protocols)
        cfg.verify_mode = ssl.CERT_NONE
        cfg.server_name = "localhost"
        conn = QuicConnection(configuration=cfg)
        conn.connect(("127.0.0.1", PORT), now=clk())
    finally:
        tls.Context.__init__ = original

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)

    def flush():
        try:
            for d, _ in conn.datagrams_to_send(now=clk()):
                s.sendto(d, ("127.0.0.1", PORT))
        except Exception:
            pass

    def close_code():
        # aioquic parses the CONNECTION_CLOSE straight away but only turns it
        # into a ConnectionTerminated event once the draining timer fires, so
        # read the parsed close directly as well.
        ev = getattr(conn, "_close_event", None)
        return getattr(ev, "error_code", None) if ev is not None else None

    flush()
    closed = None
    deadline = time.time() + budget
    while closed is None and not conn._handshake_confirmed and time.time() < deadline:
        try:
            data, _ = s.recvfrom(65535)
            conn.receive_datagram(data, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            try:
                conn.handle_timer(now=clk())
            except Exception:
                break
        except Exception:
            break
        for ev in iter(conn.next_event, None):
            if type(ev).__name__ == "ConnectionTerminated":
                closed = ev.error_code
        if closed is None:
            closed = close_code()
        flush()
    done = conn._handshake_confirmed
    s.close()
    return done, closed


fails = 0

# control: the handshake we DO serve still completes, and is not closed
done, err = attempt(["h3"], budget=10.0)
if done and err is None:
    print("ok   an h3 client still completes the handshake")
else:
    print(f"FAIL the h3 baseline broke: completed={done} close={err}")
    fails += 1

for offer in (["doq"], ["hq-interop"]):
    done, err = attempt(offer)
    if err == NO_APPLICATION_PROTOCOL:
        print(f"ok   {offer} is closed with no_application_protocol (0x{err:04x})")
    elif done:
        print(f"FAIL {offer} completed — we named a protocol it never offered")
        fails += 1
    elif err is None:
        print(f"FAIL {offer} got SILENCE — the client cannot tell refused from lost")
        fails += 1
    else:
        print(f"FAIL {offer} closed with 0x{err:04x}, want 0x{NO_APPLICATION_PROTOCOL:04x}")
        fails += 1

done, err = attempt(["h3"], groups=[tls.Group.SECP256R1])
if err == HANDSHAKE_FAILURE:
    print(f"ok   a client without x25519 is closed with handshake_failure (0x{err:04x})")
elif done:
    print("FAIL a client with no x25519 key share completed — it cannot have keyed the ECDHE")
    fails += 1
elif err is None:
    print("FAIL a client without x25519 got SILENCE rather than handshake_failure")
    fails += 1
else:
    print(f"FAIL no-x25519 closed with 0x{err:04x}, want 0x{HANDSHAKE_FAILURE:04x}")
    fails += 1

sys.exit(1 if fails else 0)
