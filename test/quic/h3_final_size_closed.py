#!/usr/bin/env python3
"""RFC 9000 4.5 for a stream that is already DONE with.

Its sibling test h3_final_size.py covers the same section while the stream is
still being reassembled: it holds a gap at offset 0 so the reassembly context
stays alive, and that context is where fin/final live. This is the other half --
what happens once the request has been SERVED and the context is gone.

A stream's final size is fixed by the first FIN, for good.

A later FIN naming a different size, or data past that size, is FINAL_SIZE_ERROR
(0x06) -- a CONNECTION error, not something to ignore. Linnea enforced it in the
HTTP/3 reassembly context, which is where a multi-frame request lives. A request
that arrives whole in ONE offset-0 STREAM frame with FIN never allocates a
context: it is served straight from the packet, and nothing remembered its final
size, so a contradicting frame afterwards took the already-served exit in
silence (audit-report-77).

Each row is its OWN connection, because the expected outcome of two of them is
that the connection is gone. Row 1 is the control that keeps the fix from
becoming "close on any duplicate": an identical retransmission of a completed
request is LEGAL (RFC 9000 13.3 -- a lost ack makes the peer resend), and must
still be answered with an ack and nothing else.

Usage: h3_final_size.py <port>.  Prints one line per row, then ok/FAIL.
"""
import socket
import ssl
import sys
import time

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived as H3Headers
from aioquic.tls import Epoch

PORT = int(sys.argv[1])
FINAL_SIZE_ERROR = 0x06


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def run(label, mutate, want_close, split=False):
    """Serve one request, inject `mutate(sid, h3bytes)`, report the close.

    split=False sends the request in ONE offset-0 STREAM frame with FIN -- the
    copy-free path, which never allocates a reassembly context. split=True sends
    it in two frames, so it IS reassembled. Both must remember the final size
    afterwards: the context that held it is released the moment the request is
    served, so the completed multi-frame request had exactly the same hole.
    """
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"
    conn = QuicConnection(configuration=cfg)
    vt = [0.0]

    def clk():
        vt[0] += 0.001
        return vt[0]

    conn.connect(("127.0.0.1", PORT), now=clk())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.2)

    def flush():
        for d, _ in conn.datagrams_to_send(now=clk()):
            s.sendto(d, ("127.0.0.1", PORT))

    flush()
    dl = time.time() + 8
    while not conn._handshake_confirmed and time.time() < dl:
        try:
            r, _ = s.recvfrom(4096)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    if not conn._handshake_confirmed:
        print("FAIL %-44s handshake failed" % label)
        return False

    # the request as raw h3 bytes, so the same bytes can be re-framed by hand
    enc = pylsqpack.Encoder()
    enc.apply_settings(max_table_capacity=0, blocked_streams=0)
    _, fields = enc.encode(0, [(b":method", b"GET"), (b":scheme", b"https"),
                               (b":authority", b"localhost"),
                               (b":path", b"/hello.txt")])
    h3bytes = vlq(1) + vlq(len(fields)) + fields          # one HEADERS frame
    sid = conn.get_next_available_stream_id()
    if split:
        conn.send_stream_data(sid, h3bytes[:4], end_stream=False)
        flush()
        time.sleep(0.05)                                  # a frame of its own
        conn.send_stream_data(sid, h3bytes[4:], end_stream=True)
    else:
        conn.send_stream_data(sid, h3bytes, end_stream=True)   # offset 0 + FIN
    flush()

    status = None
    dl = time.time() + 8
    h3 = H3Connection(conn)
    while status is None and time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            for qe in iter(conn.next_event, None):
                for ev in h3.handle_event(qe):
                    if isinstance(ev, H3Headers) and ev.stream_id == sid:
                        for k, v in ev.headers:
                            if k == b":status":
                                status = v.decode()
        except socket.timeout:
            conn.handle_timer(now=clk())
        flush()
    if status is None:
        print("FAIL %-44s the first request got no response" % label)
        return False

    # --- inject the offending frame under a fresh packet number ---
    frame = mutate(sid, h3bytes)
    dcid = conn._peer_cid.cid
    send = conn._cryptos[Epoch.ONE_RTT].send
    pn = conn._packet_number + 5000
    header = bytes([0x43]) + dcid + pn.to_bytes(4, "big")  # short header, 4-byte pn
    s.sendto(send.encrypt_packet(header, frame, pn), ("127.0.0.1", PORT))

    # ...and read the answer off the WIRE, decrypting with aioquic's receive keys
    # but NOT handing the datagram to its connection state machine. That machine
    # never surfaced the close: it reported ConnectionIdIssued and nothing else,
    # while the server had in fact sent 1c 06 08 00. A test that asks the client
    # library "were you told?" is asking the wrong party -- what is being asserted
    # is what LINNEA put on the wire (audit-report-77).
    recv = conn._cryptos[Epoch.ONE_RTT].recv
    pn_offset = 1 + len(conn.host_cid)         # short header: flags + our own cid
    closed = None
    dl = time.time() + 3
    while closed is None and time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
        except socket.timeout:
            continue
        try:
            _, plain, _, _ = recv.decrypt_packet(r, pn_offset, 0)
        except Exception:
            continue                            # not for us / undecryptable
        if plain and plain[0] in (0x1c, 0x1d):  # CONNECTION_CLOSE, transport or app
            closed = plain[1]
    s.close()

    if want_close:
        if closed == FINAL_SIZE_ERROR:
            print("ok   %-44s CONNECTION_CLOSE 0x%02x" % (label, closed))
            return True
        print("FAIL %-44s wanted 0x06, got %s"
              % (label, "no close" if closed is None else hex(closed)))
        return False
    if closed is None:
        print("ok   %-44s no close (control)" % label)
        return True
    print("FAIL %-44s closed 0x%02x on a LEGAL retransmission" % (label, closed))
    return False


def same(sid, h3bytes):            # the identical frame again: legal
    return b"\x0b" + vlq(sid) + vlq(len(h3bytes)) + h3bytes


def shorter_fin(sid, h3bytes):     # a second FIN naming a SMALLER final size
    cut = h3bytes[:-1]
    return b"\x0b" + vlq(sid) + vlq(len(cut)) + cut


def longer_fin(sid, h3bytes):      # ...and one naming a LARGER final size
    grown = h3bytes + b"\x00"
    return b"\x0b" + vlq(sid) + vlq(len(grown)) + grown


def partial_head(sid, h3bytes):    # the stream's FIRST bytes again, no FIN
    # 0x0a = STREAM | LEN. Offset 0 without FIN, so it reaches .ra_alloc rather
    # than .serve_bidi: the site that used to claim a reassembly context for a
    # stream that is already finished, and could then never finish it.
    return b"\x0a" + vlq(sid) + vlq(4) + h3bytes[:4]


def partial_mid(sid, h3bytes):     # ...and bytes from the MIDDLE, also legal
    return b"\x0e" + vlq(sid) + vlq(4) + vlq(4) + h3bytes[4:8]


def past_final(sid, h3bytes):      # data beyond the final size, no FIN of its own
    # 0x0e = STREAM | OFF | LEN, no FIN
    return b"\x0e" + vlq(sid) + vlq(len(h3bytes)) + vlq(4) + b"\x00\x00\x00\x00"


rows = []
for kind, split in (("inline", False), ("reassembled", True)):
    rows += [
        ("%s: identical retransmission (control)" % kind, same, False, split),
        ("%s: partial retransmission, head (control)" % kind, partial_head, False, split),
        ("%s: partial retransmission, mid (control)" % kind, partial_mid, False, split),
        ("%s: second FIN, smaller final size" % kind, shorter_fin, True, split),
        ("%s: second FIN, larger final size" % kind, longer_fin, True, split),
        ("%s: data past the final size" % kind, past_final, True, split),
    ]
bad = 0
for label, mutate, want_close, split in rows:
    if not run(label, mutate, want_close, split):
        bad += 1
print("FAIL %d row(s)" % bad if bad else "ok")
sys.exit(1 if bad else 0)
