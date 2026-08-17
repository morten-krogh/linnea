#!/usr/bin/env python3
# QUIC connection-ID lifecycle (audit Finding 21, RFC 9000 5.1). NEW_CONNECTION_ID
# and RETIRE_CONNECTION_ID used to be walked past and never acted on: the peer
# could rotate its CID and the old id was still all we addressed it with, and no
# malformed CID frame was ever rejected. The server now keeps a bounded table of
# each side's CIDs, so:
#   * NEW_CONNECTION_ID with retire_prior_to > sequence  -> PROTOCOL_VIOLATION
#   * a second NEW_CONNECTION_ID reusing a sequence with a different CID -> "
#   * more live peer CIDs than our active_connection_id_limit (2) -> CID_LIMIT_ERROR
#   * RETIRE_CONNECTION_ID for a sequence we never issued -> PROTOCOL_VIOLATION
#   * a valid RETIRE of an id we issued -> that id stops routing and we mint and
#     announce a replacement (a NEW_CONNECTION_ID for the next sequence).
#
# aioquic never emits these malformed frames, so each is hand-built and injected in
# a 1-RTT packet under a fresh packet number using aioquic's own send keys (as
# h3_final_size.py does). The positive case reads the server's reply back with
# aioquic's receive keys rather than through its state machine, because the injected
# packet numbers would otherwise trip aioquic's own loss detection.
#
# Usage: h3_cid_lifecycle.py <port>.  Prints ok/FAIL and exits non-zero on failure.
import socket
import ssl
import sys
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated
from aioquic.tls import Epoch

PORT = int(sys.argv[1])
PROTOCOL_VIOLATION = 0x0A
CONNECTION_ID_LIMIT_ERROR = 0x09


def vlq(n):
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def rd_var(b, i):
    first = b[i]
    ln = 1 << (first >> 6)
    v = first & 0x3F
    for k in range(1, ln):
        v = (v << 8) | b[i + k]
    return v, i + ln


def ncid(seq, rpt, cid, token=b"\x11" * 16):
    # NEW_CONNECTION_ID: type, sequence, retire_prior_to, length(1), cid, token(16)
    return bytes([0x18]) + vlq(seq) + vlq(rpt) + bytes([len(cid)]) + cid + token


def retire(seq):
    return bytes([0x19]) + vlq(seq)


def handshake():
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
    assert conn._handshake_confirmed, "handshake failed"
    # let aioquic emit (and the server absorb) its own NEW_CONNECTION_ID for seq 1
    for _ in range(3):
        flush()
        time.sleep(0.03)
    return conn, s, clk


def inject(conn, s, frames, pn_bump):
    dcid = conn._peer_cid.cid
    send = conn._cryptos[Epoch.ONE_RTT].send
    pn = conn._packet_number + pn_bump
    header = bytes([0x43]) + dcid + pn.to_bytes(4, "big")  # short header, 4-byte pn
    packet = send.encrypt_packet(header, frames, pn)
    s.sendto(packet, ("127.0.0.1", PORT))


def close_code(conn, s, clk):
    dl = time.time() + 3
    while time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
            conn.receive_datagram(r, ("127.0.0.1", PORT), now=clk())
            for ev in iter(conn.next_event, None):
                if isinstance(ev, ConnectionTerminated):
                    return ev.error_code
        except socket.timeout:
            conn.handle_timer(now=clk())
        ce = getattr(conn, "_close_event", None)
        if isinstance(ce, ConnectionTerminated):
            return ce.error_code
    return None


fails = 0


def check(name, got, want):
    global fails
    ok = got == want
    g = "none" if got is None else f"0x{got:02x}"
    print(("ok   " if ok else "FAIL ") + f"{name} (close={g}, want 0x{want:02x})")
    if not ok:
        fails += 1


def err_case(name, frames, want):
    conn, s, clk = handshake()
    inject(conn, s, frames, 5000)
    check(name, close_code(conn, s, clk), want)
    s.close()


# --- malformed CID frames must close the connection -------------------------
# retire_prior_to greater than the sequence it is carried with
err_case("rpt > seq", ncid(9, 10, b"\xbb" * 8), PROTOCOL_VIOLATION)
# more live peer CIDs than our limit of 2: the handshake already holds two, so two
# more (whether one or both land) push the active count past the limit
err_case("cid over limit", ncid(5, 0, b"\xc5" * 8) + ncid(6, 0, b"\xc6" * 8),
         CONNECTION_ID_LIMIT_ERROR)
# a NEW_CONNECTION_ID reusing sequence 0 (the handshake CID) with a different id
err_case("seq 0 reused with new cid", ncid(0, 0, b"\xaa" * 8), PROTOCOL_VIOLATION)
# retiring a sequence we never issued (we have issued only 0 and 1)
err_case("retire unissued", retire(99), PROTOCOL_VIOLATION)


# --- a valid retirement is accepted and draws a replacement CID -------------
def scan_ncid_seqs(payload):
    seqs, i, n = [], 0, len(payload)
    while i < n:
        t = payload[i]
        if t in (0x00, 0x01, 0x1E):     # PADDING, PING, HANDSHAKE_DONE
            i += 1
            continue
        if t != 0x18:                   # anything with a body: stop the walk
            break
        i += 1
        seq, i = rd_var(payload, i)
        _rpt, i = rd_var(payload, i)
        ln = payload[i]
        i += 1 + ln + 16                # cid + reset token
        seqs.append(seq)
    return seqs


def positive():
    global fails
    conn, s, clk = handshake()
    off = 1 + len(conn._host_cids[0].cid)     # short header: flags + our DCID
    recv = conn._cryptos[Epoch.ONE_RTT]
    space = conn._spaces[Epoch.ONE_RTT]
    inject(conn, s, retire(1), 5000)          # retire the server's issued seq-1 CID
    seen, closed = set(), False
    ndg = 0
    dl = time.time() + 3
    while time.time() < dl:
        try:
            r, _ = s.recvfrom(65535)
        except socket.timeout:
            continue
        ndg += 1
        try:
            _hdr, payload, pn = recv.decrypt_packet(r, off, space.expected_packet_number)
            space.expected_packet_number = pn + 1
        except Exception:
            continue
        for sq in scan_ncid_seqs(payload):
            seen.add(sq)
        # a CONNECTION_CLOSE (0x1c transport / 0x1d application) leads its packet
        if payload and payload[0] in (0x1C, 0x1D):
            closed = True
        if 2 in seen:
            break
    s.close()
    ok = (2 in seen) and not closed
    print(("ok   " if ok else "FAIL ")
          + f"valid retire draws replacement (seqs announced={sorted(seen)}, closed={closed}, dgrams={ndg})")
    if not ok:
        fails += 1


positive()

print("ok" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
