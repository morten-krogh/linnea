#!/usr/bin/env python3
"""Capture real ClientHellos to seed the handshake fuzzer.

The original seed offers none of server_name, ALPN or pre_shared_key, and the
mutator only flips bytes and truncates — it can never synthesise an extension
that is not already there. Those three are the most involved parsers in
parse_ch, and are where most of the handshake's bounds bugs have been, so the
fuzzer was blind to exactly the code that most needed it.

Each seed is captured by pointing a real TLS client at a socket that only
records the first flight and never answers; that is enough to get a genuine,
correctly framed ClientHello. The pre_shared_key one needs a session first,
so it completes a real handshake against the running server, then offers the
resulting session to the recorder.

usage: gen_ch_seeds.py <cafile> <port>
Writes clienthello_seed_ext.bin (SNI + ALPN) and, if resumption is available,
clienthello_seed_psk.bin next to this script. Existing files are replaced.
"""
import os
import socket
import ssl
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))


def capture(connect_client):
    """Run connect_client against a recording socket; return the first flight."""
    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    got = []

    def record():
        try:
            conn, _ = lsock.accept()
            conn.settimeout(2)
            try:
                got.append(conn.recv(16384))
            finally:
                conn.close()
        except OSError:
            pass

    t = threading.Thread(target=record)
    t.start()
    try:
        connect_client(port)
    except (ssl.SSLError, OSError):
        pass                              # the recorder never replies
    t.join(3)
    lsock.close()
    return got[0] if got else b""


def client(ctx, port, session=None):
    raw = socket.create_connection(("127.0.0.1", port), timeout=2)
    ctx.wrap_socket(raw, server_hostname="localhost", session=session)


def write(name, data, what):
    if not data or data[0] != 0x16:
        print(f"warning: no {what} captured", file=sys.stderr)
        return False
    path = os.path.join(HERE, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes ({what})")
    return True


def main():
    cafile, port = sys.argv[1], int(sys.argv[2])
    # One context throughout: a session may only be offered back through the
    # context that established it.
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.check_hostname = False
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    ok = write("clienthello_seed_ext.bin",
               capture(lambda p: client(ctx, p)),
               "server_name + ALPN")

    # A resumption ClientHello carries pre_shared_key and
    # psk_key_exchange_modes, and the binder that goes with them. That needs a
    # session, which needs a completed handshake against the real server.
    session = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                s.recv(4096)
                session = s.session
    except (ssl.SSLError, OSError) as e:
        print(f"warning: no session for the PSK seed: {e}", file=sys.stderr)

    if session is not None:
        ok = write("clienthello_seed_psk.bin",
                   capture(lambda p: client(ctx, p, session=session)),
                   "pre_shared_key + psk_key_exchange_modes") and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
