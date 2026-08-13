#!/usr/bin/env python3
"""Send one raw HTTP/1.1 request and print the response verbatim.

This replaces a bash /dev/tcp one-liner:

    timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/61080; printf %b '$1' >&3; cat <&3"

whose two seconds were a single hard budget covering bash startup, the connect,
the write AND the read. `cat` reads to EOF, so for any keep-alive response — most
200s — the server never closes and the only way out was the timeout killing it.
Every such call therefore burned the full two seconds, and the budget became a
race the moment the suite was busy: the timeout would fire before the response
had been read and the test saw an EMPTY string, with the error on a discarded
stderr and nothing to say about why. Three runs of this suite lost a test to it,
always a different one, always reproducing perfectly in isolation.

Reading until the peer closes OR goes quiet fixes both halves. A keep-alive
response comes back as soon as it has arrived instead of two seconds later, a
genuinely slow one still has room, and a connection that fails says so.
"""
import socket
import sys

_PB = int(__import__("os").environ.get("LINNEA_TEST_PORT_BASE", 61000))
_p = lambda n: _PB + n - 61000   # the suite's port rule, one base per run

QUIET_S = 0.4        # no more bytes for this long: the peer has said its piece
CEILING_S = 15.0     # ...but never hang the suite


def unescape(text):
    r"""Turn the literal \r\n\t\xNN of the call sites into bytes."""
    return (text.encode("latin1", "backslashreplace")
                .decode("unicode_escape")
                .encode("latin1"))


def main():
    if len(sys.argv) < 2:
        print("usage: raw_http.py <request> [port]", file=sys.stderr)
        return 2
    req = unescape(sys.argv[1])
    port = int(sys.argv[2]) if len(sys.argv) > 2 else _p(61080)

    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=CEILING_S)
    except OSError as e:
        print(f"<connect to 127.0.0.1:{port} failed: {e}>", file=sys.stderr)
        return 1

    out = b""
    try:
        s.settimeout(CEILING_S)
        s.sendall(req)
        # Generous until the first byte — the server may be busy, and that wait
        # is exactly what the old two-second budget kept losing. Only once the
        # peer has started talking does the short quiet window decide the end,
        # which is what lets a keep-alive response return without waiting for a
        # close that is never coming.
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                if not out:
                    print(f"<no response within {CEILING_S}s>", file=sys.stderr)
                break
            if not d:
                break            # the peer closed: the response is complete
            out += d
            s.settimeout(QUIET_S)
    except OSError as e:
        if not out:
            print(f"<{type(e).__name__}: {e}>", file=sys.stderr)
    finally:
        s.close()

    sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
