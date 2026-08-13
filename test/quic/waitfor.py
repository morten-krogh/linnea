"""Readiness for a server a test starts itself.

Every one of these tests used to sleep a fixed fraction of a second after
launching linnea and then assume it was serving. That is a guess about how
long a fork, a config parse, a TLS setup and an io_uring arm take, and it was
tuned on an idle machine — so the moment anything else runs, the guess is
wrong and the test fails for a reason that has nothing to do with what it
asserts. Concurrency did not create that fragility, it revealed it.

What proves a server is up is that it SERVED something. A TCP connect does
not: the master creates and listens on the socket before it forks, so the
kernel completes the handshake into the listen backlog whether or not any
worker has reached accept(). Measured on this box, a connect lands at 2 ms
and a request completes at 12 ms — six times later.

The wait is bounded, but the bound is a hang guard rather than a deadline the
server is expected to meet: it returns the moment the server answers, so a
generous limit costs nothing when things work and only spends time when
something is genuinely broken.
"""
import json
import os
import socket
import ssl
import time

READY_LIMIT = float(os.environ.get("LINNEA_TEST_READY_LIMIT", "30"))


def _serves(port, tls, timeout=1.0):
    """One request. Any reply at all counts — 404 and 421 included; what is
    being proved is that a worker inside its event loop answered."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
            sock = raw
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw, server_hostname="localhost")
            sock.settimeout(timeout)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            return sock.recv(16) != b""
    except (OSError, ssl.SSLError):
        return False


def config_is_tls(config):
    try:
        return '"cert"' in open(config).read()
    except OSError:
        return True


def server_ready(port, config=None, proc=None, tls=None, limit=READY_LIMIT):
    """Block until the server on `port` answers a request.

    Returns True once it does. If `proc` is given and exits first, returns
    False at once rather than waiting out the limit — a server that died is
    not going to become ready, and the caller's own assert should say so.
    """
    if tls is None:
        tls = config_is_tls(config) if config else True
    end = time.time() + limit
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            return False
        if _serves(port, tls):
            return True
        time.sleep(0.02)
    return False
