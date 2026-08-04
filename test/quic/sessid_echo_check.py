#!/usr/bin/env python3
# QUIC forbids TLS 1.3 middlebox compatibility mode (RFC 9001 s8.4): a client MUST
# set legacy_session_id to a zero-length value, and while a server MAY accept any
# value a client sends, it MUST NOT use any value other than an empty one for the
# legacy_session_id in its own ServerHello. linnea-probe's probe_h3_sessid_echo
# checks exactly that — it deliberately sends a non-empty id and reads the echo —
# so this script verifies the same property with an INDEPENDENT implementation
# (aioquic). A finding about someone else's server should never rest on our own
# client being right.
#
# It hooks aioquic's ClientHello writer to force a non-empty legacy_session_id and
# its ServerHello reader to record what came back, then reports one of:
#   empty echo      conformant — what linnea does
#   N-byte echo     the server violates s8.4 (and "== client's" if it mirrored ours)
#   no ServerHello  the server refused the non-empty id outright. Stricter than
#                   required, since s8.4 lets a server accept any value, but not a
#                   violation either.
#
# Verified 2026-08-04: facebook.com, www.facebook.com and instagram.com echo the
# client's id back verbatim at any length; www.google.com and cloudflare-quic.com
# refuse it; linnea echoes empty. Run the control too — with `--sid-len 0`, the
# empty id every real client sends, facebook echoes empty — so the violation is
# latent: only a client that itself breaks s8.4 can provoke it, which is presumably
# how it survives in production.
#
# This needs the network and third-party servers, so it is deliberately NOT wired
# into run_tests.sh; that suite stays offline and deterministic.
# Usage: sessid_echo_check.py [--sid-len N] <host> [host ...]
# Exit:  0 nobody echoed a non-empty id, 1 at least one server did, 2 bad usage.
import asyncio
import os
import ssl
import sys

import aioquic.tls as tls
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

STATE = {"sid": b"", "echo": None}

_push_client_hello = tls.push_client_hello
_pull_server_hello = tls.pull_server_hello


def _push_hooked(buf, hello):
    # the whole point: send what a conformant QUIC client never would
    hello.legacy_session_id = STATE["sid"]
    return _push_client_hello(buf, hello)


def _pull_hooked(buf):
    hello = _pull_server_hello(buf)
    STATE["echo"] = bytes(hello.legacy_session_id)
    return hello


tls.push_client_hello = _push_hooked
tls.pull_server_hello = _pull_hooked


async def probe(host, sid_len):
    STATE["sid"] = os.urandom(sid_len) if sid_len else b""
    STATE["echo"] = None
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name=host)
    config.verify_mode = ssl.CERT_NONE          # we inspect the handshake, not the chain
    reason = None
    try:
        async with connect(host, 443, configuration=config, wait_connected=True):
            pass
    except Exception as exc:                    # a refusal is a result, not an error
        reason = type(exc).__name__
    return STATE["echo"], reason


def main():
    argv = sys.argv[1:]
    sid_len = 32
    hosts = []
    i = 0
    while i < len(argv):
        if argv[i] == "--sid-len" and i + 1 < len(argv):
            sid_len = int(argv[i + 1])
            i += 2
        else:
            hosts.append(argv[i])
            i += 1
    if not hosts:
        print(__doc__ or "usage: sessid_echo_check.py [--sid-len N] <host> [host ...]")
        return 2

    violations = 0
    for host in hosts:
        try:
            echo, reason = asyncio.run(asyncio.wait_for(probe(host, sid_len), 15))
        except Exception as exc:
            print("%-24s sent %2dB -> harness error (%s)" % (host, sid_len, type(exc).__name__))
            continue
        if echo is None:
            verdict = "no ServerHello — server refused the id (%s)" % (reason or "no reply")
        elif echo:
            same = " == client's" if echo == STATE["sid"] else ""
            verdict = "echoed %dB%s — RFC 9001 s8.4 VIOLATION" % (len(echo), same)
            violations += 1
        else:
            verdict = "echoed empty — conformant"
        print("%-24s sent %2dB -> %s" % (host, sid_len, verdict))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
