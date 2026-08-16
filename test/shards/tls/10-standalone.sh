# Standalone TLS 1.3 against real clients: openssl and python ssl handshakes,
# HelloRetryRequest, resumption, ALPN, version/downgrade refusals, a
# ClientHello fuzz. Uses linnea-tlstest's echo server, not the full server.

# and www fixtures. (was region 2 of run_tests.sh, lines 3484-5204.)

# Needs the openssl CLI (cert generation + s_client) and python3 ssl,
# both already test-only dependencies. Skips cleanly if either is absent.
TLSBIN=./bin/linnea-tlstest
# Build it here rather than trusting whatever is on disk. It links src/linnea_tls.o
# but `make` alone does not produce it, so an out-of-date binary sits there looking
# perfectly runnable and quietly exercises the PREVIOUS TLS code — every check below
# passing against a build that no longer matches the source.
make -s tlstest >/dev/null 2>&1
if [ -x "$TLSBIN" ] && command -v openssl >/dev/null 2>&1; then
    tlsdir=$(mktemp -d)
    if openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$tlsdir/k.pem" -out "$tlsdir/c.pem" -days 1 -nodes \
            -subj /CN=localhost >/dev/null 2>&1; then
        tport=${P61443}
        "$TLSBIN" "$tlsdir/c.pem" "$tlsdir/k.pem" $tport &
        tls_pid=$!
        sleep 0.4

        # openssl s_client: full handshake + application echo
        got=$(printf 'linnea-tls' | timeout 5 openssl s_client \
              -connect 127.0.0.1:$tport -CAfile "$tlsdir/c.pem" \
              -tls1_3 -quiet 2>/dev/null)
        [ "$got" = "linnea-tls" ]
        check "tls openssl handshake + echo" $?

        # An ALPN mismatch SHALL be a fatal no_application_protocol alert (RFC
        # 7301 3.2). The handshake used to complete with no protocol selected and
        # the server then spoke HTTP/1 at whatever arrived.
        timeout 30 python3 test/tls/alpn_mismatch.py "$tlsdir/c.pem" $tport >/dev/null 2>&1
        check "tls ALPN mismatch is a fatal alert" $?

        # HelloRetryRequest (RFC 8446 4.1.4). OpenSSL sends a key_share for its
        # FIRST -groups entry only, so a client listing P-256 ahead of x25519
        # supports our group but guessed wrong about it. That MUST draw a retry;
        # it used to draw a fatal handshake_failure, locking the client out.
        got=$(printf 'linnea-hrr' | timeout 8 openssl s_client \
              -connect 127.0.0.1:$tport -CAfile "$tlsdir/c.pem" \
              -groups P-256:X25519 -tls1_3 -quiet 2>/dev/null)
        [ "$got" = "linnea-hrr" ]
        check "tls HelloRetryRequest: P-256-first client completes" $?

        # the same with several groups ahead of x25519, so the retry is not an
        # artefact of the two-group case
        got=$(printf 'linnea-hrr2' | timeout 8 openssl s_client \
              -connect 127.0.0.1:$tport -CAfile "$tlsdir/c.pem" \
              -groups P-521:P-384:P-256:X25519 -tls1_3 -quiet 2>/dev/null)
        [ "$got" = "linnea-hrr2" ]
        check "tls HelloRetryRequest: several groups before x25519" $?

        # a session must still resume across a retry. The binder is computed over
        # message_hash || HRR || Truncate(ClientHello2); hashing ClientHello2 on
        # its own fails it silently, and since such a client is retried on every
        # connection it would never resume at all.
        #
        # Hold stdin open past the handshake: s_client exits the moment stdin
        # hits EOF, and if NewSessionTicket has not landed by then -sess_out
        # writes NO FILE AT ALL and the resume below cannot succeed. That is a
        # race in the test, not the server -- it cost this check about 1 run in
        # 13, and a no-retry control flaked at the same rate, so it never had
        # anything to do with the retry. -ign_eof also fixes it but waits out
        # the full 8s timeout, since the echo server closes only when we do.
        { printf 'x'; sleep 0.5; } | timeout 8 openssl s_client \
              -connect 127.0.0.1:$tport \
              -CAfile "$tlsdir/c.pem" -groups P-256:X25519 -tls1_3 \
              -sess_out "$tlsdir/s.pem" >/dev/null 2>&1
        printf 'x' | timeout 8 openssl s_client -connect 127.0.0.1:$tport \
              -CAfile "$tlsdir/c.pem" -groups P-256:X25519 -tls1_3 \
              -sess_in "$tlsdir/s.pem" 2>&1 | grep -q 'Reused, TLSv1.3'
        check "tls session resumes across a HelloRetryRequest" $?

        # a client that genuinely cannot do x25519 must still be refused: a
        # retry would ask for a group it has already declined, and 4.1.4 allows
        # exactly one, so looping is not an option either
        timeout 8 openssl s_client -connect 127.0.0.1:$tport \
              -CAfile "$tlsdir/c.pem" -groups P-256 -tls1_3 \
              </dev/null >/dev/null 2>&1
        [ $? -ne 0 ]
        check "tls no shared group is still a handshake failure" $?

        # python ssl: assert protocol + cipher, echo 4B and 16KB
        timeout 8 python3 - "$tlsdir/c.pem" $tport <<'PYEOF'
import ssl, socket, sys, os
ca, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=ca)
with socket.create_connection(("127.0.0.1", port)) as raw:
    with ctx.wrap_socket(raw, server_hostname="localhost") as s:
        assert s.version() == "TLSv1.3", s.version()
        assert s.cipher()[0] == "TLS_AES_128_GCM_SHA256", s.cipher()
        s.sendall(b"ping"); assert s.recv(16) == b"ping"
        big = os.urandom(16384); s.sendall(big)
        got = b""
        while len(got) < len(big): got += s.recv(65536)
        assert got == big
PYEOF
        check "tls python ssl (TLSv1.3, AES-128-GCM, 16KB echo)" $?

        # session resumption: a NewSessionTicket from the first handshake
        # lets the second skip the certificate. python's ssl exposes the
        # PSK acceptance directly as session_reused.
        timeout 10 python3 - "$tlsdir/c.pem" $tport <<'PYEOF'
import ssl, socket, sys
ca, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=ca)
ctx.check_hostname = False           # the fixture cert is CN=localhost
# first connection: complete the handshake and collect the ticket
with socket.create_connection(("127.0.0.1", port)) as raw:
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    s.sendall(b"x"); assert s.recv(4) == b"x"
    sess = s.session               # populated once the NST arrives
    assert not s.session_reused
    s.close()
assert sess is not None, "no NewSessionTicket received"
# second connection: offer the ticket, expect resumption
with socket.create_connection(("127.0.0.1", port)) as raw:
    s = ctx.wrap_socket(raw, server_hostname="localhost", session=sess)
    assert s.version() == "TLSv1.3", s.version()
    assert s.session_reused, "server did not resume the session"
    s.sendall(b"y"); assert s.recv(4) == b"y"
    s.close()
PYEOF
        check "tls session resumption (PSK, session_reused)" $?

        # negative: plain HTTP to the TLS port -> a fatal alert record
        alert=$(timeout 3 python3 - $tport <<'PYEOF'
import socket, sys
s = socket.socket(); s.settimeout(2)
s.connect(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
d = s.recv(16)
print("alert" if d[:1] == b"\x15" else "no")
PYEOF
)
        [ "$alert" = alert ]
        check "tls plain-HTTP to TLS port -> fatal alert" $?

        # negative: a TLS 1.2-only client cannot negotiate our profile
        timeout 4 openssl s_client -connect 127.0.0.1:$tport -tls1_2 \
            </dev/null 2>&1 | grep -q "alert"
        check "tls 1.2 client rejected" $?

        # a short ClientHello fuzz: the server must survive and keep serving
        timeout 60 python3 test/tls/fuzz_clienthello.py \
            "$tlsdir/c.pem" $tport 150 >/dev/null 2>&1
        check "tls clienthello fuzz (150 cases, server survives)" $?

        kill $tls_pid 2>/dev/null
        wait $tls_pid 2>/dev/null
    else
        check "tls (openssl could not generate a P-256 cert — skipped)" 0
    fi
    rm -rf "$tlsdir"
else
    check "tls (linnea-tlstest not built or openssl absent — skipped)" 0
fi

