# Shard: TLS 1.3 (standalone echo + end-to-end kTLS), HTTP/2, and the h3
# proxy battery. Self-contained: starts its own proxy backend, TLS servers
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

# --- TLS end to end: the real server, handshake in userspace then kTLS ---
# Everything past the handshake is the ordinary HTTP path over a socket the
# kernel encrypts, so these tests are really asking whether the handoff left
# the connection indistinguishable from a plaintext one.
if ! grep -qw tls /proc/sys/net/ipv4/tcp_available_ulp 2>/dev/null; then
    # No kTLS: the handshake would still succeed and every request would then
    # fail, so skip rather than report a pile of misleading failures.
    check "tls e2e (kernel tls module not loaded: modprobe tls — skipped)" 0
else
    rm -f "$LOG"
    # Recreated here: the HTTP section removed its copy, and a file spanning
    # many records is the point of the large-file case below.
    python3 -c "open('$WWW/big.txt','w').write('B'*100000)"
    python3 test/proxy_backend.py >/dev/null 2>&1 &
    tls_backend_pid=$!
    backend_ready
    start_server $CFG/tls.json
    P61443=$SRV_PORT
    tls_server_pid=$SRV_PID
    sleep 0.3
    CA=test/tls/server.crt
    U=https://localhost:${P61443}

    resp=$(curl -si --http1.1 --max-time 5 --cacert $CA $U/hello.txt)
    check_http "tls static body"   "hello from linnea" "$resp"
    check_http "tls static status" "200 OK" "$resp"

    # One connection, two requests: keep-alive has to survive the handoff.
    # -w reports per transfer, so sum it: the second request must open no
    # new connection (and so must not repeat the handshake).
    n=$(curl -s --max-time 5 --cacert $CA -o /dev/null -o /dev/null \
        -w '%{num_connects}\n' $U/hello.txt $U/index.html | awk '{t += $1} END {print t}')
    [ "$n" = "1" ]
    check "tls keep-alive reuses one connection" $?

    # A file spanning many records exercises the kTLS TX path against an
    # mmap'd send, where the kernel does the fragmenting.
    n=$(curl -s --max-time 10 --cacert $CA $U/big.txt | wc -c)
    [ "$n" = "100000" ]
    check "tls large file intact ($n bytes)" $?

    resp=$(curl -si --http1.1 --max-time 5 --cacert $CA $U/api/simple)
    check_http "tls proxy body"   "backend body" "$resp"
    check_http "tls proxy status" "200 OK" "$resp"

    # A captured upload over TLS: the capture window is filled by the kTLS
    # recvmsg path rather than a plain recv, which is a different arm.
    python3 -c "
import random
random.seed(13)
open('$WWW/tlsupload.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
    curl -s --max-time 30 --cacert $CA --data-binary @$WWW/tlsupload.bin \
        $U/api/echo > $RUNDIR/tls_upload_echo.bin
    [ "$(md5sum < $RUNDIR/tls_upload_echo.bin | cut -d' ' -f1)" = \
      "$(md5sum < $WWW/tlsupload.bin | cut -d' ' -f1)" ]
    check "tls proxy captures a 300000-byte request body (byte-exact)" $?
    rm -f $RUNDIR/tls_upload_echo.bin $WWW/tlsupload.bin

    timeout 8 python3 - "$CA" ${P61443} <<'PYEOF'
import ssl, socket, sys
ctx = ssl.create_default_context(cafile=sys.argv[1])
with socket.create_connection(("localhost", int(sys.argv[2])), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname="localhost") as s:
        assert s.version() == "TLSv1.3", s.version()
        assert s.cipher()[0] == "TLS_AES_128_GCM_SHA256", s.cipher()
        s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        # The head and the mmap'd body are separate sends, so under kTLS
        # they are separate records: read until the body turns up rather
        # than assuming one recv holds the whole response.
        buf = b""
        while b"hello from linnea" not in buf:
            d = s.recv(4096)
            assert d, f"connection closed after {buf!r}"
            buf += d
        assert b"200 OK" in buf, buf
PYEOF
    check "tls python ssl (TLSv1.3, AES-128-GCM)" $?

    # configured security headers ride every response this vhost builds
    hdrs=$(curl -si --http1.1 --max-time 5 --cacert $CA $U/hello.txt)
    check_http "hsts header (h1)"     "Strict-Transport-Security: max-age=31536000" "$hdrs"
    check_http "nosniff header (h1)"  "X-Content-Type-Options: nosniff" "$hdrs"
    hdrs=$(curl -si --http1.1 --max-time 5 --cacert $CA $U/no-such-file)
    check_http "hsts on a 404 (h1)"   "Strict-Transport-Security:" "$hdrs"
    # a proxy failure answers from the same canned blobs, but used to send them
    # straight from rodata — so a 502 from a dead upstream, often the first
    # thing a client ever sees from the origin, carried no policy at all
    hdrs=$(curl -si --http1.1 --max-time 5 --cacert $CA $U/down/x)
    check_http "hsts on a proxy 502 (h1)"    "Strict-Transport-Security:" "$hdrs"
    check_http "nosniff on a proxy 502 (h1)" "X-Content-Type-Options: nosniff" "$hdrs"

    # This vhost has a REDIRECT location, and that used to keep it off h3
    # entirely — no listener, no registration — because "QPACK has no Location
    # header to emit". That was never true: RFC 9204's static table has
    # "location" at index 12. Since h3 serves redirects, the vhost belongs on
    # h3 like any other and must say so, because Alt-Svc migration is
    # per-origin: withholding it is what cost every OTHER location on this
    # server its h3. The curl-h3 block at the end of this section follows the
    # advertisement and checks that h3 really answers /old.
    hdrs=$(curl -si --max-time 5 --cacert $CA $U/hello.txt)
    echo "$hdrs" | grep -qi 'alt-svc'
    check "h3 advertised by a redirect vhost (alt-svc present)" $?

    # HTTP/3 proxying end to end, against the backend already listening on
    # 61100. A proxied h3 request has no client socket to answer on: the leg
    # borrows a connection slot for its upstream half, captures the response
    # whole, and streams it out of a response-stream slot like a file. Every
    # part of that is checked here — status and body, the target and query, a
    # client header reaching the backend, chunked de-chunked and re-lengthed,
    # a close-delimited body, 40000 bytes streamed past a single packet,
    # hop-by-hop fields stopped in both directions, a POST body forwarded, and
    # an unreachable upstream answered 502 rather than left silent.
    # Its own log file, deliberately: these clients hang up hard (a raw socket
    # closed the moment the field block is read, a QUIC client that stops
    # answering), and the close_notify checks further down grep $LOG for the
    # absence of "recv error". Sharing a log would have this block decide that.
    rm -f $RUNDIR/linnea-h3p.log
    start_server $CFG/tls-h3-proxy.json
    P61462=$SRV_PORT
    h3p_pid=$SRV_PID
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        out=$(timeout 120 python3 test/quic/h3_proxy_test.py ${P61462} 2>&1)
        [ "$out" = "OK" ]
        check "h3 proxies to an HTTP/1.1 upstream ($out)" $?

        # How a request stream ends, and what becomes of one that never does:
        # a FIN on a frame carrying no bytes, and contexts left claimed by
        # clients that walked away. Both are consequences of consuming a stream
        # as it arrives, and both were silent — the client simply waited.
        if extensive; then
            out=$(timeout 150 python3 test/quic/h3_stream_end_test.py ${P61462} 2>&1)
            [ "$out" = "OK" ]
            check "h3 request streams end and are reclaimed ($out)" $?
        else
            skip "h3 request streams end and are reclaimed -- 10s, it waits for a context reaper"
        fi

        # An upload abandoned midway leaves a capture file behind. Closing that
        # descriptor is the only thing that returns the space, and PrivateTmp
        # makes the space RAM — so the count has to come back DOWN once the
        # connections are reaped, not merely stop climbing. Counted on the
        # worker, since the master opens none of them.
        # Not the peak, which races the idle sweep — whether the count comes
        # back DOWN. Eight of them, so a server that keeps them is unmistakable:
        # before the fix all eight were still open minutes later, and it is the
        # count settling at the baseline that says the descriptor and its tmpfs
        # pages went back.
        if extensive; then
            h3p_worker=$(pgrep -P "$h3p_pid" | head -1)
            fd_deleted() { ls -l /proc/"$1"/fd 2>/dev/null | grep -c '(deleted)'; }
            before=$(fd_deleted "$h3p_worker")
            timeout 120 python3 test/quic/h3_abandon_upload.py ${P61462} 8 >/dev/null 2>&1
            after=$(fd_deleted "$h3p_worker")
            for _ in $(seq 1 75); do      # the reap runs ~30 s in; leave room
                [ "$after" -le "$before" ] && break
                sleep 1
                after=$(fd_deleted "$h3p_worker")
            done
            [ "$after" -le "$before" ]
            check "h3 abandoned uploads release their capture file (${before} -> ${after} after 8)" $?
        else
            skip "h3 abandoned uploads release their capture file -- 32s, it waits out the ~30s reap"
        fi
    else
        check "h3 proxying (skipped: aioquic/pylsqpack unavailable)" 0
        check "h3 request streams end and are reclaimed (skipped)" 0
        check "h3 abandoned uploads release their capture file (skipped)" 0
    fi
    # RFC 9002 7.6: a path that stops delivering for longer than 3x the PTO is
    # persistent congestion, and the window must go to its floor rather than
    # merely halve. It is the ONLY thing answering a dead path now that a PTO
    # expiry no longer reduces cwnd (7.6.1 forbids that, and obeying it is what
    # unstalled large downloads) -- so this shows it FIRING, by going deaf for a
    # second mid-transfer, and shows the transfer finishing anyway. A floor with
    # ssthresh left above it recovers in slow start; that is the difference
    # between a pause and a dead connection. Verified against 1077793, which
    # does not declare it.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        truncate -s 32M $WWW/pcbig.bin
        outpc=$(timeout 200 python3 test/quic/h3_persistent_congestion_test.py \
                  ${P61462} /pcbig.bin $RUNDIR/linnea-h3p.log 2>&1 | tail -1)
        case "$outpc" in ok*) true ;; *) false ;; esac
        check "h3 persistent congestion is declared, and recovered from ($outpc)" $?
        rm -f $WWW/pcbig.bin
    else
        check "h3 persistent congestion (skipped: aioquic unavailable)" 0
    fi
    # the same path over h2, which has proxied since Q86: the two must agree
    b2=$(curl -s --http2 --max-time 6 --cacert test/tls/server.crt \
              https://localhost:${P61462}/api/simple)
    [ "$b2" = "backend body" ]
    check "h3/h2 agree on the proxied body" $?

    # ...and they must agree about REFUSING one. A response carrying both
    # Transfer-Encoding: chunked and Content-Length is contradictory (RFC 9112
    # 6.3) and h1 has always answered 502 -- "forwarding both would let a
    # compromised backend split the next keep-alive response". h2 and h3 each
    # picked a side and relayed instead, so one backend answer produced three
    # different client-visible outcomes: 502 on h1, a 200 on h2 declaring the
    # upstream's content-length over a de-chunked body of a different length
    # (which the client rejects as PROTOCOL_ERROR), and a clean 200 on h3 with
    # the chunked length restated. Which one a client saw came down to the
    # protocol it happened to negotiate.
    tc2=$(curl -s --http2 -o /dev/null -w '%{http_code}' --max-time 6 \
          --cacert test/tls/server.crt https://localhost:${P61462}/api/tecl)
    [ "$tc2" = "502" ]
    check "h2 refuses a proxied response framed both ways ($tc2)" $?
    if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
        tc3=$("$CURLH3" --http3-only -s -o /dev/null -w '%{http_code}' --max-time 15 \
              --cacert test/tls/server.crt https://localhost:${P61462}/api/tecl)
        [ "$tc3" = "502" ]
        check "h3 refuses the same response h1 and h2 refuse ($tc3)" $?
    else
        check "h3 refuses a doubly-framed proxied response (skipped: no HTTP/3 curl)" 0
    fi
    # The control, and it is the one that matters: a legitimately chunked
    # response carries no Content-Length and must still relay. Without it the
    # two checks above would pass on a build that had simply stopped
    # de-chunking anything.
    ch2=$(curl -s --http2 --max-time 6 --cacert test/tls/server.crt \
          https://localhost:${P61462}/api/chunked)
    [ "$ch2" = "chunked body" ]
    check "h2 still relays an ordinary chunked response ($ch2)" $?

    # RFC 9110 7.6.1 / RFC 9113 8.2.2: the backend's connection fields describe
    # its connection to us, and a message carrying one is malformed on h2. Six
    # names were dropped and TE was not — the one a backend is most likely to
    # send back for an ordinary reason — so the same answer travelled
    # differently over h1 (which drops it) and h2. Checked by decoding the
    # field block: a substring search finds "te" inside "content-length".
    timeout 60 python3 test/tls/h2_proxy_hop_by_hop.py test/tls/server.crt ${P61462} \
        >/dev/null 2>&1
    check "h2 does not relay hop-by-hop response fields" $?

    # A request BODY spanning packets, delivered out of order and duplicated,
    # echoed back and compared by checksum. h3_reorder_test.py covers a field
    # SECTION the same way; this covers the bytes a body is made of, where a
    # misplacement is silent rather than a parse failure. Both matter more once
    # the buffer starts sliding out from under a stream as it is consumed.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        out=$(timeout 180 python3 test/quic/h3_reorder_body_test.py ${P61462} 2>&1)
        [ "$out" = "OK" ]
        check "h3 request body reassembled out of order and duplicated ($out)" $?
    else
        check "h3 body reassembly (skipped: deps unavailable)" 0
    fi

    # max_body bounds an upload on h1, and did nothing at all on h2: a body
    # with a Content-Length streams through the slot FIFO to the backend, and
    # nothing compared the declared length against the cap. Lowering max_body
    # to bound uploads therefore left the one protocol browsers use uncapped.
    # The fixture's max_body is 200000.
    rm -f "$SEEN"
    code=$(head -c 199000 /dev/zero | tr '\0' 'a' | curl -s -o /dev/null \
           -w '%{http_code}' --http2 --max-time 20 --cacert test/tls/server.crt \
           -X POST --data-binary @- https://localhost:${P61462}/api/echo)
    [ "$code" = "200" ]
    check "h2 upload under max_body is served ($code)" $?
    code=$(head -c 400000 /dev/zero | tr '\0' 'b' | curl -s -o /dev/null \
           -w '%{http_code}' --http2 --max-time 20 --cacert test/tls/server.crt \
           -X POST --data-binary @- https://localhost:${P61462}/api/echo)
    [ "$code" = "413" ]
    check "h2 upload past max_body is 413 ($code)" $?
    # and the point of a cap: the bytes never land
    ! grep -q ' 400000$' "$SEEN"
    check "the refused h2 upload never reached the backend" $?
    # TWO uploads on ONE connection. Every other h2 upload check is its own
    # curl, i.e. its own connection, and that shape is what let a026f0d ship:
    # every SECOND upload on a connection was refused 413 at 8192 bytes however
    # large max_body was, because the first left an exclusive claim behind and
    # the second fell to the bounded collect path. Verified against the parent
    # of a026f0d, which answers 200 then 413 here.
    up1=$(mktemp); up2=$(mktemp); upf=$(mktemp)
    head -c 50000 /dev/zero | tr '\0' 'x' > "$upf"
    codes=$(curl -sS --http2 --cacert test/tls/server.crt \
              -o "$up1" -w '%{http_code} ' -X POST --data-binary @"$upf" \
              https://localhost:${P61462}/api/echo \
              --next --http2 --cacert test/tls/server.crt \
              -o "$up2" -w '%{http_code}' -X POST --data-binary @"$upf" \
              https://localhost:${P61462}/api/echo)
    [ "$codes" = "200 200" ] && cmp -s "$up1" "$upf" && cmp -s "$up2" "$upf"
    check "h2 a second upload on the same connection is served ($codes)" $?
    # ...and it really WAS one connection. Without this the check quietly stops
    # testing anything the day curl decides not to reuse: two 200s from two
    # connections is exactly what the broken build would also have produced.
    reused=$(grep 'POST /api/echo HTTP/2' $RUNDIR/linnea-h3p.log | tail -2 |
             sed 's/.*from [0-9.]*:\([0-9]*\) .*/\1/' | sort -u | wc -l)
    [ "$reused" = "1" ]
    check "...and both of those really shared one connection" $?
    rm -f "$up1" "$up2" "$upf"
    kill $h3p_pid 2>/dev/null
    wait $h3p_pid 2>/dev/null

    # A canned h3 error must describe ITSELF. The QPACK encoder reads
    # content-encoding, the validators, content-range, location and
    # cache-control out of .bss globals that only linnea_h3_serve clears — and
    # they are per WORKER, so every connection it holds shares them. Responses
    # built anywhere else inherited the last request's: the reader's
    # 413/421/431/500, answered before a request has routed at all, and the
    # proxy's 502/503/504, built on a completion long after the serve that
    # parked it returned. One static hit was enough to make the next 413 go out
    # as content-encoding: gzip over a plain-text body — undecodable to any
    # client that honours it — with that file's etag and its location's
    # Cache-Control, which made a transient failure storable for as long as the
    # static content was. A separate fixture because it needs workers:1, an
    # upstream timeout short enough to fire while a second request runs, and a
    # location carrying a cache_control.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        rm -f $RUNDIR/linnea-h3canned.log
        start_server $CFG/tls-h3-canned.json
        P61464=$SRV_PORT
        h3cn_pid=$SRV_PID
        # a pre-compressed variant to arm the encoding, beside a plain file so
        # the negotiation is real rather than a .gz served to everyone
        printf 'canned plain payload' > $WWW/canned.txt
        python3 -c "
import gzip, sys
with gzip.open(sys.argv[1], 'wb') as f:
    f.write(b'canned gzip payload')" "$WWW/canned.txt.gz"
        out=$(timeout 90 python3 test/quic/h3_canned_fields_test.py ${P61464} 2>&1)
        [ "$out" = "OK" ]
        check "h3 canned errors carry no other request's field section ($out)" $?
        rm -f $WWW/canned.txt $WWW/canned.txt.gz
        kill $h3cn_pid 2>/dev/null
        wait $h3cn_pid 2>/dev/null
    else
        check "h3 canned error field sections (skipped: aioquic unavailable)" 0
    fi

    # The response buffers must fit the LARGEST head the documented config can
    # produce, not a typical one. hsts and cache_control are each up to 255
    # bytes, which is 510 of the old 512-byte per-connection head buffer on
    # their own — so a vhost setting both at their documented maxima could not
    # serve ANY file over LINNEA_H3_INLINE_MAX over h3: the head failed the
    # bound and the stream was RESET, with no status and no body, while h1 and
    # h2 served the same file normally. Silent, and invisible to every other
    # check here because they all use short header values.
    rm -f $RUNDIR/linnea-h3maxhdr.log
    start_server $CFG/tls-h3-maxhdr.json
    P61465=$SRV_PORT
    h3mx_pid=$SRV_PID
    python3 -c "
import sys
open(sys.argv[1],'wb').write(bytes(range(256))*40)" "$WWW/maxhdr.bin"     # 10240 bytes
    # the independent-client block below sets this too; both want it, and the
    # assignment is idempotent
    CURLH3=${LINNEA_CURL_H3:-$HOME/curl-h3/bin/curl}
    if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
        got=$("$CURLH3" --http3-only -s --max-time 20 --cacert $CA \
              --resolve localhost:${P61465}:127.0.0.1 \
              -o $RUNDIR/maxhdr.out -w '%{http_code}' \
              https://localhost:${P61465}/maxhdr.bin)
        [ "$got" = "200" ] && cmp -s $RUNDIR/maxhdr.out "$WWW/maxhdr.bin"
        check "h3 serves a chunked response with max-length hsts+cache_control ($got)" $?
        rm -f $RUNDIR/maxhdr.out
    else
        check "h3 max-length header response (skipped: no HTTP/3 curl)" 0
    fi
    # h2 is the control: it always could, so a failure above is h3's buffer
    # and not the config being rejected somewhere earlier.
    g2=$(curl -s --http2 --max-time 20 --cacert $CA \
         --resolve localhost:${P61465}:127.0.0.1 \
         -o $RUNDIR/maxhdr2.out -w '%{http_code}' \
         https://localhost:${P61465}/maxhdr.bin)
    [ "$g2" = "200" ] && cmp -s $RUNDIR/maxhdr2.out "$WWW/maxhdr.bin"
    check "h2 serves the same max-length-header response ($g2)" $?
    rm -f $RUNDIR/maxhdr2.out $WWW/maxhdr.bin
    kill $h3mx_pid 2>/dev/null
    wait $h3mx_pid 2>/dev/null

    # A cancelled h3 request must let its upstream leg go rather than run it to
    # completion. Dropping the answer at delivery was always correct, but the
    # leg held a connection slot and an upstream socket for as long as the
    # backend took — one of each per abandoned request. The fixture sets
    # max_upstream to 1, so a leg that was not released blocks the next proxied
    # request with a 503; that is the observable, and it is checked for a reset
    # STREAM and a closed CONNECTION separately, since they reach the leg by
    # different paths. The third case keeps the fix honest: a leg nobody
    # cancelled must STILL hold its slot.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        rm -f $RUNDIR/linnea-h3c.log
        start_server $CFG/tls-h3-cancel.json
        P61463=$SRV_PORT
        h3c_pid=$SRV_PID
        out=$(timeout 120 python3 test/quic/h3_cancel_test.py ${P61463} 2>&1)
        [ "$out" = "OK" ]
        check "h3 cancel releases the upstream leg ($out)" $?
        kill $h3c_pid 2>/dev/null
        wait $h3c_pid 2>/dev/null
    else
        check "h3 cancel releases the upstream leg (skipped: deps unavailable)" 0
    fi

    # kTLS reports the peer's close_notify as -EIO rather than a 0-length
    # read, so an orderly shutdown must not be logged as a recv error.
    curl -s --max-time 5 --cacert $CA $U/hello.txt >/dev/null
    sleep 0.3
    grep -q "closed connection on 127.0.0.1:${P61443} .*: peer closed" "$LOG"
    check "tls close_notify logs as peer closed" $?
    ! grep -q "recv error" "$LOG"
    check "tls orderly close is not a recv error" $?

    # resumption over the real kTLS server: the ticket from connection one
    # must let connection two resume (openssl prints "Reused"), and a byte
    # must still flow — proving the app-key handoff used the right sequence
    # (the NST went out at seq 0, so the kernel starts at seq 1). The first
    # connection makes a full request and reads to EOF (-ign_eof), so the
    # post-handshake ticket is received before -sess_out writes it.
    req=$'GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'
    printf '%s' "$req" | timeout 5 openssl s_client -connect 127.0.0.1:${P61443} \
        -CAfile $CA -tls1_3 -ign_eof -sess_out "$LOG.sess" >/dev/null 2>&1
    reused=$(printf '%s' "$req" | timeout 5 openssl s_client \
        -connect 127.0.0.1:${P61443} -CAfile $CA -tls1_3 -ign_eof \
        -sess_in "$LOG.sess" 2>/dev/null | grep -c '^Reused')
    [ "$reused" -eq 1 ]
    check "tls resumption over kTLS (Reused)" $?
    rm -f "$LOG.sess"

    # ALPN: since Q86 a proxy location is served over h2 too, so this
    # server (61443, which has proxy locations) offers h2 like any other.
    # Offering nothing gets no ALPN extension back.
    echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61443} -CAfile $CA \
        -tls1_3 -alpn h2,http/1.1 2>/dev/null | grep -q "ALPN protocol: h2"
    check "alpn: proxy vhost offers h2 (proxy-over-h2)" $?

    # security headers over h2, on static, error and proxied responses
    sec() { timeout 10 curl -s --http2 -D - -o /dev/null --cacert $CA \
        --resolve localhost:${P61443}:127.0.0.1 "$1"; }
    h=$(sec "https://localhost:${P61443}/hello.txt")
    echo "$h" | grep -qi '^strict-transport-security: max-age=31536000' \
        && echo "$h" | grep -qi '^x-content-type-options: nosniff'
    check "http2 security headers (static)" $?
    h=$(sec "https://localhost:${P61443}/nope")
    echo "$h" | grep -qi '^strict-transport-security:' \
        && echo "$h" | grep -qi '^x-content-type-options:'
    check "http2 security headers (404)" $?
    h=$(sec "https://localhost:${P61443}/api/simple")
    echo "$h" | grep -qi '^strict-transport-security:' \
        && echo "$h" | grep -qi '^x-content-type-options:'
    check "http2 security headers (proxied response)" $?

    # h2/h3 hand the whole :path to the normalizer, where h1 first cut the query
    # off and, for a directory, put back the slash normalize consumed. Without
    # that, every URL carrying a query and every directory but "/" 404'd on h2.
    q() { timeout 10 curl -s -o /dev/null -w '%{http_code}' --http2 --cacert $CA \
              --resolve localhost:${P61443}:127.0.0.1 "https://localhost:${P61443}$1"; }
    [ "$(q '/index.html?v=1')" = 200 ] && [ "$(q '/hello.txt?a=b&c=d')" = 200 ]
    check "http2: a query string is not part of the file name" $?
    # (a directory without the trailing slash 404s on h1 too — no redirect)
    [ "$(q '/sub/')" = 200 ] && [ "$(q '/sub/.')" = 200 ] && [ "$(q '/sub')" = 404 ]
    check "http2: a directory serves its index.html" $?
    # a control byte in the path truncates the name at open(2) while the MIME
    # lookup reads past it, and CR/LF forges a request line in a proxied head
    [ "$(q '/hello.txt%00.html')" = 400 ] && [ "$(q '/api%0d%0aX:%201')" = 400 ]
    check "http2: an encoded control byte in the path is rejected" $?

    # --- proxy over HTTP/2 (Q86): each stream runs its own HTTP/1.1 upstream
    # exchange, so the backend still only ever speaks h1 (and WebSocket).
    h2p() { timeout 10 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 "$@"; }
    P=https://localhost:${P61443}
    [ "$(h2p "$P/api/simple")" = "backend body" ]
    check "http2 proxy: counted body relayed" $?
    v=$(h2p -o /dev/null -w '%{http_version}' "$P/api/simple")
    [ "$v" = "2" ]
    check "http2 proxy: served over h2 (not downgraded)" $?
    [ "$(h2p -d 'hello body' "$P/api/echo")" = "hello body" ]
    check "http2 proxy: POST request body forwarded" $?
    [ "$(h2p "$P/api/target?q=1&x=2")" = "/api/target?q=1&x=2" ]
    check "http2 proxy: raw target incl. query forwarded" $?
    [ "$(h2p "$P/api/chunked")" = "chunked body" ]
    check "http2 proxy: chunked upstream de-chunked" $?
    [ "$(h2p "$P/api/eof")" = "eof delimited body" ]
    check "http2 proxy: close-delimited body relayed" $?
    n=$(h2p "$P/api/big" | wc -c)
    [ "$n" -eq 40000 ]
    check "http2 proxy: large body through flow control ($n bytes)" $?
    # a stream pool slot that once served a proxied stream keeps its .up unless
    # the static path clears it, which sent the scheduler to the upstream branch
    # and left the file body unsent (200 with an empty body, slot never reaped)
    sz=$(timeout 15 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
             -o /dev/null -o /dev/null -o /dev/null -o /dev/null \
             -w '%{size_download} ' \
             "$P/api/simple" "$P/index.html" "$P/api/simple" "$P/index.html")
    [ "$sz" = "12 335 12 335 " ]
    check "http2: static body still served after a proxied stream reuses the slot" $?
    # request-body bytes are debited from the connection window on arrival and
    # credited only once they go upstream, so a reset mid-upload used to strand
    # them: four ~16KB rounds exhausted the 65535 window for the connection's life
    python3 test/tls/h2_upload_credit.py $CA ${P61443} >/dev/null 2>&1
    check "http2: an aborted upload returns its connection flow control" $?
    # tearing an h2 connection down while the other direction still has an op in
    # flight now shuts the socket down and defers the free until it completes,
    # so the kernel cannot write into a recycled buffer. Confirm the deferral
    # always resolves: fds must come back to the baseline, not accumulate.
    w1=$(workers_of $tls_server_pid | awk '{print $1}')
    fd0=$(ls /proc/$w1/fd 2>/dev/null | wc -l)
    for _ in $(seq 1 30); do
        timeout 5 curl -s --http2 --max-time 0.05 --cacert $CA \
            --resolve localhost:${P61443}:127.0.0.1 -o /dev/null \
            "https://localhost:${P61443}/api/big" 2>/dev/null
        timeout 5 curl -s --http2 --max-time 0.05 --cacert $CA \
            --resolve localhost:${P61443}:127.0.0.1 -o /dev/null \
            "https://localhost:${P61443}/big.txt" 2>/dev/null
    done
    sleep 3
    fd1=$(ls /proc/$w1/fd 2>/dev/null | wc -l)
    [ -n "$fd0" ] && [ "$fd0" -gt 0 ] && [ "$fd1" -le $((fd0 + 2)) ] \
        && [ "$(h2p -o /dev/null -w '%{http_code}' "$P/index.html")" = 200 ]
    check "http2: aborted mid-transfer connections are freed, not leaked ($fd0 -> $fd1 fds)" $?
    # the rewritten upstream request: Host from :authority, client headers
    # forwarded, Content-Length re-derived, Connection: close ours
    head=$(h2p -H 'X-Probe: abc' "$P/api/headers")
    echo "$head" | grep -qi "^Host: localhost:${P61443}" \
        && echo "$head" | grep -qi '^x-probe: abc' \
        && echo "$head" | grep -qi '^Connection: close' \
        && ! echo "$head" | grep -qi '^:'
    check "http2 proxy: request rewritten for the h1 backend" $?
    # response headers translated, hop-by-hop dropped
    hdrs=$(h2p -D - -o /dev/null "$P/api/simple")
    echo "$hdrs" | grep -qi '^HTTP/2 200' \
        && echo "$hdrs" | grep -qi '^content-length: 12' \
        && ! echo "$hdrs" | grep -qi '^connection:'
    check "http2 proxy: response head translated (no hop-by-hop)" $?
    # a dead backend fails the stream, not the connection
    code=$(h2p -o /dev/null -w '%{http_code}' "$P/down/x")
    [ "$code" = "502" ]
    check "http2 proxy: dead upstream answers 502" $?
    # static and proxied streams multiplexed on ONE connection
    out=$(timeout 15 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
        -w '%{num_connects}\n' -o /dev/null "$P/hello.txt" \
        -w '%{num_connects}\n' -o /dev/null "$P/api/simple" | awk '{t += $1} END {print t}')
    [ "$out" = "1" ]
    check "http2 proxy: static + proxied share one connection" $?
    # several proxied streams in flight at once (the slot pool)
    S=$(mktemp -d)
    timeout 20 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 --parallel \
        -o "$S/a" "$P/api/simple" -o "$S/b" "$P/api/chunked" \
        -o "$S/c" "$P/api/big" -o "$S/d" "$P/api/eof"
    [ "$(cat "$S/a")" = "backend body" ] && [ "$(cat "$S/b")" = "chunked body" ] \
        && [ "$(wc -c < "$S/c")" -eq 40000 ] && [ "$(cat "$S/d")" = "eof delimited body" ]
    check "http2 proxy: four concurrent upstream exchanges" $?
    rm -rf "$S"
    # a page's worth of concurrent API calls (six, the usual browser cap)
    codes=$(timeout 20 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 --parallel \
        -w '%{http_code} ' -o /dev/null "$P/api/simple" -o /dev/null "$P/api/simple" \
        -o /dev/null "$P/api/simple" -o /dev/null "$P/api/simple" \
        -o /dev/null "$P/api/simple" -o /dev/null "$P/api/simple")
    [ "$(echo $codes | tr ' ' '\n' | grep -c '^200$')" -eq 6 ]
    check "http2 proxy: six concurrent proxied streams all answered" $?
    # a large upload over h2: the body streams through the flow-control
    # window instead of being collected, so it is not capped by a buffer
    python3 -c "
import random
random.seed(13)
open('$WWW/upload2.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
uwant=$(md5sum < $WWW/upload2.bin | cut -d' ' -f1)
timeout 60 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
    --data-binary @$WWW/upload2.bin "https://localhost:${P61443}/api/echo" \
    > $RUNDIR/upload2_echo.bin
[ "$(md5sum < $RUNDIR/upload2_echo.bin | cut -d' ' -f1)" = "$uwant" ]
check "http2 captures a 300000-byte counted request body (byte-exact)" $?
rm -f $RUNDIR/upload2_echo.bin
# Two bodies that used to miss the streaming buffer and fall to a collecting
# path capped at 8 KiB whatever max_body said: one with no usable
# Content-Length, and the second of two uploads running at the same time on one
# connection. Every body is captured now, so neither is a special case any
# more -- they stay because they are still the two shapes most likely to break.
#
# curl cannot express the concurrent case at all -- --parallel opens a second
# connection, so it measures two independent uploads and proves nothing --
# hence the hand-rolled client. Against the pre-fix binary it reports
# "stream 3: status 413".
timeout 60 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
    -o /dev/null -w '%{http_code}' -X POST -T - \
    "https://localhost:${P61443}/api/echo" < $WWW/upload2.bin > $RUNDIR/upl_nocl.txt
# NB: the status is read into a variable BEFORE the test. Writing it as
# `check "... ($(cat f))" $?` reads correctly and is broken: bash expands the
# command substitution before calling check, and that expansion overwrites the
# $? the test just set, so the check reported whether CAT succeeded. It passed
# unconditionally, and it hid a real 408 here for as long as it took to notice
# the number printed inside a line that said PASS.
upl_nocl=$(cat $RUNDIR/upl_nocl.txt)
[ "$upl_nocl" = "200" ]
check "http2 captures a 300000-byte body with no Content-Length ($upl_nocl)" $?
rm -f $RUNDIR/upl_nocl.txt
out=$(timeout 90 python3 test/h2_concurrent_upload.py ${P61443} 200000 2>&1)
check "http2: two 200000-byte uploads at once on one connection ($out)" $?
# A body with a Content-Length, byte-exact, PAST the advertised window. Every
# other counted-body check here is 300000 bytes, which fits inside one slot
# plus a little spill and is nowhere near the 4 MiB window; the one case that
# does go past it sends no Content-Length, so it was always on the capture path
# and cannot speak for the path that a counted body now takes.
dd if=/dev/urandom of=$RUNDIR/upload6.bin bs=1M count=6 2>/dev/null
u6=$(md5sum < $RUNDIR/upload6.bin | cut -d' ' -f1)
timeout 120 curl -s --http2 --max-time 110 --cacert $CA \
    --resolve localhost:${P61443}:127.0.0.1 \
    --data-binary @$RUNDIR/upload6.bin "https://localhost:${P61443}/api/echo" \
    > $RUNDIR/upload6_echo.bin
[ "$(md5sum < $RUNDIR/upload6_echo.bin | cut -d' ' -f1)" = "$u6" ]
check "http2: a 6 MiB counted body past the stream window is byte-exact" $?
rm -f $RUNDIR/upload6.bin $RUNDIR/upload6_echo.bin
# ...and the point of capturing it at all: the backend is not touched until the
# body is in, so a request on another stream of the same connection is answered
# while the upload is still arriving. The backend for this one is SERIAL (the
# test brings its own), because a threaded backend answers the second request
# regardless and both builds would pass. See the header of the script.
out=$(timeout 120 python3 test/h2_upload_blocking.py ${P61443} 4000000 1500000 2>&1)
check "http2: a proxied GET is answered while an upload is still arriving ($out)" $?
# ...and how many times the upload had to STOP to be given more window. A
# ROUND-TRIP COUNT, because it is the half of this that loopback can see: the
# frame handler cannot run while a client send is in flight, so every batch of
# WINDOW_UPDATEs is a pause in reading the body -- free here, one RTT each on a
# real link. Crediting per DATA frame instead of per GRANT_MIN took a real
# client from 4.4 MB/s to 1.4 MB/s with every loopback check in this file green.
out=$(timeout 120 python3 test/h2_upload_grants.py ${P61443} 8000000 2>&1)
check "http2: an upload's window grants stay batched ($out)" $?
# ...and one PAST the advertised stream window. This size is the point: a
# collected body is credited back as it is consumed, and crediting only the
# CONNECTION window was enough while such a body could not exceed 8 KiB. With
# the cap lifted, an upload stalled for ever at exactly
# SETTINGS_INITIAL_WINDOW_SIZE (4 MiB) with the stream window at zero and the
# connection window wide open. Every other upload check here is under that, so
# none of them can catch it — keep this one above LINNEA_H2_INITIAL_WINDOW.
dd if=/dev/urandom of=$RUNDIR/upload5.bin bs=1M count=5 2>/dev/null
u5=$(md5sum < $RUNDIR/upload5.bin | cut -d' ' -f1)
timeout 90 curl -s --http2 --max-time 80 --cacert $CA \
    --resolve localhost:${P61443}:127.0.0.1 -X POST -T - \
    "https://localhost:${P61443}/api/echo" < $RUNDIR/upload5.bin > $RUNDIR/upload5_echo.bin
[ "$(md5sum < $RUNDIR/upload5_echo.bin | cut -d' ' -f1)" = "$u5" ]
check "http2: a 5 MiB no-Content-Length body past the stream window completes" $?
rm -f $RUNDIR/upload5.bin $RUNDIR/upload5_echo.bin
# and over TLS HTTP/1.1, where the client pipelines it behind the handshake
timeout 60 curl -s --http1.1 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
    --data-binary @$WWW/upload2.bin "https://localhost:${P61443}/api/echo" \
    > $RUNDIR/upload3_echo.bin
[ "$(md5sum < $RUNDIR/upload3_echo.bin | cut -d' ' -f1)" = "$uwant" ]
check "tls http1.1 relays a 300000-byte request body (byte-exact)" $?
rm -f $RUNDIR/upload3_echo.bin

    # A streamed upload must leave the connection consistent: the request
    # head stays in place (so the access log can still name it) and the
    # keep-alive bookkeeping never sees in_len below head_len — that
    # underflowed into a gigabyte-scale copy off the end of the connection
    # pool, killing the worker.
    timeout 60 curl -s --http1.1 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
        -o /dev/null -w '%{http_code}' --data-binary @$WWW/upload2.bin \
        "https://localhost:${P61443}/api/echo" > $RUNDIR/upl_code.txt
    timeout 60 curl -s --http1.1 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
        -o /dev/null -w '%{num_connects} %{http_code}' --data-binary @$WWW/upload2.bin \
        "https://localhost:${P61443}/api/echo" --next --http1.1 --cacert $CA \
        --resolve localhost:${P61443}:127.0.0.1 -o /dev/null \
        -w ' %{num_connects} %{http_code}' "https://localhost:${P61443}/hello.txt" \
        > $RUNDIR/upl_ka.txt
    [ "$(cat $RUNDIR/upl_ka.txt)" = "1 200 0 200" ]
    check "tls upload: keep-alive survives a streamed body" $?
    grep -q '"POST /api/echo HTTP/1.1" 200' "$LOG"
    check "tls upload: the streamed request is logged with its target" $?
    # the worker must still be the one that started (no crash + respawn).
    # Match ", respawning" and not the whole old sentence: the line now carries
    # the exit cause between the pid and that word ("exited on signal 9,
    # respawning"), so the former pattern would never match again and this
    # assertion would pass whatever happened.
    ! grep -q ", respawning" "$LOG"
    check "tls upload: no worker died" $?
    rm -f $RUNDIR/upl_code.txt $RUNDIR/upl_ka.txt

    # a HEAD is bodiless, and its slot must come back: more sequential
    # bodiless requests than there are slots, all on one connection
    args=""
    for i in $(seq 12); do args="$args -I -o /dev/null $P/api/simple"; done
    codes=$(timeout 20 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
        -w '%{http_code}\n' $args)
    [ "$(echo "$codes" | grep -c '^200$')" -eq 12 ]
    check "http2 proxy: bodiless HEAD responses free their slot" $?
    # ...and the Via entry names HTTP/2 there, since that is what the request
    # arrived on, while the response says 1.1 — what the backend answered on.
    body=$(h2p "$P/api/headers")
    echo "$body" | grep -qi '^Via: 2 linnea' \
        && h2p -D - -o /dev/null "$P/api/simple" | grep -qi '^via: 1.1 linnea'
    check "http2 proxy: Via names h2 upstream and 1.1 downstream" $?

    # a redirect location over h2 (also newly reachable: h2 used to 404 it)
    hdrs=$(h2p -D - -o /dev/null "$P/old/page.html")
    echo "$hdrs" | grep -qi '^HTTP/2 301' \
        && echo "$hdrs" | grep -qi '^location: https://example.com/old/page.html'
    check "http2 redirect location (301 + Location)" $?
    echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61443} -CAfile $CA \
        -tls1_3 2>/dev/null | grep -q "No ALPN negotiated"
    check "alpn absent when not offered" $?

    # HTTP/2 connection bring-up: a separate http2:1 server. ALPN selects
    # h2; preface + SETTINGS + PING exchange; a request draws GOAWAY.
    start_server $CFG/tls-h2.json
    P61446=$SRV_PORT
    h2_pid=$SRV_PID
    sleep 0.3
    timeout 10 python3 test/tls/h2_bringup.py $CA ${P61446} >/dev/null 2>&1
    check "http2 connection bring-up (preface, settings, ping, goaway)" $?

    # M16/M17: a real HTTP/2 client (curl's nghttp2 — genuine HPACK with
    # Huffman + the static table) has its HEADERS decoded and the named
    # static file served back over h2. Serving the right file end to end is
    # the proof the :path decoded correctly.
    # tls-8 / tls-9: the alert DESCRIPTION the server sends. Refusing correctly
    # but naming the wrong reason sends a client to fix the wrong thing --
    # handshake_failure for a version mismatch tells an old client to change its
    # cipher list. Six cases, one of them a control that must NOT move, and one
    # (bad_record_mac) read out of a record sealed under the server's handshake
    # key. 5 of the 6 report the wrong code before the fix.
    timeout 60 python3 test/tls/alert_codes.py ${P61446} >/dev/null 2>&1
    check "tls alert codes name the actual fault (tls-8, tls-9)" $?

    # ...and the log has to say WHICH of them happened. "tls handshake failed"
    # was the single largest close reason in the production log -- 4018 in
    # eighteen days -- with nothing whatever to tell a bad ClientHello from an
    # unsupported version from a client that walked away. The alert we already
    # send the client names the fault exactly; it was simply never written
    # down. The six cases above must leave at least four distinct codes.
    alerts=$(grep -c 'tls handshake failed, alert ' "$LOG" 2>/dev/null || echo 0)
    distinct=$(grep -oE 'tls handshake failed, alert [0-9]+' "$LOG" 2>/dev/null |
               sort -u | wc -l)
    [ "$alerts" -ge 4 ] && [ "$distinct" -ge 4 ]
    check "tls a failed handshake records which alert it sent ($alerts lines, $distinct distinct)" $?

    # RFC 8446 7.4.2 MUST: a low-order X25519 key share drives the ECDHE
    # product to all-zero whatever the server's private key is, and the
    # handshake must be abandoned rather than keyed from a secret both sides
    # could name in advance. All eight of Curve25519's low-order points, plus
    # the non-canonical encodings p, p+1 and p-1 — which is why the check is on
    # the computed secret and not a blocklist of inputs. Every one of them was
    # accepted before the check existed.
    timeout 60 python3 test/tls/low_order_share.py 127.0.0.1 ${P61446} >/dev/null 2>&1
    check "a low-order x25519 share is refused, not keyed from (RFC 8446 7.4.2)" $?

    # linnea-probe is a SHIPPED product whose purpose is pointing at servers
    # someone else runs, and it appended every handshake message a server sent
    # into fixed .bss buffers with a rep movsb and no bound. A 22 KB chain
    # walked over tr_len, th_buf, every TLS secret and both key schedules:
    # SIGSEGV on TLS and on QUIC alike. h3buf had the same shape at one of its
    # two reassembly sites — 875154c had bounded only the other. The assertion
    # is exit 2 (the "larger than this prober can hold" diagnostic), never 139,
    # and never 0, which would mean a silently truncated transcript reporting a
    # handshake fault that was not the server's.
    timeout 200 python3 test/tls/probe_bigchain.py ./bin/linnea-probe \
        test/tls/server.crt test/tls/bigchain.crt test/tls/server.key \
        >/dev/null 2>&1
    check "linnea-probe survives an oversized certificate chain" $?

    # tls-4: a mid-connection KeyUpdate (RFC 8446 4.6.3). The peer derives the
    # next generation of its traffic secret and switches to it; a receiver that
    # cannot follow loses the connection. kTLS reports the KeyUpdate record by
    # attaching a control message, which a plain recv cannot carry -- such a read
    # fails with -EIO AND CONSUMES THE RECORD -- so this is also what proves the
    # receive path is reading with RECVMSG.
    #
    # openssl s_client's 'k' sends one. TWO TRAPS, both of which make a broken
    # server look healthy:
    #   -ign_eof DISABLES the interactive commands, so 'k' is sent as request
    #     data and no KeyUpdate ever reaches the wire;
    #   one KeyUpdate does not prove the secret was ADVANCED -- deriving the same
    #     generation twice would still serve the second request. Hence two.
    ku_req() { printf 'GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n'; }
    ku_n=$({ ku_req; sleep 0.6; sleep 0.6; ku_req; sleep 1; } | timeout 15 \
        openssl s_client -connect 127.0.0.1:${P61446} -alpn http/1.1 2>/dev/null \
        | grep -c '^HTTP/1.1')
    [ "$ku_n" = "2" ]
    check "tls control: two requests on one kTLS connection" $?

    ku_n=$({ ku_req; sleep 0.6; echo k; sleep 0.6; ku_req; sleep 0.6; echo k; \
             sleep 0.6; ku_req; sleep 1; } | timeout 20 \
        openssl s_client -connect 127.0.0.1:${P61446} -alpn http/1.1 2>/dev/null \
        | grep -c '^HTTP/1.1')
    [ "$ku_n" = "3" ]
    check "tls survives two mid-connection KeyUpdates (kTLS rekey)" $?

    # ...and the other half of 4.6.3: update_requested obliges US to send a
    # KeyUpdate of our own before our next application record, which means
    # switching the transmit key underneath it. 'K' asks for that; two of them
    # prove our sending secret advances as well as our receiving one.
    ku_n=$({ ku_req; sleep 0.6; echo K; sleep 0.6; ku_req; sleep 0.6; echo K; \
             sleep 0.6; ku_req; sleep 1; } | timeout 25 \
        openssl s_client -connect 127.0.0.1:${P61446} -alpn http/1.1 2>/dev/null \
        | grep -c '^HTTP/1.1')
    [ "$ku_n" = "3" ]
    check "tls answers an update_requested KeyUpdate (both directions rekey)" $?

    # the KeyUpdate must be OURS, on the wire, not merely survived: -msg prints
    # both directions, so two lines mean the peer's and the answer to it
    ku_m=$({ ku_req; sleep 0.6; echo K; sleep 0.6; ku_req; sleep 1; } | timeout 20 \
        openssl s_client -connect 127.0.0.1:${P61446} -alpn http/1.1 -msg 2>&1 \
        | grep -ac 'KeyUpdate')
    [ "$ku_m" = "2" ]
    check "tls sends its own KeyUpdate in answer ($ku_m records)" $?

    # the deferred path: a KeyUpdate landing while a large response is still
    # streaming cannot rekey immediately -- switching the transmit key with a
    # send in flight would encrypt data under a key the peer is not expecting --
    # so it waits for the socket to go quiet. Both responses must still arrive.
    # Its own fixture, generated here. This asked for /h3s11.bin, which NOTHING
    # in the suite produces: h3_stress_test.py makes h3s0..h3s5 at 70000+i*12000,
    # so index 11 would be 202000 bytes even if it existed. The 690000-byte file
    # on disk was a fossil from an older version of that test, and this check had
    # been passing on it — on a clean checkout it failed, which is how it was
    # found. A test that borrows another's artefact is one refactor from silently
    # asserting nothing.
    python3 -c "
import sys
open(sys.argv[1], 'wb').write(bytes((i * 131 + (i >> 8) * 17) & 0xFF
                                    for i in range(690000)))" "$WWW/kuflow.bin"
    ku_out=$({ printf 'GET /kuflow.bin HTTP/1.1\r\nHost: localhost\r\n\r\n'; \
               sleep 0.03; echo K; sleep 3; ku_req; sleep 2; } | timeout 30 \
        openssl s_client -connect 127.0.0.1:${P61446} -alpn http/1.1 2>/dev/null \
        | grep -ac -e 'Content-Length: 690000' -e 'hello from linnea')
    [ "$ku_out" = "2" ]
    check "tls KeyUpdate mid-stream: the response and the next request survive" $?

    rl="--resolve localhost:${P61446}:127.0.0.1"
    u="https://localhost:${P61446}"
    body=$(curl -s --http2 --cacert $CA $rl "$u/hello.txt")
    [ "$body" = "hello from linnea" ]
    check "http2 serves a static file (HPACK decode -> file)" $?
    # status line, content-type and content-length over h2
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null "$u/hello.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 200' \
        && echo "$hdrs" | grep -qi '^content-type: text/plain' \
        && echo "$hdrs" | grep -qi '^content-length: 18'
    check "http2 response headers (status, content-type, content-length)" $?
    # validators, date and server over h2 — and revalidation draws a 304
    h2etag=$(echo "$hdrs" | grep -i '^etag:' | tr -d '\r' | cut -d' ' -f2)
    echo "$hdrs" | grep -qiE '^etag: "[0-9a-f]+-12"' \
        && echo "$hdrs" | grep -qiE '^last-modified: [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT' \
        && echo "$hdrs" | grep -qiE '^date: [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT' \
        && echo "$hdrs" | grep -qi '^server: linnea'
    check "http2 validators, date and server headers" $?
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null \
        -H "If-None-Match: $h2etag" "$u/hello.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 304' \
        && echo "$hdrs" | grep -qi "^etag: $h2etag" \
        && ! echo "$hdrs" | grep -qi '^content-length:'
    check "http2 if-none-match 304 (etag repeated, no body)" $?
    sc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'If-None-Match: "stale"' "$u/hello.txt")
    [ "$sc" = "200" ]
    check "http2 stale etag 200" $?

    # If-Match / If-Unmodified-Since over h2 (RFC 9110 13.1.1, 13.1.4). h1 got
    # these in Q187; until h2 and h3 followed, the same request got a different
    # answer depending on which protocol carried it.
    sc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H "If-Match: $h2etag" "$u/hello.txt")
    sc2=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'If-Match: "0000000000000000"' "$u/hello.txt")
    sc3=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'If-Unmodified-Since: Wed, 01 Jan 2020 00:00:00 GMT' "$u/hello.txt")
    # 13.2.2: a failing If-Match wins over an If-None-Match that would say 304
    sc4=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'If-Match: "0000000000000000"' -H "If-None-Match: $h2etag" \
        "$u/hello.txt")
    [ "$sc" = "200" ] && [ "$sc2" = "412" ] && [ "$sc3" = "412" ] && [ "$sc4" = "412" ]
    check "http2 preconditions: If-Match/If-Unmodified-Since ($sc/$sc2/$sc3/$sc4)" $?
    h2lm=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null "$u/hello.txt" \
        | grep -i '^last-modified:' | tr -d '\r' | cut -d' ' -f2-)
    sc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H "If-Modified-Since: $h2lm" "$u/hello.txt")
    [ "$sc" = "304" ]
    check "http2 if-modified-since 304" $?
    # accept-ranges + configured cache-control on the 200
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null "$u/hello.txt")
    echo "$hdrs" | grep -qi '^accept-ranges: bytes' \
        && echo "$hdrs" | grep -qi '^cache-control: max-age=60'
    check "http2 accept-ranges + cache-control headers" $?
    # a single byte range: 206, the exact slice, content-range names it
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null -r 5-9 "$u/hello.txt")
    body=$(curl -s --http2 --cacert $CA $rl -r 5-9 "$u/hello.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 206' \
        && echo "$hdrs" | grep -qi '^content-range: bytes 5-9/18' \
        && echo "$hdrs" | grep -qi '^content-length: 5' \
        && [ "$body" = " from" ]
    check "http2 range 206 (slice + content-range)" $?
    # suffix and open-ended forms
    b1=$(curl -s --http2 --cacert $CA $rl -r -5 "$u/hello.txt")
    b2=$(curl -s --http2 --cacert $CA $rl -r 12- "$u/hello.txt")
    [ "$b1" = "nnea" ] && [ "$b2" = "innea" ]
    check "http2 range suffix + open-ended" $?
    # a large mid-file slice streams through flow control byte-exact
    python3 -c "
d = bytearray()
i = 0
while len(d) < 100000: d += (b'%07d\n' % i); i += 1
open('$WWW/h2range.bin','wb').write(d[:100000])"
    want=$(python3 -c "
import hashlib
print(hashlib.md5(open('$WWW/h2range.bin','rb').read()[25000:75000]).hexdigest())")
    got=$(curl -s --http2 --cacert $CA $rl -r 25000-74999 "$u/h2range.bin" | md5sum | cut -d' ' -f1)
    [ "$got" = "$want" ]
    check "http2 range: 50000-byte mid-file slice byte-exact" $?
    # unsatisfiable: bodiless 416 naming the actual length
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null -r 999999-1000000 "$u/hello.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 416' \
        && echo "$hdrs" | grep -qi '^content-range: bytes \*/18'
    check "http2 unsatisfiable range 416" $?
    # If-Range: strong match applies the range; a stale validator serves it all
    sc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -r 5-9 -H "If-Range: $h2etag" "$u/hello.txt")
    sc2=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -r 5-9 -H 'If-Range: "stale"' "$u/hello.txt")
    [ "$sc" = "206" ] && [ "$sc2" = "200" ]
    check "http2 if-range gates the 206" $?
    # a 304 repeats the cache policy
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null \
        -H "If-None-Match: $h2etag" "$u/hello.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 304' \
        && echo "$hdrs" | grep -qi '^cache-control: max-age=60'
    check "http2 304 repeats cache-control" $?
    # pre-compressed variants: enc.txt has both a .br and a .gz beside it
    python3 - "$WWW" <<'PY'
import gzip, sys
W = sys.argv[1]                      # the run's own document root
open(W + '/enc.txt', 'w').write('plain payload')
with gzip.open(W + '/enc.txt.gz', 'wb') as f:
    f.write(b'gzip payload')
open(W + '/enc.txt.br', 'wb').write(b'br payload')
PY
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null \
        -H 'Accept-Encoding: gzip, br' "$u/enc.txt")
    body=$(curl -s --http2 --cacert $CA $rl -H 'Accept-Encoding: gzip, br' "$u/enc.txt")
    echo "$hdrs" | grep -qi '^content-encoding: br' \
        && echo "$hdrs" | grep -qi '^vary: Accept-Encoding' \
        && [ "$body" = "br payload" ]
    check "http2 pre-compressed br preferred (+ vary)" $?
    gz=$(curl -s --http2 --compressed --cacert $CA $rl -H 'Accept-Encoding: gzip' "$u/enc.txt")
    [ "$gz" = "gzip payload" ]
    check "http2 gzip variant (curl decodes it)" $?
    body=$(curl -s --http2 --cacert $CA $rl "$u/enc.txt")
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null "$u/enc.txt")
    [ "$body" = "plain payload" ] && ! echo "$hdrs" | grep -qi '^content-encoding' \
        && echo "$hdrs" | grep -qi '^vary: Accept-Encoding'
    check "http2 no accept-encoding: plain, vary still set" $?
    # the variant's etag revalidates: 304 keeps vary, no content-encoding
    enctag=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null \
        -H 'Accept-Encoding: br' "$u/enc.txt" | grep -i '^etag:' | tr -d '\r' | cut -d' ' -f2)
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null \
        -H 'Accept-Encoding: br' -H "If-None-Match: $enctag" "$u/enc.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 304' \
        && echo "$hdrs" | grep -qi '^vary: Accept-Encoding' \
        && ! echo "$hdrs" | grep -qi '^content-encoding'
    check "http2 variant etag 304 (vary kept, coding not restated)" $?
    ver=$(curl -s -o /dev/null --http2 --cacert $CA $rl \
        -w '%{http_version}' "$u/hello.txt")
    [ "$ver" = "2" ]
    check "http2 request uses HTTP/2 (not downgraded)" $?
    ct=$(curl -s -o /dev/null --http2 --cacert $CA $rl \
        -w '%{content_type}' "$u/style.css")
    [ "$ct" = "text/css; charset=utf-8" ]
    check "http2 content-type from extension (css)" $?
    # a body larger than the initial flow-control window (100000 > 65535):
    # exercises DATA chunking and WINDOW_UPDATE-driven resumption
    n=$(curl -s --http2 --cacert $CA $rl "$u/big.txt" | wc -c)
    junk=$(curl -s --http2 --cacert $CA $rl "$u/big.txt" | tr -d 'B' | wc -c)
    [ "$n" -eq 100000 ] && [ "$junk" -eq 0 ]
    check "http2 flow control: 100000-byte body, exact + intact" $?
    # keep-alive with a Huffman-coded custom header (decoder must parse+skip)
    two=$(curl -s --http2 --cacert $CA $rl \
        -H "x-linnea-probe: a-huffman-coded-header-value-98765" \
        "$u/hello.txt" "$u/big.txt" | wc -c)
    [ "$two" -eq 100018 ]
    check "http2 keep-alive: two requests, one connection" $?
    # RFC 9218 `priority` request header (u=, i): a browser sends it on EVERY
    # request, so capturing it must not corrupt the request. It once overwrote the
    # h2 stream-id stack local, resetting the connection — every browser page blank.
    pc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'priority: u=3, i' "$u/big.txt")
    [ "$pc" = "200" ]
    check "http2 priority header served (RFC 9218, no stream-id corruption)" $?
    # HPACK dynamic table: a client may index into its own table before it
    # has processed our SETTINGS(HEADER_TABLE_SIZE=0), and does exactly that
    # when it opens several streams at once. Without a decoder-side table
    # those references cost a GOAWAY and every in-flight request with it, so
    # hammer the case: six parallel streams on a fresh connection, repeatedly.
    hpack_fail=0
    for _ in 1 2 3 4 5 6 7 8; do
        codes=$(timeout 15 curl -s --http2 --cacert $CA $rl --parallel -w '%{http_code}\n' \
            -o /dev/null "$u/hello.txt" -o /dev/null "$u/index.html" \
            -o /dev/null "$u/style.css" -o /dev/null "$u/hello.txt" \
            -o /dev/null "$u/index.html" -o /dev/null "$u/style.css" 2>/dev/null)
        [ "$(echo "$codes" | grep -c '^200$')" -eq 6 ] || hpack_fail=$((hpack_fail + 1))
    done
    [ "$hpack_fail" -eq 0 ]
    check "http2 HPACK dynamic table (8x six parallel streams)" $?

    # a full browser-like header set (many headers, incl. priority + sec-fetch-*)
    bc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'user-agent: Mozilla/5.0 Firefox/128.0' -H 'accept: text/html,*/*' \
        -H 'accept-language: en-US' -H 'accept-encoding: gzip, br' \
        -H 'priority: u=0, i' -H 'sec-fetch-dest: document' \
        -H 'sec-fetch-mode: navigate' -H 'te: trailers' "$u/hello.txt")
    [ "$bc" = "200" ]
    check "http2 browser-like header set served" $?
    # several resources multiplexed on one connection (a page load), each with a
    # priority header, all 200 (per-URL -o so bodies do not leak into -w output)
    mpd=$(mktemp -d)
    mc=$(curl -s --http2 --cacert $CA $rl --parallel -H 'priority: u=3, i' \
        -w '%{http_code}\n' \
        "$u/hello.txt" -o "$mpd/a" \
        "$u/big.txt" -o "$mpd/b" \
        "$u/style.css" -o "$mpd/c" | sort -u | tr -d '\n')
    rm -rf "$mpd"
    [ "$mc" = "200" ]
    check "http2 concurrent multiplexed requests with priority (page load)" $?
    # HEAD: headers only, no body
    hb=$(curl -s --http2 -I --cacert $CA $rl "$u/hello.txt" | grep -ci .)
    hd=$(curl -s --http2 -I --cacert $CA $rl "$u/hello.txt" | grep -qi 'content-length: 18' && echo ok)
    [ "$hd" = "ok" ]
    check "http2 HEAD: headers with content-length, no body" $?
    # a directory maps to index.html
    dc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' "$u/")
    [ "$dc" = "200" ]
    check "http2 directory serves index.html" $?
    # missing file -> 404, disallowed method -> 405
    c404=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' "$u/nope.txt")
    c405=$(curl -s -o /dev/null --http2 --cacert $CA $rl -X DELETE -w '%{http_code}' "$u/hello.txt")
    [ "$c404" = "404" ] && [ "$c405" = "405" ]
    check "http2 error statuses (404 missing, 405 method)" $?
    # path traversal above the root is refused
    ct400=$(curl -s -o /dev/null --http2 --cacert $CA $rl --path-as-is \
        -w '%{http_code}' "$u/../../../etc/passwd")
    [ "$ct400" = "400" ]
    check "http2 path traversal refused (400)" $?

    # M18: multiplexing — concurrent streams with interleaved DATA, the
    # rapid-reset (CVE-2023-44487) defense, and stream-pool exhaustion.
    if extensive; then
        timeout 30 python3 test/tls/h2_multiplex.py $CA ${P61446} >/dev/null 2>&1
        check "http2 multiplexing (concurrent streams, rapid-reset, pool cap)" $?
    else
        skip "http2 multiplexing (concurrent streams, rapid-reset, pool cap) -- 25s"
    fi

    # A whole docroot over ONE connection, every body compared to the file:
    # the ordinary case a browser performs and the one no other h2 test did.
    # It is what caught the round-robin cursor wrapping with a power-of-two
    # mask — raise MAX_STREAMS to anything else and most slots became
    # unreachable, so their streams were accepted, logged 200, and never sent
    # a byte. The single-stream and six-stream tests all passed throughout.
    out=$(timeout 90 python3 test/tls/h2_page_load.py $CA ${P61446} $WWW 2>&1)
    case "$out" in ok*) true ;; *) false ;; esac
    check "http2 page load: every body byte-exact ($out)" $?

    # RFC 9218 scheduling, the same policy h3's pump applies: the default
    # priority is NON-incremental, so concurrent responses complete one at a
    # time in arrival order; u=0 jumps the queue; i opts back in to sharing the
    # window. h2 parsed the priority field and then ignored it entirely.
    timeout 200 python3 test/tls/h2_priority.py $CA ${P61446} >/dev/null 2>&1
    check "http2 responses scheduled by RFC 9218 priority" $?

    # M19: fuzz the frame layer and HPACK decoder — malformed streams must
    # never crash the worker; a live h2 GET still serves between batches.
    # 150s, not 60: since unknown frame types are discarded rather than drawing
    # a GOAWAY (RFC 9113 4.1), the server no longer ends a fuzzed connection
    # early, so the client waits out its own timeout on more cases. The run is
    # slower by design — it measures ~80s — and a crash still shows as a
    # non-zero exit rather than as the timeout.
    if extensive; then
        timeout 150 python3 test/tls/fuzz_h2.py $CA ${P61446} 120 >/dev/null 2>&1
        check "http2 fuzz (malformed frames + HPACK survive, server serves)" $?
    else
        skip "http2 fuzz (malformed frames + HPACK survive) -- 78s, slow BY DESIGN per its own comment"
    fi

    # M20: strict stream-id validation + honouring SETTINGS_INITIAL_WINDOW_SIZE.
    # A connection error must carry the code RFC 9113 names for it. Every fault
    # reported PROTOCOL_ERROR, because the reason was never threaded through to
    # the single site that writes the GOAWAY.
    timeout 30 python3 test/tls/h2_error_codes.py $CA ${P61446} >/dev/null 2>&1
    check "http2 connection errors carry the RFC's code" $?

    # RFC 9113 8.1.1: content-length must equal the sum of the DATA payloads.
    # An over-long body was already refused; one that stopped SHORT was not
    # noticed at all — the request sat holding an upstream slot until the body
    # clock timed it out, reporting a timeout for a framing fault visible at
    # once. Runs against the proxy vhost, which is where bodies go.
    timeout 60 python3 test/tls/h2_content_length.py $CA ${P61443} >/dev/null 2>&1
    check "http2 content-length is reconciled with the DATA sent" $?

    timeout 20 python3 test/tls/h2_conformance.py $CA ${P61446} >/dev/null 2>&1
    check "http2 conformance (stream-id rules, initial window size)" $?

    # A biggish cookie load (4.8 KB) fits the Q121 limits and must be SERVED —
    # whole, not with the overflowing fields silently dropped (the Q100 bug),
    # and certainly not by killing the connection (the pre-Q121 behaviour).
    bigck=$(python3 -c "print('a'*4800)")
    code=$(timeout 10 curl -s -o /dev/null -w '%{http_code}' --http2 --cacert $CA \
        --resolve localhost:${P61446}:127.0.0.1 -H "Cookie: $bigck" \
        https://localhost:${P61446}/hello.txt 2>/dev/null)
    [ "$code" = 200 ]
    check "http2 big-but-legal cookie served (fits the raised limits)" $?

    # Q121: an oversized header block answers the stream 431 (the connection
    # survives and keeps serving), and SETTINGS advertises the real
    # MAX_HEADER_LIST_SIZE so clients can trim before hitting it.
    timeout 30 python3 test/tls/h2_big_headers.py $CA ${P61446} >/dev/null 2>&1
    check "http2 oversized header block: stream 431, connection survives" $?

    # wrong-length PING / WINDOW_UPDATE are a connection error, not an over-read
    # (a zero-length PING used to echo 8 stale in_buf bytes to the peer)
    timeout 20 python3 test/tls/h2_frame_size.py $CA ${P61446} >/dev/null 2>&1
    check "http2 control-frame size validated (no PING over-read/echo)" $?

    kill $h2_pid 2>/dev/null
    wait $h2_pid 2>/dev/null
    # (h2 graceful drain — GOAWAY(last-stream) then finish open streams — is
    # exercised by test/tls/h2_drain.py against a running worker; it is not in
    # the automated suite because reliably retiring one worker of a forked
    # multi-process server without the master's supervision reaping the
    # draining worker is timing-fragile. The hot-upgrade path keeps other
    # workers alive, so old workers drain cleanly there.)

    # This used to go red in full runs and was put down to suite STATE. It was
    # not: the test itself refused a prompt server. It pushes 8000 bytes at a
    # server that rejects the record on its 5-byte header, so the reset lands
    # while sendall is still writing, and only the recv was wrapped to expect
    # it — measured at ~10-20% under load, on this code and on the code before
    # it. Fixed in the test. The probe below stays, because the one failure
    # worth chasing is still the same one: on failure ask the same server for
    # an ordinary page — if that answers, the server is healthy and the 2s
    # reply deadline was simply missed; if it does not, a worker is wedged.
    timeout 30 python3 test/tls/oversized_record.py $CA ${P61443} \
        test/tls/clienthello_seed.bin >/dev/null 2>&1
    ovr_rc=$?
    if [ $ovr_rc -ne 0 ]; then
        ovr_probe=$(timeout 5 curl -s -o /dev/null -w '%{http_code}' --cacert $CA \
            --resolve localhost:${P61443}:127.0.0.1 https://localhost:${P61443}/hello.txt 2>&1)
        echo "  (oversized-record failed; the same server answers /hello.txt with: ${ovr_probe:-nothing})"
    fi
    [ $ovr_rc -eq 0 ]
    check "tls oversized record refused (msg_buf bound)" $?

    # Q125: a ClientHello split across records must still complete. A
    # handshake message is a byte stream carried by records, so a client may
    # fragment it at will — and one over 2^14 bytes has no choice. Every
    # fragmented hello used to draw a fatal alert.
    timeout 60 python3 test/tls/fragmented_ch.py ${P61443} >/dev/null 2>&1
    check "tls fragmented ClientHello completes the handshake" $?

    # Records pipelined behind the Finished, including one split the way an
    # MSS boundary would split it — the case loopback never produces.
    timeout 40 python3 test/tls/pipelined_early.py $CA ${P61443} >/dev/null 2>&1
    check "tls pipelined early records (whole and split)" $?

    # A tunnelled upgrade over TLS: the tunnel has its own recv path, so it
    # needs the close_notify handling too, and the relay must stay blind to
    # the fact that the kernel is encrypting underneath it.
    timeout 10 python3 - "$CA" ${P61443} <<'PYEOF' >/dev/null 2>&1
import base64, os, socket, ssl, sys
ctx = ssl.create_default_context(cafile=sys.argv[1])
raw = socket.create_connection(("localhost", int(sys.argv[2])), timeout=5)
s = ctx.wrap_socket(raw, server_hostname="localhost")
key = base64.b64encode(os.urandom(16)).decode()
s.sendall(f"GET /api/ws-echo HTTP/1.1\r\nHost: localhost\r\n"
          f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
          f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
resp = b""
while b"\r\n\r\n" not in resp:
    d = s.recv(4096)
    assert d, "closed before the 101"
    resp += d
assert b"101 Switching Protocols" in resp, resp[:60]
s.sendall(b"tunnel-bytes-over-tls")          # linnea never parses frames
assert s.recv(64) == b"tunnel-bytes-over-tls"
s.close()
PYEOF
    check "tls websocket tunnel (101 + blind relay)" $?

    # RST_STREAM must crash no worker: resetting a proxied stream whose upstream
    # is live and in flight (h2p_kill closing it with a syscall), and RST on
    # stream 0 (a connection error, not a lookup that re-frees a reaped slot).
    if extensive; then
        prst_before=$(workers_of $tls_server_pid)
        timeout 60 python3 test/tls/h2_proxy_rst.py $CA ${P61443} >/dev/null 2>&1
        sleep 0.5
        resp=$(curl -si --http2 --max-time 5 --cacert $CA $U/hello.txt)
        prst_after=$(workers_of $tls_server_pid)
        [ -n "$prst_before" ] && [ "$prst_before" = "$prst_after" ] \
            && printf '%s' "$resp" | grep -qF "hello from linnea"
        check "http2 proxied-stream RST + RST-stream-0 crash no worker" $?
    else
        skip "http2 proxied-stream RST + RST-stream-0 crash no worker -- 25s"
    fi

    # Q124: the authority rules — :authority is h2's Host, and a duplicate,
    # a Host contradicting it, a misplaced pseudo-header or a missing
    # authority must fail THAT STREAM (the connection keeps serving), while
    # a Host standing in for :authority still works.
    timeout 90 python3 test/tls/h2_authority.py $CA ${P61443} >/dev/null 2>&1
    check "http2 authority rules (stream errors, connection survives)" $?

    # RFC 9113 5.1.1: a client's stream id is odd and above the floor, and
    # breaking either is a CONNECTION error. Both were checked AFTER the
    # malformed-request tests, so a malformed request on an even id drew only a
    # stream reset and stamped the floor with an even number. The last case
    # guards the other side: a malformed request on a VALID id must still fail
    # only its stream.
    timeout 60 python3 test/tls/h2_stream_id.py $CA ${P61443} >/dev/null 2>&1
    check "http2 stream-id rules are connection errors" $?

    # A GOAWAY must name the highest stream we might have acted on (RFC 9113 6.8).
    # Every error GOAWAY said 0 — "nothing was processed" — so a client would
    # retry everything in flight, including a proxied POST already executed.
    timeout 60 python3 test/tls/h2_goaway_last_stream.py $CA ${P61443} >/dev/null 2>&1
    check "http2 GOAWAY names the last processed stream" $?

    # Inline error bodies are flow-controlled too (RFC 9113 6.9.1). They were
    # written straight at the out cursor and charged against nothing, so a peer
    # advertising a zero window was sent one anyway, and the server's idea of the
    # connection window drifted above the peer's by every error body it had sent.
    if extensive; then
        timeout 120 python3 test/tls/h2_error_flow_control.py $CA ${P61443} >/dev/null 2>&1
        check "http2 error bodies respect the flow-control window" $?
    else
        skip "http2 error bodies respect the flow-control window -- 18s"
    fi

    # Request-field rules the shared HPACK/QPACK decoder enforces: :scheme must
    # be present, :path must not be empty, connection-specific fields are
    # malformed (TE only for "trailers"), a space may not sit in a field name and
    # a value may not begin or end with whitespace (RFC 9113 8.2-8.3).
    timeout 60 python3 test/tls/h2_field_rules.py $CA ${P61443} >/dev/null 2>&1
    check "http2 request field rules" $?

    # A trailer section is allowed (RFC 9113 8.1) and used to draw a GOAWAY: its
    # stream id is one already seen, which the strictly-increasing test called
    # broken numbering, taking every concurrent stream down with it. The last
    # case checks the subtle half — the trailer's fields are decoded even though
    # unused, or HPACK's connection-wide table falls out of step.
    timeout 60 python3 test/tls/h2_trailers.py $CA ${P61443} >/dev/null 2>&1
    check "http2 trailer sections do not kill the connection" $?

    # Every TLS connection must end with close_notify (RFC 8446 6.1) or the peer
    # cannot tell a finished response from a cut one. The alert may only be
    # written where no other send is outstanding, so the cases after a large
    # response and after h2 traffic are the ones that matter.
    timeout 90 python3 test/tls/close_notify.py $CA ${P61443} >/dev/null 2>&1
    check "tls connections end with close_notify" $?


    # HPACK is stateful, so a block we REJECT must still be walked to its end:
    # the inserts after the offending field reach the peer's dynamic table
    # whether we like the request or not. Stopping early left our table behind
    # the peer's, and a later request referencing a dynamic index then decoded
    # against the wrong entry — the probe sees a 'range' header from the
    # rejected request applied to a later one, turning its 200 into a 206.
    timeout 30 python3 test/tls/hpack_sync.py $CA ${P61443} >/dev/null 2>&1
    check "http2 HPACK table stays in sync across a rejected block" $?

    # ...and across the arena's wrap. The arena was a bump allocator that
    # reclaimed only when the table emptied, so an entry landing at the end was
    # silently not stored while the peer DID store it — leaving our table an
    # entry behind and every later dynamic index resolving to the wrong header.
    timeout 240 python3 test/tls/hpack_arena.py $CA ${P61443} >/dev/null 2>&1
    check "http2 HPACK entries survive the arena wrapping" $?

    # We advertise HEADER_TABLE_SIZE 4096, so the table is load-bearing for real
    # traffic rather than dead state: this drives eviction from "drop one" to
    # "drop everything", the entry-slot ceiling, size updates down to 0 and back,
    # and reads back a marker by dynamic index after every phase.
    if extensive; then
        timeout 400 python3 test/tls/hpack_stress.py $CA ${P61443} >/dev/null 2>&1
        check "http2 HPACK dynamic table under sustained use" $?
    else
        skip "http2 HPACK dynamic table under sustained use -- 34s, a soak"
    fi

    # Q130: h2/h3 read a SEPARATE mime table from h1's, so the types are
    # checked here too — a type added to one table only is the easy mistake.
    printf 'x' > $WWW/probe.wasm
    ct=$(timeout 10 curl -s -D - -o /dev/null --http2 --cacert $CA \
        --resolve localhost:${P61443}:127.0.0.1 https://localhost:${P61443}/probe.wasm \
        | grep -i '^content-type' | tr -d '\r')
    printf '%s' "$ct" | grep -qF "application/wasm"
    check "http2 mime table has the same types (.wasm)" $?

    # RFC 9110 15.5.6: a 405 must name what the resource does take. h1 always
    # sent Allow; h2 sent none, so a client could not tell what to retry with.
    al=$(timeout 10 curl -si --http2 --cacert $CA \
        --resolve localhost:${P61443}:127.0.0.1 -X PROPFIND \
        https://localhost:${P61443}/hello.txt | tr -d '\r')
    printf '%s' "$al" | grep -q "405" && printf '%s' "$al" | grep -qi "^allow: GET, HEAD"
    check "http2 405 carries Allow: GET, HEAD" $?
    # and nothing else claims to: a 200 and a 404 carry no allow
    for u in /hello.txt /nope.txt; do
        n=$(timeout 10 curl -si --http2 --cacert $CA \
            --resolve localhost:${P61443}:127.0.0.1 https://localhost:${P61443}$u \
            | tr -d '\r' | grep -ci "^allow:")
        [ "$n" -eq 0 ]
        check "http2 no Allow on a normal response ($u)" $?
    done
    rm -f $WWW/probe.wasm

    # Q120: h2 requests reach the access log — static and proxied alike, in
    # h1's exact format. Before this only h1 was logged, so most real browser
    # traffic was invisible.
    # checked separately: as one AND-ed grep a red run could not say which
    # half was missing, and the static and proxied lines are emitted by
    # different code (h2_serve's funnel vs h2p_finish_stream).
    grep -qE 'request localhost from [0-9.:]+ "GET /hello.txt HTTP/2" 200 ' "$LOG"
    check "http2 static request access-logged" $?
    grep -qE '"GET /api/simple HTTP/2" 200 ' "$LOG"
    check "http2 proxied request access-logged" $?

    # h2-14: a GOAWAY from the client announces it will open no NEW streams; the
    # ones already running still have to be finished (RFC 9113 6.8). Closing on
    # receipt threw away a response that was already in flight.
    timeout 30 python3 test/tls/h2_goaway_inflight.py $CA ${P61443} >/dev/null 2>&1
    check "http2 client GOAWAY still finishes the in-flight response" $?

    # h2-16 receive-window accounting: a request body costs the client both its
    # stream and its connection flow-control window, and neither refills on its
    # own. A body larger than the 65535-byte initial window therefore only
    # completes if we credit the bytes back as WINDOW_UPDATE on the stream AND on
    # stream 0 as they go upstream (h2p rq_credit). 300000 bytes needs the credit
    # to keep coming ~5 times over, so a client that stops after one window — or a
    # server that only credits the connection — hangs here rather than mismatching.
    # The h1 upload case above covers the same relay over HTTP/1.1, which has no
    # flow control, so this is the only place the h2 windows are exercised.
    python3 -c "
import random
random.seed(12)
open('$WWW/h2upload.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
    want=$(md5sum < $WWW/h2upload.bin | cut -d' ' -f1)
    curl -s --http2 --max-time 30 --cacert $CA --data-binary @$WWW/h2upload.bin \
        $U/api/echo > $RUNDIR/h2upload_echo.bin
    [ "$(md5sum < $RUNDIR/h2upload_echo.bin | cut -d' ' -f1)" = "$want" ]
    check "http2 carries a 300000-byte request body past the flow-control window" $?
    rm -f $RUNDIR/h2upload_echo.bin $WWW/h2upload.bin

    # ...and what that check structurally cannot see: how many ROUND TRIPS the
    # body costs. It passed, byte-exact, while the server advertised no
    # SETTINGS_INITIAL_WINDOW_SIZE and credited 16 KiB at a time — 16 KiB per
    # RTT, invisible on loopback and 546 KB/s from a laptop. The round-trip
    # count is a property of the flow-control policy alone, so it reads the
    # same here as it would over a real network.
    timeout 90 python3 test/tls/h2_upload_window.py $CA ${P61443} >/dev/null 2>&1
    check "http2 upload: window advertised, credit batched, round trips bounded" $?
    # THE PEER'S FRAMING MUST NOT CHANGE WHAT ITS UPLOAD COSTS. The same 16 MB at
    # two frame sizes 64x apart, against the SAME grant bound: h2's thresholds are
    # both cumulative (the spill gate is the running body total, the credit gate
    # accumulated bytes), so 64 stream grants is 16 MB / 256 KiB either way. If
    # credit ever goes back to per-frame the 256-byte run misses by 64x while the
    # 16 KiB one still passes, which is the shape of the fault h3 shipped: a rule
    # keyed on a FRAME's size gave Chrome 2.9 MB/s and Firefox 440 kB/s.
    #
    # Loopback sees no stall at either size (credit returns before a 4 MiB window
    # can be spent), so the round-trip metric above is blind to this and the grant
    # COUNT is what discriminates. Bound 200 against 129 measured.
    for h2f in 16384 256; do
        out=$(timeout 120 python3 test/tls/h2_upload_window.py $CA ${P61443} 16777216 $h2f --max-grants 200 2>&1)
        check "http2 upload: credit cost is flat at ${h2f}-byte frames ($out)" $?
    done

    # Uploads one after another on ONE connection. The streaming buffer's
    # claim (conn.h2_upload) was released by the service pass but TESTED when
    # the next request head was parsed, so the second upload saw a claim whose
    # owner had finished, fell back to the bounded collect path, and was
    # refused 413 at LINNEA_H2P_BODY_MAX — 8 KiB — however large max_body was.
    # Dead alternation: 200 413 200 413. Every existing upload check used a
    # fresh connection, so none of them could see it.
    # Both the buffer and its claim are gone now (every body is captured), so
    # this guards the shape rather than the mechanism: several uploads down one
    # connection must all come back 200, whatever is carrying them.
    # The local_port comparison is load-bearing: if curl ever stopped reusing
    # the connection this would pass while testing nothing.
    python3 -c "open('$WWW/h2seq.bin','wb').write(b'S'*100000)"
    u3=$(curl -s --http2 --cacert $CA -H "Expect:" --max-time 30 \
            -X POST --data-binary @$WWW/h2seq.bin -w '%{http_code}:%{local_port} ' -o /dev/null $U/api/echo \
         --next -s --http2 --cacert $CA -H "Expect:" \
            -X POST --data-binary @$WWW/h2seq.bin -w '%{http_code}:%{local_port} ' -o /dev/null $U/api/echo \
         --next -s --http2 --cacert $CA -H "Expect:" \
            -X POST --data-binary @$WWW/h2seq.bin -w '%{http_code}:%{local_port}' -o /dev/null $U/api/echo)
    u3codes=$(echo "$u3" | tr ' ' '\n' | cut -d: -f1 | tr '\n' ' ')
    u3conns=$(echo "$u3" | tr ' ' '\n' | cut -d: -f2 | sort -u | grep -c .)
    [ "$u3codes" = "200 200 200 " ] && [ "$u3conns" -eq 1 ]
    check "http2: three uploads in a row on one connection all stream ($u3codes on $u3conns conn)" $?
    rm -f $WWW/h2seq.bin

    # Body-phase slowloris (Q119): head_timeout used to stop at the request
    # head, so a client trickling a proxied request body — or sitting silent
    # on an h2 upload, dodging the idle timeout — held its upstream slot
    # forever. The body clock (LINNEA_BODY_NS_PER_BYTE per received byte) cuts
    # a trickler about head_timeout after its last honest burst: h1 closes,
    # h2 fails the stream 408 and the connection and slot live on. A
    # full-speed upload must be untouched. Own server: head_timeout=3.
    start_server $CFG/tls-slowbody.json
    P61457=$SRV_PORT
    slowbody_pid=$SRV_PID
    sleep 0.3
    timeout 60 python3 test/tls/slow_body.py $CA ${P61457} >/dev/null 2>&1
    check "request-body slowloris cut on h1 and h2; honest uploads untouched" $?
    kill $slowbody_pid 2>/dev/null
    wait $slowbody_pid 2>/dev/null

    # --- HTTP/3 through an INDEPENDENT implementation -----------------------
    # Every other h3 check in this file drives aioquic. If linnea and aioquic
    # share a misreading of RFC 9114, that agreement looks exactly like
    # correctness and nothing here can tell. curl built against ngtcp2 +
    # nghttp3 shares no code with either, so where the two agree the reading is
    # very unlikely to be wrong.
    #
    # Optional, like the aioquic checks: skipped when the binary is absent, so
    # a clean checkout still passes. Build one with
    #   ./configure --with-ngtcp2 --with-nghttp3 --prefix=$HOME/curl-h3
    # and point LINNEA_CURL_H3 at it, or leave it at the default path.
    #
    # --http3-only, never --http3: the latter falls back to h2 when h3 fails,
    # which would let a broken h3 pass every check below.
    CURLH3=${LINNEA_CURL_H3:-$HOME/curl-h3/bin/curl}
    if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
        h3o="--http3-only -s --max-time 25 --cacert $CA"
        h3r="--resolve localhost:${P61443}:127.0.0.1"

        # big.txt, not hello.txt: 100000 bytes is many packets, so this covers
        # stream reassembly and flow control rather than one lucky datagram.
        "$CURLH3" $h3o $h3r -o $RUNDIR/h3big.out $U/big.txt
        curl -s --http2 --max-time 10 --cacert $CA -o $RUNDIR/h2big.out $U/big.txt
        [ -s $RUNDIR/h3big.out ] && cmp -s $RUNDIR/h3big.out $RUNDIR/h2big.out
        check "h3 (ngtcp2): a 100000-byte file is byte-identical to h2's copy" $?
        rm -f $RUNDIR/h3big.out $RUNDIR/h2big.out

        # h3 could not express a redirect at all until it could emit Location
        # (QPACK static index 12); before that a vhost with one was kept off h3
        # entirely, so this is also the check that the vhost HAS a listener.
        l3=$("$CURLH3" $h3o $h3r -o /dev/null -D - "$U/old/page?x=1" \
             | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
        l1=$(curl -s --http1.1 --max-time 10 --cacert $CA -o /dev/null -D - \
             "$U/old/page?x=1" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
        [ -n "$l3" ] && [ "$l3" = "$l1" ]
        check "h3 redirect: Location matches h1 exactly ($l3)" $?

        s3=$("$CURLH3" $h3o $h3r -o /dev/null -w '%{http_code}' "$U/old/page?x=1")
        [ "$s3" = "301" ]
        check "h3 redirect: 301 over QUIC ($s3)" $?

        # an upload over h3, which is the capture path rather than the FIFO
        python3 -c "
import random, sys
random.seed(23)
open(sys.argv[1],'wb').write(bytes(random.getrandbits(8) for _ in range(300000)))" "$WWW/h3up.bin"
        "$CURLH3" $h3o $h3r -o $RUNDIR/h3up.out -X POST \
            --data-binary @$WWW/h3up.bin $U/api/echo
        [ -s $RUNDIR/h3up.out ] &&
        [ "$(md5sum < $RUNDIR/h3up.out | cut -d' ' -f1)" = \
          "$(md5sum < $WWW/h3up.bin | cut -d' ' -f1)" ]
        check "h3 (ngtcp2): a 300000-byte upload round-trips byte-exact" $?
        rm -f $WWW/h3up.bin $RUNDIR/h3up.out

        m3=$("$CURLH3" $h3o $h3r -o /dev/null -w '%{http_code}' $U/nope.txt)
        [ "$m3" = "404" ]
        check "h3 (ngtcp2): a missing file is 404, not a hang ($m3)" $?
    else
        check "h3 via an independent client (skipped: no HTTP/3 curl — see the note above)" 0
    fi

    kill $tls_server_pid $tls_backend_pid 2>/dev/null
    wait $tls_server_pid 2>/dev/null
    wait $tls_backend_pid 2>/dev/null
    rm -f "$LOG" $WWW/big.txt
fi   # end region 2


    # --- SNI: two TLS vhosts share 127.0.0.1:61444, each with its own cert
    start_server $CFG/tls-sni.json
    sni_server_pid=$SRV_PID
    sleep 0.3
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -servername sni.test 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=sni.test"
    check "sni selects the named vhost cert" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -servername localhost 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "sni selects the owner cert by name" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -noservername 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "no sni falls back to the listener owner" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -servername unknown.test 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "unknown sni falls back to the listener owner" $?
    # the SAME must hold over HTTP/3: the QUIC listener on this port registers both
    # vhosts, and the ClientHello SNI selects the certificate (before this, h3 always
    # served the first vhost's cert, so a second name got the wrong one).
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        python3 test/quic/h3_sni_cert_test.py ${P61444} sni.test sni.test >/dev/null 2>&1
        check "h3 sni selects the named vhost cert" $?
        python3 test/quic/h3_sni_cert_test.py ${P61444} localhost localhost >/dev/null 2>&1
        check "h3 sni selects the owner cert by name" $?
    fi
    # every h3 vhost advertises Alt-Svc, not only the socket owner, so each origin
    # tells its own clients they can switch to h3 (a non-owner vhost is checked).
    curl -s -D - -o /dev/null --http2 --cacert test/tls/sni.crt \
        --resolve sni.test:${P61444}:127.0.0.1 https://sni.test:${P61444}/page.html \
        | grep -qi 'alt-svc: h3='
    check "h3 alt-svc advertised by a non-owner vhost" $?
    # h2 is on by default (tls-sni.json sets no "http2" key): a static vhost
    # negotiates h2.
    echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} -CAfile test/tls/sni.crt \
        -servername sni.test -tls1_3 -alpn h2,http/1.1 2>/dev/null \
        | grep -q "ALPN protocol: h2"
    check "alpn: h2 on by default (static vhost)" $?
    # a full request via the SNI vhost: curl verifies against the sni.test
    # cert AND the Host routing must land on the sni.test docroot (which
    # holds page.html; the listener owner does not). h2 is on by default now,
    # so this also exercises SNI vhost routing over HTTP/2.
    resp=$(curl -s --max-time 5 --cacert test/tls/sni.crt \
        --resolve sni.test:${P61444}:127.0.0.1 https://sni.test:${P61444}/page.html)
    check_http "sni end to end (cert + vhost routing)" "subdirectory page" "$resp"

    # Q126: h2 answers only for names the certificate it presented covers —
    # the rule h3 got in Q124. A cross-certificate request gets 421, a name
    # we do not host is served by the connection's own vhost, and two vhosts
    # sharing ONE certificate still coalesce onto a single connection. The
    # worker-PID check is not ceremony: the first version of this crashed the
    # worker (the 421 path skipped the vhost the response builder reads), and
    # a crash looks exactly like a closed connection from the client side.
    start_server $CFG/tls-coalesce.json
    coal_h2_pid=$SRV_PID
    sleep 0.4
    md_before=$(workers_of $sni_server_pid)
    timeout 60 python3 test/tls/h2_misdirected.py $CA ${P61444} ${P61459} >/dev/null 2>&1
    md_rc=$?
    md_after=$(workers_of $sni_server_pid)
    [ "$md_rc" -eq 0 ] && [ -n "$md_before" ] && [ "$md_before" = "$md_after" ]
    check "http2 misdirected request: 421 across certs, coalescing kept" $?
    kill $coal_h2_pid 2>/dev/null
    wait $coal_h2_pid 2>/dev/null

    # Q124: h3 honours :authority instead of serving whatever the TLS SNI
    # chose, and answers a name this connection's certificate does not cover
    # with 421 rather than the other vhost's page.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        timeout 90 python3 test/quic/h3_authority_test.py ${P61444} >/dev/null 2>&1
        check "h3 authority selects the vhost; cross-cert gets 421" $?
    else
        check "h3 authority test (skipped: deps unavailable)" 0
    fi

    # ...and the other side of that strictness: two vhosts sharing ONE
    # certificate are both names the connection can speak for, so a single
    # h3 connection serves both (what a browser coalesces). Own server: the
    # two vhosts differ from the SNI pair in using the same cert.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        start_server $CFG/tls-coalesce.json
        coal_pid=$SRV_PID
        sleep 0.4
        timeout 60 python3 test/quic/h3_coalesce_test.py ${P61459} >/dev/null 2>&1
        check "h3 coalescing: one cert, two vhosts, one connection" $?
        kill $coal_pid 2>/dev/null
        wait $coal_pid 2>/dev/null
    else
        check "h3 coalescing test (skipped: deps unavailable)" 0
    fi
    kill $sni_server_pid 2>/dev/null
    wait $sni_server_pid 2>/dev/null
    rm -f "$LOG"
