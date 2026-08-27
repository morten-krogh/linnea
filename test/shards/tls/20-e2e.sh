# TLS end to end through the real server: the userspace handshake hands off
# to kTLS and the rest is the ordinary HTTP path over a kernel-encrypted
# socket. The kTLS-availability guard is a $ktls flag so the fixtures below
# (h3 proxy, http2, slow body) can live in their own files; each gates on it.

# --- TLS end to end: the real server, handshake in userspace then kTLS ---
# Everything past the handshake is the ordinary HTTP path over a socket the
# kernel encrypts, so these tests are really asking whether the handoff left
# the connection indistinguishable from a plaintext one.
if grep -qw tls /proc/sys/net/ipv4/tcp_available_ulp 2>/dev/null; then
    ktls=1
else
    ktls=0
    check "tls e2e (kernel tls module not loaded: modprobe tls — skipped)" 0
fi
if [ "$ktls" = 1 ]; then
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

    # --- a UNIX-socket backend, driven by all three CLIENT protocols ---------
    # h2 and h3 clients are served through the h2p leg since e78b131, whatever
    # the backend speaks, so they reach a backend socket by a DIFFERENT path
    # than an h1 client does. The unix: rows in the h1 shard drive h1 only, so
    # nothing pinned the other two -- the shape upstream_failover.py's own
    # header warns about: "h2 and h3 passed without executing a line of the
    # paths they were meant to cover".
    usock2="$PWD/$RUNDIR/tls-be.sock"
    LINNEA_BACKEND_UNIX="$usock2" python3 test/proxy_backend.py >/dev/null 2>&1 &
    ub2_pid=$!
    for _ in $(seq 1 50); do [ -S "$usock2" ] && break; sleep 0.1; done
    cat > $CFG/tls-unix.json <<EOF
{ "log": "$PWD/$RUNDIR/tls-unix.log",
  "servers": [ { "host": "127.0.0.1", "port": ${P61734}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/api", "proxy": "unix:$usock2" },
                   { "prefix": "/", "root": "$PWD/$WWW" } ] } ] }
EOF
    start_server $CFG/tls-unix.json
    UU=https://localhost:${P61734}
    for proto in --http1.1 --http2; do
        body=$(curl -s $proto --max-time 8 --cacert $CA $UU/api/simple)
        [ "$body" = "backend body" ]
        check "unix backend over TLS: a ${proto#--} client is served" $?
    done
    if [ -n "$CURLH3" ] && [ -x "$CURLH3" ]; then
        body=$("$CURLH3" -s --http3-only --max-time 10 --cacert $CA $UU/api/simple)
        [ "$body" = "backend body" ]
        check "unix backend over TLS: an h3 client is served" $?
    fi
    # nothing may have fallen back to a TCP connect: there is no TCP backend
    ! grep -q "connect failed" "$RUNDIR/tls-unix.log" 2>/dev/null
    check "unix backend over TLS: no connect failed on any leg" $?
    kill $ub2_pid 2>/dev/null

    # If-Match and If-None-Match are entity-tag LISTS, so repeated field lines
    # are the comma-joined value (RFC 9110 5.3). h1 kept the FIRST occurrence
    # and h2/h3 the LAST, so the same legal request got different answers from
    # each protocol and reversing the client's two lines swapped which was
    # right (audit-report-30). Driven across all three, because "they agree"
    # is half of what was wrong.
    h3arg=""
    if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
        h3arg="$CURLH3"
    fi
    out=$(timeout 90 python3 test/tls/etag_list_lines.py ${P61443} $CA $h3arg 2>&1)
    rc=$?
    first_fail=$(echo "$out" | grep -m1 FAIL)
    [ $rc -eq 0 ]
    check "repeated If-Match/If-None-Match lines are one list on every protocol ${first_fail}" $?

    # ...and the fields beside them, which divide the other way: the singleton
    # conditionals (one date, validator or range each) refuse a repeat on all
    # three, while Accept-Encoding combines its lines on all three
    # (audit-report-32). h1 kept the first and h2/h3 the last for both kinds,
    # so one request served different bytes depending on the protocol.
    printf 'plain payload' > $WWW/aetest.txt
    printf 'br payload' > $WWW/aetest.txt.br
    # a second coding, so the wildcard rows can tell "any coding will do" from
    # "the only one there is": with both present, `Accept-Encoding: *` has to
    # land on the one this server prefers (audit-report-36).
    printf 'gz payload' > $WWW/aetest.txt.gz
    # ...and a resource with gzip but no br, so the wildcard is seen reaching a
    # coding that is not simply the first one tried.
    printf 'plain only' > $WWW/gztest.txt
    printf 'gz only' > $WWW/gztest.txt.gz
    # A precompressed variant OLDER than its source must not be served: the two
    # forms of one URL would carry different bodies, each with its own
    # self-consistent validator, and a cache would hold both. The sleep is
    # load-bearing -- the check compares mtimes, and files written in the same
    # second would be indistinguishable.
    printf 'STALE-VARIANT' > $WWW/stale.txt.br
    printf 'FRESH-SOURCE' > $WWW/fresh.txt
    sleep 1.1
    printf 'STALE-SOURCE' > $WWW/stale.txt
    printf 'FRESH-VARIANT' > $WWW/fresh.txt.br
    printf 'BR-ONLY' > $WWW/bronly.txt.br
    # Max-Forwards counts the hops an OPTIONS may cross, and TRACE reflects the
    # request back to whoever sent it -- one is a directive addressed to the
    # intermediary and was ignored, the other was forwarded to a backend that
    # might implement it (audit-report-33 follow-up).
    out=$(timeout 90 python3 test/tls/max_forwards_trace.py ${P61443} $CA $h3arg 2>&1)
    rc=$?
    first_fail=$(echo "$out" | grep -m1 FAIL)
    [ $rc -eq 0 ]
    check "Max-Forwards is counted and TRACE refused, on every protocol ${first_fail}" $?

    out=$(timeout 90 python3 test/tls/conditional_field_dups.py ${P61443} $CA $h3arg 2>&1)
    rc=$?
    first_fail=$(echo "$out" | grep -m1 FAIL)
    out=$(timeout 90 python3 test/tls/variant_staleness.py ${P61443} $CA $h3arg 2>&1)
    rc=$?
    first_fail=$(echo "$out" | grep -m1 FAIL)
    [ $rc -eq 0 ]
    check "a precompressed variant older than its source is not served ${first_fail}" $?
    rm -f $WWW/aetest.txt $WWW/aetest.txt.br $WWW/aetest.txt.gz \
          $WWW/gztest.txt $WWW/gztest.txt.gz \
          $WWW/stale.txt $WWW/stale.txt.br $WWW/fresh.txt $WWW/fresh.txt.br \
          $WWW/bronly.txt.br
    [ $rc -eq 0 ]
    check "repeated singleton conditionals refused, Accept-Encoding combined, on every protocol ${first_fail}" $?

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
fi
