# HTTP/2 over TLS: multiplexing, flow control, HPACK, GOAWAY, uploads past the window, credit batching, and the proxy-over-h2 path.

if [ "$ktls" = 1 ]; then
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

    # RFC 9113 8.1/8.1.1: a HEADERS carrying END_STREAM ends the message, so a
    # nonzero content-length on it is a body announced with no DATA (Finding 24);
    # a trailer section MUST carry END_STREAM, and one that omits it does not end
    # the body (Finding 4). The first was forwarded bodiless to the backend, the
    # second left the collecting slot open until its 408. Both are stream errors.
    timeout 60 python3 test/tls/h2_malformed.py $CA ${P61443} >/dev/null 2>&1
    check "http2 rejects terminal content-length and END_STREAM-less trailers" $?

    # RFC 9113 8.1: an upstream body cut short mid-stream must not reach the
    # client as a clean END_STREAM -- that calls a truncated body complete
    # (Finding 31). /api/chunktrunc flushes its head and one chunk, then closes
    # with no terminating 0-chunk; de-chunked, the client is handed a body with
    # no length to check, so before the fix curl reported success. The head is
    # already out, so the honest signal is RST_STREAM, which curl surfaces as a
    # transfer error (a truncated body the client can now see).
    timeout 8 curl -s --http2 --max-time 6 --cacert $CA -o /dev/null $U/api/chunktrunc
    [ $? -ne 0 ]
    check "http2 proxied truncated chunked body is reset, not completed clean (Finding 31)" $?

    # RFC 9113 8.8.5 (Finding 30): an upstream 1xx is an interim HEADERS block
    # that does not end the stream; the final response still follows. Before the
    # fix the 103/100 was emitted with END_STREAM and the real response
    # discarded, so the client saw a 103 with an empty body. /api/early sends
    # 103 (with a Link hint) then 200: the 103 must be relayed AND the final 200
    # body delivered. -v captures the interim status curl otherwise hides.
    ev=$(timeout 8 curl -sk --http2 -v --max-time 6 --cacert $CA $U/api/early 2>&1)
    printf '%s' "$ev" | grep -q "HTTP/2 103" \
        && printf '%s' "$ev" | grep -q "HTTP/2 200" \
        && printf '%s' "$ev" | grep -q "final-reply"
    check "http2 proxy relays a 1xx interim then the final response (Finding 30)" $?

    # the interim and the final response in one upstream write must not be
    # treated as final, nor hang waiting for a head already buffered
    atonce=$(timeout 8 curl -sk --http2 --max-time 6 --cacert $CA $U/api/early-atonce)
    [ "$atonce" = "final-reply" ]
    check "http2 proxy handles a buffered interim+final in one read (Finding 30)" $?

    # several informational responses (103, 103, 100) before the final one
    multi=$(timeout 8 curl -sk --http2 --max-time 6 --cacert $CA $U/api/multi-early)
    [ "$multi" = "final-reply" ]
    check "http2 proxy relays multiple 1xx responses before the final (Finding 30)" $?

    # a 101 has no meaning over an h2 proxy: reject it (502), do not relay
    code=$(timeout 8 curl -sk --http2 --max-time 6 --cacert $CA -o /dev/null -w '%{http_code}' $U/api/upgrade101)
    [ "$code" = 502 ]
    check "http2 proxy rejects an upstream 101 (Finding 30)" $?

    # RFC 9113 8.2.3 (Finding 32): an h2 client may split Cookie into several
    # fields; the proxy must join them, in order, with "; " for the h1 backend.
    timeout 30 python3 test/tls/h2_cookie.py $CA ${P61443} >/dev/null 2>&1
    check "http2 proxy coalesces split cookie fields (Finding 32)" $?

    # RFC 9110 10.1.1 (Finding 33): the proxy buffers the body, so a request with
    # "expect: 100-continue" must be answered with an immediate local 100 rather
    # than stalling the client until the body timeout.
    timeout 30 python3 test/tls/h2_expect.py $CA ${P61443} >/dev/null 2>&1
    check "http2 proxy answers expect: 100-continue with a local 100 (Finding 33)" $?

    # RFC 9113 8.2.1 / RFC 9110 8.6 (Finding 34): a malformed upstream response
    # head must not be translated into a client-facing field block. A non-token
    # field name, a control byte in a value, a missing colon, and conflicting
    # Content-Length all become 502; identical duplicate Content-Length is
    # normalized to one line and still served.
    mfok=1
    for r in badname badvalue nocolon clconflict; do
        code=$(timeout 8 curl -sk --http2 --max-time 6 --cacert $CA -o /dev/null -w '%{http_code}' $U/api/$r)
        [ "$code" = 502 ] || mfok=0
    done
    [ "$mfok" = 1 ]
    check "http2 proxy rejects malformed upstream response fields with 502 (Finding 34)" $?
    body=$(timeout 8 curl -sk --http2 --max-time 6 --cacert $CA $U/api/cldupe)
    [ "$body" = "hello" ]
    check "http2 proxy normalizes identical duplicate Content-Length (Finding 34)" $?

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

    # RFC 9113 6.3/6.8/8.4/4.2 (Findings 25/26/27): a client PUSH_PROMISE, a
    # malformed PRIORITY (wrong length or stream 0), a malformed GOAWAY (nonzero
    # stream or short), and a CONTINUATION over the advertised frame size each
    # draw a GOAWAY with the RFC's error code instead of being ignored/drained.
    timeout 30 python3 test/tls/h2_frame_validation.py $CA ${P61446} >/dev/null 2>&1
    check "http2 malformed control frames draw the right GOAWAY (Findings 25/26/27)" $?

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
fi
