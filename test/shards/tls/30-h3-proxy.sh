# The HTTP/3 proxy battery over TLS: h3->h1 proxying, canned errors, max header size, stream cancellation, and h2/h3 response-framing agreement.

if [ "$ktls" = 1 ]; then
    start_server $CFG/tls-h3-proxy.json
    P61462=$SRV_PORT
    h3p_pid=$SRV_PID
    # audit-report-6 Finding 1: a malformed upstream response head must be
    # refused the same way whichever protocol relays it. It was not: h2 had
    # validated since Finding 34, h1 relayed a non-token field name and a NUL in
    # a value to the client VERBATIM, and h3 QPACK-encoded both onto the wire --
    # while a pair of disagreeing Content-Lengths was 502 on h1 and h2 and a
    # clean 200 on h3, the contradiction erased by re-deriving the length from
    # what was captured. One matrix over all three protocols, because the defect
    # was never "protocol X is wrong", it was the three disagreeing. Runs
    # without aioquic too, checking h1 and h2 and saying h3 was skipped.
    timeout 120 python3 test/proxy_upstream_head.py $CA ${P61462} >/dev/null 2>&1
    check "proxy: h1/h2/h3 agree on refusing a malformed upstream head" $?

    # Reported from production: an EMPTY file upload came back 411 Length
    # Required. The 411 was the backend's, correctly -- linnea had handed it a
    # POST with no framing at all, because h2 and h3 dropped the Content-Length
    # whenever the measured body was zero. "A body of no bytes" and "no body"
    # are different requests upstream, and only the first declares a length;
    # h1 forwarded "Content-Length: 0" and worked. Asserts what was SENT
    # upstream, via the head-echo route, not just the status that came back.
    timeout 120 python3 test/proxy_empty_body.py $CA ${P61462} >/dev/null 2>&1
    check "proxy: an empty body forwards Content-Length: 0 on every protocol" $?

    # audit-report-122: DEL (0x7f) is legal in an h2/h3 field value (RFC 9113
    # 8.2.1, RFC 9114 4.2 forbid only NUL, LF and CR) and illegal in an h1 one
    # (RFC 9110 5.5), so the h2/h3 proxy translated a legal request into an
    # invalid HTTP/1.1 one and sent it upstream -- the differential report 121
    # closed at the h1 door, reopened through this one. All three must now
    # answer 400 with the backend never hearing the request, which is what the
    # echoed head proves. Two acceptance controls ride along: the same header
    # one byte different, and "a<0x7e>b<0x80>c" -- 0x7e closes VCHAR and 0x80
    # opens obs-text, so a fix clamping above 0x7e would refuse a legal value
    # and nothing else here would notice.
    timeout 120 python3 test/proxy_del_field.py $CA ${P61462} >/dev/null 2>&1
    check "proxy: h1/h2/h3 agree on refusing DEL in a forwarded field value" $?

    # audit-report-123: an HTTP field name is a token (RFC 9110 5.1, 5.6.2), and
    # h1 has always been held to that -- h2 and h3 were held only to RFC 9113
    # 8.2.1's MINIMAL list (no 0x00-0x20, no uppercase, no 0x7f-0xff, no
    # non-leading colon), which lets every delimiter but ':' through. "x@test"
    # was therefore served over h2/h3 and written verbatim into the HTTP/1.1
    # head sent upstream -- an h1 request our own h1 door answers 400 to. All
    # three must refuse it now, with the echoed head proving the backend never
    # heard of it. The controls that keep the refusal honest: every tchar
    # punctuation mark 5.6.2 allows, in one name, still served and echoed -- a
    # fix that refused punctuation wholesale would pass every rejection row here
    # and fail that one -- and the four pseudo-headers, whose leading ':' is not
    # a tchar, ride on every request in the file.
    timeout 120 python3 test/proxy_field_name.py $CA ${P61462} >/dev/null 2>&1
    check "proxy: h1/h2/h3 agree on refusing a non-token field name" $?

    # The h3 half of /api/bigearly, which that matrix cannot judge: six 103
    # Early Hints whose ENCODED sum overran the one buffer the interim frames
    # share, so h3 answered 502 to an exchange h1 and h2 served (audit-report-8
    # Finding 2). aioquic's decoder gives up once a stream's field sections
    # total more than a few KiB -- which any response large enough to exercise
    # this bound also exceeds -- so the check needs a real h3 client. It must
    # come back 200 with the five-byte body behind all six hints.
    if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
        be=$("$CURLH3" --http3-only -sk --max-time 20              --resolve localhost:${P61462}:127.0.0.1              https://localhost:${P61462}/api/bigearly 2>/dev/null)
        [ "$be" = "valid" ]
        check "h3 relays a long interim chain and the final response ($be)" $?

        # ...and the documented end of that rope. h3 buffers the whole interim
        # sequence before it sends anything, so unlike h2 -- which relays each
        # 1xx as it arrives and needs no cap -- and h1, whose chain is bounded
        # by the head buffer it is parsed out of, it needs one, or a chain of
        # minimal 1xx heads encodes to an unbounded number of field sections
        # each carrying its own via, date and server. The cap is
        # LINNEA_H3_PROXY_IMAX (8), enforced while PARSING so an over-long chain
        # is refused before a body is captured for a response that could never
        # be sent. /api/manyearly sends nine. This is a deliberate divergence
        # from h1/h2, which serve it: asserted here so it stays deliberate.
        many=$("$CURLH3" --http3-only -sk -o /dev/null -w '%{http_code}'                --max-time 20 --resolve localhost:${P61462}:127.0.0.1                https://localhost:${P61462}/api/manyearly 2>/dev/null)
        [ "$many" = "502" ]
        check "h3 refuses an interim chain past the documented cap ($many)" $?

        # /api/204 sends the Content-Length RFC 9110 8.6 forbids on a 204. The
        # cross-protocol matrix judges the FIELD; this judges whether the
        # response can be received at all, which is the half aioquic could not
        # see -- it decoded the relayed version happily, while curl's h3 leg
        # answered it with "ngtcp2_conn_writev_stream returned error:
        # ERR_CLOSING" and returned nothing (audit-report-9 Finding 2). So the
        # exit status is the assertion here, not the body.
        "$CURLH3" --http3-only -sk -o /dev/null --max-time 20 \
            --resolve localhost:${P61462}:127.0.0.1 \
            https://localhost:${P61462}/api/204 >/dev/null 2>&1
        check "h3 completes a 204 whose upstream sent a forbidden length" $?
    else
        check "h3 long interim chain (skipped: curl-h3 unavailable)" 0
        check "h3 interim cap (skipped: curl-h3 unavailable)" 0
        check "h3 204 completion (skipped: curl-h3 unavailable)" 0
    fi

    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        out=$(timeout 120 python3 test/quic/h3_proxy_test.py ${P61462} 2>&1)
        [ "$out" = "OK" ]
        check "h3 proxies to an HTTP/1.1 upstream ($out)" $?

        # audit-report-143: the peer's SETTINGS_MAX_FIELD_SECTION_SIZE, over the
        # responses this config actually builds. The proxy path never consulted
        # it -- a proxied response is encoded on an upstream completion, long
        # after the per-request globals stopped describing the connection that
        # asked for it -- and the static path compared the ENCODED QPACK length
        # to a limit RFC 9114 4.2.2 defines over the UNCOMPRESSED section, so
        # /hello.txt (626 bytes of fields, under 200 encoded) was sent to a peer
        # advertising 200. Each rejection row is paired with an acceptance row
        # above the same response's size, and the interim chain is judged per
        # SECTION (largest 1670) rather than by its 10397-byte sum.
        timeout 180 python3 test/quic/h3_fss_limit.py ${P61462} >/dev/null 2>&1
        check "h3: the peer's field-section limit is applied, proxied and static (143)" $?

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
        check "h3 field-section limit (skipped: aioquic/pylsqpack unavailable)" 0
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

    # Finding 19: max_body must bound a body carried by ONE offset-zero STREAM
    # frame with FIN. That copy-free single-frame path reaches routing without
    # either reassembly cap check, so a max_body below one packet's worth was
    # ignored on exactly that shape -- the h3 twin of Finding 3. curl cannot show
    # it (it flushes HEADERS and DATA as separate frames, taking the reassembly
    # path that was already capped), so the aioquic driver puts the whole request
    # in one frame. A dedicated max_body=64 server: 64 bytes served, 65 refused.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        sfb=$CFG/h3-smallbody.json
        # absolute paths: start_server runs with CWD=$RUNDIR (see the h1 twin).
        cat > "$sfb" <<EOF
{ "log": "$PWD/$RUNDIR/h3-smallbody.log", "timeout": 5, "workers": 1, "max_body": 64,
  "spill_dir": "$PWD/$RUNDIR",
  "servers": [ { "host": "127.0.0.1", "port": ${P61470}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/api", "proxy": "127.0.0.1:${P61100}" },
                   { "prefix": "/", "root": "$PWD/$WWW" } ] } ] }
EOF
        start_server "$sfb"
        sfb_pid=$SRV_PID
        out=$(timeout 30 python3 test/quic/h3_single_frame_maxbody.py ${P61470} 64 2>&1 | tail -1)
        [ "$out" = "OK" ]
        check "h3 max_body bounds a single-frame body too ($out)" $?
        # ...and the OTHER cap check, on the reassembly path, which bounds each
        # DATA frame's declared length against the headroom that is LEFT. The
        # case that exercises the subtraction is a body SPLIT across frames
        # whose sum crosses the cap while no single frame comes near it; the
        # boundary itself is asserted one below, exactly at, and one above
        # (audit-report-38 asked for all three positions). The driver asserts
        # that its sends actually left as separate packets, because coalesced
        # they would silently retest the single-frame path above and pass.
        out=$(timeout 60 python3 test/quic/h3_multi_frame_maxbody.py ${P61470} 64 2>&1 | tail -1)
        [ "$out" = "OK" ]
        check "h3 max_body bounds a body split across DATA frames ($out)" $?
        # Finding 18: content-length must equal the DATA sum (RFC 9114 4.1.3), the
        # check h2 makes at END_STREAM and h3 did not -- a short/long body was
        # routed around the client's declared framing. Small bodies, so the same
        # max_body=64 server serves them.
        out=$(timeout 30 python3 test/quic/h3_content_length.py ${P61470} 2>&1 | tail -1)
        [ "$out" = "OK" ]
        check "h3 reconciles content-length with the DATA sent ($out)" $?
        # ...and a STATIC location takes no request content at all (RFC 9110
        # 9.3.1), the same rule h1 and h2 now apply. h3 decides it on the
        # CONTENT rather than the declaration -- it has the whole request before
        # routing -- so a length that DISAGREES is still the stream error RFC
        # 9114 4.1.2 requires, raised before routing, while content that
        # actually arrived earns a 400.
        timeout 60 python3 test/quic/h3_static_body.py ${P61470} >/dev/null 2>&1
        check "h3 static locations take no request content" $?
        # Finding 11: a COMPLETED request must not be dispatched twice. Serve one,
        # then re-inject its exact STREAM frame under a fresh packet number (aioquic
        # PTO-probes a small completed request with a PING, so this forges the
        # retransmission directly); the access log must show it dispatched ONCE.
        timeout 30 python3 test/quic/h3_dup_served.py ${P61470} dedup11probe >/dev/null 2>&1
        sleep 0.3
        n=$(grep -c 'dedup11probe' "$RUNDIR/h3-smallbody.log")
        [ "$n" = "1" ]
        check "h3 does not re-dispatch a completed request on retransmission ($n dispatch)" $?
        # RFC 9000 4.5: a stream's final size is fixed by the first FIN. Once a
        # request was SERVED, nothing remembered its size -- the copy-free path
        # never had a reassembly context and a reassembled one is released at
        # dispatch -- so a later FIN naming a different size, or data past it,
        # was acked in silence (audit-report-77). Twelve rows: three violations
        # and three legal retransmissions, each on both receive paths. The
        # controls are the point: a partial retransmission of a completed
        # request is LEGAL and must still be acked, not closed on.
        timeout 180 python3 test/quic/h3_final_size_closed.py ${P61470} >/dev/null 2>&1
        check "h3 holds a completed stream's final size (RFC 9000 4.5)" $?
        kill $sfb_pid 2>/dev/null
        wait $sfb_pid 2>/dev/null
        rm -f "$sfb"
    else
        check "h3 single-frame max_body (skipped: aioquic unavailable)" 0
    fi

    # --- several backends: round-robin, failover, and health ------------
    # A location may name a list of upstreams. Two marker backends say
    # which one answered; a third address has nothing behind it, so a
    # connect to it is refused and the request must move to the next.
    #
    # EIGHT locations exactly, which is LINNEA_MAX_LOCATIONS -- there is no
    # root location because nothing here asks for one, and adding a ninth is
    # what a future edit will trip over.
    #
    # Each protocol gets its OWN dead-first location. Health state is per
    # worker and per LOCATION, not per protocol, so one shared location
    # would be failed out by whichever protocol ran first and the other two
    # would inherit the answer -- passing without executing the paths they
    # exist to cover.
    python3 test/marker_backend.py ${P61481} A >/dev/null 2>&1 &
    mk_a=$!
    python3 test/marker_backend.py ${P61482} B >/dev/null 2>&1 &
    mk_b=$!
    # accepts every connection and never answers: the fault a connect-only
    # health check is blind to
    python3 test/hang_backend.py ${P61488} >/dev/null 2>&1 &
    mk_h=$!
    sleep 0.5
    fol=$PWD/$RUNDIR/failover.log
    fo=$CFG/failover.json
    cat > "$fo" <<EOF
{ "log": "$fol", "timeout": 5, "proxy_timeout": 2, "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61483}, "hostname": "localhost",
"cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
"locations": [
  { "prefix": "/both",    "proxy": ["127.0.0.1:${P61481}", "127.0.0.1:${P61482}"] },
  { "prefix": "/dead-h1", "proxy": ["127.0.0.1:${P61489}", "127.0.0.1:${P61481}"] },
  { "prefix": "/dead-h2", "proxy": ["127.0.0.1:${P61489}", "127.0.0.1:${P61481}"] },
  { "prefix": "/dead-h3", "proxy": ["127.0.0.1:${P61489}", "127.0.0.1:${P61481}"] },
  { "prefix": "/only",    "proxy": ["127.0.0.1:${P61489}"] },
  { "prefix": "/hang-h1", "proxy": ["127.0.0.1:${P61488}", "127.0.0.1:${P61481}"] },
  { "prefix": "/hang-h2", "proxy": ["127.0.0.1:${P61488}", "127.0.0.1:${P61481}"] },
  { "prefix": "/hang-h3", "proxy": ["127.0.0.1:${P61488}", "127.0.0.1:${P61481}"] } ] } ] }
EOF
    start_server "$fo"
    fo_pid=$SRV_PID
    out=$(timeout 300 python3 test/tls/upstream_failover.py ${P61483} $CA "$fol" $h3arg 2>&1)
    rc=$?
    first_fail=$(echo "$out" | grep -m1 FAIL)
    kill $mk_a $mk_b $mk_h 2>/dev/null
    [ $rc -eq 0 ]
    check "a proxy location spreads over its backends, steps past a dead one, and stops retrying it ${first_fail}" $?

    kill $fo_pid 2>/dev/null
    wait $fo_pid 2>/dev/null
    rm -f "$fo"

    # --- upstream keep-alive --------------------------------------------
    # Opt-in per location, because sending "Connection: close" upstream is what
    # makes a close-delimited response terminate -- a backend that sends neither
    # Content-Length nor chunked would hang without it. Turning it on is the
    # operator asserting their backend delimits its responses.
    #
    # Reuse is invisible from the client: same status, same body, same headers
    # either way. Every check reads the BACKEND's accept counter, which is the
    # only direct evidence there is. Driven over all three protocols, because
    # h1, h2 and h3 each build their own upstream head and each had to be
    # taught the same rule.
    python3 test/marker_backend.py ${P61481} A >/dev/null 2>&1 &
    ka_a=$!
    python3 test/rude_backend.py ${P61484} >/dev/null 2>&1 &
    ka_r=$!
    python3 test/reuse_close_backend.py ${P61494} >/dev/null 2>&1 &
    ka_rc=$!
    sleep 0.5
    kt=$CFG/keepalive.json
    cat > "$kt" <<EOF
{ "log": "$PWD/$RUNDIR/keepalive.log", "timeout": 5, "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61485}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [
      { "prefix": "/ka",   "proxy": "127.0.0.1:${P61481}", "proxy_keepalive": 1 },
      { "prefix": "/noka", "proxy": "127.0.0.1:${P61481}" },
      { "prefix": "/r",    "proxy": "127.0.0.1:${P61484}", "proxy_keepalive": 1 },
      { "prefix": "/rc",   "proxy": "127.0.0.1:${P61494}", "proxy_keepalive": 1 },
      { "prefix": "/", "root": "$PWD/$WWW" } ] } ] }
EOF
    start_server "$kt"
    kt_pid=$SRV_PID
    out=$(RC_PORT=${P61494} timeout 200 python3 test/tls/upstream_keepalive.py ${P61485} $CA \
          ${P61481} ${P61484} $h3arg 2>&1)
    rc=$?
    first_fail=$(echo "$out" | grep -m1 FAIL)
    kill $ka_a $ka_r $ka_rc 2>/dev/null
    [ $rc -eq 0 ]
    check "upstream connections are reused on every protocol, and not when reuse would be unsafe ${first_fail}" $?
    kill $kt_pid 2>/dev/null
    wait $kt_pid 2>/dev/null
    rm -f "$kt"

    # --- max_upstream must not refuse the pool's own inventory -----------
    # A parked keep-alive connection is a live backend connection and is
    # counted against max_upstream. Borrowing it opens no descriptor, so the
    # ceiling has to be consulted where a socket is actually opened -- not
    # before the pool is consulted. h2 and h3 tested it first and answered 503
    # with a reusable descriptor sitting there, and because `take` is the only
    # thing that reaps an expired entry, the refusal never reclaimed it either:
    # the location stayed 503 rather than recovering (audit-report-39).
    #
    # The saturation row matters as much: a ceiling that stops refusing is not
    # a fix. It uses a separate location with no keep-alive and a backend that
    # sleeps, so nothing is poolable and 503 is the right answer.
    python3 test/marker_backend.py ${P61481} A >/dev/null 2>&1 &
    cap_a=$!
    python3 test/slow_backend.py ${P61486} >/dev/null 2>&1 &
    cap_s=$!
    sleep 0.5
    cp=$CFG/ceiling.json
    cat > "$cp" <<EOF
{ "log": "$PWD/$RUNDIR/ceiling.log", "timeout": 15, "proxy_timeout": 15,
  "workers": 1, "max_upstream": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61487}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [
      { "prefix": "/ka",   "proxy": "127.0.0.1:${P61481}", "proxy_keepalive": 1 },
      { "prefix": "/slow", "proxy": "127.0.0.1:${P61486}" },
      { "prefix": "/", "root": "$PWD/$WWW" } ] } ] }
EOF
    start_server "$cp"
    cp_pid=$SRV_PID
    out=$(timeout 240 python3 test/tls/upstream_ceiling.py ${P61487} $CA \
          ${P61481} $h3arg 2>&1)
    rc=$?
    first_fail=$(echo "$out" | grep -m1 FAIL)
    kill $cap_a $cap_s 2>/dev/null
    [ $rc -eq 0 ]
    check "max_upstream refuses a new connection, not a reusable one ${first_fail}" $?
    kill $cp_pid 2>/dev/null
    wait $cp_pid 2>/dev/null
    rm -f "$cp"

    # --- a vhost is (listener, hostname), never hostname alone ------------
    # Two TLS servers sharing a hostname on different ports. h1 has always
    # scoped its scan to the servers on the connection's own listener; h2
    # matched the hostname across every server and returned the first, so the
    # second port was served from the first server's root (audit follow-up).
    # 443 and 8443 under one name is an ordinary shape.
    mkdir -p $RUNDIR/vha $RUNDIR/vhb
    echo SERVER-A > $RUNDIR/vha/who.txt
    echo SERVER-B > $RUNDIR/vhb/who.txt
    vp=$CFG/vhost-port.json
    cat > "$vp" <<EOF
{ "log": "$PWD/$RUNDIR/vhost-port.log", "timeout": 5, "workers": 1,
  "servers": [
    { "host": "127.0.0.1", "port": ${P61491}, "hostname": "localhost",
      "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
      "locations": [ { "prefix": "/", "root": "$PWD/$RUNDIR/vha" } ] },
    { "host": "127.0.0.1", "port": ${P61493}, "hostname": "localhost",
      "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
      "locations": [ { "prefix": "/", "root": "$PWD/$RUNDIR/vhb" } ] } ] }
EOF
    start_server "$vp"
    vp_pid=$SRV_PID
    out=$(timeout 60 python3 test/tls/vhost_port_scope.py ${P61491} ${P61493} $CA 2>&1)
    rc=$?
    first_fail=$(echo "$out" | grep -m1 FAIL)
    [ $rc -eq 0 ]
    check "a vhost is (listener, hostname), on h1 and h2 alike ${first_fail}" $?
    # ...and the one-port h3 limitation is stated rather than left silent
    grep -q "served on one port only" "$RUNDIR/vhost-port.log"
    check "http3's one-port limit is reported at startup" $?
    kill $vp_pid 2>/dev/null
    wait $vp_pid 2>/dev/null
    rm -f "$vp"


    # Every h3 response must describe ITSELF. The QPACK encoder reads
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
    # location carrying cache_control and arbitrary response_headers. The same
    # harness also follows that static hit with a redirect on the same QUIC
    # connection, proving the in-serve per-request state is cleared before a
    # non-root route is answered.
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
        check "h3 responses carry no other request's field section ($out)" $?
        rm -f $WWW/canned.txt $WWW/canned.txt.gz
        kill $h3cn_pid 2>/dev/null
        wait $h3cn_pid 2>/dev/null
    else
        check "h3 canned error field sections (skipped: aioquic unavailable)" 0
    fi

    # The response buffers must fit the LARGEST head the documented config can
    # produce, not a typical one. hsts and cache_control are each up to 255
    # bytes, and response_headers adds an exact 512-byte aggregate budget. The
    # old 1024-byte per-stream head could not carry that documented maximum: it
    # RESET a large static response while h1/h2 served it normally.
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

    # Finding 1 (audit-report-3): a proxied HTTP/3 response for a connection
    # that arrived on a SECONDARY address must go out that connection's OWN
    # socket, not the global primary. Config: primary "::1", secondary
    # "127.0.0.1", one h3 port, /api proxied. Before the fix, the async upstream
    # completion emitted the first response packet on the primary (::1) socket
    # to the v4 peer -> sendto ENETUNREACH -> recovered only by a later
    # retransmission on the right socket. strace the server across one proxied
    # request through the secondary and require the request to SUCCEED (so a
    # response really was sent) with ZERO cross-socket ENETUNREACH.
    if command -v strace >/dev/null 2>&1 && [ -x "$CURLH3" ]; then
        rm -f $RUNDIR/f1sec.strace $RUNDIR/linnea-h3pm.log
        strace -f -e trace=sendto -o $RUNDIR/f1sec.strace \
            ./bin/linnea --config $CFG/h3proxy-multi.json >/dev/null 2>&1 &
        f1_spid=$!
        for _ in $(seq 1 40); do ss -ulnH 2>/dev/null | grep -q ":${P61463}\b" && break; sleep 0.1; done
        f1_code=$("$CURLH3" --http3-only -s -o /dev/null -w '%{http_code}' --max-time 15 \
            --cacert $CA --resolve localhost:${P61463}:127.0.0.1 \
            https://localhost:${P61463}/api/simple 2>/dev/null)
        sleep 0.4
        # strace does NOT kill its tracee when it dies -- killing the strace pid
        # alone would orphan a live linnea. Kill the linnea master (strace's
        # child; pgrep -P matches by parent pid, so no cmdline self-match), then
        # strace, then reap anything still on the port as a backstop.
        f1_srv=$(pgrep -P $f1_spid 2>/dev/null | head -1)
        [ -n "$f1_srv" ] && kill $f1_srv 2>/dev/null
        kill $f1_spid 2>/dev/null
        sleep 0.3
        [ -n "$f1_srv" ] && kill -9 $f1_srv 2>/dev/null
        kill -9 $f1_spid 2>/dev/null
        for _fp in $(ss -ulnpH 2>/dev/null | grep ":${P61463}\b" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
            kill -9 "$_fp" 2>/dev/null
        done
        [ "$f1_code" = 200 ] && ! grep -q ENETUNREACH $RUNDIR/f1sec.strace
        check "h3 proxy: secondary-address response uses its own socket (no cross-socket ENETUNREACH; code=$f1_code)" $?
    else
        check "h3 proxy secondary-address fd (skipped: strace/curl-h3 unavailable)" 0
    fi
    if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
        got=$("$CURLH3" --http3-only -s --max-time 20 --cacert $CA \
              --resolve localhost:${P61465}:127.0.0.1 \
              -D $RUNDIR/maxhdr.hdr -o $RUNDIR/maxhdr.out -w '%{http_code}' \
              https://localhost:${P61465}/maxhdr.bin)
        [ "$got" = "200" ] && cmp -s $RUNDIR/maxhdr.out "$WWW/maxhdr.bin" \
            && grep -qi '^x-max-a: x' $RUNDIR/maxhdr.hdr \
            && grep -qi '^x-max-b: y' $RUNDIR/maxhdr.hdr
        check "h3 serves max hsts+cache_control+response_headers ($got)" $?
        rm -f $RUNDIR/maxhdr.out $RUNDIR/maxhdr.hdr
    else
        check "h3 max-length header response (skipped: no HTTP/3 curl)" 0
    fi
    # h2 is the control: it always could, so a failure above is h3's buffer
    # and not the config being rejected somewhere earlier.
    g2=$(curl -s --http2 --max-time 20 --cacert $CA \
         --resolve localhost:${P61465}:127.0.0.1 \
         -D $RUNDIR/maxhdr2.hdr -o $RUNDIR/maxhdr2.out -w '%{http_code}' \
         https://localhost:${P61465}/maxhdr.bin)
    [ "$g2" = "200" ] && cmp -s $RUNDIR/maxhdr2.out "$WWW/maxhdr.bin" \
        && grep -qi '^x-max-a: x' $RUNDIR/maxhdr2.hdr \
        && grep -qi '^x-max-b: y' $RUNDIR/maxhdr2.hdr
    check "h2 serves the same max-length-header response ($g2)" $?
    rm -f $RUNDIR/maxhdr2.out $RUNDIR/maxhdr2.hdr $WWW/maxhdr.bin
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
fi
