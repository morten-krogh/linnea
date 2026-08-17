# HTTP/3 corner fixtures: clienthello fuzz, mixed h1/h2/h3, dual-stack IPv6, trailers, and the GOAWAY/drain variants.


# h3 routes to locations. A vhost with a proxy location used to be barred from
# h3 altogether, and when another vhost on the same port owned the listener its
# requests were answered from THAT vhost's document root, under that vhost's
# certificate — 404s over h3 for paths that served 200 over h2. The fixture is
# that exact shape, with disjoint roots so the fall-through cannot pass quietly.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-mixed.json
    mixed_pid=$SRV_PID
    out=$(python3 test/quic/h3_locations_test.py ${P61461} 2>&1)
    [ "$out" = "OK" ]
    check "h3 routes to locations: own root, longest prefix, 502 on proxy ($out)" $?
    # the same paths over h2, which has always routed: the two must agree
    body=$(curl -s --http2 --max-time 6 --cacert test/tls/server.crt \
                https://localhost:${P61461}/page.html)
    case "$body" in *"subdirectory page"*) true ;; *) false ;; esac
    check "h3/h2 agree on the mixed vhost's own root" $?
    kill $mixed_pid 2>/dev/null
    wait $mixed_pid 2>/dev/null
else
    check "h3 location routing (skipped: deps unavailable)" 0
fi

# Dual-stack IPv6: one AF_INET6 listener (host "::", IPV6_V6ONLY off) serves both
# families. A full h3 GET must complete over native IPv6 (::1) AND over IPv4
# (127.0.0.1) against that single listener — the native-v6 peer also exercises the
# 28-byte sockaddr_in6 handling on the receive, conn.peer and sendto-reply paths.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-v6.json
    P61455=$SRV_PORT
    v6_pid=$SRV_PID
    python3 test/quic/h3_ipv6_test.py ${P61455} >/dev/null 2>&1
    check "h3 (io_uring): dual-stack — served over native IPv6 (::1) and IPv4" $?
    # TCP too: the same dual-stack socket answers HTTP/2 over native IPv6
    body=$(curl -s --http2 --cacert test/tls/server.crt \
                 --resolve localhost:${P61455}:[::1] \
                 https://localhost:${P61455}/hello.txt)
    [ "$body" = "hello from linnea" ]
    check "h3 (io_uring): dual-stack — HTTP/2 over TCP served on native IPv6" $?
    kill $v6_pid 2>/dev/null
    wait $v6_pid 2>/dev/null
    rm -f $RUNDIR/linnea.log
else
    check "dual-stack IPv6 test (skipped: deps unavailable)" 0
fi

# Q134: a trailing HEADERS frame (trailers) must not merge into the request
# and change the response — a trailer "range: bytes=0-4" used to turn a
# whole-file GET into a 206.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-drain.json
    P61453=$SRV_PORT
    tr_master=$SRV_PID
    tr_workers=$(workers_of_now $tr_master)
    timeout 60 python3 test/quic/h3_trailer_test.py ${P61453} >/dev/null 2>&1
    check "h3 (io_uring): trailers do not influence the response" $?
    # Q136: frames illegal on a request stream (reserved h2 types, control/push
    # frames, DATA before HEADERS) are a connection error H3_FRAME_UNEXPECTED,
    # not silently ignored; GREASE/unknown stay ignored.
    if extensive; then
        timeout 90 python3 test/quic/h3_frame_reject_test.py ${P61453} >/dev/null 2>&1
        check "h3 (io_uring): illegal request-stream frames rejected (0x105)" $?
    else
        skip "h3 (io_uring): illegal request-stream frames rejected -- 16s"
    fi
    kill $tr_master 2>/dev/null
    wait $tr_master 2>/dev/null
    reap_workers $tr_workers
    rm -f $RUNDIR/linnea.log
fi

# HTTP/3 GOAWAY on drain: a worker told to drain sends GOAWAY on its control
# stream so the client opens no new requests, then exits. A single-worker config
# keeps the signalling deterministic; the test kills the master itself.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-drain.json
    P61453=$SRV_PORT
    ga_master=$SRV_PID
    ga_workers=$(workers_of_now $ga_master)
    python3 test/quic/h3_goaway_test.py ${P61453} $ga_master >/dev/null 2>&1
    check "h3 (io_uring): drain sends GOAWAY on the control stream" $?
    # Q120: the request that test served must be in the access log
    grep -qE 'request localhost from [0-9.:]+ "GET /hello.txt HTTP/3" 200 ' $RUNDIR/linnea.log
    check "h3 request access-logged" $?
    wait $ga_master 2>/dev/null
    reap_workers $ga_workers
    rm -f $RUNDIR/linnea.log
else
    check "h3 GOAWAY drain test (skipped: deps unavailable)" 0
fi

# A STOP must tell h3 peers, not merely vanish. SIGTERM exits at once — there
# is nothing to drain — but a QUIC connection that goes silent leaves its peer
# to an idle timeout, and a browser reads repeated unexplained losses as the
# origin's h3 being unreliable. One CONNECTION_CLOSE each fixes that without
# making the stop slower.
if python3 -c 'import aioquic' 2>/dev/null; then
    start_server $CFG/tls-h3-drain.json
    P61453=$SRV_PORT
    sc_master=$SRV_PID
    out=$(timeout 40 python3 test/quic/h3_stop_close_test.py ${P61453} $sc_master 2>&1)
    case "$out" in OK*) true ;; *) false ;; esac
    check "h3 (io_uring): a stop closes peers instead of vanishing ($out)" $?
    kill -9 $sc_master 2>/dev/null
    wait $sc_master 2>/dev/null
else
    check "h3 stop-close test (skipped: deps unavailable)" 0
fi

# RFC 9000 4.5 (Finding 12): a stream's final size is fixed once a FIN learns
# it. The test hand-injects 1-RTT packets that aioquic will not craft -- two
# FINs with a decreasing then an increasing size, and data past a declared final
# -- each of which was silently accepted before and must now close the
# connection FINAL_SIZE_ERROR (0x06).
if python3 -c 'import aioquic' 2>/dev/null; then
    start_server $CFG/tls-h3-drain.json
    fs_port=$SRV_PORT
    fs_master=$SRV_PID
    timeout 40 python3 test/quic/h3_final_size.py ${fs_port} >/dev/null 2>&1
    check "h3 QUIC final-size invariants close FINAL_SIZE_ERROR (Finding 12)" $?
    timeout 60 python3 test/quic/h3_stream_state_test.py ${fs_port} >/dev/null 2>&1
    check "h3 QUIC stream direction/state errors close STREAM_STATE_ERROR (Finding 14)" $?
    kill -9 $fs_master 2>/dev/null
    wait $fs_master 2>/dev/null
else
    check "h3 final-size test (skipped: deps unavailable)" 0
fi

# Finding 16: a burst of small requests larger than the loss-recovery ring must
# still be answered in full. Inline responses beyond the ring (or the congestion
# window) are handed to the congestion-controlled pump instead of being emitted
# untracked, so none is dropped.
if python3 -c 'import aioquic' 2>/dev/null; then
    start_server $CFG/tls-h3-drain.json
    ib_port=$SRV_PORT
    ib_master=$SRV_PID
    out=$(timeout 40 python3 test/quic/h3_inline_burst.py ${ib_port} 40 2>&1)
    case "$out" in ok*) true ;; *) false ;; esac
    check "h3 inline-response burst is answered in full ($out) (Finding 16)" $?
    kill -9 $ib_master 2>/dev/null
    wait $ib_master 2>/dev/null
else
    check "h3 inline-burst test (skipped: deps unavailable)" 0
fi

# RFC 9114 6.2.1 (Finding 10): a second QPACK encoder/decoder stream is
# H3_STREAM_CREATION_ERROR, like a second control stream -- not silently
# accepted with the saved id overwritten.
if python3 -c 'import aioquic' 2>/dev/null; then
    start_server $CFG/tls-h3-drain.json
    dq_master=$SRV_PID
    timeout 30 python3 test/quic/h3_dup_qpack.py $SRV_PORT >/dev/null 2>&1
    check "h3 duplicate QPACK stream is a creation error (Finding 10)" $?
    kill -9 $dq_master 2>/dev/null
    wait $dq_master 2>/dev/null
else
    check "h3 duplicate QPACK stream test (skipped: deps unavailable)" 0
fi

# RFC 9114 6.2 (Finding 22): a unidirectional stream type is a varint, so control
# type 0 sent as "40 00" and the QPACK types as "40 02" must be decoded, not read
# as one byte and discarded as unknown.
if python3 -c 'import aioquic' 2>/dev/null; then
    start_server $CFG/tls-h3-drain.json
    ut_master=$SRV_PID
    timeout 30 python3 test/quic/h3_uni_type.py $SRV_PORT >/dev/null 2>&1
    check "h3 multi-byte unidirectional stream type is decoded (Finding 22)" $?
    kill -9 $ut_master 2>/dev/null
    wait $ut_master 2>/dev/null
else
    check "h3 uni stream-type test (skipped: deps unavailable)" 0
fi

# RFC 9000 7.4/18.2 (Finding 13): a truncated, duplicate, server-only, or
# trailing-byte transport parameter must close the handshake with
# TRANSPORT_PARAMETER_ERROR, not complete as though the list ended cleanly.
if python3 -c 'import aioquic' 2>/dev/null; then
    start_server $CFG/tls-h3-drain.json
    tp_master=$SRV_PID
    timeout 40 python3 test/quic/tp_validation.py $SRV_PORT >/dev/null 2>&1
    check "quic malformed transport parameters close the handshake (Finding 13)" $?
    kill -9 $tp_master 2>/dev/null
    wait $tp_master 2>/dev/null
else
    check "quic transport-parameter test (skipped: deps unavailable)" 0
fi

# RFC 9000 5.1 (Finding 21): NEW_CONNECTION_ID and RETIRE_CONNECTION_ID were only
# walked past. Now a malformed one (retire_prior_to > sequence, a sequence reused
# with a different id, more live peer CIDs than our limit, or retiring an id we
# never issued) closes the connection, and a valid retirement of an id we issued
# stops it routing and draws a replacement NEW_CONNECTION_ID.
if python3 -c 'import aioquic' 2>/dev/null; then
    start_server $CFG/tls-h3-drain.json
    cid_master=$SRV_PID
    timeout 60 python3 test/quic/h3_cid_lifecycle.py $SRV_PORT >/dev/null 2>&1
    check "quic connection-id lifecycle: validate, rotate, replace (Finding 21)" $?
    kill -9 $cid_master 2>/dev/null
    wait $cid_master 2>/dev/null
else
    check "quic connection-id lifecycle test (skipped: deps unavailable)" 0
fi

# Drain with an in-flight h3 response (Q117): the drain-exit test used to count
# only TCP connections, so a worker whose work was all QUIC exited the moment
# the drain began (and stopped re-arming the datagram recv besides) — the peer
# hung mid-download with nothing on the wire to tell it. Now the worker keeps
# receiving, finishes the response, says goodbye with CONNECTION_CLOSE
# (H3_NO_ERROR), and only then exits.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-drain.json
    P61453=$SRV_PORT
    di_master=$SRV_PID
    di_workers=$(workers_of_now $di_master)
    timeout 40 python3 test/quic/h3_drain_inflight_test.py ${P61453} $di_master >/dev/null 2>&1
    check "h3 (io_uring): drain finishes the in-flight response, then closes" $?
    wait $di_master 2>/dev/null
    # the drain must END: wait for OUR workers to go, by pid. A pattern here
    # asserted that no such server exists anywhere, which a suite running
    # beside this one falsified while draining perfectly correctly.
    workers_gone $di_workers
    check "h3 drain exits after the last QUIC connection" $?
    rm -f $RUNDIR/linnea.log
else
    check "h3 in-flight drain test (skipped: deps unavailable)" 0
fi

# GOAWAY must stop processing what it disowns (h3-7, RFC 9114 5.2): on a
# draining connection a request at/above the GOAWAY's stream id draws
# RESET_STREAM(H3_REQUEST_REJECTED), not a response — else a client that
# retried it elsewhere (as the GOAWAY instructs) runs it twice. The window
# only exists on a connection the drain sweep left alive, so the test holds a
# stalled response in flight across the drain, then checks the disowned
# stream is rejected AND the in-flight response still completes.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-drain.json
    P61453=$SRV_PORT
    gr_master=$SRV_PID
    gr_workers=$(workers_of_now $gr_master)
    timeout 60 python3 test/quic/h3_goaway_reject_test.py ${P61453} $gr_master >/dev/null 2>&1
    check "h3 (io_uring): drain rejects disowned streams (0x10b), serves owned" $?
    kill $gr_master 2>/dev/null
    wait $gr_master 2>/dev/null
    reap_workers $gr_workers
    rm -f $RUNDIR/linnea.log
else
    check "h3 GOAWAY reject test (skipped: deps unavailable)" 0
fi

# Steering handoff across a hot upgrade (Q118): a master handed the previous
# generation's bpf map+program in LINNEA_UPGRADE stamps its connection ids from
# the other half of the index space (base 64), so the draining generation's
# connections keep steering to their workers; unusable inherited fds cost only
# the steering. The script plays the old master itself (inherited listener,
# zombie old-worker pid, pipe fds standing in for the bpf pair).
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    timeout 30 python3 test/quic/h3_steer_base_test.py \
        $CFG/tls-h3-drain.json ${P61453} >/dev/null 2>&1
    check "h3 (io_uring): upgrade handoff stamps the other steering half" $?
    rm -f $RUNDIR/linnea.log
else
    check "h3 steering handoff test (skipped: deps unavailable)" 0
fi
