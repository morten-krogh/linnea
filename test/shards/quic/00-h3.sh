# Shard: QUIC and HTTP/3. Every block starts and stops its own fixture.
# (was region 0 of run_tests.sh, lines 728-1577.)

if python3 -c 'import pylsqpack' 2>/dev/null && [ -x ./bin/linnea-h3resp ]; then
    python3 test/quic/h3resp_test.py >/dev/null 2>&1
    check "h3: response HEADERS+DATA built and QPACK-decodes (status/ct/cl)" $?
else
    check "h3 response test (skipped: pylsqpack/binary unavailable)" 0
fi

# End-to-end HTTP/3: complete the handshake, send an h3 GET, and check linnea
# replies with a 200 HEADERS+DATA response over the request stream.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_e2e_test.py ${P61501} >/dev/null 2>&1
    check "h3: serves real static files over QUIC (MIME, index, 404)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "h3 end-to-end test (skipped: deps unavailable)" 0
fi

# Several HTTP/3 requests on one connection: three GETs on three streams arrive
# coalesced in one packet; linnea answers each on its own stream.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_multi_test.py ${P61501} >/dev/null 2>&1
    check "h3: multiple requests on one connection, each on its own stream" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "h3 multi-stream test (skipped: deps unavailable)" 0
fi

# NewSessionTicket over QUIC: after the handshake the server sends a ticket (in a
# CRYPTO frame coalesced with HANDSHAKE_DONE) carrying the early_data extension
# with max_early_data_size = 0xffffffff, so the client can resume / send 0-RTT.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_ticket_test.py ${P61501} >/dev/null 2>&1
    check "h3: server issues a NewSessionTicket (early_data for 0-RTT)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "h3 NewSessionTicket test (skipped: deps unavailable)" 0
fi

# Session resumption: a second connection presents the first's ticket as a PSK;
# the server opens it, verifies the binder, resumes with a pre_shared_key
# ServerHello and a certificate-free flight (materially fewer bytes).
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 12 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_resume_test.py ${P61501} >/dev/null 2>&1
    check "h3: resumes from a ticket (PSK, binder, no certificate)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "h3 resumption test (skipped: deps unavailable)" 0
fi

# 0-RTT early data: a resuming client sends its GET coalesced with the
# ClientHello; the server decrypts the 0-RTT packet, accepts (EE early_data),
# and serves the buffered request once the 1-RTT keys are up.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 12 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_0rtt_test.py ${P61501} >/dev/null 2>&1
    check "h3: serves a 0-RTT request (early data accepted)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "h3 0-RTT test (skipped: deps unavailable)" 0
fi

# HTTP/3 through the real server: linnea binds a UDP listener for its TLS
# server and drives the QUIC handler from the io_uring loop, so h3 is served by
# the production binary from the config's document root — while TCP keeps
# serving HTTP/1.1 and HTTP/2 on the same port. The config runs four workers,
# so this also covers SO_REUSEPORT steering.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    python3 test/mk_test_image.py $WWW/linnea.png >/dev/null    # served over h3
    start_server $CFG/tls-h3.json
    P61452=$SRV_PORT
    h3_pid=$SRV_PID
    python3 test/quic/h3_e2e_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): real server serves static files over QUIC" $?

    python3 test/quic/h3_etag_test.py ${P61452} >/dev/null 2>&1
    check "h3 validators, date + server headers, conditional 304s" $?

    python3 test/quic/h3_range_test.py ${P61452} >/dev/null 2>&1
    check "h3 range 206/416, if-range, cache-control, chunked slice" $?

    python3 test/quic/h3_enc_test.py ${P61452} >/dev/null 2>&1
    check "h3 pre-compressed variants (br/gzip, vary, variant etag 304)" $?

    python3 test/quic/h3_qpack_err_test.py ${P61452} >/dev/null 2>&1
    check "h3 undecodable field section ends the connection (0x200)" $?
    python3 test/quic/h3_multi_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): several requests on one connection" $?
    python3 test/quic/h3_conns_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): two interleaved connections" $?
    # the idle timeout is the MINIMUM of the two advertised max_idle_timeouts
    # (RFC 9000 10.1), so a client that will forget us in a second must not hold
    # a pool slot for our 30; the paired control keeps that from being any
    # connection simply going idle
    if extensive; then
        timeout 60 python3 test/quic/h3_idle_tp_test.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): the client's max_idle_timeout is honoured (and only it)" $?
    else
        skip "h3 (io_uring): the client's max_idle_timeout is honoured -- 16s, it waits out a real idle timeout"
    fi
    # several workers each bind the QUIC port with SO_REUSEPORT; the kernel
    # steers by 4-tuple so a connection always reaches the worker holding it
    python3 test/quic/h3_workers_test.py ${P61452} 8 >/dev/null 2>&1
    check "h3 (io_uring): connections spread across workers are all served" $?

    python3 test/quic/h3_ack_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): replies acknowledge received packets" $?

    # loss recovery: drop the server's reply and it must retransmit (under a
    # fresh packet number) once its probe timeout fires
    python3 test/quic/h3_rtx_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a dropped reply is retransmitted after the PTO" $?

    # control streams: the server opens its control stream (SETTINGS first) and
    # the QPACK encoder/decoder streams once the handshake completes
    python3 test/quic/h3_control_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): server opens control + QPACK streams with SETTINGS" $?

    # receive side: a client control stream that opens with SETTINGS is accepted
    # and served; one whose first frame is not SETTINGS is closed (H3_MISSING_SETTINGS)
    python3 test/quic/h3_settings_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): client control stream validated (SETTINGS-first enforced)" $?

    # and the rest of the control stream's frame sequence, not just its first two
    # bytes: DATA/HEADERS/PUSH_PROMISE, the reserved HTTP/2 types and a second
    # SETTINGS end the connection, GREASE and the control frames are skipped by
    # length, and a header split across STREAM frames still parses
    if extensive; then
        timeout 180 python3 test/quic/h3_ctrl_frames_test.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): control-stream frames walked and validated" $?
    else
        skip "h3 (io_uring): control-stream frames walked and validated -- 5s"
    fi

    # request bodies: POST is a 405 now, but the body must still be reassembled
    # whole and the stream answered, with its flow-control credit settled
    python3 test/quic/h3_body_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a multi-packet request body is consumed and answered" $?

    # large responses: a 600 KB file streams as ack-clocked STREAM-frame chunks
    # (each datagram under the 1200-byte floor); one dropped chunk is rebuilt
    # from the file after the PTO; a small GET is answered mid-transfer; a
    # client whose flow-control window cannot take the file gets a 503
    python3 test/quic/h3_big_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): large response streamed in chunks (loss + interleave + 503)" $?

    # four large (chunked) responses requested at once: all stream concurrently,
    # interleaved by the pump over the shared congestion window, none refused —
    # each arrives byte-exact. This is a full browser page load (a 503 on a
    # concurrent large request made Firefox abandon h3 for h2).
    python3 test/quic/h3_queue_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): four concurrent large responses, all intact" $?

    # concurrent large responses through an emulated lossy, REORDERING network
    # (both directions), across several seeds — the conditions a real browser hits
    # and that lockstep tests miss. Exercises ack-based fast retransmit and the
    # priority pump; every stream must arrive byte-exact on every seed.
    python3 test/quic/h3_stress_test.py ${P61452} 6 6 3 >/dev/null 2>&1
    check "h3 (io_uring): concurrent responses survive loss + reordering" $?

    # RFC 9218 priority: default (non-incremental) responses are served to
    # completion in arrival order — sequentially, so complete images appear sooner
    # — and a `priority: u=0` request jumps ahead of default-urgency ones.
    python3 test/quic/h3_priority_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): responses scheduled by RFC 9218 priority" $?

    # static files answer GET and HEAD (and h3's own POST echo); every other
    # method used to fall through and be SERVED AS A GET, body and all, where
    # h1 and h2 both answer 405. The method is matched case-sensitively.
    timeout 200 python3 test/quic/h3_method_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): unknown methods get 405, not the file" $?

    # and the client can change its mind afterwards: a PRIORITY_UPDATE on the
    # control stream reprioritises a response already streaming, and one that
    # overtakes the request it names is kept and applied when that stream opens
    timeout 300 python3 test/quic/h3_priority_update_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): PRIORITY_UPDATE reprioritises a response" $?

    # a size/boundary/request-style matrix: every response, from 0 bytes through
    # the inline/chunked threshold and exact chunk multiples to 200 KB, must
    # terminate (deliver a FIN) — sequentially reusing one connection, all at once
    # under the priority scheduler, and as a HEAD. A request that never finishes
    # fails here.
    python3 test/quic/h3_matrix_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): size/boundary/HEAD/concurrent matrix all terminate" $?

    # connection reuse: far more than the advertised 100 bidi streams on ONE
    # connection (a browser reusing it across refreshes) — the server must raise
    # the peer's limit with MAX_STREAMS or new requests can't be sent (images stop
    # loading, h2 fallback after ~30s).
    python3 test/quic/h3_reuse_test.py ${P61452} 250 >/dev/null 2>&1
    check "h3 (io_uring): reused connection past 100 streams (MAX_STREAMS)" $?

    # under load: many concurrent connections (browser tabs / refreshes) plus a
    # burst of open-load-close churn — every request completes and the workers stay
    # alive with no descriptor leak.
    python3 test/quic/h3_load_test.py ${P61452} 12 4 >/dev/null 2>&1
    check "h3 (io_uring): concurrent connections + churn under load" $?

    # browser reloads on one reused connection: each reload cancels the previous
    # page's in-flight downloads (STOP_SENDING). The server must tear a cancelled
    # stream down or its abandoned chunks pin the congestion window and, after
    # enough reloads, the connection stalls (hang, then h2 fallback).
    python3 test/quic/h3_reload_test.py ${P61452} 10 >/dev/null 2>&1
    check "h3 (io_uring): reload-cancel (STOP_SENDING) does not stall the connection" $?

    # connection-level credit (MAX_DATA) must be read from every packet, including
    # the ones that arrive while no response stream is open — which is exactly what a
    # reload's cancels leave behind. The peer sends each value once (its packet is
    # acknowledged), so a raise the server misses is gone for good: the server then
    # stalls at a window the peer has long since widened, with nothing in flight.
    python3 test/quic/h3_maxdata_test.py ${P61452} 8 >/dev/null 2>&1
    check "h3 (io_uring): MAX_DATA is absorbed with no response stream open" $?

    # a request whose ack is lost is retransmitted by the client; the server must
    # ack the retransmit, not serve the stream a second time — a duplicate response
    # slot resends the whole body and pins the shared congestion window (the real-
    # browser wedge). Several chunked streams over one connection, ack-loss forced.
    python3 test/quic/h3_dup_request_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): retransmitted request is not served twice (no duplicate wedge)" $?

    # an Initial's header carries the token a client echoes from a Retry, and the
    # server copies that header into a fixed scratch buffer to authenticate the
    # packet. The token is client-supplied, so an oversized one must be refused
    # rather than copied over whatever follows the buffer — a worker that dies here
    # is a remote, pre-handshake stack overwrite with attacker-chosen bytes.
    python3 test/quic/h3_initial_token_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): oversized Initial token refused, not copied past its buffer" $?

    # a flood of Initials that are never answered must not fill the connection pool
    # and lock real clients out: once enough slots are held by unvalidated peers the
    # server demands a Retry token, which only a client at a real address can echo.
    # Runs late and settles afterwards — it deliberately leaves the pool under
    # pressure, and the pool needs a moment to reclaim the forged slots.
    python3 test/quic/h3_retry_test.py ${P61452} 300 >/dev/null 2>&1
    check "h3 (io_uring): forged-Initial flood does not lock out real clients" $?
    sleep 6

    # a spoofed packet from a different source, carrying a valid connection id but
    # no valid AEAD tag, must NOT redirect the server's sends (RFC 9000 9.3): the
    # peer address is adopted only from an authenticated packet.
    if extensive; then
        python3 test/quic/h3_migration_spoof_test.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): unauthenticated source does not redirect the connection" $?
    else
        skip "h3 (io_uring): unauthenticated source does not redirect -- 8s"
    fi

    # and the replayed half: a captured 1-RTT datagram resent from another source
    # carries a VALID tag, so authenticity alone cannot gate the address change.
    # RFC 9000 12.3 (discard an already-processed packet number) + 9.3 (only the
    # highest-numbered packet may move the address) are what close it.
    python3 test/quic/h3_replay_spoof_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): replayed packet does not redirect the connection" $?

    # the server's own first flight must survive being lost. There was no loss
    # recovery for the Initial or Handshake spaces at all, so dropping that one
    # ~1150-byte datagram ended the handshake and the client fell back to TCP.
    python3 test/quic/h3_hs_rtx_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a lost handshake flight is retransmitted" $?

    # Frames coalesced ahead of a request must not hide it (RFC 9000 12.4). Six
    # scanners each carried a partial frame-length table and stopped at the first
    # type theirs did not list, so a CONNECTION_CLOSE hid what followed it and an
    # unknown type hid the rest of the packet from all six — silently, with the
    # packet acknowledged, so the client never retried.
    python3 test/quic/h3_frame_walk_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): coalesced frames do not hide the rest of the packet" $?

    # the same field rules over HTTP/3 (RFC 9114 4.2, 4.3.1) — one shared
    # decoder, and this side had it worse: the connection-specific names were
    # matched only inside the proxy rebuild, which HTTP/3 never enters at all.
    python3 test/quic/h3_field_rules_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): request field rules" $?

    # The server must not name a protocol the client never offered (RFC 7301
    # 3.2): build_ee wrote "h3" into EncryptedExtensions without ever reading
    # the client's list, so a doq or hq-interop client was told it had h3.
    if extensive; then
        python3 test/quic/h3_alpn_test.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): ALPN is checked, not assumed" $?
    else
        skip "h3 (io_uring): ALPN is checked, not assumed -- 12s"
    fi

    # ...and a refusal must SAY SO (RFC 9001 4.8): the TLS alert becomes a QUIC
    # error of 0x0100+description in a CONNECTION_CLOSE. Every handshake-space
    # refusal used to be silent, because the only close path needed 1-RTT keys
    # that do not exist that early, so the client could not tell "refused" from
    # "lost" and simply retransmitted its ClientHello until it gave up.
    python3 test/quic/h3_hs_close_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a refused handshake closes with the TLS alert" $?

    # RESET_STREAM's Final Size is OURS, not the peer's (RFC 9000 19.4). Resetting
    # a malformed request reported the client's request length, so the peer held
    # connection-level credit for data it would never be sent — and one large
    # enough obliges a conforming client to close with FLOW_CONTROL_ERROR.
    python3 test/quic/h3_reset_final_size_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): RESET_STREAM reports our own final size" $?

    # ...and the code that reset carries has to say WHICH thing went wrong: a
    # truncated last frame is a connection error (7.1), a stream that never
    # carried HEADERS is H3_REQUEST_INCOMPLETE so the client may retry (4.1),
    # and only a request that decodes and then breaks a rule is MESSAGE_ERROR.
    if extensive; then
        python3 test/quic/h3_stream_codes_test.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): a failed request stream names its fault" $?
    else
        skip "h3 (io_uring): a failed request stream names its fault -- 6s"
    fi

    # ...and the same preconditions over h3, so the answer does not depend on
    # which protocol carried the request (RFC 9110 13.1.1, 13.1.4, 13.2.2).
    python3 test/quic/h3_preconditions_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): If-Match and If-Unmodified-Since" $?

    # RFC 9114 6.2: a critical stream must not be closed BY ANY MEANS. Only a
    # FIN was noticed, so a peer could RESET_STREAM its control stream and the
    # connection carried on as though it still had one.
    if extensive; then
        python3 test/quic/h3_critical_reset_test.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): resetting a critical stream is detected" $?
    else
        skip "h3 (io_uring): resetting a critical stream is detected -- 8s"
    fi

    # h3-8: the QPACK encoder stream must be read, not ignored. We advertise
    # capacity 0, so the only legal instruction is Set Dynamic Table Capacity
    # to 0; an insert or another capacity means the peer's table state and
    # ours have silently diverged — QPACK_ENCODER_STREAM_ERROR. Also: a FIN
    # on a LATER frame of a QPACK stream is a critical-stream closure too.
    if extensive; then
        python3 test/quic/h3_qpack_enc_stream_test.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): QPACK encoder-stream instructions are policed" $?
    else
        skip "h3 (io_uring): QPACK encoder-stream instructions are policed -- 7s"
    fi

    # h3-6: control-stream enforcement must survive reordering. A STREAM frame
    # delivered (and acked) ahead of the walked prefix used to be dropped, and
    # since a reordered frame comes only once, the hole was permanent — every
    # control-stream rule quietly stopped being enforced there. Held now, and
    # legal reordering must still close nothing.
    python3 test/quic/h3_ctrl_reorder_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): control-stream rules survive reordering" $?

    # An ack-eliciting packet MUST be acknowledged (RFC 9000 13.2.1). An ACK was
    # only built when the server had something of its own to send, so a lone PING
    # (a browser keepalive) or a lone stream reset drew nothing and the peer
    # resent it with a doubling timeout for the life of the connection.
    python3 test/quic/h3_ack_eliciting_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a packet with nothing to answer is still acked" $?

    # the same for the handshake flights: no long-header packet authenticates its
    # sender, so neither a replayed Initial nor a forged Handshake may move the
    # peer address (RFC 9000 9 — no migration before the handshake is confirmed)
    python3 test/quic/h3_longhdr_spoof_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): spoofed long-header packets do not redirect the connection" $?

    # the client initiates a 1-RTT key update mid-transfer (RFC 9001 §6); the server
    # must derive the next key generation and follow, or it can no longer decrypt the
    # client's packets and the transfer wedges.
    python3 test/quic/h3_key_update_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): follows a client-initiated 1-RTT key update" $?

    # quic-8: after sending a CONNECTION_CLOSE the server keeps the closing state
    # for a while (RFC 9000 10.2), re-sending the close in response to the peer's
    # packets — so the peer learns the real error even if the first close is lost,
    # instead of the stateless reset a freed connection id would draw.
    python3 test/quic/h3_closing_state_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): closing state re-sends the close, no stateless reset" $?

    # quic-11: once the handshake is confirmed the server discards its Initial and
    # Handshake keys (RFC 9001 4.9/4.9.1) and drops any long-header packet rather
    # than AEAD-processing it under keys that are supposed to be gone. A burst of
    # such packets on an established connection must not disturb it.
    python3 test/quic/h3_post_handshake_long.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): long-header packets after confirmation are dropped" $?

    # a 1-RTT packet for a connection id we hold no state for gets a stateless reset
    # (RFC 9000 §10.3), so the peer fails fast instead of waiting out its idle timeout.
    python3 test/quic/h3_stateless_reset_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): stateless reset for an unknown connection id" $?

    # a peer that sends more request-stream data than the advertised window commits a
    # flow-control violation; the server closes with a transport CONNECTION_CLOSE
    # (FLOW_CONTROL_ERROR) rather than silently dropping (RFC 9000 §4.1 / §10.2).
    python3 test/quic/h3_flow_violation_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): flow-control violation closes with a transport error" $?

    # a long-header packet with an unsupported version draws a Version Negotiation
    # packet listing the versions we speak (RFC 9000 §6.1), so the client can retry.
    python3 test/quic/h3_version_negotiation_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): unsupported version draws Version Negotiation" $?

    # a full QUIC v2 (RFC 9369) handshake — different Initial salt, "quicv2" labels
    # and remapped long-header packet types — serving HTTP/3 byte-exact.
    python3 test/quic/h3_v2_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): QUIC v2 handshake serves HTTP/3" $?

    # a client whose Initials start above packet number 0 (Chrome starts at 1): the
    # ServerHello ACK must cover the real [min,max] range, not [0,max] — acking an
    # unsent packet is invalid and a strict client aborts to h2 (QUIC_INVALID_ACK_DATA).
    python3 test/quic/h3_pn_offset_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): ACK covers only received Initials (Chrome starts pn at 1)" $?

    # a real binary asset: a PNG served with the right MIME type, byte-exact,
    # over the chunked h3 path
    python3 test/quic/h3_image_test.py ${P61452} $WWW >/dev/null 2>&1
    check "h3 (io_uring): PNG image served intact (image/png, chunked)" $?

    # a ClientHello too large for one Initial packet (as a browser's post-quantum
    # key share makes it) is reassembled across Initials by the client's original
    # DCID; a ClientHello with no x25519 share is refused without crashing
    if extensive; then
        python3 test/quic/h3_bigch_test.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): multi-packet ClientHello reassembled; no-x25519 refused" $?
    else
        skip "h3 (io_uring): multi-packet ClientHello reassembled -- 18s"
    fi

    # ngtcp2/curl fragments the ClientHello into many small CRYPTO frames sent out
    # of offset order, several per packet; the reassembly must place each at its
    # offset, not assume order (this is what made real browsers fall back to h2)
    python3 test/quic/h3_frag_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): out-of-order multi-frame ClientHello reassembled" $?

    # the request-stream reassembler: a request too big for one packet, with the
    # datagrams reversed and shuffled, so a hole opens and later fills. Every
    # other h3 test sends a request that fits one packet, which never exercises
    # the arrived-bytes map at all
    timeout 120 python3 test/quic/h3_reorder_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): multi-packet request reassembled out of order" $?

    # a header section past our bound is our resource limit, not the peer's
    # encoder misbehaving: it must be answered on its own stream (431), not
    # reported as a decompression failure that takes the whole connection down
    timeout 60 python3 test/quic/h3_bigheaders_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): oversized header list gets 431, connection survives" $?

    # a malformed request whose stream has already ended is answered with a
    # reset; it used to be dropped, leaving the client waiting on a response
    # that could never come
    timeout 60 python3 test/quic/h3_malformed_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): malformed complete request is reset, not dropped" $?

    # QUIC TRANSPORT frames, which h3_malformed_test.py does not reach — it
    # covers HTTP/3 application frames one layer up. These are the parsers in
    # src/lib/linnea_quic.asm walking raw bytes from an UNAUTHENTICATED peer:
    # Initial keys come from the connection id, so none of this needs a
    # handshake. Every length in them is a varint that can claim up to 2^62,
    # and the whole of their safety is bounds checks. Deterministic seed, so a
    # failure is reproducible. Passing is not "it refused" — refusing is the
    # point — it is that every worker survived and the port still serves.
    #
    # ON A SERVER OF ITS OWN, which cost a suite run to learn: five hundred
    # half-open connections from five hundred unrelated connection ids leave a
    # pool nothing like the one the other h3 tests expect, and run against the
    # shared fixture this broke the 0-RTT test forty lines later. Ordering it
    # last would have worked until someone appended a test after it.
    if python3 -c 'import cryptography' 2>/dev/null; then
        start_server $CFG/tls-h3-fuzz.json
        P61456=$SRV_PORT
        fuzz_pid=$SRV_PID
        sleep 0.4
        if extensive; then
            timeout 120 python3 test/quic/fuzz_quic_frames.py ${P61456} 500 "$fuzz_pid" \
                >/dev/null 2>&1
            check "quic transport frames: 500 malformed Initials leave it serving" $?
        else
            skip "quic transport frames: 500 malformed Initials -- 11s, a fixed-size soak"
        fi
        kill $fuzz_pid 2>/dev/null
        wait $fuzz_pid 2>/dev/null
    else
        check "quic frame fuzz (skipped: cryptography unavailable)" 0
    fi

    # session resumption: the real server issues a NewSessionTicket with the
    # early_data extension once the handshake completes
    python3 test/quic/h3_ticket_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): server issues a NewSessionTicket (early_data)" $?

    # and accepts it back: a second connection resumes with the ticket (PSK), so
    # the server skips the certificate
    python3 test/quic/h3_resume_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): resumes from a ticket (no certificate re-sent)" $?

    # 0-RTT: a resuming client's GET, sent as early data with the ClientHello, is
    # decrypted and served
    python3 test/quic/h3_0rtt_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): serves a 0-RTT request (early data)" $?

    # quic-6b: the same over QUIC v2. RFC 9369 shifts every long-header type up
    # by one, so the 0-RTT packet is 0x20 rather than 0x10 -- the walk that hunts
    # for it used to look for the v1 type only, so a v2 client's early data was
    # silently ignored and its request went unanswered until it resent it at
    # 1-RTT. One byte different on the wire, same assertions.
    python3 test/quic/h3_0rtt_test.py ${P61452} 2 >/dev/null 2>&1
    check "h3 (io_uring): serves a 0-RTT request over QUIC v2 (RFC 9369 types)" $?

    # quic-6: the 0-RTT packet shares the Application pn space with 1-RTT and MUST
    # be acknowledged (RFC 9000 13.2.1); the server used to discard its number, so
    # the early request was never acked. The qlog must show the server ack cover
    # the packet number the client sent its 0-RTT on.
    python3 test/quic/h3_0rtt_ack_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): the 0-RTT packet is acknowledged" $?

    # BPF connection-ID steering: a connection survives the client migrating to a
    # fresh source port. Needs CAP_BPF on the binary (a rebuild drops the file
    # capability), so it is skipped when the steering program could not load.
    if getcap "$BIN" 2>/dev/null | grep -q cap_bpf; then
        python3 test/quic/h3_migrate_test.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): connection survives client migration (BPF CID steering)" $?
    else
        check "h3 (io_uring): CID steering (skipped: binary lacks CAP_BPF)" 0
    fi

    # Alt-Svc: the TCP responses advertise HTTP/3 on this port, which is how a
    # browser discovers it at all
    hdrs=$(curl -si --http1.1 --cacert test/tls/server.crt \
                --resolve localhost:${P61452}:127.0.0.1 \
                https://localhost:${P61452}/hello.txt)
    echo "$hdrs" | grep -qi "alt-svc: h3=\":${P61452}\""
    check "h3 (io_uring): HTTP/1.1 advertises Alt-Svc for h3" $?
    hdrs=$(curl -si --http2 --cacert test/tls/server.crt \
                --resolve localhost:${P61452}:127.0.0.1 \
                https://localhost:${P61452}/hello.txt)
    echo "$hdrs" | grep -qi "alt-svc: h3=\":${P61452}\""
    check "h3 (io_uring): HTTP/2 advertises Alt-Svc for h3" $?

    # the UDP listener must not disturb TCP on the same host and port
    body=$(curl -s --http2 --cacert test/tls/server.crt \
                 --resolve localhost:${P61452}:127.0.0.1 \
                 https://localhost:${P61452}/hello.txt)
    [ "$body" = "hello from linnea" ]
    check "h3 (io_uring): HTTP/2 over TCP still served on the same port" $?

    # a pre-auth malformed Initial (long-header Length rewritten to 0) must not
    # underflow the AEAD ciphertext length and crash a worker; the workers must
    # be the same processes afterwards, and normal h3 must still be served
    ulw_before=$(workers_of $h3_pid)
    python3 test/quic/h3_length_underflow_test.py ${P61452} >/dev/null 2>&1
    sleep 0.5
    python3 test/quic/h3_e2e_test.py ${P61452} >/dev/null 2>&1
    ulw_ok=$?
    ulw_after=$(workers_of $h3_pid)
    [ -n "$ulw_before" ] && [ "$ulw_before" = "$ulw_after" ] && [ $ulw_ok -eq 0 ]
    check "h3 (io_uring): malformed Length Initial crashes no worker (pre-auth)" $?

    # a resumption offer whose PskIdentity is longer than a real ticket must be
    # rejected before the AEAD: the open writes identity_len-28 bytes into a
    # 48-byte stack slot, so an oversized identity overwrote the return address
    # of a pre-auth path. Real resumption must keep working afterwards.
    pio_before=$(workers_of $h3_pid)
    python3 test/quic/h3_psk_id_overflow_test.py ${P61452} >/dev/null 2>&1
    sleep 0.5
    python3 test/quic/h3_resume_test.py ${P61452} >/dev/null 2>&1
    pio_ok=$?
    pio_after=$(workers_of $h3_pid)
    [ -n "$pio_before" ] && [ "$pio_before" = "$pio_after" ] && [ $pio_ok -eq 0 ]
    check "h3 (io_uring): oversized PskIdentity crashes no worker (pre-auth)" $?

    kill $h3_pid 2>/dev/null
    wait $h3_pid 2>/dev/null
else
    check "h3 io_uring tests (skipped: deps unavailable)" 0
fi

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

# Drain with an in-flight h2 response and a slow reader (Q117): the connection
# was freed once the last body byte reached the kernel, and close(2) with the
# client's unread WINDOW_UPDATEs queued answered with an RST that discarded
# the untransmitted tail of the send buffer — ~90% of the body arrived, then a
# reset. The lingering close (shutdown the write side, drain reads until the
# peer closes) delivers every byte.
rm -f $RUNDIR/linnea.log
python3 -c "open('$WWW/h2drain.bin','wb').write(bytes(3000000))"
start_server $CFG/tls-h3-drain.json
P61453=$SRV_PORT
h2d_master=$SRV_PID
timeout 60 python3 test/tls/h2_drain_slow.py test/tls/server.crt ${P61453} $h2d_master >/dev/null 2>&1
check "http2 drain delivers the whole in-flight body to a slow reader" $?
wait $h2d_master 2>/dev/null
rm -f $RUNDIR/linnea.log $WWW/h2drain.bin

# Large certificate chain (~5.2 KB, seven certs — over the old ~3.9 KB cap) on
# both transports. On h3 the flight is both larger than one datagram (QUIC forbids
# IP fragmentation, so the Certificate CRYPTO is split across <=MTU Handshake
# packets) and larger than the 3x amplification budget (RFC 9000 s8.1, so the tail
# is withheld until the client's address is validated, then resumed): the test
# confirms the first burst stays within 3x, no datagram breaches the 1200-byte
# floor, and the handshake completes. That the server even boots with this chain
# exercises the raised cap; the curl check confirms the same chain over h2/TCP.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-bigcert.json
    P61454=$SRV_PORT
    bc_pid=$SRV_PID
    sleep 0.6
    python3 test/quic/h3_bigcert_test.py ${P61454} >/dev/null 2>&1
    check "h3 (io_uring): large flight segmented + held to the 3x amp budget" $?
    body=$(curl -s --http2 --cacert test/tls/bigchain.crt \
                --resolve localhost:${P61454}:127.0.0.1 https://localhost:${P61454}/hello.txt)
    [ "$body" = "hello from linnea" ]
    check "h2 (kTLS): large certificate chain over TCP (past the old cap)" $?
    kill $bc_pid 2>/dev/null
    wait $bc_pid 2>/dev/null
    rm -f $RUNDIR/linnea.log
else
    check "h3 handshake segmentation/amplification test (skipped: deps unavailable)" 0
fi

# Acknowledgements: our reply must acknowledge the request packet, or the peer
# keeps retransmitting work already done.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_ack_test.py ${P61501} >/dev/null 2>&1
    check "quic: replies acknowledge the packets we received" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "quic ack test (skipped: deps unavailable)" 0
fi

# Connection churn: more connections than the pool has slots, each closing
# cleanly, must all be served — the slot has to come back on CONNECTION_CLOSE.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 60 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_churn_test.py ${P61501} 100 >/dev/null 2>&1
    check "quic: 100 connections through a 64-slot pool (close frees the slot)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "quic churn test (skipped: deps unavailable)" 0
fi

# Connection pool: two connections whose handshakes and requests are fully
# interleaved must not share keys, transcript, connection ids or packet numbers.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_conns_test.py ${P61501} >/dev/null 2>&1
    check "quic: two interleaved connections keep separate state (pool demux)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "quic connection-pool test (skipped: deps unavailable)" 0
fi

