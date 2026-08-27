# HTTP/3 through the real server (tls-h3.json): static/proxy/range/error serving, the io_uring receive path, and the forged-Initial defences.

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

    # QUIC's max_idle_timeout comes from the config's `timeout` (5 here), like
    # every other protocol's idle clock. h3 used to advertise a hardcoded 30 s
    # whatever the config said, so raising `timeout` to keep browser
    # connections warm bought h3 nothing. The 60 s fixture in the h1 shard is
    # the other half of this: one value cannot tell a lookup from a constant.
    python3 test/quic/h3_idle_timeout.py ${P61452} 5 >/dev/null 2>&1
    check "h3 advertises the configured idle timeout (5s), not a fixed one" $?

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

    # Finding 8: the SETTINGS payload itself, not just the frame sequence. A frame
    # past the capture buffer with a truncated tail is H3_FRAME_ERROR and one past
    # the policy limit H3_EXCESSIVE_LOAD (both were skipped unvalidated); a repeat
    # after 33 identifiers is H3_SETTINGS_ERROR (detection stopped at 32); and a
    # tiny SETTINGS_MAX_FIELD_SECTION_SIZE resets the response stream rather than
    # sending an oversized field section, while a generous one serves.
    if extensive; then
        timeout 90 python3 test/quic/h3_settings_validation.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): SETTINGS payload validated, field-section limit applied (Finding 8)" $?
    else
        skip "h3 (io_uring): SETTINGS payload / field-section limit -- 8s"
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
    # Keep the output. This went red once in a three-job run and said nothing:
    # the per-seed detail -- which seed, which streams, how many bytes of how
    # many, and whether it was the handshake or the data phase -- had gone to
    # /dev/null, and the answer cost a morning to recover. It prints only on a
    # failure, so a green run is as quiet as before.
    # ...against a server of its own, because the shared one advertises a
    # five-second QUIC idle timeout and the check two blocks up asserts exactly
    # that. Five seconds is too short for THIS client: it is a Python pump
    # driving six concurrent transfers through an emulated network, and on a box
    # running three suite jobs it can go quiet for longer than that between
    # iterations. RFC 9000 10.1 closes an idle connection SILENTLY -- no
    # CONNECTION_CLOSE, no RESET_STREAM -- so the transfer simply stopped and
    # looked exactly like unrecovered loss.
    #
    # Measured under full CPU load at 6% loss, 60 seeds a side:
    #   idle timeout 5s   3 failures in 120 seeds
    #   idle timeout 30s  0 failures in 60
    # and no RESET_STREAM in any of them, which is what ruled out the
    # give-up-after-16-PTOs path before this was found.
    cat > $CFG/tls-h3-stress.json <<EOF
{ "log": "$PWD/$RUNDIR/h3-stress.log", "timeout": 30, "workers": 4,
  "servers": [ { "host": "127.0.0.1", "port": ${P61502}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/", "root": "$PWD/$WWW" } ] } ] }
EOF
    start_server $CFG/tls-h3-stress.json
    stress_out=$(python3 test/quic/h3_stress_test.py ${P61502} 6 6 3 2>&1)
    [ $? -eq 0 ]
    check "h3 (io_uring): concurrent responses survive loss + reordering" $?
    printf '%s\n' "$stress_out" | grep -q "FAIL\|HANDSHAKE" \
        && printf '%s\n' "$stress_out" | sed -n 's/^seed/  h3 stress: seed/p'

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

    # A valid retransmission uses a fresh packet number, so packet-number
    # duplicate suppression cannot protect connection-level receive accounting.
    # Reinject a completed request until the old raw-frame counter would have
    # crossed its MAX_DATA grant threshold; only the first stream high-water may
    # consume credit.
    python3 test/quic/h3_fc_dedup_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): fresh-PN STREAM retransmissions do not double-count MAX_DATA" $?

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

    # Finding 9: the same closure REORDERED ahead of the stream's offset-0 type
    # frame. A FIN or RESET_STREAM that reached the stream while it was still
    # untyped was taken for a teardown; the late type frame then registered a
    # critical stream the connection believed was live. It must close
    # H3_CLOSED_CRITICAL_STREAM (0x0104) once the type is learned.
    if extensive; then
        timeout 40 python3 test/quic/h3_critical_reorder.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): a critical stream closed before typing is detected (Finding 9)" $?
    else
        skip "h3 (io_uring): critical stream closed before typing -- 8s"
    fi

    # ...and TWO such streams closed before either types. The memory of a
    # closure was one slot, so the second overwrote the first and the earlier
    # stream typed as though it had never been closed (audit-report-78). The
    # rows type the stream whose record was overwritten -- the LAST one closed
    # was caught all along, which is why the test above passes either way.
    if extensive; then
        timeout 240 python3 test/quic/h3_critical_reset_multi.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): two critical streams closed before typing (audit-report-78)" $?
    else
        skip "h3 (io_uring): two critical streams closed before typing -- 40s"
    fi

    # RFC 9000 10.1 MUST: the idle period is raised to at least three PTOs, so a
    # peer asking for a short max_idle_timeout does not lose its connection
    # while it could still be probing. The floor was a flat second, which on a
    # connection with no RTT sample is a third of three PTOs (audit-report-90 --
    # which arrived arguing the opposite, that ROUNDING UP held slots too long).
    timeout 60 python3 test/quic/h3_idle_floor.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a short idle timeout still clears three PTOs" $?

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

    # quic-7: multiple 0-RTT packets may be coalesced with the ClientHello.
    # They must all be decrypted, acknowledged, and fed to stream reassembly;
    # the second packet used to be silently left in the datagram.
    python3 test/quic/h3_0rtt_coalesced_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): processes all coalesced 0-RTT packets" $?

    # Finding 15: accepted 0-RTT ran the SAME validate+scan pipeline a 1-RTT
    # packet does. A frame a 0-RTT packet may not carry (ACK, CRYPTO, ...) is a
    # PROTOCOL_VIOLATION, and an early STREAM above the granted limit is a
    # STREAM_LIMIT_ERROR -- both were silently stepped over before. The early
    # packet is hand-built and encrypted with aioquic's own 0-RTT keys.
    python3 test/quic/h3_0rtt_validation.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): 0-RTT runs frame and stream-limit validation (Finding 15)" $?

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
