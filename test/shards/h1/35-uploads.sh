# HTTP/1 uploads (counted + chunked, too large to buffer), proxied request-log lines, websockets, and spill-dir capture.

# --- large uploads: a body too large to buffer with the head is captured in
# full (on disk, past what fits in memory) and only then forwarded, so it is
# bounded by max_body rather than by in_buf ---
python3 -c "
import random, sys
random.seed(11)
open('$WWW/upload.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
want=$(md5sum < $WWW/upload.bin | cut -d' ' -f1)
curl -s --max-time 30 --data-binary @$WWW/upload.bin \
    http://127.0.0.1:${P61080}/api/echo > $RUNDIR/upload_echo.bin
[ "$(md5sum < $RUNDIR/upload_echo.bin | cut -d' ' -f1)" = "$want" ]
check "proxy captures a 300000-byte request body (byte-exact)" $?
rm -f $RUNDIR/upload_echo.bin

# The point of capturing rather than relaying: a client that abandons its
# upload must leave the backend with NOTHING — not a truncated request it
# cannot distinguish from a complete one, and may already have acted on.
# Asserted against the backend's own record of what reached it, and the
# control below proves that record is being written.
python3 test/upload_abort.py >/dev/null
sleep 0.5
! grep -q ' /api/abandoned ' "$SEEN"
check "abandoned upload reaches the backend not at all" $?
grep -q ' /api/echo 300000$' "$SEEN"
check "backend record control (the completed upload IS in it)" $?

# --- chunked uploads too large to buffer: captured and decoded as they
# arrive, then forwarded as an ordinary counted request. Before this they were
# a 413 outright, since only the counted path could stream. ---
for m in big head bad abort cap flood twice pipeline sizeline smuggle; do
    out=$(python3 test/upload_chunked.py $m)
    [ "$out" = "OK" ]
    case $m in
      big)   check "chunked upload captured byte-exact through ragged framing ($out)" $? ;;
      head)  check "chunked upload reaches the backend counted, not chunked ($out)" $? ;;
      bad)   check "chunked upload with a bad chunk size is 400 ($out)" $? ;;
      abort) check "abandoned chunked upload reaches the backend not at all ($out)" $? ;;
      cap)   check "chunked upload past max_body is 413, not a reset ($out)" $? ;;
      flood) check "endless chunked trailers hit max_body too ($out)" $? ;;
      twice) check "two chunked captures on one kept-alive connection ($out)" $? ;;
      pipeline) check "a GET pipelined behind a chunked upload is still served ($out)" $? ;;
      sizeline) check "both chunk decoders agree on the chunk-size line grammar ($out)" $? ;;
      smuggle)  check "a chunk size that overflows 64 bits smuggles nothing ($out)" $? ;;
    esac
done

# The rewritten upstream head goes into up_buf behind ONE up-front bound, and
# .append is an unchecked rep movsb — so a head that clears the bound but whose
# rewrite outgrows it runs off the end of the slot into the next connection.
# The bound has ~24 bytes of margin over everything the rewrite adds (Via, the
# Connection line, a Content-Length when a chunked one was dropped); this walks
# a head across the boundary in both framings and expects only 200 or 431.
if extensive; then
    out=$(python3 test/h1_upbuf_test.py ${P61080} 2>&1 | tail -1)
    [ "$out" = "OK" ]
    check "a proxied head at the up_buf boundary is served or refused ($out)" $?
else
    skip "a proxied head at the up_buf boundary -- 44s, it walks every size across the bound"
fi

# The same, counted: two captures on one connection. The bodies must DIFFER —
# with identical ones a second upload served out of the first one's file looks
# perfectly correct.
python3 -c "
import random
random.seed(31); open('$WWW/up1.bin','wb').write(bytes(random.getrandbits(8) for _ in range(200000)))
random.seed(41); open('$WWW/up2.bin','wb').write(bytes(random.getrandbits(8) for _ in range(250000)))"
curl -s --max-time 30 -o $RUNDIR/up1_echo.bin --data-binary @$WWW/up1.bin http://127.0.0.1:${P61080}/api/echo \
     --next -s --max-time 30 -o $RUNDIR/up2_echo.bin --data-binary @$WWW/up2.bin http://127.0.0.1:${P61080}/api/echo
[ "$(md5sum < $RUNDIR/up1_echo.bin | cut -d' ' -f1)" = "$(md5sum < $WWW/up1.bin | cut -d' ' -f1)" ] &&
[ "$(md5sum < $RUNDIR/up2_echo.bin | cut -d' ' -f1)" = "$(md5sum < $WWW/up2.bin | cut -d' ' -f1)" ]
check "two counted captures on one kept-alive connection" $?
rm -f $RUNDIR/up1_echo.bin $RUNDIR/up2_echo.bin $WWW/up1.bin $WWW/up2.bin

# A request pipelined in the SAME recv as a streamed body's final bytes must
# still be answered. It used to be dropped: the capture read the whole recv into
# out_buf and kept only the body, discarding the request behind it, so the
# client hung. Covers counted and chunked framing with the seam forced to the
# body's end, one byte into the next request, and mid-terminal-chunk. The
# existing "twice" checks miss it because they read the first response before
# sending the second request, so the two never share a recv.
out=$(python3 test/h1_stream_pipeline.py ${P61080} 2>&1 | tail -1)
[ "$out" = "OK" ]
check "a request pipelined behind a streamed body is served, not dropped ($out)" $?

# max_body is what stands between one client and the filesystem, so it is
# refused on the declared length — before a byte of it is written anywhere.
resp=$(raw_http "POST /api/toobig HTTP/1.1\r\nHost: one.test\r\nContent-Length: 99999999999\r\n\r\n")
check_http "upload past max_body is 413" "413 Content Too Large" "$resp"
! grep -q ' /api/toobig ' "$SEEN"
check "the refused upload never reached the backend" $?

# ...and it applies to a body that FITS the request buffer, not only one large
# enough to stream (Finding 3): the cap check used to live only on the streaming
# path, so a max_body below the ~17 KiB in_buf was bypassed by any smaller body.
# A dedicated server with max_body=64 proxies to the same backend; a 64-byte
# body must be served and 65 must be 413, counted and chunked alike.
mbs=$CFG/max-body-small.json
# absolute paths: start_server runs the server with CWD=$RUNDIR, so a relative
# log/spill path would resolve under the run dir a second time and fail to open.
cat > "$mbs" <<EOF
{ "log": "$PWD/$RUNDIR/max-body-small.log", "timeout": 5, "max_connections": 64,
  "max_body": 64, "workers": 1, "spill_dir": "$PWD/$RUNDIR",
  "servers": [ { "host": "127.0.0.1", "port": ${P61498}, "hostname": "one.test",
    "locations": [ { "prefix": "/api", "proxy": "127.0.0.1:${P61100}" } ] } ] }
EOF
start_server "$mbs"
mbs_pid=$SRV_PID
out=$(python3 test/max_body_small.py ${P61498} 64 2>&1 | tail -1)
[ "$out" = "OK" ]
check "max_body is honoured for a buffered body, not only a streamed one ($out)" $?
! grep -q ' /api/echo 65 ' "$SEEN"
check "the over-limit buffered body never reached the backend" $?
kill $mbs_pid 2>/dev/null
wait $mbs_pid 2>/dev/null
rm -f "$mbs"

# --- proxied request log lines: upstream status, relayed byte count ---
grep -qE 'request one\.test from 127\.0\.0\.1:[0-9]+ "GET /api/simple HTTP/1\.1" 200 12' "$LOG"
check "proxy log 200" $?
grep -qF '"POST /api/echo HTTP/1.1" 200 10' "$LOG"
check "proxy log body bytes" $?
grep -qF '"GET /api/target?x=1&y=2 HTTP/1.1" 200' "$LOG"
check "proxy log query" $?
grep -qF '"GET /down/x HTTP/1.1" 502 0' "$LOG"
check "proxy log 502" $?
grep -qF '"GET /api/slow HTTP/1.1" 504 0' "$LOG"
check "proxy log 504" $?
grep -qF '"HEAD /api/simple HTTP/1.1" 200 0' "$LOG"
check "proxy log HEAD" $?

# --- websockets: upgrade passthrough and the full-duplex tunnel ---
out=$(python3 test/ws_client.py echo)
[ "$out" = "OK" ]
check "ws echo round trips ($out)" $?
out=$(python3 test/ws_client.py pipelined)
[ "$out" = "OK" ]
check "ws client bytes before the 101 ($out)" $?
out=$(python3 test/ws_client.py push)
[ "$out" = "OK" ]
check "ws server push and 101 leftover ($out)" $?
out=$(python3 test/ws_client.py tick)
[ "$out" = "OK" ]
check "ws one-way traffic outlives idle timeout ($out)" $?
out=$(python3 test/ws_client.py silent)
[ "$out" = "OK" ]
check "ws idle tunnel times out ($out)" $?
out=$(python3 test/ws_client.py reject)
[ "$out" = "OK" ]
check "ws upgrade refusal passes through ($out)" $?
# a 101 the client never asked for must not start a tunnel
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/101)
check_http "unrequested 101 becomes 502" "502 Bad Gateway" "$resp"
# ...and nothing open may hold up a stop. These two run their own servers,
# because they stop them — 61080 is serving the rest of the suite. The second
# waits out the 30s drain deadline, and is the slowest check in the file.
# linnea-ws heartbeats its clients rather than letting the proxy reap them on
# silence. Both halves are checked, and each is the other's control: a server
# that never reaped, and one that dropped everyone, each pass exactly one of
# them. ~50s, which is the price of a real 30s ping and its 15s grace.
if extensive; then
    hb=$(timeout 120 python3 test/ws_heartbeat_test.py ${P61701} 30 15 2>&1)
    [ "$hb" = "OK" ]
    check "ws: clients that answer the ping live, silent ones are dropped ($hb)" $?
else
    # 105 s at the shipped intervals, and every second of it is waiting -- the
    # most expensive check in the file by a factor of two. So the fast suite
    # runs the SAME test against the SAME source built at 3 s / 1.5 s, on a
    # backend of its own so the other ws checks keep the shipped one (a 1.5 s
    # pong deadline would drop the tunnel clients that never answer a ping).
    # It proves what the check is for -- an answering client lives, a silent
    # one is dropped, and dropped inside its window -- and stops proving the
    # interval, which is why the full run above still pays the 105 s.
    make -s bin/linnea-ws-fast >/dev/null 2>&1
    if [ -x bin/linnea-ws-fast ]; then
        ./bin/linnea-ws-fast ${P61704} >/dev/null 2>&1 &
        wsfast_pid=$!
        for _ in $(seq 1 60); do
            (echo > /dev/tcp/127.0.0.1/${P61704}) >/dev/null 2>&1 && break
            sleep 0.1
        done
        hb=$(timeout 60 python3 test/ws_heartbeat_test.py ${P61704} 3 1.5 2>&1)
        [ "$hb" = "OK" ]
        check "ws: clients that answer the ping live, silent ones are dropped, at 3s/1.5s ($hb)" $?
        kill $wsfast_pid 2>/dev/null
        wait $wsfast_pid 2>/dev/null
    else
        check "ws heartbeat (skipped: bin/linnea-ws-fast would not build)" 1
    fi
fi

out=$(python3 test/ws_drain_test.py)
[ "$out" = "OK" ]
check "a stop is immediate whatever is open ($out)" $?
out=$(python3 test/reload_deadline_test.py)
case "$out" in OK*) true ;; *) false ;; esac
check "a reload retires an old worker a tunnel pins ($out)" $?

# --- the upload capture lands on the filesystem spill_dir names -----------
# doc_claims_test covers the parsing and validation of the key. What it cannot
# see is the two open() sites going back to a hardcoded "/tmp" — silent, and
# its only symptom is uploads held in RAM instead of on disk. An O_TMPFILE has
# no directory entry, so the descriptor in /proc is the only evidence there is.
mkdir -p test/spill
python3 test/proxy_backend.py >/dev/null 2>&1 &
spill_backend_pid=$!
backend_ready
start_server $CFG/tls-h3-big.json
P61498=$SRV_PORT
h3big_pid=$SRV_PID
sleep 0.3
# The second half of the idle-timeout check in the quic shard: this fixture says
# 60, that one says 5, and neither is the 30 h3 used to advertise regardless --
# so together they show the value is READ rather than merely constant.
if python3 -c 'import aioquic' 2>/dev/null; then
    timeout 30 python3 test/quic/h3_idle_timeout.py ${P61498} 60 >/dev/null 2>&1
    check "h3 advertises the configured idle timeout (60s here, 5s elsewhere)" $?
else
    check "h3 configured idle timeout (skipped: aioquic unavailable)" 0
fi
start_server $CFG/spill-dir.json
P61495=$SRV_PORT
spill_pid=$SRV_PID
sleep 0.3
out=$(timeout 60 python3 test/spill_dir_test.py ${P61495} test/spill $spill_pid 2>&1)
case "$out" in ok*) true ;; *) false ;; esac
check "the upload capture file is created under spill_dir ($out)" $?
# h3 uploads whose body goes straight to the capture file, at two sizes that
# fail for two different reasons. Every OTHER h3 upload check in the suite uses
# a body under 7 KB, which keeps the whole request on the RAM path -- so none of
# them reaches this code at all, and 635/0 said nothing about the case the
# direct-to-file change was FOR.
#
# 40000 is the one that pins the bug. Inside a payload the granted ceiling is
# capped at the payload's end, and a grant smaller than RA_GRANT (16 KiB) was
# suppressed as not worth a packet -- so the last step up to that cap was never
# sent and the peer stalled a few bytes short of a body it had already declared.
# The broken band was payloads from RA_BUF (where the file path engages) up to
# where the final step reaches RA_GRANT: 34000..49000 hung every time, 33000 and
# 50000 never did. It is deterministic and answers in ~0.1s, so it is the cheap
# guard; if only this one fails, the grant floor has come back.
#
# 16000000 crosses RA_WINDOW (4 MiB) instead, where the ceiling has to keep
# following body_hi across many grants rather than being set once. It is slow
# (~8s) but it is the only check that exercises a payload longer than the window.
#
# A NOTE ON MEASURING THESE, which cost most of a day: the leftover that
# triggered the stall is just the payload end modulo how far body_hi happened to
# jump between grant evaluations, so at a size near the band edge one run hangs
# and the next does not. 8 MB completed three times and then hung on the same
# binary, and a bisect read that as a tidy "2 x RA_WINDOW" threshold that never
# existed. Sizes inside the band above are deterministic; sizes outside it are
# not evidence of anything.
# Three sizes, one per ingest path, and each one SAYS which path it took rather
# than being trusted to take it: 3000 stays in RAM (the control), 200000 opens a
# capture-file region, 16000000 opens one longer than RA_WINDOW and so is the
# only one that reaches the grant loop where the suppressed-last-step deadlock
# lived.
#
# The RAM case has now had to move three times, and the third time is the one
# worth reading. It was 40000, then 8000 when the inline buffer dropped to 16
# KiB -- both times because the number here had to follow a constant. This time
# the derivation itself was wrong: the gate stopped being the advertised window
# when a body started BORROWING its buffer, so 8000 and 200000 were BOTH on the
# RAM path and the middle case had been testing the control's path while saying
# "capture-file". h3_upload_big.py now reads the gate out of the header, and
# 3000 is under it (LINNEA_QUIC_RA_REGION_MIN, 4096).
for spec in "3000 ram" "200000 file" "16000000 file"; do
    set -- $spec
    out2=$(timeout 120 python3 test/quic/h3_upload_big.py localhost $1 ${P61498} --path $2 2>&1)
    case "$out2" in ok*) true ;; *) false ;; esac
    check "h3 upload of $1 bytes echoes back byte-exact ($out2)" $?
done
# A stream ENDED at exactly the flow-control limit, in an empty frame of its
# own, while a gap remains in the payload. Inside a payload the limit we grant
# IS the payload's end, and the reassembly base stays pinned at its start, so
# that offset looked a whole payload past a 32 KiB window: the connection was
# closed with FLOW_CONTROL_ERROR against a peer that had done nothing wrong.
# The check also sends 64 bytes PAST the end, which must STILL be refused --
# without that half it would pass just as well against a server that stopped
# checking the bound at all.
out3=$(timeout 120 python3 test/quic/h3_fin_at_limit_test.py ${P61498} 2>&1)
case "$out3" in ok*) true ;; *) false ;; esac
check "h3 a stream ended at the flow-control limit is not a violation ($out3)" $?
# An upload in progress survives other connections ending. A teardown releases
# all RA_CTXS contexts and closes any descriptor they hold, but "holds one" was
# spelled != -1 while a freshly allocated connection slot is ZEROED -- so every
# connection that ended closed fd 0 once per unused context, and fd 0 is
# routinely another request's capture file (the worker closes stdin). That
# upload then died with a 413 naming no method and no path.
out4=$(timeout 120 python3 test/quic/h3_capture_fd_test.py ${P61498} 2>&1)
case "$out4" in ok*) true ;; *) false ;; esac
check "h3 an upload survives other connections being torn down ($out4)" $?
# A body split across several DATA frames, where a non-final one is big enough
# to take the capture-file path. Closing a payload region leaves through the
# done-check with nothing to feed, and the grant lived only on the feed's tail
# -- so the peer was left holding a ceiling equal to the base, with no credit
# for the next frame's header, and both sides waited for ever. Every other h3
# upload check sends ONE DATA frame, which is what hid it.
out5=$(timeout 120 python3 test/quic/h3_multi_data_test.py ${P61498} 2>&1)
case "$out5" in ok*) true ;; *) false ;; esac
check "h3 a body in several DATA frames keeps its credit ($out5)" $?
# Several uploads at once on ONE connection. Every other upload check runs one
# request at a time, so nothing asked what happens when the RA_CTXS (6)
# reassembly contexts are all in use -- which a browser posting several files
# does immediately. Six must be served byte-exact (the bodies differ in length,
# so a reassembly landing in the wrong context cannot pass), and past six the
# rest must be REFUSED with H3_REQUEST_REJECTED rather than dropped: that is
# what makes a limit of six acceptable, because the client is told it may
# retry. A stream ending in NEITHER a response nor a reset is the regression.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    # The LAST packet of an exchange can only be recovered by the probe timer:
    # tx_detect_loss needs LINNEA_QUIC_LOSS_THRESH later packets acknowledged and
    # there are none after the last one. So the timer's value IS the tail latency,
    # and it was the 1022 ms kInitialRtt guess on every connection because no RTT
    # sample was ever taken -- the largest acknowledged packet is usually one of
    # our own bare ACKs, which were emitted with no send time recorded, so the
    # lookup missed and the sample was discarded. Measured 1035 ms before, 33 ms
    # after. The bound is generous: anything near a second means the sampling has
    # stopped working again, whatever the box is doing.
    # A browser-shaped upload: several LARGE DATA frames, which is what a Chrome
    # netlog showed (three of 371,712 bytes for 1 MB). The stall lives at the
    # frame BOUNDARY -- inside a payload the ceiling runs ahead of what has
    # landed, so every other upload check here is single-frame and blind to it.
    # Chrome blocked five times on it, for ~390 ms of a 3.1 s upload.
    #
    # WHAT IS ASSERTED IS WHERE THE CEILING STOPS, not a time: no grant may land
    # on a payload's end, because a peer holding one of those cannot start the
    # next frame until this one is whole and a further grant has come back. That
    # is exact and needs no round trip, which matters because loopback grants
    # instantly and no timing bound here separates the builds (the test's own
    # header records the measurements that showed it, and why).
    out10=$(timeout 180 python3 test/quic/h3_upload_frames.py localhost ${P61498} 3 371712 --max-blocked 0 --rtt-ms 20 2>&1)
    check "h3 a browser-shaped multi-frame upload is invited past every frame ($out10)" $?
    # ...and the same shape driven at ~19 MB/s, which is what it takes to make a
    # boundary cost anything on loopback: the congestion window and the pacer
    # both lifted, so the server's window is the only brake and every boundary
    # is crossed by a STREAM frame straddling the payload's end. That split is
    # the new code; this is what runs it at rate.
    out11=$(timeout 180 python3 test/quic/h3_upload_frames.py localhost ${P61498} 10 400000 --max-blocked 0 --rtt-ms 40 --fast-client 2>&1)
    check "h3 ...and the same at 19 MB/s, every boundary a straddling frame ($out11)" $?
    # THE OTHER BROWSER'S SHAPE, and the one every other upload check here misses:
    # frames SMALLER than the advertised window. Firefox frames a body that way
    # and Chrome does not, so a rule keyed on a frame's size treats them
    # differently -- which is exactly how a build that gave Chrome 2.9 MB/s and
    # Firefox 440 kB/s on the same 40 MB file passed this suite 693/0.
    #
    # What it asserts is the window the peer ends up with, not a time: the server
    # lends a big buffer for the duration of a body and grants half of whatever
    # buffer a stream holds, so a ceiling step wider than the advertised window
    # is proof the lend happened. Measured 525344 against 8945 on the build that
    # shipped the fault.
    #
    # --max-grants rides along on the same run because this is the framing that
    # provokes it: 500 frames of 8 KiB each open a capture-file region, and a
    # region fires the "last step up to the cap" grant on its first evaluation.
    # Measured on this exact check: 500 grants against 8, and the widest ceiling
    # STEP falls from 524480 to 8195 with it -- so the peer is re-granted a
    # frame at a time, and the borrow assertion above reads that as no buffer
    # having been lent at all. The bound of 150 sits between the two.
    out12=$(timeout 180 python3 test/quic/h3_upload_frames.py localhost ${P61498} 500 8192 --rtt-ms 20 --expect-borrow --max-grants 150 2>&1)
    check "h3 a body framed SMALL still gets a real window, and not a grant per frame ($out12)" $?
    out8=$(timeout 120 python3 test/quic/h3_tail_loss.py localhost ${P61498} /api/simple --drop 1 --max-ms 400 2>&1)
    check "h3 a lost final response is recovered from a MEASURED rtt ($out8)" $?
    out9=$(timeout 120 python3 test/quic/h3_tail_loss.py localhost ${P61498} /api/simple --drop 0 --max-ms 400 2>&1)
    check "h3 ...and the same exchange with nothing dropped ($out9)" $?
    out7=$(timeout 200 python3 test/quic/h3_concurrent_uploads_test.py ${P61498} 2>&1 | tail -1)
    case "$out7" in ok*) true ;; *) false ;; esac
    check "h3 six concurrent uploads on one connection ($out7)" $?
else
    check "h3 concurrent uploads (skipped: aioquic/pylsqpack unavailable)" 0
fi
# A peer that says it is blocked must be told the window again. MAX_DATA rides
# whatever 1-RTT packet is going out, and for an uploading peer that is usually
# a bare ACK -- which this server emits UNTRACKED, so a lost one is never
# retransmitted, and the next grant only fires when more data arrives, which is
# what a blocked peer cannot send. DATA_BLOCKED is the peer's own remedy under
# RFC 9000 4.1 and was parsed only to be stepped over.
if python3 -c 'import aioquic' 2>/dev/null; then
    outb=$(timeout 90 python3 test/quic/h3_data_blocked_test.py ${P61498} 2>&1)
    case "$outb" in ok*) true ;; *) false ;; esac
    check "h3 DATA_BLOCKED re-advertises the connection window ($outb)" $?
else
    check "h3 DATA_BLOCKED (skipped: aioquic unavailable)" 0
fi
# A body the server CANNOT CAPTURE must not be reported as one the client sent
# too much of. Opening the capture file, writing it, a full filesystem and a
# payload fragmented past the range list all returned a bare -1, and the caller
# turned every -1 into the same verdict as a body past max_body: 413. The
# access line carries no method and no path (the head never parsed), so a
# failed write and an oversized upload were indistinguishable in the log too --
# which is how a capture file closed by another connection went unattributed.
# The check walks 200 -> 413 -> 500 -> 200, the last so that a server which
# answered 500 for ever afterwards could not pass it.
mkdir -p test/spill_fail
start_server $CFG/tls-h3-spillfail.json
P61492=$SRV_PORT
h3sf_pid=$SRV_PID
sleep 0.3
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    out6=$(timeout 200 python3 test/quic/h3_capture_fail_test.py ${P61492} test/spill_fail 2>&1)
    case "$out6" in ok*|skipped*) true ;; *) false ;; esac
    check "h3 an uncapturable body is a 500, not the client's fault ($out6)" $?
else
    check "h3 uncapturable body (skipped: aioquic/pylsqpack unavailable)" 0
fi
kill $h3sf_pid 2>/dev/null
wait $h3sf_pid 2>/dev/null
chmod 755 test/spill_fail 2>/dev/null
kill $spill_pid $h3big_pid $spill_backend_pid 2>/dev/null
wait $spill_pid 2>/dev/null
wait $spill_backend_pid 2>/dev/null

