#!/usr/bin/env bash
# Test suite for the linnea server. Run from anywhere; exits non-zero
# if any test fails.
set -u
cd "$(dirname "$0")/.."

BIN=./bin/linnea
LOG=test/linnea.log
pass=0
fail=0
rm -f "$LOG"

# run_test <name> <expected-exit> <stdout|stderr> <grep-pattern> <cmd...>
run_test() {
    local name=$1 want_rc=$2 stream=$3 pattern=$4
    shift 4
    local tmp stdout stderr rc text
    tmp=$(mktemp)
    stdout=$("$@" 2>"$tmp")
    rc=$?
    stderr=$(<"$tmp")
    rm -f "$tmp"
    if [ "$stream" = stdout ]; then text=$stdout; else text=$stderr; fi
    if [ "$rc" -eq "$want_rc" ] && printf '%s' "$text" | grep -qF "$pattern"; then
        echo "PASS: $name"
        pass=$((pass + 1))
    else
        echo "FAIL: $name (exit=$rc, wanted $want_rc; pattern: $pattern)"
        echo "  stdout: $stdout"
        echo "  stderr: $stderr"
        fail=$((fail + 1))
    fi
}

# check <name> <condition-exit-code (0 = pass)>
check() {
    if [ "$2" -eq 0 ]; then
        echo "PASS: $1"
        pass=$((pass + 1))
    else
        echo "FAIL: $1"
        fail=$((fail + 1))
    fi
}

# workers_of <master-pid>: the sorted worker PIDs of a running server. A crash
# is invisible through a fresh request because the master respawns the worker,
# so an attack test compares this before and after: any change is a crash.
workers_of() { pgrep -P "$1" 2>/dev/null | sort | tr '\n' ' '; }

# --- config parsing and validation ---
run_test "good config"     124 stdout "server 1: host=127.0.0.1 port=47090 hostname=two.test locations=3" \
    timeout 0.5 $BIN --config test/configs/listen.json
run_test "config dump"     124 stdout "config: 3 servers timeout=2 max_connections=64" \
    timeout 0.5 $BIN --config test/configs/listen.json
run_test "location dump"   124 stdout "location 1: prefix=/sub root=test/www" \
    timeout 0.5 $BIN --config test/configs/listen.json
run_test "bad timeout"     1 stderr "timeout must be between 1 and 3600" \
    $BIN --config test/configs/bad-timeout.json
run_test "workers dump"    124 stdout "workers=2" \
    timeout 0.5 $BIN --config test/configs/listen.json
run_test "bad workers"     1 stderr "workers must be between 1 and 256" \
    $BIN --config test/configs/bad-workers.json
run_test "invalid host"    1 stderr "invalid host address" \
    $BIN --config test/configs/bad-host.json
# a hard fd limit below the configured pool is fatal: the pool could never
# fill, and accept would fail with EMFILE while the server thought it had room
run_test "fd limit too low" 1 stderr "file descriptor limit too low" \
    bash -c "ulimit -n 200; exec $BIN --config test/configs/listen.json"
# a low SOFT limit is not fatal — a process may raise its own up to the hard
# limit, so the server does that for itself rather than refusing to start
run_test "fd soft limit raised" 124 stdout "config:" \
    bash -c "ulimit -S -n 64; exec timeout 0.5 $BIN --config test/configs/listen.json"
run_test "missing argv"    1 stderr "usage:" \
    $BIN
run_test "missing file"    1 stderr "cannot open config file" \
    $BIN --config test/configs/does-not-exist.json
run_test "truncated json"  1 stderr "parse error at line" \
    $BIN --config test/configs/truncated.json
run_test "port too large"  1 stderr "port" \
    $BIN --config test/configs/bad-port-large.json
run_test "port zero"       1 stderr "port" \
    $BIN --config test/configs/bad-port-zero.json
run_test "empty servers"   1 stderr "at least one server" \
    $BIN --config test/configs/empty-servers.json
run_test "unknown key"     1 stderr "unknown key" \
    $BIN --config test/configs/unknown-key.json
run_test "escape sequence" 1 stderr "escape sequences not supported" \
    $BIN --config test/configs/escape.json
run_test "location no prefix" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN --config test/configs/location-missing-prefix.json
run_test "location root+proxy" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN --config test/configs/location-both-kinds.json
run_test "location root+redirect" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN --config test/configs/location-root-and-redirect.json
run_test "redirect dump"   124 stdout "prefix=/old redirect=https://example.com" \
    timeout 0.5 $BIN --config test/configs/listen.json
run_test "bad redirect target" 1 stderr "redirect target must start with http:// or https://" \
    $BIN --config test/configs/bad-redirect-target.json
run_test "bad proxy address" 1 stderr "invalid proxy address" \
    $BIN --config test/configs/bad-proxy-addr.json
run_test "prefix not absolute" 1 stderr "location prefix must start with '/'" \
    $BIN --config test/configs/location-bad-prefix.json
run_test "empty locations"  1 stderr "at least one location" \
    $BIN --config test/configs/empty-locations.json
# the middle server reuses the hostname on another port, which is fine;
# the clash is on the shared listener, case-insensitively
run_test "duplicate hostname" 1 stderr "duplicate hostname DUP.Test on 127.0.0.1:47080" \
    $BIN --config test/configs/dup-hostname.json

# --- TLS config: "cert" and "key" are both-or-neither, and servers sharing
# --- a listener must agree (SNI picks the cert within a TLS listener,
# --- but TLS and plaintext cannot share a socket)
run_test "tls dump"        124 stdout "tls=on cert=test/tls/server.crt" \
    timeout 0.5 $BIN --config test/configs/tls.json
run_test "sni dump"        124 stdout "hostname=sni.test tls=on cert=test/tls/sni.crt" \
    timeout 0.5 $BIN --config test/configs/tls-sni.json
run_test "tls cert without key" 1 stderr "server needs both cert and key, or neither" \
    $BIN --config test/configs/bad-cert-only.json
run_test "tls listener mismatch" 1 stderr "servers sharing a listener must all set TLS or none" \
    $BIN --config test/configs/bad-tls-mismatch.json

# --- crypto self-test: known-answer vectors for the TLS primitives ---
# Build the unit-test binaries here rather than trusting what is on disk. `make`
# does not produce them, and the checks below only test for existence — so a tree
# that has been cleaned reports a failure that looks like a real one, while a
# STALE binary is worse: it passes, silently testing code that no longer exists.
make -s bin/linnea-selftest bin/linnea-quictest bin/linnea-rtxtest >/dev/null 2>&1
if [ -x ./bin/linnea-selftest ]; then
    if ./bin/linnea-selftest >/tmp/linnea_selftest.out 2>&1; then
        check "crypto selftest ($(tr '\n' ' ' </tmp/linnea_selftest.out))" 0
    else
        check "crypto selftest" 1
        cat /tmp/linnea_selftest.out
    fi
    rm -f /tmp/linnea_selftest.out
else
    check "crypto selftest (binary not built — run 'make selftest')" 1
fi

# QUIC crypto known-answer tests (RFC 9001 / 9000). Built by `make quictest`.
if [ -x ./bin/linnea-quictest ]; then
    if ./bin/linnea-quictest >/tmp/linnea_quictest.out 2>&1; then
        check "quic crypto selftest ($(tr '\n' ' ' </tmp/linnea_quictest.out))" 0
    else
        check "quic crypto selftest" 1
        cat /tmp/linnea_quictest.out
    fi
    rm -f /tmp/linnea_quictest.out
else
    check "quic crypto selftest (binary not built — run 'make quictest')" 1
fi

# QUIC on the wire: a standalone UDP receiver decrypts a real Initial packet
# built by aioquic (the QUIC/HTTP-3 reference client).
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quicserver ]; then
    timeout 10 ./bin/linnea-quicserver >/tmp/linnea_quicsrv.out 2>&1 &
    qsrv=$!
    sleep 0.4
    python3 test/quic/h3_initial.py 47500 >/dev/null 2>&1
    sleep 0.4
    wait $qsrv 2>/dev/null
    # decrypt the Initial, recover the ClientHello, and read its SNI + h3 ALPN
    grep -q "quic-initial sni=localhost alpn-h3=1" /tmp/linnea_quicsrv.out
    check "quic: decrypt aioquic Initial + parse ClientHello (SNI, h3 ALPN)" $?
    rm -f /tmp/linnea_quicsrv.out
else
    check "quic wire test (skipped: aioquic or quicserver unavailable)" 0
fi

# QUIC transport parameters (for EncryptedExtensions): aioquic parses linnea's
# encoding and the values round-trip.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quictp ]; then
    ./bin/linnea-quictp | python3 test/quic/tp_parse.py >/dev/null 2>&1
    check "quic: transport parameters parse in aioquic" $?
else
    check "quic transport-params test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC ServerHello (first message of the handshake flight): aioquic's TLS
# parser accepts it and the negotiated profile round-trips.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quicsh ]; then
    ./bin/linnea-quicsh | python3 test/quic/sh_parse.py >/dev/null 2>&1
    check "quic: ServerHello parses in aioquic (x25519, TLS 1.3)" $?
else
    check "quic ServerHello test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC EncryptedExtensions (h3 ALPN + transport parameters): aioquic's TLS
# parser reads the ALPN and the transport-parameters extension decodes.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quicee ]; then
    ./bin/linnea-quicee | python3 test/quic/ee_parse.py >/dev/null 2>&1
    check "quic: EncryptedExtensions parse in aioquic (h3 + transport params)" $?
else
    check "quic EncryptedExtensions test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC Certificate message: the real test chain, framed and parsed by aioquic.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quiccert ]; then
    ./bin/linnea-quiccert | python3 test/quic/cert_parse.py >/dev/null 2>&1
    check "quic: Certificate message parses in aioquic" $?
else
    check "quic Certificate test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC CertificateVerify: the ECDSA signature verifies against the test cert.
if python3 -c 'import aioquic, cryptography' 2>/dev/null && [ -x ./bin/linnea-quiccv ]; then
    ./bin/linnea-quiccv | python3 test/quic/cv_verify.py >/dev/null 2>&1
    check "quic: CertificateVerify signature verifies against the cert" $?
else
    check "quic CertificateVerify test (skipped: deps unavailable)" 0
fi

# QUIC Finished: the HMAC verify_data matches an independent computation.
if python3 -c 'import aioquic, cryptography' 2>/dev/null && [ -x ./bin/linnea-quicfin ]; then
    ./bin/linnea-quicfin | python3 test/quic/fin_verify.py >/dev/null 2>&1
    check "quic: Finished verify_data matches the reference HMAC" $?
else
    check "quic Finished test (skipped: deps unavailable)" 0
fi

# QUIC handshake on the wire: linnea replies to a client Initial with a
# coalesced Initial (ACK + ServerHello) and Handshake packet (EE, Certificate,
# CertificateVerify, Finished); aioquic completes the TLS 1.3 handshake.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/hs_test.py 47501 >/dev/null 2>&1
    check "quic: full handshake completes in aioquic (h3 negotiated)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "quic handshake test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC handshake confirmation: the client sends its Finished; linnea decrypts
# the Handshake packet, verifies the MAC (prints CFIN-OK), and replies with
# HANDSHAKE_DONE in a 1-RTT packet. cfin_test.py asserts aioquic accepts it and
# confirms the handshake — both server-side auth and the 1-RTT keys.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    cfinlog=$(mktemp)
    timeout 10 ./bin/linnea-quichs >"$cfinlog" 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/cfin_test.py 47501 >/dev/null 2>&1
    cfinrc=$?
    sleep 0.3
    if [ $cfinrc -eq 0 ] && grep -q CFIN-OK "$cfinlog"; then cfinok=0; else cfinok=1; fi
    check "quic: client Finished verified + HANDSHAKE_DONE confirms handshake" $cfinok
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
    rm -f "$cfinlog"
else
    check "quic handshake-confirm test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC connection pool: allocation, exhaustion, the idle sweep and slot reuse.
if [ -x ./bin/linnea-pooltest ]; then
    out=$(./bin/linnea-pooltest)
    rc=$?
    check "quic pool selftest ($out)" $rc
else
    check "quic pool selftest (skipped: binary unavailable)" 0
fi

# QUIC 1-RTT loss recovery: the sent-packet ring (record/ack-range/inflight) and
# the ACK-frame range decoder, in isolation and together.
if [ -x ./bin/linnea-rtxtest ]; then
    out=$(./bin/linnea-rtxtest)
    rc=$?
    check "quic loss-recovery selftest ($out)" $rc
else
    check "quic loss-recovery selftest (skipped: binary unavailable)" 0
fi

# 0-RTT anti-replay: the strike register accepts a fresh binder, rejects a replay
# within the window, reuses expired slots, and fails closed when full.
if [ -x ./bin/linnea-replaytest ]; then
    out=$(./bin/linnea-replaytest)
    rc=$?
    check "quic 0-RTT anti-replay + ticket-lifetime selftest ($out)" $rc
else
    check "quic 0-RTT anti-replay selftest (skipped: binary unavailable)" 0
fi

# QPACK decode: field sections encoded by pylsqpack (static + literals + Huffman,
# zero dynamic table) decode to the right HTTP/3 request pseudo-headers.
if python3 -c 'import pylsqpack' 2>/dev/null && [ -x ./bin/linnea-qpacktest ]; then
    python3 test/quic/qpack_test.py >/dev/null 2>&1
    check "qpack: HTTP/3 request headers decode (static, literal, Huffman)" $?
else
    check "qpack decode test (skipped: pylsqpack/binary unavailable)" 0
fi

# HTTP/3 request framing: linnea walks the request-stream frames, skips
# DATA/unknown frames, and QPACK-decodes the HEADERS frame to the request.
if python3 -c 'import pylsqpack' 2>/dev/null && [ -x ./bin/linnea-h3test ]; then
    python3 test/quic/h3_test.py >/dev/null 2>&1
    check "h3: request HEADERS frame parsed and decoded (skips GREASE/unknown)" $?
else
    check "h3 framing test (skipped: pylsqpack/binary unavailable)" 0
fi

# HTTP/3 response building: linnea frames a HEADERS (QPACK-encoded status,
# content-type, content-length) + DATA response that pylsqpack decodes.
if python3 -c 'import pylsqpack' 2>/dev/null && [ -x ./bin/linnea-h3resp ]; then
    python3 test/quic/h3resp_test.py >/dev/null 2>&1
    check "h3: response HEADERS+DATA built and QPACK-decodes (status/ct/cl)" $?
else
    check "h3 response test (skipped: pylsqpack/binary unavailable)" 0
fi

# End-to-end HTTP/3: complete the handshake, send an h3 GET, and check linnea
# replies with a 200 HEADERS+DATA response over the request stream.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_e2e_test.py 47501 >/dev/null 2>&1
    check "h3: serves real static files over QUIC (MIME, index, 404)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "h3 end-to-end test (skipped: deps unavailable)" 0
fi

# Several HTTP/3 requests on one connection: three GETs on three streams arrive
# coalesced in one packet; linnea answers each on its own stream.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_multi_test.py 47501 >/dev/null 2>&1
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
    timeout 10 ./bin/linnea-quichs >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_ticket_test.py 47501 >/dev/null 2>&1
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
    timeout 12 ./bin/linnea-quichs >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_resume_test.py 47501 >/dev/null 2>&1
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
    timeout 12 ./bin/linnea-quichs >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_0rtt_test.py 47501 >/dev/null 2>&1
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
    python3 test/mk_test_image.py test/www/linnea.png >/dev/null    # served over h3
    $BIN --config test/configs/tls-h3.json >/dev/null 2>&1 &
    h3_pid=$!
    sleep 0.5
    python3 test/quic/h3_e2e_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): real server serves static files over QUIC" $?

    python3 test/quic/h3_etag_test.py 47452 >/dev/null 2>&1
    check "h3 validators, date + server headers, conditional 304s" $?

    python3 test/quic/h3_range_test.py 47452 >/dev/null 2>&1
    check "h3 range 206/416, if-range, cache-control, chunked slice" $?

    python3 test/quic/h3_enc_test.py 47452 >/dev/null 2>&1
    check "h3 pre-compressed variants (br/gzip, vary, variant etag 304)" $?

    python3 test/quic/h3_qpack_err_test.py 47452 >/dev/null 2>&1
    check "h3 undecodable field section ends the connection (0x200)" $?
    python3 test/quic/h3_multi_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): several requests on one connection" $?
    python3 test/quic/h3_conns_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): two interleaved connections" $?
    # several workers each bind the QUIC port with SO_REUSEPORT; the kernel
    # steers by 4-tuple so a connection always reaches the worker holding it
    python3 test/quic/h3_workers_test.py 47452 8 >/dev/null 2>&1
    check "h3 (io_uring): connections spread across workers are all served" $?

    python3 test/quic/h3_ack_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): replies acknowledge received packets" $?

    # loss recovery: drop the server's reply and it must retransmit (under a
    # fresh packet number) once its probe timeout fires
    python3 test/quic/h3_rtx_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): a dropped reply is retransmitted after the PTO" $?

    # control streams: the server opens its control stream (SETTINGS first) and
    # the QPACK encoder/decoder streams once the handshake completes
    python3 test/quic/h3_control_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): server opens control + QPACK streams with SETTINGS" $?

    # receive side: a client control stream that opens with SETTINGS is accepted
    # and served; one whose first frame is not SETTINGS is closed (H3_MISSING_SETTINGS)
    python3 test/quic/h3_settings_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): client control stream validated (SETTINGS-first enforced)" $?

    # and the rest of the control stream's frame sequence, not just its first two
    # bytes: DATA/HEADERS/PUSH_PROMISE, the reserved HTTP/2 types and a second
    # SETTINGS end the connection, GREASE and the control frames are skipped by
    # length, and a header split across STREAM frames still parses
    timeout 180 python3 test/quic/h3_ctrl_frames_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): control-stream frames walked and validated" $?

    # request bodies: POST is a 405 now, but the body must still be reassembled
    # whole and the stream answered, with its flow-control credit settled
    python3 test/quic/h3_body_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): a multi-packet request body is consumed and answered" $?

    # large responses: a 600 KB file streams as ack-clocked STREAM-frame chunks
    # (each datagram under the 1200-byte floor); one dropped chunk is rebuilt
    # from the file after the PTO; a small GET is answered mid-transfer; a
    # client whose flow-control window cannot take the file gets a 503
    python3 test/quic/h3_big_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): large response streamed in chunks (loss + interleave + 503)" $?

    # four large (chunked) responses requested at once: all stream concurrently,
    # interleaved by the pump over the shared congestion window, none refused —
    # each arrives byte-exact. This is a full browser page load (a 503 on a
    # concurrent large request made Firefox abandon h3 for h2).
    python3 test/quic/h3_queue_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): four concurrent large responses, all intact" $?

    # concurrent large responses through an emulated lossy, REORDERING network
    # (both directions), across several seeds — the conditions a real browser hits
    # and that lockstep tests miss. Exercises ack-based fast retransmit and the
    # priority pump; every stream must arrive byte-exact on every seed.
    python3 test/quic/h3_stress_test.py 47452 6 6 3 >/dev/null 2>&1
    check "h3 (io_uring): concurrent responses survive loss + reordering" $?

    # RFC 9218 priority: default (non-incremental) responses are served to
    # completion in arrival order — sequentially, so complete images appear sooner
    # — and a `priority: u=0` request jumps ahead of default-urgency ones.
    python3 test/quic/h3_priority_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): responses scheduled by RFC 9218 priority" $?

    # static files answer GET and HEAD (and h3's own POST echo); every other
    # method used to fall through and be SERVED AS A GET, body and all, where
    # h1 and h2 both answer 405. The method is matched case-sensitively.
    timeout 200 python3 test/quic/h3_method_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): unknown methods get 405, not the file" $?

    # and the client can change its mind afterwards: a PRIORITY_UPDATE on the
    # control stream reprioritises a response already streaming, and one that
    # overtakes the request it names is kept and applied when that stream opens
    timeout 300 python3 test/quic/h3_priority_update_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): PRIORITY_UPDATE reprioritises a response" $?

    # a size/boundary/request-style matrix: every response, from 0 bytes through
    # the inline/chunked threshold and exact chunk multiples to 200 KB, must
    # terminate (deliver a FIN) — sequentially reusing one connection, all at once
    # under the priority scheduler, and as a HEAD. A request that never finishes
    # fails here.
    python3 test/quic/h3_matrix_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): size/boundary/HEAD/concurrent matrix all terminate" $?

    # connection reuse: far more than the advertised 100 bidi streams on ONE
    # connection (a browser reusing it across refreshes) — the server must raise
    # the peer's limit with MAX_STREAMS or new requests can't be sent (images stop
    # loading, h2 fallback after ~30s).
    python3 test/quic/h3_reuse_test.py 47452 250 >/dev/null 2>&1
    check "h3 (io_uring): reused connection past 100 streams (MAX_STREAMS)" $?

    # under load: many concurrent connections (browser tabs / refreshes) plus a
    # burst of open-load-close churn — every request completes and the workers stay
    # alive with no descriptor leak.
    python3 test/quic/h3_load_test.py 47452 12 4 >/dev/null 2>&1
    check "h3 (io_uring): concurrent connections + churn under load" $?

    # browser reloads on one reused connection: each reload cancels the previous
    # page's in-flight downloads (STOP_SENDING). The server must tear a cancelled
    # stream down or its abandoned chunks pin the congestion window and, after
    # enough reloads, the connection stalls (hang, then h2 fallback).
    python3 test/quic/h3_reload_test.py 47452 10 >/dev/null 2>&1
    check "h3 (io_uring): reload-cancel (STOP_SENDING) does not stall the connection" $?

    # connection-level credit (MAX_DATA) must be read from every packet, including
    # the ones that arrive while no response stream is open — which is exactly what a
    # reload's cancels leave behind. The peer sends each value once (its packet is
    # acknowledged), so a raise the server misses is gone for good: the server then
    # stalls at a window the peer has long since widened, with nothing in flight.
    python3 test/quic/h3_maxdata_test.py 47452 8 >/dev/null 2>&1
    check "h3 (io_uring): MAX_DATA is absorbed with no response stream open" $?

    # a request whose ack is lost is retransmitted by the client; the server must
    # ack the retransmit, not serve the stream a second time — a duplicate response
    # slot resends the whole body and pins the shared congestion window (the real-
    # browser wedge). Several chunked streams over one connection, ack-loss forced.
    python3 test/quic/h3_dup_request_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): retransmitted request is not served twice (no duplicate wedge)" $?

    # an Initial's header carries the token a client echoes from a Retry, and the
    # server copies that header into a fixed scratch buffer to authenticate the
    # packet. The token is client-supplied, so an oversized one must be refused
    # rather than copied over whatever follows the buffer — a worker that dies here
    # is a remote, pre-handshake stack overwrite with attacker-chosen bytes.
    python3 test/quic/h3_initial_token_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): oversized Initial token refused, not copied past its buffer" $?

    # a flood of Initials that are never answered must not fill the connection pool
    # and lock real clients out: once enough slots are held by unvalidated peers the
    # server demands a Retry token, which only a client at a real address can echo.
    # Runs late and settles afterwards — it deliberately leaves the pool under
    # pressure, and the pool needs a moment to reclaim the forged slots.
    python3 test/quic/h3_retry_test.py 47452 300 >/dev/null 2>&1
    check "h3 (io_uring): forged-Initial flood does not lock out real clients" $?
    sleep 6

    # a spoofed packet from a different source, carrying a valid connection id but
    # no valid AEAD tag, must NOT redirect the server's sends (RFC 9000 9.3): the
    # peer address is adopted only from an authenticated packet.
    python3 test/quic/h3_migration_spoof_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): unauthenticated source does not redirect the connection" $?

    # and the replayed half: a captured 1-RTT datagram resent from another source
    # carries a VALID tag, so authenticity alone cannot gate the address change.
    # RFC 9000 12.3 (discard an already-processed packet number) + 9.3 (only the
    # highest-numbered packet may move the address) are what close it.
    python3 test/quic/h3_replay_spoof_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): replayed packet does not redirect the connection" $?

    # the server's own first flight must survive being lost. There was no loss
    # recovery for the Initial or Handshake spaces at all, so dropping that one
    # ~1150-byte datagram ended the handshake and the client fell back to TCP.
    python3 test/quic/h3_hs_rtx_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): a lost handshake flight is retransmitted" $?

    # Frames coalesced ahead of a request must not hide it (RFC 9000 12.4). Six
    # scanners each carried a partial frame-length table and stopped at the first
    # type theirs did not list, so a CONNECTION_CLOSE hid what followed it and an
    # unknown type hid the rest of the packet from all six — silently, with the
    # packet acknowledged, so the client never retried.
    python3 test/quic/h3_frame_walk_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): coalesced frames do not hide the rest of the packet" $?

    # the same field rules over HTTP/3 (RFC 9114 4.2, 4.3.1) — one shared
    # decoder, and this side had it worse: the connection-specific names were
    # matched only inside the proxy rebuild, which HTTP/3 never enters at all.
    python3 test/quic/h3_field_rules_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): request field rules" $?

    # The server must not name a protocol the client never offered (RFC 7301
    # 3.2): build_ee wrote "h3" into EncryptedExtensions without ever reading
    # the client's list, so a doq or hq-interop client was told it had h3.
    python3 test/quic/h3_alpn_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): ALPN is checked, not assumed" $?

    # ...and a refusal must SAY SO (RFC 9001 4.8): the TLS alert becomes a QUIC
    # error of 0x0100+description in a CONNECTION_CLOSE. Every handshake-space
    # refusal used to be silent, because the only close path needed 1-RTT keys
    # that do not exist that early, so the client could not tell "refused" from
    # "lost" and simply retransmitted its ClientHello until it gave up.
    python3 test/quic/h3_hs_close_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): a refused handshake closes with the TLS alert" $?

    # RESET_STREAM's Final Size is OURS, not the peer's (RFC 9000 19.4). Resetting
    # a malformed request reported the client's request length, so the peer held
    # connection-level credit for data it would never be sent — and one large
    # enough obliges a conforming client to close with FLOW_CONTROL_ERROR.
    python3 test/quic/h3_reset_final_size_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): RESET_STREAM reports our own final size" $?

    # ...and the code that reset carries has to say WHICH thing went wrong: a
    # truncated last frame is a connection error (7.1), a stream that never
    # carried HEADERS is H3_REQUEST_INCOMPLETE so the client may retry (4.1),
    # and only a request that decodes and then breaks a rule is MESSAGE_ERROR.
    python3 test/quic/h3_stream_codes_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): a failed request stream names its fault" $?

    # ...and the same preconditions over h3, so the answer does not depend on
    # which protocol carried the request (RFC 9110 13.1.1, 13.1.4, 13.2.2).
    python3 test/quic/h3_preconditions_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): If-Match and If-Unmodified-Since" $?

    # RFC 9114 6.2: a critical stream must not be closed BY ANY MEANS. Only a
    # FIN was noticed, so a peer could RESET_STREAM its control stream and the
    # connection carried on as though it still had one.
    python3 test/quic/h3_critical_reset_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): resetting a critical stream is detected" $?

    # h3-8: the QPACK encoder stream must be read, not ignored. We advertise
    # capacity 0, so the only legal instruction is Set Dynamic Table Capacity
    # to 0; an insert or another capacity means the peer's table state and
    # ours have silently diverged — QPACK_ENCODER_STREAM_ERROR. Also: a FIN
    # on a LATER frame of a QPACK stream is a critical-stream closure too.
    python3 test/quic/h3_qpack_enc_stream_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): QPACK encoder-stream instructions are policed" $?

    # h3-6: control-stream enforcement must survive reordering. A STREAM frame
    # delivered (and acked) ahead of the walked prefix used to be dropped, and
    # since a reordered frame comes only once, the hole was permanent — every
    # control-stream rule quietly stopped being enforced there. Held now, and
    # legal reordering must still close nothing.
    python3 test/quic/h3_ctrl_reorder_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): control-stream rules survive reordering" $?

    # An ack-eliciting packet MUST be acknowledged (RFC 9000 13.2.1). An ACK was
    # only built when the server had something of its own to send, so a lone PING
    # (a browser keepalive) or a lone stream reset drew nothing and the peer
    # resent it with a doubling timeout for the life of the connection.
    python3 test/quic/h3_ack_eliciting_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): a packet with nothing to answer is still acked" $?

    # the same for the handshake flights: no long-header packet authenticates its
    # sender, so neither a replayed Initial nor a forged Handshake may move the
    # peer address (RFC 9000 9 — no migration before the handshake is confirmed)
    python3 test/quic/h3_longhdr_spoof_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): spoofed long-header packets do not redirect the connection" $?

    # the client initiates a 1-RTT key update mid-transfer (RFC 9001 §6); the server
    # must derive the next key generation and follow, or it can no longer decrypt the
    # client's packets and the transfer wedges.
    python3 test/quic/h3_key_update_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): follows a client-initiated 1-RTT key update" $?

    # quic-8: after sending a CONNECTION_CLOSE the server keeps the closing state
    # for a while (RFC 9000 10.2), re-sending the close in response to the peer's
    # packets — so the peer learns the real error even if the first close is lost,
    # instead of the stateless reset a freed connection id would draw.
    python3 test/quic/h3_closing_state_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): closing state re-sends the close, no stateless reset" $?

    # quic-11: once the handshake is confirmed the server discards its Initial and
    # Handshake keys (RFC 9001 4.9/4.9.1) and drops any long-header packet rather
    # than AEAD-processing it under keys that are supposed to be gone. A burst of
    # such packets on an established connection must not disturb it.
    python3 test/quic/h3_post_handshake_long.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): long-header packets after confirmation are dropped" $?

    # a 1-RTT packet for a connection id we hold no state for gets a stateless reset
    # (RFC 9000 §10.3), so the peer fails fast instead of waiting out its idle timeout.
    python3 test/quic/h3_stateless_reset_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): stateless reset for an unknown connection id" $?

    # a peer that sends more request-stream data than the advertised window commits a
    # flow-control violation; the server closes with a transport CONNECTION_CLOSE
    # (FLOW_CONTROL_ERROR) rather than silently dropping (RFC 9000 §4.1 / §10.2).
    python3 test/quic/h3_flow_violation_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): flow-control violation closes with a transport error" $?

    # a long-header packet with an unsupported version draws a Version Negotiation
    # packet listing the versions we speak (RFC 9000 §6.1), so the client can retry.
    python3 test/quic/h3_version_negotiation_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): unsupported version draws Version Negotiation" $?

    # a full QUIC v2 (RFC 9369) handshake — different Initial salt, "quicv2" labels
    # and remapped long-header packet types — serving HTTP/3 byte-exact.
    python3 test/quic/h3_v2_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): QUIC v2 handshake serves HTTP/3" $?

    # a client whose Initials start above packet number 0 (Chrome starts at 1): the
    # ServerHello ACK must cover the real [min,max] range, not [0,max] — acking an
    # unsent packet is invalid and a strict client aborts to h2 (QUIC_INVALID_ACK_DATA).
    python3 test/quic/h3_pn_offset_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): ACK covers only received Initials (Chrome starts pn at 1)" $?

    # a real binary asset: a PNG served with the right MIME type, byte-exact,
    # over the chunked h3 path
    python3 test/quic/h3_image_test.py 47452 test/www >/dev/null 2>&1
    check "h3 (io_uring): PNG image served intact (image/png, chunked)" $?

    # a ClientHello too large for one Initial packet (as a browser's post-quantum
    # key share makes it) is reassembled across Initials by the client's original
    # DCID; a ClientHello with no x25519 share is refused without crashing
    python3 test/quic/h3_bigch_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): multi-packet ClientHello reassembled; no-x25519 refused" $?

    # ngtcp2/curl fragments the ClientHello into many small CRYPTO frames sent out
    # of offset order, several per packet; the reassembly must place each at its
    # offset, not assume order (this is what made real browsers fall back to h2)
    python3 test/quic/h3_frag_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): out-of-order multi-frame ClientHello reassembled" $?

    # the request-stream reassembler: a request too big for one packet, with the
    # datagrams reversed and shuffled, so a hole opens and later fills. Every
    # other h3 test sends a request that fits one packet, which never exercises
    # the arrived-bytes map at all
    timeout 120 python3 test/quic/h3_reorder_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): multi-packet request reassembled out of order" $?

    # a header section past our bound is our resource limit, not the peer's
    # encoder misbehaving: it must be answered on its own stream (431), not
    # reported as a decompression failure that takes the whole connection down
    timeout 60 python3 test/quic/h3_bigheaders_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): oversized header list gets 431, connection survives" $?

    # a malformed request whose stream has already ended is answered with a
    # reset; it used to be dropped, leaving the client waiting on a response
    # that could never come
    timeout 60 python3 test/quic/h3_malformed_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): malformed complete request is reset, not dropped" $?

    # session resumption: the real server issues a NewSessionTicket with the
    # early_data extension once the handshake completes
    python3 test/quic/h3_ticket_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): server issues a NewSessionTicket (early_data)" $?

    # and accepts it back: a second connection resumes with the ticket (PSK), so
    # the server skips the certificate
    python3 test/quic/h3_resume_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): resumes from a ticket (no certificate re-sent)" $?

    # 0-RTT: a resuming client's GET, sent as early data with the ClientHello, is
    # decrypted and served
    python3 test/quic/h3_0rtt_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): serves a 0-RTT request (early data)" $?

    # quic-6: the 0-RTT packet shares the Application pn space with 1-RTT and MUST
    # be acknowledged (RFC 9000 13.2.1); the server used to discard its number, so
    # the early request was never acked. The qlog must show the server ack cover
    # the packet number the client sent its 0-RTT on.
    python3 test/quic/h3_0rtt_ack_test.py 47452 >/dev/null 2>&1
    check "h3 (io_uring): the 0-RTT packet is acknowledged" $?

    # BPF connection-ID steering: a connection survives the client migrating to a
    # fresh source port. Needs CAP_BPF on the binary (a rebuild drops the file
    # capability), so it is skipped when the steering program could not load.
    if getcap "$BIN" 2>/dev/null | grep -q cap_bpf; then
        python3 test/quic/h3_migrate_test.py 47452 >/dev/null 2>&1
        check "h3 (io_uring): connection survives client migration (BPF CID steering)" $?
    else
        check "h3 (io_uring): CID steering (skipped: binary lacks CAP_BPF)" 0
    fi

    # Alt-Svc: the TCP responses advertise HTTP/3 on this port, which is how a
    # browser discovers it at all
    hdrs=$(curl -si --http1.1 --cacert test/tls/server.crt \
                --resolve localhost:47452:127.0.0.1 \
                https://localhost:47452/hello.txt)
    echo "$hdrs" | grep -qi 'alt-svc: h3=":47452"'
    check "h3 (io_uring): HTTP/1.1 advertises Alt-Svc for h3" $?
    hdrs=$(curl -si --http2 --cacert test/tls/server.crt \
                --resolve localhost:47452:127.0.0.1 \
                https://localhost:47452/hello.txt)
    echo "$hdrs" | grep -qi 'alt-svc: h3=":47452"'
    check "h3 (io_uring): HTTP/2 advertises Alt-Svc for h3" $?

    # the UDP listener must not disturb TCP on the same host and port
    body=$(curl -s --http2 --cacert test/tls/server.crt \
                 --resolve localhost:47452:127.0.0.1 \
                 https://localhost:47452/hello.txt)
    [ "$body" = "hello from linnea" ]
    check "h3 (io_uring): HTTP/2 over TCP still served on the same port" $?

    # a pre-auth malformed Initial (long-header Length rewritten to 0) must not
    # underflow the AEAD ciphertext length and crash a worker; the workers must
    # be the same processes afterwards, and normal h3 must still be served
    ulw_before=$(workers_of $h3_pid)
    python3 test/quic/h3_length_underflow_test.py 47452 >/dev/null 2>&1
    sleep 0.5
    python3 test/quic/h3_e2e_test.py 47452 >/dev/null 2>&1
    ulw_ok=$?
    ulw_after=$(workers_of $h3_pid)
    [ -n "$ulw_before" ] && [ "$ulw_before" = "$ulw_after" ] && [ $ulw_ok -eq 0 ]
    check "h3 (io_uring): malformed Length Initial crashes no worker (pre-auth)" $?

    # a resumption offer whose PskIdentity is longer than a real ticket must be
    # rejected before the AEAD: the open writes identity_len-28 bytes into a
    # 48-byte stack slot, so an oversized identity overwrote the return address
    # of a pre-auth path. Real resumption must keep working afterwards.
    pio_before=$(workers_of $h3_pid)
    python3 test/quic/h3_psk_id_overflow_test.py 47452 >/dev/null 2>&1
    sleep 0.5
    python3 test/quic/h3_resume_test.py 47452 >/dev/null 2>&1
    pio_ok=$?
    pio_after=$(workers_of $h3_pid)
    [ -n "$pio_before" ] && [ "$pio_before" = "$pio_after" ] && [ $pio_ok -eq 0 ]
    check "h3 (io_uring): oversized PskIdentity crashes no worker (pre-auth)" $?

    kill $h3_pid 2>/dev/null
    wait $h3_pid 2>/dev/null
else
    check "h3 io_uring tests (skipped: deps unavailable)" 0
fi

# Dual-stack IPv6: one AF_INET6 listener (host "::", IPV6_V6ONLY off) serves both
# families. A full h3 GET must complete over native IPv6 (::1) AND over IPv4
# (127.0.0.1) against that single listener — the native-v6 peer also exercises the
# 28-byte sockaddr_in6 handling on the receive, conn.peer and sendto-reply paths.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f test/linnea.log
    $BIN --config test/configs/tls-h3-v6.json >/dev/null 2>&1 &
    v6_pid=$!
    sleep 0.5
    python3 test/quic/h3_ipv6_test.py 47455 >/dev/null 2>&1
    check "h3 (io_uring): dual-stack — served over native IPv6 (::1) and IPv4" $?
    # TCP too: the same dual-stack socket answers HTTP/2 over native IPv6
    body=$(curl -s --http2 --cacert test/tls/server.crt \
                 --resolve localhost:47455:[::1] \
                 https://localhost:47455/hello.txt)
    [ "$body" = "hello from linnea" ]
    check "h3 (io_uring): dual-stack — HTTP/2 over TCP served on native IPv6" $?
    kill $v6_pid 2>/dev/null
    wait $v6_pid 2>/dev/null
    rm -f test/linnea.log
else
    check "dual-stack IPv6 test (skipped: deps unavailable)" 0
fi

# Q134: a trailing HEADERS frame (trailers) must not merge into the request
# and change the response — a trailer "range: bytes=0-4" used to turn a
# whole-file GET into a 206.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f test/linnea.log
    $BIN --config test/configs/tls-h3-drain.json >/dev/null 2>&1 &
    tr_master=$!
    sleep 0.5
    timeout 60 python3 test/quic/h3_trailer_test.py 47453 >/dev/null 2>&1
    check "h3 (io_uring): trailers do not influence the response" $?
    # Q136: frames illegal on a request stream (reserved h2 types, control/push
    # frames, DATA before HEADERS) are a connection error H3_FRAME_UNEXPECTED,
    # not silently ignored; GREASE/unknown stay ignored.
    timeout 90 python3 test/quic/h3_frame_reject_test.py 47453 >/dev/null 2>&1
    check "h3 (io_uring): illegal request-stream frames rejected (0x105)" $?
    kill $tr_master 2>/dev/null
    wait $tr_master 2>/dev/null
    for p in $(pgrep -f 'tls-h3-drain'); do kill -9 $p 2>/dev/null; done
    rm -f test/linnea.log
fi

# HTTP/3 GOAWAY on drain: a worker told to drain sends GOAWAY on its control
# stream so the client opens no new requests, then exits. A single-worker config
# keeps the signalling deterministic; the test kills the master itself.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f test/linnea.log
    $BIN --config test/configs/tls-h3-drain.json >/dev/null 2>&1 &
    ga_master=$!
    sleep 0.5
    python3 test/quic/h3_goaway_test.py 47453 $ga_master >/dev/null 2>&1
    check "h3 (io_uring): drain sends GOAWAY on the control stream" $?
    # Q120: the request that test served must be in the access log
    grep -qE 'request localhost from [0-9.:]+ "GET /hello.txt HTTP/3" 200 ' test/linnea.log
    check "h3 request access-logged" $?
    wait $ga_master 2>/dev/null
    pkill -f tls-h3-drain 2>/dev/null
    rm -f test/linnea.log
else
    check "h3 GOAWAY drain test (skipped: deps unavailable)" 0
fi

# Drain with an in-flight h3 response (Q117): the drain-exit test used to count
# only TCP connections, so a worker whose work was all QUIC exited the moment
# the drain began (and stopped re-arming the datagram recv besides) — the peer
# hung mid-download with nothing on the wire to tell it. Now the worker keeps
# receiving, finishes the response, says goodbye with CONNECTION_CLOSE
# (H3_NO_ERROR), and only then exits.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f test/linnea.log
    $BIN --config test/configs/tls-h3-drain.json >/dev/null 2>&1 &
    di_master=$!
    sleep 0.5
    timeout 40 python3 test/quic/h3_drain_inflight_test.py 47453 $di_master >/dev/null 2>&1
    check "h3 (io_uring): drain finishes the in-flight response, then closes" $?
    wait $di_master 2>/dev/null
    sleep 0.5
    ! pgrep -f 'tls-h3-drain\.json' >/dev/null
    check "h3 drain exits after the last QUIC connection" $?
    rm -f test/linnea.log
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
    rm -f test/linnea.log
    $BIN --config test/configs/tls-h3-drain.json >/dev/null 2>&1 &
    gr_master=$!
    sleep 0.5
    timeout 60 python3 test/quic/h3_goaway_reject_test.py 47453 $gr_master >/dev/null 2>&1
    check "h3 (io_uring): drain rejects disowned streams (0x10b), serves owned" $?
    kill $gr_master 2>/dev/null
    wait $gr_master 2>/dev/null
    pkill -f tls-h3-drain 2>/dev/null
    rm -f test/linnea.log
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
    rm -f test/linnea.log
    timeout 30 python3 test/quic/h3_steer_base_test.py \
        test/configs/tls-h3-drain.json 47453 >/dev/null 2>&1
    check "h3 (io_uring): upgrade handoff stamps the other steering half" $?
    rm -f test/linnea.log
else
    check "h3 steering handoff test (skipped: deps unavailable)" 0
fi

# Drain with an in-flight h2 response and a slow reader (Q117): the connection
# was freed once the last body byte reached the kernel, and close(2) with the
# client's unread WINDOW_UPDATEs queued answered with an RST that discarded
# the untransmitted tail of the send buffer — ~90% of the body arrived, then a
# reset. The lingering close (shutdown the write side, drain reads until the
# peer closes) delivers every byte.
rm -f test/linnea.log
python3 -c "open('test/www/h2drain.bin','wb').write(bytes(3000000))"
$BIN --config test/configs/tls-h3-drain.json >/dev/null 2>&1 &
h2d_master=$!
sleep 0.5
timeout 60 python3 test/tls/h2_drain_slow.py test/tls/server.crt 47453 $h2d_master >/dev/null 2>&1
check "http2 drain delivers the whole in-flight body to a slow reader" $?
wait $h2d_master 2>/dev/null
rm -f test/linnea.log test/www/h2drain.bin

# Large certificate chain (~5.2 KB, seven certs — over the old ~3.9 KB cap) on
# both transports. On h3 the flight is both larger than one datagram (QUIC forbids
# IP fragmentation, so the Certificate CRYPTO is split across <=MTU Handshake
# packets) and larger than the 3x amplification budget (RFC 9000 s8.1, so the tail
# is withheld until the client's address is validated, then resumed): the test
# confirms the first burst stays within 3x, no datagram breaches the 1200-byte
# floor, and the handshake completes. That the server even boots with this chain
# exercises the raised cap; the curl check confirms the same chain over h2/TCP.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f test/linnea.log
    $BIN --config test/configs/tls-h3-bigcert.json >/dev/null 2>&1 &
    bc_pid=$!
    sleep 0.6
    python3 test/quic/h3_bigcert_test.py 47454 >/dev/null 2>&1
    check "h3 (io_uring): large flight segmented + held to the 3x amp budget" $?
    body=$(curl -s --http2 --cacert test/tls/bigchain.crt \
                --resolve localhost:47454:127.0.0.1 https://localhost:47454/hello.txt)
    [ "$body" = "hello from linnea" ]
    check "h2 (kTLS): large certificate chain over TCP (past the old cap)" $?
    kill $bc_pid 2>/dev/null
    wait $bc_pid 2>/dev/null
    rm -f test/linnea.log
else
    check "h3 handshake segmentation/amplification test (skipped: deps unavailable)" 0
fi

# Acknowledgements: our reply must acknowledge the request packet, or the peer
# keeps retransmitting work already done.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_ack_test.py 47501 >/dev/null 2>&1
    check "quic: replies acknowledge the packets we received" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "quic ack test (skipped: deps unavailable)" 0
fi

# Connection churn: more connections than the pool has slots, each closing
# cleanly, must all be served — the slot has to come back on CONNECTION_CLOSE.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 60 ./bin/linnea-quichs >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_churn_test.py 47501 100 >/dev/null 2>&1
    check "quic: 100 connections through a 64-slot pool (close frees the slot)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "quic churn test (skipped: deps unavailable)" 0
fi

# Connection pool: two connections whose handshakes and requests are fully
# interleaved must not share keys, transcript, connection ids or packet numbers.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_conns_test.py 47501 >/dev/null 2>&1
    check "quic: two interleaved connections keep separate state (pool demux)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "quic connection-pool test (skipped: deps unavailable)" 0
fi

# --- HTTP tests against a running server ---
rm -f "$LOG"
# A file spanning several pages: every other fixture fits in one, which is
# exactly what let a wrong mmap length go unnoticed.
python3 -c "open('test/www/big.txt','w').write('B'*100000)"
# Pre-compressed variants. Each one holds different text, so a test can
# tell which file was served; real deployments would compress the same
# bytes. The .gz is real gzip (curl --compressed decodes it); the .br is
# not real brotli, which linnea neither produces nor inspects.
python3 - <<'PY'
import gzip
open('test/www/enc.txt', 'w').write('plain payload')
with gzip.open('test/www/enc.txt.gz', 'wb') as f:
    f.write(b'gzip payload')
open('test/www/enc.txt.br', 'wb').write(b'br payload')
PY
# The suite runs two backends in turn, both on 47100: one for the plain-HTTP
# block and a second for the TLS block. SO_REUSEADDR lets the second past a
# TIME_WAIT, but not past a first that is still listening — and the backend's
# output goes to /dev/null, so a failed bind is invisible until every proxied
# request in the rest of the run answers 502. Seen once: 23 failures, all
# proxy, none reproducible. Wait for it to actually accept.
backend_ready() {
    for _ in $(seq 1 60); do
        (echo > /dev/tcp/127.0.0.1/47100) >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    echo "WARNING: the proxy backend never came up on 47100" >&2
    return 1
}

python3 test/proxy_backend.py >/dev/null 2>&1 &
backend_pid=$!
backend_ready
$BIN --config test/configs/listen.json >/dev/null 2>&1 &
server_pid=$!
sleep 0.3

# check_http <name> <grep-pattern> <response-text>
check_http() {
    local name=$1 pattern=$2 resp=$3
    if printf '%s' "$resp" | grep -qF "$pattern"; then
        echo "PASS: $name"
        pass=$((pass + 1))
    else
        echo "FAIL: $name (pattern: $pattern)"
        printf '%s\n' "--- response ---" "$resp" "----------------"
        fail=$((fail + 1))
    fi
}

# raw_http <request> — send bytes, print the full response.
# The request carries literal \r\n escapes; raw_http.py expands them.
raw_http() {
    # See test/raw_http.py: the bash /dev/tcp one-liner this replaces gave the
    # connect, the write and the read a single two-second budget, and `cat` only
    # ever escaped a keep-alive response by being killed at the deadline. Under
    # load the deadline beat the response and the test saw an empty string with
    # its stderr discarded — a flake that cost this suite a different test on
    # three separate runs and reproduced on none of them in isolation.
    python3 test/raw_http.py "$1"
}

# --- log file ---
grep -q "listening on 127.0.0.1:47080 (one.test)" "$LOG"
check "log listening line" $?
n=$(grep -c "listening on 127.0.0.1:47080" "$LOG")
[ "$n" -eq 1 ]
check "shared listener bound once" $?

# --- bind conflict against the running server ---
run_test "address in use"  1 stderr "cannot bind to 127.0.0.1:47080 (errno 98)" \
    $BIN --config test/configs/dup-bind.json

# --- static file serving ---
resp=$(curl -s --max-time 2 http://127.0.0.1:47080/hello.txt)
check_http "file txt body"     "hello from linnea" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/hello.txt)
check_http "file txt mime"     "Content-Type: text/plain" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/)
check_http "index html body"   "linnea index page" "$resp"
check_http "index html mime"   "Content-Type: text/html" "$resp"

# --- redirect location: 301 with the raw request target appended ---
resp=$(curl -si --max-time 2 http://127.0.0.1:47090/old)
check_http "redirect status"   "301 Moved Permanently" "$resp"
check_http "redirect location" "Location: https://example.com/old" "$resp"
check_http "redirect no body"  "Content-Length: 0" "$resp"
resp=$(curl -si --max-time 2 "http://127.0.0.1:47090/old/a%20b?x=1&y=2")
check_http "redirect keeps raw path+query" "Location: https://example.com/old/a%20b?x=1&y=2" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/style.css)
check_http "css mime"          "Content-Type: text/css" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/favicon.ico)
check_http "ico mime"          "Content-Type: image/x-icon" "$resp"
resp=$(curl -s --max-time 2 http://127.0.0.1:47090/sub/page.html)
check_http "subdirectory file" "subdirectory page" "$resp"

# --- location routing: 47090 has "/" -> test/www/sub and "/sub" -> test/www ---
resp=$(curl -s --max-time 2 http://127.0.0.1:47090/page.html)
check_http "location root match"  "subdirectory page" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47090/hello.txt)
check_http "location root scopes" "404 Not Found" "$resp"
# /sub/page.html matches the longer "/sub" prefix (root test/www), not "/"
resp=$(curl -s --max-time 2 http://127.0.0.1:47090/sub/page.html)
check_http "longest prefix wins"  "subdirectory page" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/no-such-file)
check_http "http 404"          "404 Not Found" "$resp"
resp=$(curl -si --max-time 2 -I http://127.0.0.1:47080/hello.txt)
check_http "HEAD length"       "Content-Length: 18" "$resp"
resp=$(curl -si --max-time 2 -X POST http://127.0.0.1:47080/hello.txt)
check_http "http 405"          "405 Method Not Allowed" "$resp"

# a file larger than one page: the mapped length must be the whole file
n=$(curl -s --max-time 5 http://127.0.0.1:47080/big.txt | wc -c)
[ "$n" -eq 100000 ]
check "large file length ($n bytes)" $?
junk=$(curl -s --max-time 5 http://127.0.0.1:47080/big.txt | tr -d 'B' | wc -c)
[ "$junk" -eq 0 ]
check "large file intact" $?

# --- caching: ETag / Last-Modified and conditional requests ---
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/hello.txt)
check_http "etag present"        "ETag: \"" "$resp"
check_http "last-modified present" "Last-Modified: " "$resp"
printf '%s' "$resp" | grep -qE '^ETag: "[0-9a-f]+-12"'
check "etag is mtime-size in hex" $?
printf '%s' "$resp" | grep -qE '^Last-Modified: [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT'
check "last-modified is an HTTP date" $?
check_http "server header"       "Server: linnea" "$resp"
printf '%s' "$resp" | grep -qE '^Date: [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT'
check "date is an HTTP date" $?
check_http "cache-control from config" "Cache-Control: max-age=60" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/no-such-file)
check_http "404 server header"   "Server: linnea" "$resp"

resp=$(curl -si --max-time 2 http://127.0.0.1:47080/hello.txt)
etag=$(printf '%s' "$resp" | grep -i '^etag:' | tr -d '\r' | cut -d' ' -f2)
lastmod=$(printf '%s' "$resp" | grep -i '^last-modified:' | tr -d '\r' | cut -d' ' -f2-)

resp=$(curl -si --max-time 2 -H "If-None-Match: $etag" http://127.0.0.1:47080/hello.txt)
check_http "if-none-match 304"   "304 Not Modified" "$resp"
check_http "304 repeats etag"    "ETag: $etag" "$resp"
check_http "304 keeps alive"     "Connection: keep-alive" "$resp"
check_http "304 server header"   "Server: linnea" "$resp"
check_http "304 date header"     "Date: " "$resp"
check_http "304 repeats cache-control" "Cache-Control: max-age=60" "$resp"
printf '%s' "$resp" | grep -qF "hello from linnea"
[ $? -ne 0 ]
check "304 carries no body" $?
# a 304 that cost a new connection each time would defeat revalidation
before=$(grep -c "accepted connection" "$LOG")
curl -s --max-time 4 -H "If-None-Match: $etag" -o /dev/null \
    http://127.0.0.1:47080/hello.txt http://127.0.0.1:47080/hello.txt
after=$(grep -c "accepted connection" "$LOG")
[ $((after - before)) -eq 1 ]
check "304 single accept" $?

resp=$(curl -si --max-time 2 -H 'If-None-Match: "stale"' http://127.0.0.1:47080/hello.txt)
check_http "stale etag 200"      "hello from linnea" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: W/$etag" http://127.0.0.1:47080/hello.txt)
check_http "weak etag 304"       "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H 'If-None-Match: *' http://127.0.0.1:47080/hello.txt)
check_http "if-none-match star"  "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: \"a\", W/\"b\", $etag" http://127.0.0.1:47080/hello.txt)
check_http "etag list 304"       "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -I -H "If-None-Match: $etag" http://127.0.0.1:47080/hello.txt)
check_http "HEAD 304"            "304 Not Modified" "$resp"

resp=$(curl -si --max-time 2 -H "If-Modified-Since: $lastmod" http://127.0.0.1:47080/hello.txt)
check_http "if-modified-since 304" "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -z "$lastmod" http://127.0.0.1:47080/hello.txt)
check_http "curl time-cond 304"  "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H "If-Modified-Since: Wed, 01 Jan 2020 00:00:00 GMT" http://127.0.0.1:47080/hello.txt)
check_http "older date 200"      "hello from linnea" "$resp"
# an unparseable date must be ignored, not treated as a condition
resp=$(curl -si --max-time 2 -H "If-Modified-Since: not a date" http://127.0.0.1:47080/hello.txt)
check_http "bad date ignored"    "hello from linnea" "$resp"
# An rfc850 date now PARSES (RFC 9110 5.6.7); 1994 is simply older than the
# file, so the body is still what comes back. The name said "ignored" when the
# format was rejected outright — the outcome is the same, the reason is not.
resp=$(curl -si --max-time 2 -H "If-Modified-Since: Sunday, 06-Nov-94 08:49:37 GMT" http://127.0.0.1:47080/hello.txt)
check_http "rfc850 date parses, and 1994 is older" "hello from linnea" "$resp"
# If-None-Match wins outright when both are present
resp=$(curl -si --max-time 2 -H 'If-None-Match: "x"' -H "If-Modified-Since: $lastmod" http://127.0.0.1:47080/hello.txt)
check_http "if-none-match wins"  "hello from linnea" "$resp"

grep -qF '"GET /hello.txt HTTP/1.1" 304 0' "$LOG"
check "request log 304" $?

# --- pre-compressed variants: enc.txt has both a .br and a .gz beside it ---
# enc_of <accept-encoding> — the Content-Encoding linnea picked, if any.
# grep -a: the gzip variant's body is binary.
enc_of() {
    curl -si --max-time 2 -H "Accept-Encoding: $1" http://127.0.0.1:47080/enc.txt \
        | grep -a -io '^content-encoding: .*' | tr -d '\r' | cut -d' ' -f2
}
body_of() {
    curl -s --max-time 2 -H "Accept-Encoding: $1" http://127.0.0.1:47080/enc.txt
}
[ "$(enc_of 'gzip, br')" = "br" ]
check "br preferred over gzip" $?
[ "$(body_of 'gzip, br')" = "br payload" ]
check "br variant served" $?
[ "$(enc_of 'gzip')" = "gzip" ]
check "gzip when br unwanted" $?
[ "$(enc_of 'deflate, br')" = "br" ]
check "unknown codings skipped" $?
[ "$(enc_of 'BR')" = "br" ]
check "accept-encoding is case-insensitive" $?
[ -z "$(enc_of 'identity')" ]
check "identity gets the plain file" $?
[ "$(body_of 'identity')" = "plain payload" ]
check "plain body when no coding taken" $?
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/enc.txt)
printf '%s' "$resp" | grep -qai '^content-encoding'
[ $? -ne 0 ]
check "no accept-encoding, no coding" $?
check_http "plain body without accept-encoding" "plain payload" "$resp"
# q=0 is a refusal, and the fallback must still find the other variant
[ -z "$(enc_of 'br;q=0')" ]
check "q=0 refuses a coding" $?
[ "$(enc_of 'br;q=0, gzip')" = "gzip" ]
check "q=0 falls back to gzip" $?
[ "$(enc_of 'br;q=0.001')" = "br" ]
check "a small q still accepts" $?
[ -z "$(enc_of 'br;q=0.000')" ]
check "q=0.000 refuses too" $?
# the type comes from the name before the suffix, not from ".br"
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' http://127.0.0.1:47080/enc.txt)
check_http "type ignores the suffix" "Content-Type: text/plain" "$resp"
check_http "variant length"          "Content-Length: 10" "$resp"
check_http "variant vary"            "Vary: Accept-Encoding" "$resp"
# h1-15: a variant with no plain file beside it is served to whoever takes the
# encoding and 404s everyone else, so the miss is content-negotiated too. If
# that 404 omits Vary, a shared cache stores it under the bare URL and then
# hands it to the very clients the variant was for — the 200 becomes
# unreachable through the cache. Both answers must agree on Vary.
printf 'br only payload' > test/www/varonly.txt.br
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' http://127.0.0.1:47080/varonly.txt)
check_http "variant-only file served to a br client" "HTTP/1.1 200" "$resp"
check_http "variant-only 200 varies"                 "Vary: Accept-Encoding" "$resp"
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: identity' http://127.0.0.1:47080/varonly.txt)
check_http "variant-only 404s a client that cannot take it" "HTTP/1.1 404" "$resp"
check_http "that 404 varies too (h1-15)"                    "Vary: Accept-Encoding" "$resp"
rm -f test/www/varonly.txt.br
# curl decoding the real gzip end to end
[ "$(curl -s --max-time 2 --compressed -H 'Accept-Encoding: gzip' http://127.0.0.1:47080/enc.txt)" = "gzip payload" ]
check "gzip variant decodes" $?
# a file with no variants must not claim an encoding, but still varies
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip, br' http://127.0.0.1:47080/hello.txt)
printf '%s' "$resp" | grep -qai '^content-encoding'
[ $? -ne 0 ]
check "no variant, no coding" $?
check_http "no variant still varies" "Vary: Accept-Encoding" "$resp"
check_http "no variant serves plain" "hello from linnea" "$resp"

# Each variant is its own representation: a cache must never hand one to a
# client that asked for another, so the validators have to differ.
etag_br=$(curl -si --max-time 2 -H 'Accept-Encoding: br' http://127.0.0.1:47080/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
etag_gz=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip' http://127.0.0.1:47080/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
etag_pl=$(curl -si --max-time 2 http://127.0.0.1:47080/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
[ -n "$etag_br" ] && [ "$etag_br" != "$etag_gz" ] && [ "$etag_gz" != "$etag_pl" ] && [ "$etag_br" != "$etag_pl" ]
check "each variant has its own etag" $?
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' -H "If-None-Match: $etag_br" http://127.0.0.1:47080/enc.txt)
check_http "variant revalidates 304" "304 Not Modified" "$resp"
check_http "variant 304 varies"      "Vary: Accept-Encoding" "$resp"
printf '%s' "$resp" | grep -qai '^content-encoding'
[ $? -ne 0 ]
check "variant 304 omits the coding" $?
# the br etag says nothing about the gzip or plain representations
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip' -H "If-None-Match: $etag_br" http://127.0.0.1:47080/enc.txt)
check_http "cross-variant etag 200" "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: $etag_br" http://127.0.0.1:47080/enc.txt)
check_http "variant etag vs plain 200" "plain payload" "$resp"

# --- Range requests: hello.txt is the 18 bytes "hello from linnea\n" ---
resp=$(curl -si --max-time 2 -r 0-4 http://127.0.0.1:47080/hello.txt)
check_http "range 206"           "206 Partial Content" "$resp"
check_http "range content-range" "Content-Range: bytes 0-4/18" "$resp"
check_http "range length"        "Content-Length: 5" "$resp"
printf '%s' "$resp" | grep -qF "hello from"
[ $? -ne 0 ]
check "range body is the slice" $?
check_http "range body"          "hello" "$resp"
resp=$(curl -s --max-time 2 -r 6- http://127.0.0.1:47080/hello.txt)
[ "$resp" = "from linnea" ]     # the trailing newline is byte 17
check "range open end" $?
resp=$(curl -s --max-time 2 -r -7 http://127.0.0.1:47080/hello.txt)
[ "$resp" = "linnea" ]
check "range suffix" $?
resp=$(curl -si --max-time 2 -r 0-0 http://127.0.0.1:47080/hello.txt)
check_http "range single byte"   "Content-Range: bytes 0-0/18" "$resp"
check_http "range single length" "Content-Length: 1" "$resp"
# a last past the end means "to the end"
resp=$(curl -si --max-time 2 -H 'Range: bytes=6-9999' http://127.0.0.1:47080/hello.txt)
check_http "range clamped last"  "Content-Range: bytes 6-17/18" "$resp"
# a suffix longer than the file is the whole file, still a 206
resp=$(curl -si --max-time 2 -H 'Range: bytes=-9999' http://127.0.0.1:47080/hello.txt)
check_http "range long suffix"   "Content-Range: bytes 0-17/18" "$resp"
# 200s advertise the support
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/hello.txt)
check_http "accept-ranges"       "Accept-Ranges: bytes" "$resp"
# unsatisfiable: starts at or past the end -> 416 naming the length
resp=$(curl -si --max-time 2 -H 'Range: bytes=99-' http://127.0.0.1:47080/hello.txt)
check_http "range 416"           "416 Range Not Satisfiable" "$resp"
check_http "416 content-range"   "Content-Range: bytes */18" "$resp"
check_http "416 keeps alive"     "Connection: keep-alive" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=-0' http://127.0.0.1:47080/hello.txt)
check_http "range -0 is 416"     "416 Range Not Satisfiable" "$resp"
# not understood -> ignored -> the full 200
resp=$(curl -si --max-time 2 -H 'Range: bytes=5-2' http://127.0.0.1:47080/hello.txt)
check_http "backwards range 200" "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=abc' http://127.0.0.1:47080/hello.txt)
check_http "garbage range 200"   "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: potatoes=0-4' http://127.0.0.1:47080/hello.txt)
check_http "other unit 200"      "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=0-1,3-4' http://127.0.0.1:47080/hello.txt)
check_http "several ranges 200"  "200 OK" "$resp"
check_http "several ranges full" "Content-Length: 18" "$resp"
# Range is defined for GET alone
resp=$(curl -si --max-time 2 -I -H 'Range: bytes=0-4' http://127.0.0.1:47080/hello.txt)
check_http "HEAD ignores range"  "200 OK" "$resp"
check_http "HEAD full length"    "Content-Length: 18" "$resp"
# the conditionals still win over Range
resp=$(curl -si --max-time 2 -r 0-4 -H "If-None-Match: $etag" http://127.0.0.1:47080/hello.txt)
check_http "range vs 304"        "304 Not Modified" "$resp"
# If-Range: the range only with a strong validator match
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: $etag" http://127.0.0.1:47080/hello.txt)
check_http "if-range match 206"  "206 Partial Content" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H 'If-Range: "stale"' http://127.0.0.1:47080/hello.txt)
check_http "if-range stale 200"  "200 OK" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: W/$etag" http://127.0.0.1:47080/hello.txt)
check_http "if-range weak 200"   "200 OK" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: $lastmod" http://127.0.0.1:47080/hello.txt)
check_http "if-range date 206"   "206 Partial Content" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H 'If-Range: Wed, 01 Jan 2020 00:00:00 GMT' http://127.0.0.1:47080/hello.txt)
check_http "if-range old date 200" "200 OK" "$resp"
# ranges hold on big files and on pre-compressed variants
n=$(curl -s --max-time 5 -r 90000-99999 http://127.0.0.1:47080/big.txt | tr -d 'B' | wc -c)
[ "$n" -eq 0 ] && [ "$(curl -s --max-time 5 -r 90000-99999 http://127.0.0.1:47080/big.txt | wc -c)" -eq 10000 ]
check "range into big file" $?
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' -r 0-1 http://127.0.0.1:47080/enc.txt)
check_http "variant range slices variant" "Content-Range: bytes 0-1/10" "$resp"
check_http "variant range body"  "br" "$resp"
# two ranged requests ride one keep-alive connection
before=$(grep -c "accepted connection" "$LOG")
curl -s --max-time 4 -r 0-4 \
    http://127.0.0.1:47080/hello.txt http://127.0.0.1:47080/hello.txt >/dev/null
after=$(grep -c "accepted connection" "$LOG")
[ $((after - before)) -eq 1 ]
check "206 keep-alive single accept" $?
grep -qF '"GET /hello.txt HTTP/1.1" 206 5' "$LOG"
check "request log 206" $?
grep -qF '"GET /hello.txt HTTP/1.1" 416 0' "$LOG"
check "request log 416" $?

# --- virtual hosts: 47080 is shared by one.test (default) and three.test ---
resp=$(curl -s --max-time 2 -H "Host: three.test" http://127.0.0.1:47080/page.html)
check_http "vhost three.test"  "subdirectory page" "$resp"
resp=$(curl -s --max-time 2 -H "Host: three.test:47080" http://127.0.0.1:47080/page.html)
check_http "vhost host:port"   "subdirectory page" "$resp"
resp=$(curl -s --max-time 2 -H "Host: unknown.test" http://127.0.0.1:47080/hello.txt)
check_http "vhost default"     "hello from linnea" "$resp"

# --- percent-decoding ---
resp=$(curl -s --max-time 2 'http://127.0.0.1:47080/a%20b.txt')
check_http "decode space"      "space file" "$resp"
resp=$(curl -s --max-time 2 'http://127.0.0.1:47080/sub%2Fpage.html')
check_http "decode slash"      "subdirectory page" "$resp"
check_http "encoded traversal" "400 Bad Request" "$(raw_http 'GET /%2e%2e/secret HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "bad escape"        "400 Bad Request" "$(raw_http 'GET /%zz HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "encoded NUL"       "400 Bad Request" "$(raw_http 'GET /%00 HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# --- path normalization (raw, curl normalizes dot segments itself) ---
check_http "double slash"   "hello from linnea" "$(raw_http 'GET //hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dot segment"    "hello from linnea" "$(raw_http 'GET /./hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dotdot resolve" "hello from linnea" "$(raw_http 'GET /sub/../hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dotdot to dir"  "linnea index page" "$(raw_http 'GET /sub/.. HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "above root"     "400 Bad Request" "$(raw_http 'GET /a/../../x HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# --- request bodies ---
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nContent-Length: 5\r\n\r\nXXXXXGET /hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')
n=$(printf '%s' "$resp" | grep -c "200 OK")
[ "$n" -eq 2 ]
check "body discarded, keep-alive" $?
# Chunked bodies used to be 501 and this test asserted it. Receiving and
# decoding the coding is a MUST (RFC 9112 7.1), so the expectation moves with
# the behaviour: a complete chunked body is served, and a coding we genuinely do
# not implement is what keeps the 501.
check_http "chunked body decoded and served" "200 OK" "$(raw_http 'GET / HTTP/1.1\r\nHost: one.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n')"
check_http "an unimplemented coding is still 501" "501 Not Implemented" "$(raw_http 'GET / HTTP/1.1\r\nHost: one.test\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n')"
# A static location cannot stream a body, so one it cannot buffer with the
# head is refused; a proxy location streams the same body instead (below).
check_http "body too large 413" "413 Content Too Large" "$(raw_http 'GET / HTTP/1.1\r\nHost: one.test\r\nContent-Length: 20000\r\n\r\n')"

# --- protocol errors and traversal (raw, curl normalizes paths) ---
check_http "http 400" "400 Bad Request" "$(raw_http 'GARBAGE\r\n\r\n')"
check_http "http 505" "505 HTTP Version Not Supported" "$(raw_http 'GET / HTTP/1.0\r\nConnection: close\r\n\r\n')"
check_http "traversal blocked" "400 Bad Request" "$(raw_http 'GET /../secret HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# --- video MIME types (Q129): a .mp4 served as application/octet-stream is
# not played by a browser's <video> element, so the type is what makes a
# media file usable at all. Range handling is exercised elsewhere; what is
# checked here is the type, on a plain GET and on a 206.
printf 'not really a video' > test/www/clip.mp4
resp=$(raw_http 'GET /clip.mp4 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "mime: .mp4 is video/mp4" "Content-Type: video/mp4" "$resp"

# Q130: the types a modern site cannot do without. The first three are hard
# failures rather than cosmetics — WebAssembly refuses to instantiate without
# application/wasm, an ES module served as octet-stream is rejected outright
# under the nosniff we send, and a .htm answered as octet-stream downloads
# instead of rendering. Both tables are checked, since h1 and h2/h3 keep
# separate ones and a type added to only one is the likely mistake.
mime_probe() {                 # mime_probe <ext> <expected type>
    printf 'x' > "test/www/probe.$1"
    resp=$(raw_http "GET /probe.$1 HTTP/1.1\r\nHost: one.test\r\n\r\n")
    check_http "mime: .$1 is $2" "Content-Type: $2" "$resp"
    rm -f "test/www/probe.$1"
}
mime_probe wasm        application/wasm
mime_probe mjs         text/javascript
mime_probe htm         text/html
mime_probe woff2       font/woff2
mime_probe webp        image/webp
mime_probe avif        image/avif
mime_probe mp3         audio/mpeg
mime_probe pdf         application/pdf
mime_probe webmanifest application/manifest+json
mime_probe js          text/javascript
# Q131: the text types declare UTF-8. A page carries <meta charset> and is
# fine either way, but a .txt or .csv without it is left to whatever the
# browser guesses. Not on application/json: RFC 8259 defines JSON as UTF-8
# and its media type has no charset parameter at all.
mime_probe txt  'text/plain; charset=utf-8'
mime_probe csv  'text/csv; charset=utf-8'
mime_probe css  'text/css; charset=utf-8'
resp=$(raw_http 'GET /probe.json HTTP/1.1\r\nHost: one.test\r\n\r\n')
printf 'x' > test/www/probe.json
resp=$(raw_http 'GET /probe.json HTTP/1.1\r\nHost: one.test\r\n\r\n')
printf '%s' "$resp" | grep -qi 'charset' && json_charset=1 || json_charset=0
[ "$json_charset" = 0 ]
check "mime: application/json carries no charset" $?
rm -f test/www/probe.json
resp=$(raw_http 'GET /clip.mp4 HTTP/1.1\r\nHost: one.test\r\nRange: bytes=0-3\r\n\r\n')
check_http "mime: a 206 keeps the video type" "Content-Type: video/mp4" "$resp"
check_http "mime: the 206 is a real partial" "206 Partial Content" "$resp"
rm -f test/www/clip.mp4

# --- request-target forms (Q127, RFC 9112 3.2). Only origin-form used to
# survive: absolute-form and "OPTIONS *" reached the path normalizer and came
# back 400. A server MUST accept absolute-form, and the authority it carries
# — not the Host header — identifies the resource.
resp=$(raw_http 'GET http://one.test/hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form served" "hello from linnea" "$resp"
resp=$(raw_http 'GET https://one.test/hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form (https scheme) served" "hello from linnea" "$resp"
resp=$(raw_http 'GET http://one.test HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form with no path is the root" "200 OK" "$resp"
# the target's authority wins over Host: three.test has its own root, which
# holds no hello.txt, so routing by it is visible as a 404
resp=$(raw_http 'GET http://three.test/hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form authority beats Host" "404" "$resp"
resp=$(raw_http 'GET http:///hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form with an empty authority is 400" "400 Bad Request" "$resp"
# an HTTP/1.1 client must still send Host, even in absolute-form
resp=$(raw_http 'GET http://one.test/hello.txt HTTP/1.1\r\n\r\n')
check_http "target: absolute-form still requires a Host line" "400 Bad Request" "$resp"
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: OPTIONS * answered" "200 OK" "$resp"
check_http "target: OPTIONS * lists the methods" "Allow: GET, HEAD, OPTIONS" "$resp"
resp=$(raw_http 'GET * HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: asterisk with any other method is 400" "400 Bad Request" "$resp"
# the asterisk form used to be answered before the Host rules ran, so it was the
# one request that could arrive with no Host or two of them and still get a 200
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\n\r\n')
check_http "target: OPTIONS * without a Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\nHost: one.test\r\nHost: evil.test\r\n\r\n')
check_http "target: OPTIONS * with two Hosts is 400" "400 Bad Request" "$resp"
# ...and the same here: the body is decoded, so OPTIONS * answers about the
# server as it always should have. The 501 was the coding being refused.
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\nHost: one.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n')
check_http "target: OPTIONS * with a chunked body is answered" "200 OK" "$resp"

# --- the method is a token (RFC 9110 9.1). The request-line parse only bounded
# it to printable ASCII, so every delimiter got through — including the double
# quote, which the access line writes the method inside, splitting its own
# quoted field. An unknown but well-formed method still parses as a method.
#
# Its ANSWER is 501, not 405: 15.6.2 makes 501 "the appropriate response when
# the server does not recognize the request method", where 405 says the method
# is known and merely not allowed here. These checks asserted 405 for both,
# which told a client PROPFIND was a real method this resource declines.
resp=$(raw_http 'PROPFIND /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: an unknown token method is 501, not 400" "501 Not Implemented" "$resp"
# RFC 9110 15.5.6: a 405 must name what the resource does take — so it is asked
# with a method we DO recognise
resp=$(raw_http 'POST /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a known method gets 405" "405 Method Not Allowed" "$resp"
check_http "method: the 405 carries Allow" "Allow: GET, HEAD" "$resp"
resp=$(raw_http '!#$%&\x27*+-.^_`|~ /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: every tchar punctuation is still a method" "501 Not Implemented" "$resp"
resp=$(raw_http 'GE"T /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a double quote is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GE/T /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a delimiter is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GE\x1bT /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a control byte is 400" "400 Bad Request" "$resp"
# a method is case-sensitive (RFC 9110 9.1), so "get" is not GET — and not a
# method we recognise at all, which is 501
resp=$(raw_http 'get /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: lowercase get is 501, not a served file" "501 Not Implemented" "$resp"
# None of those reached the access log, which is what the quote could break.
# Matched through cat -v so the ESC shows as ^[, and with -F so the quote and
# the brackets are literal — "GE alone would match every ordinary GET line.
! cat -v "$LOG" | grep -qF -e '"GE"T' -e '"GE/T' -e '"GE^[T'
check "method: no malformed method reaches the access log" $?

# --- Host header rules (Q123, RFC 9112 3.2): every request we accept is
# HTTP/1.1, so exactly one Host field line is mandatory and its value must
# look like an authority. A missing or repeated Host used to be served
# normally — and a second Host is a smuggling primitive, since an
# intermediary may route on the other one.
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "host: one Host serves"  "200 OK" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\n\r\n')
check_http "host: missing Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nHost: evil.test\r\n\r\n')
check_http "host: duplicate Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nHost: one.test\r\n\r\n')
check_http "host: repeated identical Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost:\r\n\r\n')
check_http "host: empty Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one test\r\n\r\n')
check_http "host: Host with a space is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test:47080\r\n\r\n')
check_http "host: Host with a port serves" "200 OK" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: [::1]:47080\r\n\r\n')
check_http "host: IPv6-literal Host serves" "200 OK" "$resp"
# the trailing OWS a field value may carry is trimmed before validation
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\t\r\n\r\n')
check_http "host: trailing OWS trimmed, not rejected" "200 OK" "$resp"
# a proxied location is routed only after the Host check
resp=$(raw_http 'GET /api/simple HTTP/1.1\r\n\r\n')
check_http "host: missing Host on a proxy location is 400" "400 Bad Request" "$resp"

# --- request log lines (with peer address) ---
grep -qE 'request one\.test from 127\.0\.0\.1:[0-9]+ "GET /hello\.txt HTTP/1\.1" 200 18' "$LOG"
check "request log 200" $?
grep -qE 'request three\.test from 127\.0\.0\.1:[0-9]+ "GET /page\.html HTTP/1\.1" 200' "$LOG"
check "request log vhost" $?
grep -qE '"GET /a%20b\.txt HTTP/1\.1" 200' "$LOG"
check "request log raw target" $?
grep -qF '"GET /no-such-file HTTP/1.1" 404 0' "$LOG"
check "request log 404" $?
grep -qF '"POST /hello.txt HTTP/1.1" 405 0' "$LOG"
check "request log 405" $?
grep -qE '^\[20[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\] request' "$LOG"
check "log timestamps" $?

# --- keep-alive: two requests, one connection (count accepts in the log) ---
before=$(grep -c "accepted connection" "$LOG")
resp=$(curl -s --max-time 4 http://127.0.0.1:47080/hello.txt http://127.0.0.1:47080/index.html)
after=$(grep -c "accepted connection" "$LOG")
check_http "keep-alive body 1" "hello from linnea" "$resp"
check_http "keep-alive body 2" "linnea index page" "$resp"
[ $((after - before)) -eq 1 ]
check "keep-alive single accept" $?

# --- pipelined requests in one write ---
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\nGET /hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')
n=$(printf '%s' "$resp" | grep -c "200 OK")
[ "$n" -eq 2 ]
check "pipelined requests" $?

# --- idle timeout: configured to 2s in listen.json ---
start=$SECONDS
if timeout 6 bash -c 'exec 3<>/dev/tcp/127.0.0.1/47080; cat <&3' >/dev/null 2>&1; then
    elapsed=$((SECONDS - start))
    [ "$elapsed" -ge 1 ] && [ "$elapsed" -le 4 ]
    check "configured idle timeout (${elapsed}s)" $?
else
    check "configured idle timeout (connection not closed)" 1
fi

grep -qE 'accepted connection on 127\.0\.0\.1:47080 from 127\.0\.0\.1:[0-9]+ \(fd ' "$LOG"
check "accept log line" $?

# --- proxying: /api -> the test backend, /down -> nothing listening ---
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/simple)
check_http "proxy body"          "backend body" "$resp"
check_http "proxy status"        "200 OK" "$resp"
check_http "proxy content-length" "Content-Length: 12" "$resp"
check_http "proxy keeps alive"   "Connection: keep-alive" "$resp"

# the prefix is not stripped and the query survives: the backend echoes the target
resp=$(curl -s --max-time 3 'http://127.0.0.1:47080/api/target?x=1&y=2')
check_http "proxy target forwarded" "/api/target?x=1&y=2" "$resp"

# the client's Connection header is replaced, everything else passes through
resp=$(curl -s --max-time 3 -H 'X-Test: abc' -H 'Connection: keep-alive' \
    http://127.0.0.1:47080/api/headers)
check_http "proxy forwards headers" "X-Test: abc" "$resp"
check_http "proxy forwards host"    "Host: 127.0.0.1:47080" "$resp"
check_http "proxy closes upstream"  "Connection: close" "$resp"

resp=$(curl -s --max-time 3 -d 'hello body' http://127.0.0.1:47080/api/echo)
check_http "proxy forwards body" "hello body" "$resp"

# ...but a field the client's own Connection names is hop-by-hop and MUST be
# removed before forwarding (RFC 9110 7.6.1). Only Connection and Expect were
# dropped, so a client could mark any field hop-by-hop and have it delivered to
# the backend anyway — the header-smuggling shape that rule exists to close.
timeout 60 python3 test/tls/h1_proxy_hop_by_hop.py 47080 >/dev/null 2>&1
check "proxy removes hop-by-hop fields, both directions" $?

# RFC 9110 7.6.3 MUST: a proxy names itself and the protocol it received on, in
# each message it forwards. Without it a proxied request is indistinguishable
# from a direct one — no loop detection, and no way to tell which hop
# transformed a message.
timeout 60 python3 test/tls/proxy_via.py 47080 >/dev/null 2>&1
check "proxy adds Via to the request and the response" $?

# RFC 9110 5.6.7 MUST: all three HTTP-date formats parse. Only IMF-fixdate did,
# so a conditional request carrying an obsolete form was answered
# unconditionally — the client got the whole body instead of its 304.
timeout 60 python3 test/tls/http_date_formats.py 47080 >/dev/null 2>&1
check "all three HTTP-date formats are accepted" $?

# RFC 9110 13.1.1 / 13.1.4: If-Match and If-Unmodified-Since were never read, so
# a request carrying one was answered as though it had no condition at all —
# the lost update those fields exist to prevent. 13.2.2 also fixes the order:
# a failing If-Match is a 412 even when an If-None-Match would have said 304.
timeout 60 python3 test/tls/preconditions.py 47080 >/dev/null 2>&1
check "If-Match and If-Unmodified-Since are evaluated" $?

# RFC 9112 9.1: Connection is a token LIST and `close` may sit anywhere in it.
# Only a value that was entirely "close" counted, so `keep-alive, close` was
# answered `Connection: keep-alive` and the socket held to the idle timeout.
timeout 60 python3 test/tls/connection_close_token.py 47080 >/dev/null 2>&1
check "Connection: close is honoured anywhere in the list" $?

# RFC 9110 6.6.1: Date on everything outside 1xx/5xx. The canned blobs are
# assembled ahead of time, so they shipped without one while every dynamically
# built response had it. RFC 9112 9.6: and a response that closes must say so —
# the OPTIONS * blob closed while claiming, in a comment, that it did not.
timeout 60 python3 test/tls/canned_response_headers.py 47080 >/dev/null 2>&1
check "canned responses carry Date and announce a close" $?

# RFC 9110 10.1.1 MUST: answer a 100-continue expectation with 100 or a final
# status. The field was never inspected, so the server waited for a body the
# client was withholding while the client waited for permission to send it —
# a full second added to every such request, for clients that recover at all.
timeout 60 python3 test/tls/expect_continue.py 47080 >/dev/null 2>&1
check "Expect: 100-continue is answered" $?

# Chunked request bodies (RFC 9112 7.1 MUST). Any Transfer-Encoding at all used
# to be 501, so every client that sends a body of unknown length up front was
# refused: curl -T -, fetch() with a ReadableStream, most libraries handed a
# stream. The arrival-pattern cases are the ones that matter — a body comes in
# as many reads as the network likes.
timeout 120 python3 test/tls/h1_chunked_request.py 47080 >/dev/null 2>&1
check "h1 decodes chunked request bodies" $?

# a HEAD response is head-only even though the backend sends Content-Length:
# waiting for that body would hang until the idle timeout
resp=$(curl -si --max-time 3 -I http://127.0.0.1:47080/api/simple)
check_http "proxy HEAD length"   "Content-Length: 12" "$resp"
check_http "proxy HEAD no hang"  "200 OK" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/204)
check_http "proxy 204 no body"   "204 No Content" "$resp"

# chunked and close-delimited bodies have no length we can pass on, so the
# client connection has to close to delimit them
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/chunked)
check_http "proxy chunked body"  "chunked body" "$resp"
check_http "proxy chunked framing" "Transfer-Encoding: chunked" "$resp"
check_http "proxy chunked closes" "Connection: close" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/eof)
check_http "proxy eof body"      "eof delimited body" "$resp"
check_http "proxy eof closes"    "Connection: close" "$resp"

# a body bigger than the relay buffer takes several upstream reads
n=$(curl -s --max-time 5 http://127.0.0.1:47080/api/big | wc -c)
[ "$n" -eq 40000 ]
check "proxy large body ($n bytes)" $?

resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/http10)
check_http "proxy 1.0 upstream"  "HTTP/1.1 200 OK" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/301)
check_http "proxy passes status" "301 Moved Permanently" "$resp"
check_http "proxy passes header" "Location: /elsewhere" "$resp"

# proxied and static requests share one keep-alive connection
before=$(grep -c "accepted connection" "$LOG")
resp=$(curl -s --max-time 4 http://127.0.0.1:47080/api/simple http://127.0.0.1:47080/hello.txt)
after=$(grep -c "accepted connection" "$LOG")
check_http "proxy then static body" "hello from linnea" "$resp"
[ $((after - before)) -eq 1 ]
check "proxy keep-alive single accept" $?

# --- proxy failures ---
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/down/x)
check_http "proxy refused 502"   "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/garbage)
check_http "proxy garbage 502"   "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/bighead)
check_http "proxy huge head 502" "502 Bad Gateway" "$resp"
# contradictory upstream framing must never reach the client: forwarding
# both would let a compromised backend split the next keep-alive response
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/tecl)
check_http "proxy TE+CL 502"     "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/cljunk)
check_http "proxy bad CL 502"    "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/clpad)
check_http "proxy CL whitespace" "valid" "$resp"
# Expect must not be forwarded: the body is already buffered, and an
# interim 100 Continue would be parsed as the response itself
resp=$(raw_http 'POST /api/expect HTTP/1.1\r\nHost: one.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nHELLO')
check_http "proxy drops Expect"  "real" "$resp"
printf '%s' "$resp" | grep -qF "100 Continue"
[ $? -ne 0 ]
check "proxy no interim 100 leak" $?
# the backend sleeps 4s; the config's timeout is 2s
start=$SECONDS
resp=$(curl -si --max-time 8 http://127.0.0.1:47080/api/slow)
elapsed=$((SECONDS - start))
check_http "proxy slow 504"      "504 Gateway Timeout" "$resp"
[ "$elapsed" -le 4 ]
check "proxy 504 on time (${elapsed}s)" $?
# a body cut short of its Content-Length must not look like a clean end
curl -s --max-time 3 http://127.0.0.1:47080/api/truncated >/dev/null 2>&1
grep -qF ': upstream closed early' "$LOG"
check "proxy truncated body" $?

# --- large uploads: the body streams to the upstream instead of being
# buffered whole, so it is bounded by the relay, not by in_buf ---
python3 -c "
import random, sys
random.seed(11)
open('test/www/upload.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
want=$(md5sum < test/www/upload.bin | cut -d' ' -f1)
curl -s --max-time 30 --data-binary @test/www/upload.bin \
    http://127.0.0.1:47080/api/echo > /tmp/upload_echo.bin
[ "$(md5sum < /tmp/upload_echo.bin | cut -d' ' -f1)" = "$want" ]
check "proxy streams a 300000-byte request body (byte-exact)" $?
rm -f /tmp/upload_echo.bin

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
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/101)
check_http "unrequested 101 becomes 502" "502 Bad Gateway" "$resp"
# an upgrade wish on a static location changes nothing
resp=$(curl -si --max-time 3 -H 'Connection: upgrade' -H 'Upgrade: websocket' \
    http://127.0.0.1:47080/hello.txt)
check_http "upgrade on static location" "hello from linnea" "$resp"
grep -qF '"GET /api/ws-echo HTTP/1.1" 101 0' "$LOG"
check "ws request log 101" $?
grep -qF ': upstream closed' "$LOG"
check "ws termination upstream closed" $?

# --- send timeout: a client that stops reading must not pin its slot ---
# huge.bin is sparse and far larger than any kernel socket buffering, so
# once the client's window fills the send stalls and its linked timeout
# (2s in this config) fires.
truncate -s 64M test/www/huge.bin
(exec 3<>/dev/tcp/127.0.0.1/47080
 printf 'GET /huge.bin HTTP/1.1\r\nHost: one.test\r\n\r\n' >&3
 sleep 6) &
stall_pid=$!
sleep 4
grep -qF ': send timeout' "$LOG"
check "termination send timeout" $?
kill $stall_pid 2>/dev/null
wait $stall_pid 2>/dev/null
# a slow but reading client must survive a transfer spanning several
# timeout windows: partial sends re-arm with a fresh timeout each time
n=$(curl -s --max-time 12 --limit-rate 16M http://127.0.0.1:47080/huge.bin | wc -c)
[ "$n" -eq 67108864 ]
check "slow reader outlives send timeout ($n bytes)" $?

# --- connection termination log lines ---
grep -qF ': close after response' "$LOG"
check "termination close-after-response" $?
grep -qF ': peer closed' "$LOG"
check "termination peer closed" $?
grep -qF ': idle timeout' "$LOG"
check "termination idle timeout" $?

kill $server_pid $backend_pid 2>/dev/null
# the next block binds 47100 again, so let this one's listener go first
for _ in $(seq 1 60); do
    (echo > /dev/tcp/127.0.0.1/47100) >/dev/null 2>&1 || break
    sleep 0.1
done
wait $server_pid 2>/dev/null
wait $backend_pid 2>/dev/null
rm -f "$LOG" test/www/big.txt test/www/upload.bin test/www/upload2.bin test/www/h2range.bin test/www/huge.bin test/www/enc.txt test/www/enc.txt.gz test/www/enc.txt.br

# --- connection limits: slow-head deadline and the per-address cap ---
# One host must not be able to hold the server open. The idle timeout cannot stop
# it: every byte rearms it, so a trickled request head keeps its slot forever.
# limits.json sets a long idle timeout on purpose, so only the head deadline can
# be what closes the trickling connection.
$BIN --config test/configs/limits.json >/dev/null 2>&1 &
limits_pid=$!
sleep 0.5
python3 test/limits_test.py 47470 >/dev/null 2>&1
check "connection limits: slow head cut off, per-address cap holds" $?
kill $limits_pid 2>/dev/null
wait $limits_pid 2>/dev/null

# --- the head deadline also bounds the TLS handshake (slowloris on 443) ---
# A client dribbling ClientHello bytes rearms only the per-op idle timeout; the
# head deadline (stamped at accept) must cut it, while a real handshake serves.
if python3 -c 'import ssl' 2>/dev/null; then
    $BIN --config test/configs/tls-slowhead.json >/dev/null 2>&1 &
    slowhs_pid=$!
    sleep 0.5
    timeout 40 python3 test/tls/tls_slow_handshake.py test/tls/server.crt 47455 3 \
        >/dev/null 2>&1
    check "tls handshake slowloris cut at the head deadline" $?
    kill $slowhs_pid 2>/dev/null
    wait $slowhs_pid 2>/dev/null
fi

# --- graceful drain: SIGTERM finishes in-flight work, then exits ---
# A slow download is in flight when the master is killed; the workers
# must complete it, refuse new connections meanwhile, and exit after.
python3 -c "open('test/www/drain.bin','w').write('D' * 3000000)"
rm -f "$LOG"
$BIN --config test/configs/listen.json >/dev/null 2>&1 &
drain_master=$!
sleep 0.3
curl -s --max-time 30 --limit-rate 500k http://127.0.0.1:47080/drain.bin -o /tmp/drain_out &
drain_curl=$!
sleep 0.5                       # the transfer is under way
kill $drain_master              # SIGTERM: master dies, workers drain
wait $drain_master 2>/dev/null
sleep 0.5                       # accepts cancelled by now
curl -s --max-time 2 http://127.0.0.1:47080/hello.txt -o /dev/null 2>/dev/null
[ $? -ne 0 ]
check "drain refuses new connections" $?
wait $drain_curl
n=$(wc -c < /tmp/drain_out)
[ "$n" -eq 3000000 ]
check "drain finishes the in-flight response ($n bytes)" $?
# Poll rather than assert a fixed deadline: this check is about WHETHER the
# drain ends once the last connection is gone, not how fast -- promptness has
# its own timed check above ("sigterm: workers exit with an idle connection
# open"). curl exiting does not mean the worker has already noticed the close,
# freed the connection and left, and on a loaded box that gap can exceed half a
# second; it went red once in this suite for exactly that reason and would not
# reproduce standalone (0 in 10).
drain_gone=1
for _ in $(seq 1 20); do
    sleep 0.25
    pgrep -f 'test/configs/listen.json' >/dev/null || { drain_gone=0; break; }
done
drain_left=$(pgrep -af 'test/configs/listen.json' | tr '\n' '|')
[ "$drain_gone" -eq 0 ]
check "drain exits after the last connection (${drain_left:-none left})" $?
grep -qF 'worker drained' "$LOG"
check "drain logged" $?
rm -f /tmp/drain_out test/www/drain.bin "$LOG"

# --- accepts spread across the workers (Q122): each worker owns its own
# SO_REUSEPORT listener set, so the kernel hashes connections across them.
# Before, every accept landed on one worker's ring and multi-core TCP
# scaling was theoretical. 24 held connections must reach BOTH workers.
rm -f "$LOG"
$BIN --config test/configs/listen.json >/dev/null 2>&1 &
spread_master=$!
sleep 0.3
spread_workers=$(pgrep -P $spread_master | sort | tr '\n' ' ')
python3 - <<'PYEOF2' &
import socket, time
socks = []
for i in range(24):
    s = socket.create_connection(("127.0.0.1", 47080), timeout=5)
    s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n")
    s.recv(200)
    socks.append(s)
time.sleep(2.5)
for s in socks:
    s.close()
PYEOF2
spread_holder=$!
sleep 1.2
spread_ok=1
for w in $spread_workers; do
    n=$(ls /proc/$w/fd 2>/dev/null | wc -l)
    [ "$n" -gt 12 ] || spread_ok=0
done
[ "$spread_ok" = 1 ] && [ -n "$spread_workers" ]
check "accepts spread across the workers (all above baseline)" $?
wait $spread_holder
kill $spread_master 2>/dev/null
wait $spread_master 2>/dev/null

# --- config-check mode: `linnea -t` accepts good, rejects bad ---
$BIN --test --config test/configs/listen.json >/dev/null 2>&1
check "config check accepts a good config" $?
$BIN --test --config test/configs/bad-timeout.json >/dev/null 2>&1
[ $? -ne 0 ]
check "config check rejects a bad config" $?

# --- the command line -------------------------------------------------
# The configuration is named by -c/--config and nothing else. Every spelling of
# a config check must agree, and every malformed command line — an unknown
# option, a flag with no value, a config named twice, a bare path — must be a
# usage error rather than something the server guesses its way through.
for form in "--test --config test/configs/listen.json" \
            "-t -c test/configs/listen.json" \
            "--config=test/configs/listen.json --test" \
            "--config test/configs/listen.json -t"; do
    $BIN $form >/dev/null 2>&1
    check "cli: '$form' checks the config" $?
done
# --help goes to stdout and exits 0; a usage error goes to stderr and exits 1
out=$($BIN --help 2>/dev/null); rc=$?
[ $rc -eq 0 ] && printf '%s' "$out" | grep -q -- "--bpf-probe"
check "cli: --help prints the options to stdout, exit 0" $?
$BIN -h >/dev/null 2>&1
check "cli: -h is the same as --help" $?
for bad in "--bogus x" "-x x" "--config" "-c" "--config=" "-" \
           "test/configs/listen.json" \
           "-t test/configs/listen.json" \
           "--config test/configs/listen.json test/configs/listen.json" \
           "-c test/configs/listen.json --config test/configs/listen.json"; do
    $BIN $bad >/dev/null 2>&1
    [ $? -eq 1 ]
    check "cli: '$bad' is a usage error" $?
done
$BIN 2>&1 >/dev/null | grep -q "usage: linnea"
check "cli: no arguments prints usage on stderr" $?
timeout 0.5 $BIN --config test/configs/listen.json >/dev/null 2>&1
[ $? -eq 124 ]
check "cli: --config starts the server" $?

# --- stop is prompt: an idle keep-alive connection must not hold it ---
# SIGTERM closes connections that are merely parked, so a stop takes about
# as long as the work in flight, not as long as the idle timeout. SIGQUIT
# is the patient drain used for the hot upgrade, where the new generation
# is already serving; it leaves those connections alone.
rm -f "$LOG"
$BIN --config test/configs/listen.json >/dev/null 2>&1 &
stop_master=$!
sleep 0.3
stop_workers=$(pgrep -P $stop_master | tr '\n' ' ')
# hold an idle keep-alive connection open across the stop
python3 test/keepalive_holder.py 47080 20 &
stop_holder=$!
sleep 0.5
start=$SECONDS
kill -TERM $stop_master $stop_workers 2>/dev/null
gone=0
for _ in $(seq 1 60); do
    still=0
    for w in $stop_workers; do kill -0 "$w" 2>/dev/null && still=1; done
    [ "$still" -eq 0 ] && { gone=1; break; }
    sleep 0.1
done
elapsed=$((SECONDS - start))
[ "$gone" -eq 1 ]
check "sigterm: workers exit with an idle connection open (${elapsed}s)" $?
kill $stop_holder 2>/dev/null
wait $stop_holder 2>/dev/null
wait $stop_master 2>/dev/null

# --- log rotation (SIGHUP) ---
# Every process holds its own descriptor for the log, so after a rotation
# they must be told to reopen it: without that they keep filling the renamed
# inode and the fresh file stays empty.
rm -f "$LOG" "$LOG.rot"
$BIN --config test/configs/listen.json >/dev/null 2>&1 &
rot_master=$!
sleep 0.3
curl -s --max-time 3 http://127.0.0.1:47080/hello.txt -o /dev/null
sleep 0.2
mv "$LOG" "$LOG.rot"
curl -s --max-time 3 http://127.0.0.1:47080/hello.txt -o /dev/null
sleep 0.2
rotated_before=$(wc -l < "$LOG.rot")
kill -HUP $rot_master
sleep 0.5
curl -s --max-time 3 http://127.0.0.1:47080/index.html -o /dev/null
sleep 0.3
kill -0 $rot_master 2>/dev/null
check "sighup: the server survives it" $?
[ -s "$LOG" ]
check "sighup: reopens the log (new file has lines)" $?
grep -q '"GET /index.html HTTP/1.1"' "$LOG"
check "sighup: post-rotate requests log to the new file" $?
[ "$(wc -l < "$LOG.rot")" -eq "$rotated_before" ]
check "sighup: the rotated file stops growing" $?
kill $rot_master 2>/dev/null
wait $rot_master 2>/dev/null
rm -f "$LOG.rot"

# --- zero-downtime binary upgrade (SIGUSR2) ---
# The master re-execs in place: same PID, listeners adopted (never
# closed), new workers up, old workers drained. A request in flight when
# the signal lands must finish, and no new request may be refused.
rm -f "$LOG"
python3 -c "open('test/www/up.bin','w').write('U' * 3000000)"
$BIN --config test/configs/listen.json >/dev/null 2>&1 &
up_master=$!
sleep 0.3
old_workers=$(pgrep -P $up_master | tr '\n' ' ')
# a slow download in flight across the upgrade
curl -s --max-time 30 --limit-rate 500k http://127.0.0.1:47080/up.bin \
    -o /tmp/up_out &
up_curl=$!
# a steady stream of quick requests, counting any refusal
up_fails=0
up_why=""
( sleep 0.4; kill -USR2 $up_master ) &
for i in $(seq 1 60); do
    # record HOW a request failed, not just that it did: this check has gone
    # red about once in a dozen runs and never under a targeted repro (seven
    # runs, two of them under CPU load, zero refusals), so the next red run
    # should say whether the server refused (curl 7) or the client simply ran
    # out of its 3s patience on a loaded box (curl 28).
    #
    # Take curl's status into up_rc on the very next line. Reading $? inside
    # the `if` body gets the status of the counter assignment -- which is
    # always 0 -- so this diagnostic used to record "curl0" for every failure
    # and answer none of the question it was added to answer.
    curl -s --max-time 3 http://127.0.0.1:47080/hello.txt -o /dev/null
    up_rc=$?
    if [ $up_rc -ne 0 ]; then
        up_fails=$((up_fails + 1))
        up_why="$up_why $i:curl$up_rc"
    fi
    sleep 0.03
done
kill -0 $up_master 2>/dev/null
check "upgrade keeps the master PID" $?
wait $up_curl
n=$(wc -c < /tmp/up_out)
[ "$n" -eq 3000000 ]
check "upgrade finishes the in-flight download ($n bytes)" $?
[ "$up_fails" -eq 0 ]
check "upgrade refuses no new request ($up_fails failed:${up_why:- none})" $?
sleep 1
gone=1
for w in $old_workers; do kill -0 "$w" 2>/dev/null && gone=0; done
[ "$gone" -eq 1 ]
check "upgrade drains the old workers" $?
grep -qF 'binary upgrade complete' "$LOG"
check "upgrade logged" $?
curl -s --max-time 3 http://127.0.0.1:47080/hello.txt | grep -q "hello from linnea"
check "upgraded server still serves" $?
kill $up_master 2>/dev/null
wait $up_master 2>/dev/null
rm -f /tmp/up_out test/www/up.bin "$LOG"

# The same handover under real concurrency. One-at-a-time curl caught the
# drain's resets about once in a dozen suite runs, which is not enough signal
# to tell a fix from luck; 40 clients in flight fill the accept queue and make
# it deterministic. Every attempt must be answered — a reset here means the
# drain threw away a connection it had already taken, or the listener close
# purged the queue behind it.
# The previous instance's WORKERS can outlive its master by a moment and they
# hold the listener, so starting straight on top of it fails the bind and the
# new master exits immediately -- leaving this test signalling a pid that is
# already gone. Wait for the port to go quiet, then confirm we are up.
for _ in $(seq 1 40); do
    (echo > /dev/tcp/127.0.0.1/47080) >/dev/null 2>&1 || break
    sleep 0.25
done
$BIN --config test/configs/listen.json >/dev/null 2>&1 &
burst_master=$!
for _ in $(seq 1 40); do
    curl -s --max-time 1 http://127.0.0.1:47080/hello.txt -o /dev/null && break
    sleep 0.25
done
burst_out=$(timeout 60 python3 test/upgrade_burst.py $burst_master 47080 2>&1)
burst_rc=$?
kill $burst_master 2>/dev/null
wait $burst_master 2>/dev/null
# One retry, and only on failure. Leaving the reuseport group means closing the
# listening socket, and the sweep that empties its accept queue first cannot be
# atomic with that close -- a connection can still land in the gap between the
# sweep coming up empty and the close on the next instruction. Measured at 2
# lost in ~34k attempts on a loaded box (and 0 in 386k on an idle one), so a
# single strict run flakes now and then. A real regression fails both attempts:
# pre-Q177 lost 6-18 per round, every round.
if [ $burst_rc -ne 0 ]; then
    for _ in $(seq 1 40); do
        (echo > /dev/tcp/127.0.0.1/47080) >/dev/null 2>&1 || break
        sleep 0.25
    done
    $BIN --config test/configs/listen.json >/dev/null 2>&1 &
    burst_master=$!
    for _ in $(seq 1 40); do
        curl -s --max-time 1 http://127.0.0.1:47080/hello.txt -o /dev/null && break
        sleep 0.25
    done
    burst_out="$burst_out; retry: $(timeout 60 python3 test/upgrade_burst.py $burst_master 47080 2>&1)"
    burst_rc=$?
    kill $burst_master 2>/dev/null
    wait $burst_master 2>/dev/null
fi
check "upgrade under load loses no connection ($burst_out)" $burst_rc
rm -f "$LOG"

# --- TLS 1.3: the standalone echo server against real clients ---
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
        tport=47443
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
    python3 -c "open('test/www/big.txt','w').write('B'*100000)"
    python3 test/proxy_backend.py >/dev/null 2>&1 &
    tls_backend_pid=$!
    backend_ready
    $BIN --config test/configs/tls.json >/dev/null 2>&1 &
    tls_server_pid=$!
    sleep 0.3
    CA=test/tls/server.crt
    U=https://localhost:47443

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

    timeout 8 python3 - "$CA" 47443 <<'PYEOF'
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

    # a vhost with a proxy location must not advertise h3: Alt-Svc migration
    # is per-origin, and h3 has no location routing — a browser that switched
    # would 404 on every proxied path with no fallback
    hdrs=$(curl -si --max-time 5 --cacert $CA $U/hello.txt)
    ! echo "$hdrs" | grep -qi 'alt-svc'
    check "h3 not advertised by a proxy vhost (no alt-svc)" $?

    # kTLS reports the peer's close_notify as -EIO rather than a 0-length
    # read, so an orderly shutdown must not be logged as a recv error.
    curl -s --max-time 5 --cacert $CA $U/hello.txt >/dev/null
    sleep 0.3
    grep -q "closed connection on 127.0.0.1:47443 .*: peer closed" "$LOG"
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
    printf '%s' "$req" | timeout 5 openssl s_client -connect 127.0.0.1:47443 \
        -CAfile $CA -tls1_3 -ign_eof -sess_out "$LOG.sess" >/dev/null 2>&1
    reused=$(printf '%s' "$req" | timeout 5 openssl s_client \
        -connect 127.0.0.1:47443 -CAfile $CA -tls1_3 -ign_eof \
        -sess_in "$LOG.sess" 2>/dev/null | grep -c '^Reused')
    [ "$reused" -eq 1 ]
    check "tls resumption over kTLS (Reused)" $?
    rm -f "$LOG.sess"

    # ALPN: since Q86 a proxy location is served over h2 too, so this
    # server (47443, which has proxy locations) offers h2 like any other.
    # Offering nothing gets no ALPN extension back.
    echo | timeout 5 openssl s_client -connect 127.0.0.1:47443 -CAfile $CA \
        -tls1_3 -alpn h2,http/1.1 2>/dev/null | grep -q "ALPN protocol: h2"
    check "alpn: proxy vhost offers h2 (proxy-over-h2)" $?

    # security headers over h2, on static, error and proxied responses
    sec() { timeout 10 curl -s --http2 -D - -o /dev/null --cacert $CA \
        --resolve localhost:47443:127.0.0.1 "$1"; }
    h=$(sec "https://localhost:47443/hello.txt")
    echo "$h" | grep -qi '^strict-transport-security: max-age=31536000' \
        && echo "$h" | grep -qi '^x-content-type-options: nosniff'
    check "http2 security headers (static)" $?
    h=$(sec "https://localhost:47443/nope")
    echo "$h" | grep -qi '^strict-transport-security:' \
        && echo "$h" | grep -qi '^x-content-type-options:'
    check "http2 security headers (404)" $?
    h=$(sec "https://localhost:47443/api/simple")
    echo "$h" | grep -qi '^strict-transport-security:' \
        && echo "$h" | grep -qi '^x-content-type-options:'
    check "http2 security headers (proxied response)" $?

    # h2/h3 hand the whole :path to the normalizer, where h1 first cut the query
    # off and, for a directory, put back the slash normalize consumed. Without
    # that, every URL carrying a query and every directory but "/" 404'd on h2.
    q() { timeout 10 curl -s -o /dev/null -w '%{http_code}' --http2 --cacert $CA \
              --resolve localhost:47443:127.0.0.1 "https://localhost:47443$1"; }
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
    h2p() { timeout 10 curl -s --http2 --cacert $CA --resolve localhost:47443:127.0.0.1 "$@"; }
    P=https://localhost:47443
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
    sz=$(timeout 15 curl -s --http2 --cacert $CA --resolve localhost:47443:127.0.0.1 \
             -o /dev/null -o /dev/null -o /dev/null -o /dev/null \
             -w '%{size_download} ' \
             "$P/api/simple" "$P/index.html" "$P/api/simple" "$P/index.html")
    [ "$sz" = "12 335 12 335 " ]
    check "http2: static body still served after a proxied stream reuses the slot" $?
    # request-body bytes are debited from the connection window on arrival and
    # credited only once they go upstream, so a reset mid-upload used to strand
    # them: four ~16KB rounds exhausted the 65535 window for the connection's life
    python3 test/tls/h2_upload_credit.py $CA 47443 >/dev/null 2>&1
    check "http2: an aborted upload returns its connection flow control" $?
    # tearing an h2 connection down while the other direction still has an op in
    # flight now shuts the socket down and defers the free until it completes,
    # so the kernel cannot write into a recycled buffer. Confirm the deferral
    # always resolves: fds must come back to the baseline, not accumulate.
    w1=$(workers_of $tls_server_pid | awk '{print $1}')
    fd0=$(ls /proc/$w1/fd 2>/dev/null | wc -l)
    for _ in $(seq 1 30); do
        timeout 5 curl -s --http2 --max-time 0.05 --cacert $CA \
            --resolve localhost:47443:127.0.0.1 -o /dev/null \
            "https://localhost:47443/api/big" 2>/dev/null
        timeout 5 curl -s --http2 --max-time 0.05 --cacert $CA \
            --resolve localhost:47443:127.0.0.1 -o /dev/null \
            "https://localhost:47443/big.txt" 2>/dev/null
    done
    sleep 3
    fd1=$(ls /proc/$w1/fd 2>/dev/null | wc -l)
    [ -n "$fd0" ] && [ "$fd0" -gt 0 ] && [ "$fd1" -le $((fd0 + 2)) ] \
        && [ "$(h2p -o /dev/null -w '%{http_code}' "$P/index.html")" = 200 ]
    check "http2: aborted mid-transfer connections are freed, not leaked ($fd0 -> $fd1 fds)" $?
    # the rewritten upstream request: Host from :authority, client headers
    # forwarded, Content-Length re-derived, Connection: close ours
    head=$(h2p -H 'X-Probe: abc' "$P/api/headers")
    echo "$head" | grep -qi '^Host: localhost:47443' \
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
    out=$(timeout 15 curl -s --http2 --cacert $CA --resolve localhost:47443:127.0.0.1 \
        -w '%{num_connects}\n' -o /dev/null "$P/hello.txt" \
        -w '%{num_connects}\n' -o /dev/null "$P/api/simple" | awk '{t += $1} END {print t}')
    [ "$out" = "1" ]
    check "http2 proxy: static + proxied share one connection" $?
    # several proxied streams in flight at once (the slot pool)
    S=$(mktemp -d)
    timeout 20 curl -s --http2 --cacert $CA --resolve localhost:47443:127.0.0.1 --parallel \
        -o "$S/a" "$P/api/simple" -o "$S/b" "$P/api/chunked" \
        -o "$S/c" "$P/api/big" -o "$S/d" "$P/api/eof"
    [ "$(cat "$S/a")" = "backend body" ] && [ "$(cat "$S/b")" = "chunked body" ] \
        && [ "$(wc -c < "$S/c")" -eq 40000 ] && [ "$(cat "$S/d")" = "eof delimited body" ]
    check "http2 proxy: four concurrent upstream exchanges" $?
    rm -rf "$S"
    # a page's worth of concurrent API calls (six, the usual browser cap)
    codes=$(timeout 20 curl -s --http2 --cacert $CA --resolve localhost:47443:127.0.0.1 --parallel \
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
open('test/www/upload2.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
uwant=$(md5sum < test/www/upload2.bin | cut -d' ' -f1)
timeout 60 curl -s --http2 --cacert $CA --resolve localhost:47443:127.0.0.1 \
    --data-binary @test/www/upload2.bin "https://localhost:47443/api/echo" \
    > /tmp/upload2_echo.bin
[ "$(md5sum < /tmp/upload2_echo.bin | cut -d' ' -f1)" = "$uwant" ]
check "http2 streams a 300000-byte request body (byte-exact)" $?
rm -f /tmp/upload2_echo.bin
# and over TLS HTTP/1.1, where the client pipelines it behind the handshake
timeout 60 curl -s --http1.1 --cacert $CA --resolve localhost:47443:127.0.0.1 \
    --data-binary @test/www/upload2.bin "https://localhost:47443/api/echo" \
    > /tmp/upload3_echo.bin
[ "$(md5sum < /tmp/upload3_echo.bin | cut -d' ' -f1)" = "$uwant" ]
check "tls http1.1 streams a 300000-byte request body (byte-exact)" $?
rm -f /tmp/upload3_echo.bin

    # A streamed upload must leave the connection consistent: the request
    # head stays in place (so the access log can still name it) and the
    # keep-alive bookkeeping never sees in_len below head_len — that
    # underflowed into a gigabyte-scale copy off the end of the connection
    # pool, killing the worker.
    timeout 60 curl -s --http1.1 --cacert $CA --resolve localhost:47443:127.0.0.1 \
        -o /dev/null -w '%{http_code}' --data-binary @test/www/upload2.bin \
        "https://localhost:47443/api/echo" > /tmp/upl_code.txt
    timeout 60 curl -s --http1.1 --cacert $CA --resolve localhost:47443:127.0.0.1 \
        -o /dev/null -w '%{num_connects} %{http_code}' --data-binary @test/www/upload2.bin \
        "https://localhost:47443/api/echo" --next --http1.1 --cacert $CA \
        --resolve localhost:47443:127.0.0.1 -o /dev/null \
        -w ' %{num_connects} %{http_code}' "https://localhost:47443/hello.txt" \
        > /tmp/upl_ka.txt
    [ "$(cat /tmp/upl_ka.txt)" = "1 200 0 200" ]
    check "tls upload: keep-alive survives a streamed body" $?
    grep -q '"POST /api/echo HTTP/1.1" 200' "$LOG"
    check "tls upload: the streamed request is logged with its target" $?
    # the worker must still be the one that started (no crash + respawn)
    ! grep -q "exited, respawning" "$LOG"
    check "tls upload: no worker died" $?
    rm -f /tmp/upl_code.txt /tmp/upl_ka.txt

    # a HEAD is bodiless, and its slot must come back: more sequential
    # bodiless requests than there are slots, all on one connection
    args=""
    for i in $(seq 12); do args="$args -I -o /dev/null $P/api/simple"; done
    codes=$(timeout 20 curl -s --http2 --cacert $CA --resolve localhost:47443:127.0.0.1 \
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
    echo | timeout 5 openssl s_client -connect 127.0.0.1:47443 -CAfile $CA \
        -tls1_3 2>/dev/null | grep -q "No ALPN negotiated"
    check "alpn absent when not offered" $?

    # HTTP/2 connection bring-up: a separate http2:1 server. ALPN selects
    # h2; preface + SETTINGS + PING exchange; a request draws GOAWAY.
    $BIN --config test/configs/tls-h2.json >/dev/null 2>&1 &
    h2_pid=$!
    sleep 0.3
    timeout 10 python3 test/tls/h2_bringup.py $CA 47446 >/dev/null 2>&1
    check "http2 connection bring-up (preface, settings, ping, goaway)" $?

    # M16/M17: a real HTTP/2 client (curl's nghttp2 — genuine HPACK with
    # Huffman + the static table) has its HEADERS decoded and the named
    # static file served back over h2. Serving the right file end to end is
    # the proof the :path decoded correctly.
    rl="--resolve localhost:47446:127.0.0.1"
    u="https://localhost:47446"
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
open('test/www/h2range.bin','wb').write(d[:100000])"
    want=$(python3 -c "
import hashlib
print(hashlib.md5(open('test/www/h2range.bin','rb').read()[25000:75000]).hexdigest())")
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
    python3 - <<'PY'
import gzip
open('test/www/enc.txt', 'w').write('plain payload')
with gzip.open('test/www/enc.txt.gz', 'wb') as f:
    f.write(b'gzip payload')
open('test/www/enc.txt.br', 'wb').write(b'br payload')
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
    timeout 30 python3 test/tls/h2_multiplex.py $CA 47446 >/dev/null 2>&1
    check "http2 multiplexing (concurrent streams, rapid-reset, pool cap)" $?

    # RFC 9218 scheduling, the same policy h3's pump applies: the default
    # priority is NON-incremental, so concurrent responses complete one at a
    # time in arrival order; u=0 jumps the queue; i opts back in to sharing the
    # window. h2 parsed the priority field and then ignored it entirely.
    timeout 200 python3 test/tls/h2_priority.py $CA 47446 >/dev/null 2>&1
    check "http2 responses scheduled by RFC 9218 priority" $?

    # M19: fuzz the frame layer and HPACK decoder — malformed streams must
    # never crash the worker; a live h2 GET still serves between batches.
    # 150s, not 60: since unknown frame types are discarded rather than drawing
    # a GOAWAY (RFC 9113 4.1), the server no longer ends a fuzzed connection
    # early, so the client waits out its own timeout on more cases. The run is
    # slower by design — it measures ~80s — and a crash still shows as a
    # non-zero exit rather than as the timeout.
    timeout 150 python3 test/tls/fuzz_h2.py $CA 47446 120 >/dev/null 2>&1
    check "http2 fuzz (malformed frames + HPACK survive, server serves)" $?

    # M20: strict stream-id validation + honouring SETTINGS_INITIAL_WINDOW_SIZE.
    # A connection error must carry the code RFC 9113 names for it. Every fault
    # reported PROTOCOL_ERROR, because the reason was never threaded through to
    # the single site that writes the GOAWAY.
    timeout 30 python3 test/tls/h2_error_codes.py $CA 47446 >/dev/null 2>&1
    check "http2 connection errors carry the RFC's code" $?

    # RFC 9113 8.1.1: content-length must equal the sum of the DATA payloads.
    # An over-long body was already refused; one that stopped SHORT was not
    # noticed at all — the request sat holding an upstream slot until the body
    # clock timed it out, reporting a timeout for a framing fault visible at
    # once. Runs against the proxy vhost, which is where bodies go.
    timeout 60 python3 test/tls/h2_content_length.py $CA 47443 >/dev/null 2>&1
    check "http2 content-length is reconciled with the DATA sent" $?

    timeout 20 python3 test/tls/h2_conformance.py $CA 47446 >/dev/null 2>&1
    check "http2 conformance (stream-id rules, initial window size)" $?

    # A biggish cookie load (4.8 KB) fits the Q121 limits and must be SERVED —
    # whole, not with the overflowing fields silently dropped (the Q100 bug),
    # and certainly not by killing the connection (the pre-Q121 behaviour).
    bigck=$(python3 -c "print('a'*4800)")
    code=$(timeout 10 curl -s -o /dev/null -w '%{http_code}' --http2 --cacert $CA \
        --resolve localhost:47446:127.0.0.1 -H "Cookie: $bigck" \
        https://localhost:47446/hello.txt 2>/dev/null)
    [ "$code" = 200 ]
    check "http2 big-but-legal cookie served (fits the raised limits)" $?

    # Q121: an oversized header block answers the stream 431 (the connection
    # survives and keeps serving), and SETTINGS advertises the real
    # MAX_HEADER_LIST_SIZE so clients can trim before hitting it.
    timeout 30 python3 test/tls/h2_big_headers.py $CA 47446 >/dev/null 2>&1
    check "http2 oversized header block: stream 431, connection survives" $?

    # wrong-length PING / WINDOW_UPDATE are a connection error, not an over-read
    # (a zero-length PING used to echo 8 stale in_buf bytes to the peer)
    timeout 20 python3 test/tls/h2_frame_size.py $CA 47446 >/dev/null 2>&1
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
    timeout 30 python3 test/tls/oversized_record.py $CA 47443 \
        test/tls/clienthello_seed.bin >/dev/null 2>&1
    ovr_rc=$?
    if [ $ovr_rc -ne 0 ]; then
        ovr_probe=$(timeout 5 curl -s -o /dev/null -w '%{http_code}' --cacert $CA \
            --resolve localhost:47443:127.0.0.1 https://localhost:47443/hello.txt 2>&1)
        echo "  (oversized-record failed; the same server answers /hello.txt with: ${ovr_probe:-nothing})"
    fi
    [ $ovr_rc -eq 0 ]
    check "tls oversized record refused (msg_buf bound)" $?

    # Q125: a ClientHello split across records must still complete. A
    # handshake message is a byte stream carried by records, so a client may
    # fragment it at will — and one over 2^14 bytes has no choice. Every
    # fragmented hello used to draw a fatal alert.
    timeout 60 python3 test/tls/fragmented_ch.py 47443 >/dev/null 2>&1
    check "tls fragmented ClientHello completes the handshake" $?

    # Records pipelined behind the Finished, including one split the way an
    # MSS boundary would split it — the case loopback never produces.
    timeout 40 python3 test/tls/pipelined_early.py $CA 47443 >/dev/null 2>&1
    check "tls pipelined early records (whole and split)" $?

    # A tunnelled upgrade over TLS: the tunnel has its own recv path, so it
    # needs the close_notify handling too, and the relay must stay blind to
    # the fact that the kernel is encrypting underneath it.
    timeout 10 python3 - "$CA" 47443 <<'PYEOF' >/dev/null 2>&1
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
    prst_before=$(workers_of $tls_server_pid)
    timeout 60 python3 test/tls/h2_proxy_rst.py $CA 47443 >/dev/null 2>&1
    sleep 0.5
    resp=$(curl -si --http2 --max-time 5 --cacert $CA $U/hello.txt)
    prst_after=$(workers_of $tls_server_pid)
    [ -n "$prst_before" ] && [ "$prst_before" = "$prst_after" ] \
        && printf '%s' "$resp" | grep -qF "hello from linnea"
    check "http2 proxied-stream RST + RST-stream-0 crash no worker" $?

    # Q124: the authority rules — :authority is h2's Host, and a duplicate,
    # a Host contradicting it, a misplaced pseudo-header or a missing
    # authority must fail THAT STREAM (the connection keeps serving), while
    # a Host standing in for :authority still works.
    timeout 90 python3 test/tls/h2_authority.py $CA 47443 >/dev/null 2>&1
    check "http2 authority rules (stream errors, connection survives)" $?

    # RFC 9113 5.1.1: a client's stream id is odd and above the floor, and
    # breaking either is a CONNECTION error. Both were checked AFTER the
    # malformed-request tests, so a malformed request on an even id drew only a
    # stream reset and stamped the floor with an even number. The last case
    # guards the other side: a malformed request on a VALID id must still fail
    # only its stream.
    timeout 60 python3 test/tls/h2_stream_id.py $CA 47443 >/dev/null 2>&1
    check "http2 stream-id rules are connection errors" $?

    # A GOAWAY must name the highest stream we might have acted on (RFC 9113 6.8).
    # Every error GOAWAY said 0 — "nothing was processed" — so a client would
    # retry everything in flight, including a proxied POST already executed.
    timeout 60 python3 test/tls/h2_goaway_last_stream.py $CA 47443 >/dev/null 2>&1
    check "http2 GOAWAY names the last processed stream" $?

    # Inline error bodies are flow-controlled too (RFC 9113 6.9.1). They were
    # written straight at the out cursor and charged against nothing, so a peer
    # advertising a zero window was sent one anyway, and the server's idea of the
    # connection window drifted above the peer's by every error body it had sent.
    timeout 120 python3 test/tls/h2_error_flow_control.py $CA 47443 >/dev/null 2>&1
    check "http2 error bodies respect the flow-control window" $?

    # Request-field rules the shared HPACK/QPACK decoder enforces: :scheme must
    # be present, :path must not be empty, connection-specific fields are
    # malformed (TE only for "trailers"), a space may not sit in a field name and
    # a value may not begin or end with whitespace (RFC 9113 8.2-8.3).
    timeout 60 python3 test/tls/h2_field_rules.py $CA 47443 >/dev/null 2>&1
    check "http2 request field rules" $?

    # A trailer section is allowed (RFC 9113 8.1) and used to draw a GOAWAY: its
    # stream id is one already seen, which the strictly-increasing test called
    # broken numbering, taking every concurrent stream down with it. The last
    # case checks the subtle half — the trailer's fields are decoded even though
    # unused, or HPACK's connection-wide table falls out of step.
    timeout 60 python3 test/tls/h2_trailers.py $CA 47443 >/dev/null 2>&1
    check "http2 trailer sections do not kill the connection" $?

    # Every TLS connection must end with close_notify (RFC 8446 6.1) or the peer
    # cannot tell a finished response from a cut one. The alert may only be
    # written where no other send is outstanding, so the cases after a large
    # response and after h2 traffic are the ones that matter.
    timeout 90 python3 test/tls/close_notify.py $CA 47443 >/dev/null 2>&1
    check "tls connections end with close_notify" $?


    # HPACK is stateful, so a block we REJECT must still be walked to its end:
    # the inserts after the offending field reach the peer's dynamic table
    # whether we like the request or not. Stopping early left our table behind
    # the peer's, and a later request referencing a dynamic index then decoded
    # against the wrong entry — the probe sees a 'range' header from the
    # rejected request applied to a later one, turning its 200 into a 206.
    timeout 30 python3 test/tls/hpack_sync.py $CA 47443 >/dev/null 2>&1
    check "http2 HPACK table stays in sync across a rejected block" $?

    # ...and across the arena's wrap. The arena was a bump allocator that
    # reclaimed only when the table emptied, so an entry landing at the end was
    # silently not stored while the peer DID store it — leaving our table an
    # entry behind and every later dynamic index resolving to the wrong header.
    timeout 240 python3 test/tls/hpack_arena.py $CA 47443 >/dev/null 2>&1
    check "http2 HPACK entries survive the arena wrapping" $?

    # We advertise HEADER_TABLE_SIZE 4096, so the table is load-bearing for real
    # traffic rather than dead state: this drives eviction from "drop one" to
    # "drop everything", the entry-slot ceiling, size updates down to 0 and back,
    # and reads back a marker by dynamic index after every phase.
    timeout 400 python3 test/tls/hpack_stress.py $CA 47443 >/dev/null 2>&1
    check "http2 HPACK dynamic table under sustained use" $?

    # Q130: h2/h3 read a SEPARATE mime table from h1's, so the types are
    # checked here too — a type added to one table only is the easy mistake.
    printf 'x' > test/www/probe.wasm
    ct=$(timeout 10 curl -s -D - -o /dev/null --http2 --cacert $CA \
        --resolve localhost:47443:127.0.0.1 https://localhost:47443/probe.wasm \
        | grep -i '^content-type' | tr -d '\r')
    printf '%s' "$ct" | grep -qF "application/wasm"
    check "http2 mime table has the same types (.wasm)" $?

    # RFC 9110 15.5.6: a 405 must name what the resource does take. h1 always
    # sent Allow; h2 sent none, so a client could not tell what to retry with.
    al=$(timeout 10 curl -si --http2 --cacert $CA \
        --resolve localhost:47443:127.0.0.1 -X PROPFIND \
        https://localhost:47443/hello.txt | tr -d '\r')
    printf '%s' "$al" | grep -q "405" && printf '%s' "$al" | grep -qi "^allow: GET, HEAD"
    check "http2 405 carries Allow: GET, HEAD" $?
    # and nothing else claims to: a 200 and a 404 carry no allow
    for u in /hello.txt /nope.txt; do
        n=$(timeout 10 curl -si --http2 --cacert $CA \
            --resolve localhost:47443:127.0.0.1 https://localhost:47443$u \
            | tr -d '\r' | grep -ci "^allow:")
        [ "$n" -eq 0 ]
        check "http2 no Allow on a normal response ($u)" $?
    done
    rm -f test/www/probe.wasm

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
open('test/www/h2upload.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
    want=$(md5sum < test/www/h2upload.bin | cut -d' ' -f1)
    curl -s --http2 --max-time 30 --cacert $CA --data-binary @test/www/h2upload.bin \
        $U/api/echo > /tmp/h2upload_echo.bin
    [ "$(md5sum < /tmp/h2upload_echo.bin | cut -d' ' -f1)" = "$want" ]
    check "http2 streams a 300000-byte request body past the flow-control window" $?
    rm -f /tmp/h2upload_echo.bin test/www/h2upload.bin

    # Body-phase slowloris (Q119): head_timeout used to stop at the request
    # head, so a client trickling a proxied request body — or sitting silent
    # on an h2 upload, dodging the idle timeout — held its upstream slot
    # forever. The body clock (LINNEA_BODY_NS_PER_BYTE per received byte) cuts
    # a trickler about head_timeout after its last honest burst: h1 closes,
    # h2 fails the stream 408 and the connection and slot live on. A
    # full-speed upload must be untouched. Own server: head_timeout=3.
    $BIN --config test/configs/tls-slowbody.json >/dev/null 2>&1 &
    slowbody_pid=$!
    sleep 0.3
    timeout 60 python3 test/tls/slow_body.py $CA 47457 >/dev/null 2>&1
    check "request-body slowloris cut on h1 and h2; honest uploads untouched" $?
    kill $slowbody_pid 2>/dev/null
    wait $slowbody_pid 2>/dev/null

    kill $tls_server_pid $tls_backend_pid 2>/dev/null
    wait $tls_server_pid 2>/dev/null
    wait $tls_backend_pid 2>/dev/null
    rm -f "$LOG" test/www/big.txt

    # --- SNI: two TLS vhosts share 127.0.0.1:47444, each with its own cert
    $BIN --config test/configs/tls-sni.json >/dev/null 2>&1 &
    sni_server_pid=$!
    sleep 0.3
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:47444 \
        -servername sni.test 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=sni.test"
    check "sni selects the named vhost cert" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:47444 \
        -servername localhost 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "sni selects the owner cert by name" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:47444 \
        -noservername 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "no sni falls back to the listener owner" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:47444 \
        -servername unknown.test 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "unknown sni falls back to the listener owner" $?
    # the SAME must hold over HTTP/3: the QUIC listener on this port registers both
    # vhosts, and the ClientHello SNI selects the certificate (before this, h3 always
    # served the first vhost's cert, so a second name got the wrong one).
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        python3 test/quic/h3_sni_cert_test.py 47444 sni.test sni.test >/dev/null 2>&1
        check "h3 sni selects the named vhost cert" $?
        python3 test/quic/h3_sni_cert_test.py 47444 localhost localhost >/dev/null 2>&1
        check "h3 sni selects the owner cert by name" $?
    fi
    # every h3 vhost advertises Alt-Svc, not only the socket owner, so each origin
    # tells its own clients they can switch to h3 (a non-owner vhost is checked).
    curl -s -D - -o /dev/null --http2 --cacert test/tls/sni.crt \
        --resolve sni.test:47444:127.0.0.1 https://sni.test:47444/page.html \
        | grep -qi 'alt-svc: h3='
    check "h3 alt-svc advertised by a non-owner vhost" $?
    # h2 is on by default (tls-sni.json sets no "http2" key): a static vhost
    # negotiates h2.
    echo | timeout 5 openssl s_client -connect 127.0.0.1:47444 -CAfile test/tls/sni.crt \
        -servername sni.test -tls1_3 -alpn h2,http/1.1 2>/dev/null \
        | grep -q "ALPN protocol: h2"
    check "alpn: h2 on by default (static vhost)" $?
    # a full request via the SNI vhost: curl verifies against the sni.test
    # cert AND the Host routing must land on the sni.test docroot (which
    # holds page.html; the listener owner does not). h2 is on by default now,
    # so this also exercises SNI vhost routing over HTTP/2.
    resp=$(curl -s --max-time 5 --cacert test/tls/sni.crt \
        --resolve sni.test:47444:127.0.0.1 https://sni.test:47444/page.html)
    check_http "sni end to end (cert + vhost routing)" "subdirectory page" "$resp"

    # Q126: h2 answers only for names the certificate it presented covers —
    # the rule h3 got in Q124. A cross-certificate request gets 421, a name
    # we do not host is served by the connection's own vhost, and two vhosts
    # sharing ONE certificate still coalesce onto a single connection. The
    # worker-PID check is not ceremony: the first version of this crashed the
    # worker (the 421 path skipped the vhost the response builder reads), and
    # a crash looks exactly like a closed connection from the client side.
    $BIN --config test/configs/tls-coalesce.json >/dev/null 2>&1 &
    coal_h2_pid=$!
    sleep 0.4
    md_before=$(workers_of $sni_server_pid)
    timeout 60 python3 test/tls/h2_misdirected.py $CA 47444 47459 >/dev/null 2>&1
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
        timeout 90 python3 test/quic/h3_authority_test.py 47444 >/dev/null 2>&1
        check "h3 authority selects the vhost; cross-cert gets 421" $?
    else
        check "h3 authority test (skipped: deps unavailable)" 0
    fi

    # ...and the other side of that strictness: two vhosts sharing ONE
    # certificate are both names the connection can speak for, so a single
    # h3 connection serves both (what a browser coalesces). Own server: the
    # two vhosts differ from the SNI pair in using the same cert.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        $BIN --config test/configs/tls-coalesce.json >/dev/null 2>&1 &
        coal_pid=$!
        sleep 0.4
        timeout 60 python3 test/quic/h3_coalesce_test.py 47459 >/dev/null 2>&1
        check "h3 coalescing: one cert, two vhosts, one connection" $?
        kill $coal_pid 2>/dev/null
        wait $coal_pid 2>/dev/null
    else
        check "h3 coalescing test (skipped: deps unavailable)" 0
    fi
    kill $sni_server_pid 2>/dev/null
    wait $sni_server_pid 2>/dev/null
    rm -f "$LOG"
fi

# --- accept(2) that keeps failing must back off, not spin ---
# A multishot accept the kernel disarms with an error used to be re-armed
# immediately, so a standing EMFILE burned a whole core and wrote a log line
# per failure (millions in seconds). The fd limit is reached before the
# connection pool fills, which is what makes this reachable at all.
emf=test/configs/emfile.json
cat > $emf <<EOF
{
  "log": "$LOG",
  "timeout": 30, "head_timeout": 30, "workers": 1,
  "max_connections": 1024, "max_per_ip": 4096,
  "servers": [ { "host": "127.0.0.1", "port": 47671, "hostname": "localhost",
      "locations": [ { "prefix": "/", "root": "test/www" } ] } ]
}
EOF
# The startup check now makes an EMFILE from the *configured* pool impossible,
# so squeeze the running worker instead — which is the case that remains real:
# a system-wide ENFILE, or an operator lowering the limit under a live process.
$BIN --config $emf >test/emfile.err 2>&1 &
emf_pid=$!
sleep 0.6
emf_w=$(workers_of $emf_pid | awk '{print $1}')
[ -n "$emf_w" ] && prlimit --pid $emf_w --nofile=48:524288 2>/dev/null
python3 - <<'PY' &
import socket, time
socks = []
for _ in range(200):
    try:
        socks.append(socket.create_connection(("127.0.0.1", 47671), timeout=2))
    except OSError:
        pass
time.sleep(6)
for s in socks:
    s.close()
PY
emf_flood=$!
sleep 1.5
if [ -n "$emf_w" ] && [ -r /proc/$emf_w/stat ]; then
    t0=$(awk '{print $14+$15}' /proc/$emf_w/stat)
    sleep 3
    t1=$(awk '{print $14+$15}' /proc/$emf_w/stat)
    ticks=$((t1 - t0))
else
    ticks=-1
fi
wait $emf_flood 2>/dev/null
sleep 1
# a spin is ~300 ticks per 3s (one full core); the backoff leaves it near 0
lines=$(wc -l < test/emfile.err)
[ "$ticks" -ge 0 ] && [ "$ticks" -lt 100 ] && [ "$lines" -lt 1000 ] \
    && [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            http://127.0.0.1:47671/hello.txt)" = 200 ]
check "accept: a standing EMFILE backs off instead of spinning (${ticks} ticks, ${lines} log lines)" $?
kill $emf_pid 2>/dev/null
wait $emf_pid 2>/dev/null
rm -f $emf test/emfile.err "$LOG"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
