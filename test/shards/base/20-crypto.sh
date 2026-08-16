# Crypto self-test: known-answer vectors for the TLS primitives.
# (was run_tests.sh lines 515-725.)

# --- crypto self-test: known-answer vectors for the TLS primitives ---
# Build the unit-test binaries here rather than trusting what is on disk. `make`
# does not produce them, and the checks below only test for existence — so a tree
# that has been cleaned reports a failure that looks like a real one, while a
# STALE binary is worse: it passes, silently testing code that no longer exists.
make -s bin/linnea-selftest bin/linnea-quictest bin/linnea-rtxtest >/dev/null 2>&1
if [ -x ./bin/linnea-selftest ]; then
    if ./bin/linnea-selftest >$RUNDIR/linnea_selftest.out 2>&1; then
        check "crypto selftest ($(tr '\n' ' ' <$RUNDIR/linnea_selftest.out))" 0
    else
        check "crypto selftest" 1
        cat $RUNDIR/linnea_selftest.out
    fi
    rm -f $RUNDIR/linnea_selftest.out
else
    check "crypto selftest (binary not built — run 'make selftest')" 1
fi

# QUIC crypto known-answer tests (RFC 9001 / 9000). Built by `make quictest`.
if [ -x ./bin/linnea-quictest ]; then
    if ./bin/linnea-quictest >$RUNDIR/linnea_quictest.out 2>&1; then
        check "quic crypto selftest ($(tr '\n' ' ' <$RUNDIR/linnea_quictest.out))" 0
    else
        check "quic crypto selftest" 1
        cat $RUNDIR/linnea_quictest.out
    fi
    rm -f $RUNDIR/linnea_quictest.out
else
    check "quic crypto selftest (binary not built — run 'make quictest')" 1
fi

# QUIC on the wire: a standalone UDP receiver decrypts a real Initial packet
# built by aioquic (the QUIC/HTTP-3 reference client).
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quicserver ]; then
    timeout 10 ./bin/linnea-quicserver ${P61500} >$RUNDIR/linnea_quicsrv.out 2>&1 &
    qsrv=$!
    sleep 0.4
    python3 test/quic/h3_initial.py ${P61500} >/dev/null 2>&1
    sleep 0.4
    wait $qsrv 2>/dev/null
    # decrypt the Initial, recover the ClientHello, and read its SNI + h3 ALPN
    grep -q "quic-initial sni=localhost alpn-h3=1" $RUNDIR/linnea_quicsrv.out
    check "quic: decrypt aioquic Initial + parse ClientHello (SNI, h3 ALPN)" $?
    rm -f $RUNDIR/linnea_quicsrv.out
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
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/hs_test.py ${P61501} >/dev/null 2>&1
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
    timeout 10 ./bin/linnea-quichs ${P61501} >"$cfinlog" 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/cfin_test.py ${P61501} >/dev/null 2>&1
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

# io_uring submission accounting: when the kernel consumes fewer sqes than it was
# told (a batch with an sqe it cannot init), the remainder must still be offered
# again rather than trailing our tail for the life of the process.
if [ -x ./bin/linnea-ringtest ]; then
    out=$(./bin/linnea-ringtest)
    rc=$?
    check "io_uring partial-submission recovery selftest ($out)" $rc
else
    check "io_uring partial-submission selftest (skipped: binary unavailable)" 0
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
    check "quic 0-RTT anti-replay + ticket-lifetime + ack-delay selftest ($out)" $rc
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

# The response ENCODER's output bound. It assembled a field section into a
# 768-byte buffer with no limit at all, while the proxy-relay encoder beside it
# in the same file had carried one all along -- and a redirect's Location is the
# configured target plus the CLIENT's request target, so a long path ran a
# couple of thousand bytes past the end. Nothing observed it: the bytes landed
# in a neighbouring buffer nothing read again. Only a canary can fail on that,
# which is what this asserts, alongside a control that a section which FITS is
# still produced (or the checks would pass on an encoder that wrote nothing).
if [ -x ./bin/linnea-qpacktest ]; then
    out=$(./bin/linnea-qpacktest encode 2>&1)
    [ "${out%% *}" = "qpack-encode" ] && [ "${out##* }" = "6/6" ]
    check "qpack: the response encoder refuses to write past its buffer ($out)" $?
else
    check "qpack encoder bound (skipped: binary unavailable)" 0
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
