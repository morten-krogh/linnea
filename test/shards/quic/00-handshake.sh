# QUIC handshake, NewSessionTicket, session resumption and 0-RTT, driven directly through aioquic (no linnea server yet).


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

