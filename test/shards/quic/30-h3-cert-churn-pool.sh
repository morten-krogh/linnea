# Drain with an in-flight h2 response, the large-certificate (fragmented Certificate) handshake, acknowledgements, connection churn and pool demux.


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

