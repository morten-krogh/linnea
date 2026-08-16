# The slow-body deadline over TLS, then teardown of the end-to-end server and backend.

if [ "$ktls" = 1 ]; then
    start_server $CFG/tls-slowbody.json
    P61457=$SRV_PORT
    slowbody_pid=$SRV_PID
    sleep 0.3
    timeout 60 python3 test/tls/slow_body.py $CA ${P61457} >/dev/null 2>&1
    check "request-body slowloris cut on h1 and h2; honest uploads untouched" $?
    kill $slowbody_pid 2>/dev/null
    wait $slowbody_pid 2>/dev/null

    # --- HTTP/3 through an INDEPENDENT implementation -----------------------
    # Every other h3 check in this file drives aioquic. If linnea and aioquic
    # share a misreading of RFC 9114, that agreement looks exactly like
    # correctness and nothing here can tell. curl built against ngtcp2 +
    # nghttp3 shares no code with either, so where the two agree the reading is
    # very unlikely to be wrong.
    #
    # Optional, like the aioquic checks: skipped when the binary is absent, so
    # a clean checkout still passes. Build one with
    #   ./configure --with-ngtcp2 --with-nghttp3 --prefix=$HOME/curl-h3
    # and point LINNEA_CURL_H3 at it, or leave it at the default path.
    #
    # --http3-only, never --http3: the latter falls back to h2 when h3 fails,
    # which would let a broken h3 pass every check below.
    CURLH3=${LINNEA_CURL_H3:-$HOME/curl-h3/bin/curl}
    if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
        h3o="--http3-only -s --max-time 25 --cacert $CA"
        h3r="--resolve localhost:${P61443}:127.0.0.1"

        # big.txt, not hello.txt: 100000 bytes is many packets, so this covers
        # stream reassembly and flow control rather than one lucky datagram.
        "$CURLH3" $h3o $h3r -o $RUNDIR/h3big.out $U/big.txt
        curl -s --http2 --max-time 10 --cacert $CA -o $RUNDIR/h2big.out $U/big.txt
        [ -s $RUNDIR/h3big.out ] && cmp -s $RUNDIR/h3big.out $RUNDIR/h2big.out
        check "h3 (ngtcp2): a 100000-byte file is byte-identical to h2's copy" $?
        rm -f $RUNDIR/h3big.out $RUNDIR/h2big.out

        # h3 could not express a redirect at all until it could emit Location
        # (QPACK static index 12); before that a vhost with one was kept off h3
        # entirely, so this is also the check that the vhost HAS a listener.
        l3=$("$CURLH3" $h3o $h3r -o /dev/null -D - "$U/old/page?x=1" \
             | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
        l1=$(curl -s --http1.1 --max-time 10 --cacert $CA -o /dev/null -D - \
             "$U/old/page?x=1" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
        [ -n "$l3" ] && [ "$l3" = "$l1" ]
        check "h3 redirect: Location matches h1 exactly ($l3)" $?

        s3=$("$CURLH3" $h3o $h3r -o /dev/null -w '%{http_code}' "$U/old/page?x=1")
        [ "$s3" = "301" ]
        check "h3 redirect: 301 over QUIC ($s3)" $?

        # an upload over h3, which is the capture path rather than the FIFO
        python3 -c "
import random, sys
random.seed(23)
open(sys.argv[1],'wb').write(bytes(random.getrandbits(8) for _ in range(300000)))" "$WWW/h3up.bin"
        "$CURLH3" $h3o $h3r -o $RUNDIR/h3up.out -X POST \
            --data-binary @$WWW/h3up.bin $U/api/echo
        [ -s $RUNDIR/h3up.out ] &&
        [ "$(md5sum < $RUNDIR/h3up.out | cut -d' ' -f1)" = \
          "$(md5sum < $WWW/h3up.bin | cut -d' ' -f1)" ]
        check "h3 (ngtcp2): a 300000-byte upload round-trips byte-exact" $?
        rm -f $WWW/h3up.bin $RUNDIR/h3up.out

        m3=$("$CURLH3" $h3o $h3r -o /dev/null -w '%{http_code}' $U/nope.txt)
        [ "$m3" = "404" ]
        check "h3 (ngtcp2): a missing file is 404, not a hang ($m3)" $?
    else
        check "h3 via an independent client (skipped: no HTTP/3 curl — see the note above)" 0
    fi

    kill $tls_server_pid $tls_backend_pid 2>/dev/null
    wait $tls_server_pid 2>/dev/null
    wait $tls_backend_pid 2>/dev/null
    rm -f "$LOG" $WWW/big.txt
fi
