# Backend TLS client handshake (roadmap #1, Tier 0). linnea-tlsclient runs the
# authenticating TLS 1.3 CLIENT against openssl s_server holding the test cert:
# it pins sha256 of the certificate's SubjectPublicKeyInfo, then verifies the
# CertificateVerify and Finished. A matching pin completes the handshake AND the
# server accepts our Finished (proved by a decryptable post-handshake record); a
# wrong pin, and a server that forces a HelloRetryRequest for a group we do not
# offer (x25519 only), both fail cleanly rather than hanging or mis-accepting.
#
# Built here as well as in run_shards' pre-build list so the single-process
# runner (./test/run_tests.sh tls) has it too.
make -s bin/linnea-tlsclient >/dev/null 2>&1

if command -v openssl >/dev/null 2>&1 && [ -x ./bin/linnea-tlsclient ]; then
    # pin = sha256(SubjectPublicKeyInfo DER) of the test cert; a wrong pin is 32 zeros
    python3 - "$RUNDIR" <<'PY'
import hashlib, os, subprocess, sys
d = sys.argv[1]
spki = subprocess.run(["openssl", "x509", "-in", "test/tls/server.crt",
                       "-noout", "-pubkey"], capture_output=True).stdout
der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                     input=spki, capture_output=True).stdout
open(os.path.join(d, "pin.bin"), "wb").write(hashlib.sha256(der).digest())
open(os.path.join(d, "wpin.bin"), "wb").write(b"\x00" * 32)
PY

    openssl s_server -accept ${P61710} -cert test/tls/server.crt -key test/tls/server.key \
        -tls1_3 -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 -www -quiet \
        >$RUNDIR/bt_ss.log 2>&1 &
    ssp=$!
    sleep 0.5
    out=$(timeout 8 ./bin/linnea-tlsclient ${P61710} <$RUNDIR/pin.bin 2>/dev/null)
    [ "$out" = "OK" ]
    check "backend TLS: authenticating handshake completes (pin match, vs openssl)" $?
    # resumability: force the driver to reassemble across 1-byte reads
    out=$(timeout 12 ./bin/linnea-tlsclient ${P61710} 1 <$RUNDIR/pin.bin 2>/dev/null)
    [ "$out" = "OK" ]
    check "backend TLS: handshake resumes across 1-byte record fragments" $?
    out=$(timeout 8 ./bin/linnea-tlsclient ${P61710} <$RUNDIR/wpin.bin 2>/dev/null)
    [ "$out" = "FAIL" ]
    check "backend TLS: wrong SPKI pin is refused" $?
    kill $ssp 2>/dev/null; wait $ssp 2>/dev/null

    openssl s_server -accept ${P61711} -cert test/tls/server.crt -key test/tls/server.key \
        -tls1_3 -groups P-256 -ciphersuites TLS_AES_128_GCM_SHA256 -www -quiet \
        >$RUNDIR/bt_hrr.log 2>&1 &
    ssp=$!
    sleep 0.5
    out=$(timeout 8 ./bin/linnea-tlsclient ${P61711} <$RUNDIR/pin.bin 2>/dev/null)
    [ "$out" = "FAIL" ]
    check "backend TLS: HelloRetryRequest for an unoffered group fails cleanly" $?
    kill $ssp 2>/dev/null; wait $ssp 2>/dev/null

    rm -f $RUNDIR/pin.bin $RUNDIR/wpin.bin $RUNDIR/bt_ss.log $RUNDIR/bt_hrr.log
else
    check "backend TLS client handshake (skipped: openssl/binary unavailable)" 0
fi

# --- end to end: linnea proxying to a linnea TLS backend, pinned -------------
# The handshake above is the client in isolation; this is the whole proxy path.
# A plaintext FRONT linnea has a proxy_tls location pointing at a linnea TLS
# BACKEND, pinned to the backend cert's SPKI. A GET to the front travels the
# real io_uring wiring: userspace handshake over the up leg, kTLS handoff on
# the backend socket (control-record-aware reads skip the backend's
# NewSessionTickets), then the backend's response relayed to the client. The
# backend leg is kernel-TLS, so this gates on the tls ULP exactly like 20-e2e;
# the pin is computed from the cert, so it survives a cert rotation.
if grep -qw tls /proc/sys/net/ipv4/tcp_available_ulp 2>/dev/null \
   && command -v openssl >/dev/null 2>&1; then
    btw=$RUNDIR/bt_www; mkdir -p "$btw"
    printf 'BACKEND-OK\n' > "$btw/probe.txt"
    PIN=$(openssl x509 -in test/tls/server.crt -noout -pubkey \
          | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary \
          | xxd -p -c256)

    cat > $CFG/bt-be.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-be.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61712}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/", "root": "$PWD/$btw" } ] } ] }
EOF
    cat > $CFG/bt-fe.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61713}, "hostname": "front.test",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61712}",
      "proxy_tls": 1, "proxy_pin": "$PIN", "proxy_sni": "localhost" } ] } ] }
EOF
    start_server $CFG/bt-be.json
    start_server $CFG/bt-fe.json

    body=$(curl -s --max-time 8 http://127.0.0.1:${P61713}/probe.txt)
    [ "$body" = "BACKEND-OK" ]
    check "backend TLS e2e: front proxies to a pinned linnea TLS backend (body relayed)" $?

    # 40 concurrent requests down one pinned front: the per-connection handshake
    # arenas and up-leg RX state must not collide.
    : > $RUNDIR/bt_conc.txt
    cpids=""
    for i in $(seq 40); do
        curl -s -o /dev/null --max-time 8 -w '%{http_code}\n' \
            http://127.0.0.1:${P61713}/probe.txt >>$RUNDIR/bt_conc.txt &
        cpids="$cpids $!"
    done
    wait $cpids 2>/dev/null
    [ "$(grep -c '^200' $RUNDIR/bt_conc.txt)" = 40 ]
    check "backend TLS e2e: 40 concurrent requests all 200 through one front" $?

    # A wrong pin must fail the handshake and surface as 502 — never the backend
    # body, never a hang.
    ZPIN=$(printf '0%.0s' $(seq 64))
    cat > $CFG/bt-fe-bad.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe-bad.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61714}, "hostname": "front.test",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61712}",
      "proxy_tls": 1, "proxy_pin": "$ZPIN", "proxy_sni": "localhost" } ] } ] }
EOF
    start_server $CFG/bt-fe-bad.json
    code=$(curl -s -o /dev/null --max-time 8 -w '%{http_code}' \
        http://127.0.0.1:${P61714}/probe.txt)
    [ "$code" = 502 ]
    check "backend TLS e2e: a wrong pin fails the handshake and returns 502" $?

    # --- proxy_h2: speak HTTP/2 to the pinned TLS backend (Tier 1) -----------
    # The same TLS backend (bt-be) also speaks h2 by ALPN; a proxy_h2 front
    # negotiates h2, runs the h2 client leg over the kTLS socket, and relays the
    # synthesized h1 response to the (h1) client. v1 covers h1 clients.
    cat > $CFG/bt-fe-h2.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe-h2.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61715}, "hostname": "front.test",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61712}",
      "proxy_tls": 1, "proxy_pin": "$PIN", "proxy_sni": "localhost",
      "proxy_h2": 1 } ] } ] }
EOF
    start_server $CFG/bt-fe-h2.json
    body=$(curl -s --max-time 8 http://127.0.0.1:${P61715}/probe.txt)
    [ "$body" = "BACKEND-OK" ]
    check "backend h2 e2e: h1 client -> front -> TLS+h2 -> linnea (body relayed)" $?

    # a large response must relay intact over the h2 leg (spans DATA frames)
    python3 -c "open('$btw/big.bin','w').write('B'*200000)"
    n=$(curl -s --max-time 12 http://127.0.0.1:${P61715}/big.bin | wc -c)
    [ "$n" = 200000 ]
    check "backend h2 e2e: a 200000-byte response relays intact over the h2 leg" $?

    # concurrency: independent per-leg h2 contexts must not collide
    : > $RUNDIR/h2_conc.txt
    cpids=""
    for i in $(seq 20); do
        curl -s -o /dev/null --max-time 8 -w '%{http_code}\n' \
            http://127.0.0.1:${P61715}/probe.txt >>$RUNDIR/h2_conc.txt &
        cpids="$cpids $!"
    done
    wait $cpids 2>/dev/null
    [ "$(grep -c '^200' $RUNDIR/h2_conc.txt)" = 20 ]
    check "backend h2 e2e: 20 concurrent requests all 200 over the h2 leg" $?

    # a wrong pin must fail the h2 leg's handshake -> 502
    cat > $CFG/bt-fe-h2-bad.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe-h2-bad.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61716}, "hostname": "front.test",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61712}",
      "proxy_tls": 1, "proxy_pin": "$ZPIN", "proxy_sni": "localhost",
      "proxy_h2": 1 } ] } ] }
EOF
    start_server $CFG/bt-fe-h2-bad.json
    code=$(curl -s -o /dev/null --max-time 8 -w '%{http_code}' \
        http://127.0.0.1:${P61716}/probe.txt)
    [ "$code" = 502 ]
    check "backend h2 e2e: a wrong pin fails and returns 502 (proxy_h2)" $?

    # --- an h2 client through proxy_h2: curl negotiates h2 by ALPN against a TLS
    # front, which runs the h2 backend leg and frames the synthesized response
    # back over the client's own h2 connection. This is the path the F_KTLS /
    # F_HEAD_INTERIM flag-bit collision broke (a 200 looked like a 1xx interim,
    # so the client got a spurious second HEADERS and an empty body). ---
    cat > $CFG/bt-fe-h2c.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe-h2c.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61718}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61712}",
      "proxy_tls": 1, "proxy_pin": "$PIN", "proxy_sni": "localhost",
      "proxy_h2": 1 } ] } ] }
EOF
    start_server $CFG/bt-fe-h2c.json
    body=$(curl -s --http2 --cacert "$PWD/test/tls/server.crt" --max-time 8 \
        --resolve localhost:${P61718}:127.0.0.1 \
        https://localhost:${P61718}/probe.txt)
    [ "$body" = "BACKEND-OK" ]
    check "backend h2 e2e: an h2 client (curl --http2) is framed a full-body 200 (proxy_h2)" $?

    # the h2 client must get the whole large body, not just the first slot buffer
    n=$(curl -s --http2 --cacert "$PWD/test/tls/server.crt" --max-time 12 \
        --resolve localhost:${P61718}:127.0.0.1 \
        https://localhost:${P61718}/big.bin | wc -c)
    [ "$n" = 200000 ]
    check "backend h2 e2e: an h2 client receives a 200000-byte body intact (proxy_h2)" $?

    # --- an h3 client through proxy_h2: the synthesized response is QPACK
    # re-encoded and delivered over QUIC (a real curl-h3 client) ---
    CURLH3=${LINNEA_CURL_H3:-$HOME/curl-h3/bin/curl}
    if [ -x "$CURLH3" ]; then
        cat > $CFG/bt-fe-h3.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe-h3.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61717}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61712}",
      "proxy_tls": 1, "proxy_pin": "$PIN", "proxy_sni": "localhost",
      "proxy_h2": 1 } ] } ] }
EOF
        start_server $CFG/bt-fe-h3.json
        body=$("$CURLH3" --http3-only -sk --max-time 10 \
            --resolve localhost:${P61717}:127.0.0.1 \
            https://localhost:${P61717}/probe.txt 2>/dev/null)
        [ "$body" = "BACKEND-OK" ]
        check "backend h2 e2e: an h3 client is served via QPACK re-encode (proxy_h2)" $?
    else
        check "backend h2 e2e: h3 client (skipped: curl-h3 unavailable)" 0
    fi

    # --- an h2 client to a PLAIN proxy_tls backend (no proxy_h2) -------------
    # The h2p leg started its backend TLS handshake on proxy_h2 rather than on
    # proxy_tls, so an h2 CLIENT reaching a plain TLS backend sent its request
    # head in cleartext to a socket expecting records: an unfailable 502 for a
    # documented configuration (audit-report-41). h1 and h3 clients always
    # worked, which is why nothing caught it -- every proxy_tls check above
    # drives curl, and curl speaks HTTP/1.1 to a plaintext front.
    cat > $CFG/bt-fe-tls-h2c.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe-tls-h2c.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61719}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61712}",
      "proxy_tls": 1, "proxy_pin": "$PIN", "proxy_sni": "localhost" } ] } ] }
EOF
    start_server $CFG/bt-fe-tls-h2c.json
    body=$(curl -s --http2 --cacert "$PWD/test/tls/server.crt" --max-time 8 \
        --resolve localhost:${P61719}:127.0.0.1 \
        https://localhost:${P61719}/probe.txt)
    [ "$body" = "BACKEND-OK" ]
    check "backend TLS e2e: an h2 client is served over a plain proxy_tls leg" $?

    # a response past one slot buffer: the leg reads a RECORD at a time, so this
    # walks the kTLS RECVMSG path and the buffer recycle many times over
    n=$(curl -s --http2 --cacert "$PWD/test/tls/server.crt" --max-time 12 \
        --resolve localhost:${P61719}:127.0.0.1 \
        https://localhost:${P61719}/big.bin | wc -c)
    [ "$n" = 200000 ]
    check "backend TLS e2e: an h2 client receives a 200000-byte body over proxy_tls" $?

    # concurrency: each leg holds its own handshake arena and kTLS RX block
    : > $RUNDIR/tls_h2_conc.txt
    cpids=""
    for i in $(seq 20); do
        curl -s -o /dev/null --max-time 10 --http2 --cacert "$PWD/test/tls/server.crt" \
            --resolve localhost:${P61719}:127.0.0.1 -w '%{http_code}\n' \
            https://localhost:${P61719}/probe.txt >>$RUNDIR/tls_h2_conc.txt &
        cpids="$cpids $!"
    done
    wait $cpids 2>/dev/null
    [ "$(grep -c '^200' $RUNDIR/tls_h2_conc.txt)" = 20 ]
    check "backend TLS e2e: 20 concurrent h2 clients all 200 over proxy_tls legs" $?

    # --- a backend that sends NewSessionTickets (openssl s_server) -----------
    # Every proxy check above uses a linnea BACKEND, and linnea sends no session
    # tickets — so none of them can see a leg mishandle one. A kTLS read returns
    # one RECORD, and a plain recv faults (-EIO) on a control record: the ticket
    # openssl and nginx send right after the handshake is exactly that. This is
    # the only check here that fails when a leg reads its backend with a plain
    # recv instead of a record-type-aware RECVMSG, on any of the three client
    # paths. s_server answers HTTP/1.0 and closes, so it also proves a
    # close-delimited body ends on the close_notify rather than an error.
    openssl s_server -accept ${P61722} -cert test/tls/server.crt -key test/tls/server.key \
        -tls1_3 -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 -www -quiet \
        >$RUNDIR/bt_nst.log 2>&1 &
    nstp=$!
    sleep 0.5
    cat > $CFG/bt-fe-nst.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe-nst.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61723}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61722}",
      "proxy_tls": 1, "proxy_pin": "$PIN", "proxy_sni": "localhost" } ] } ] }
EOF
    start_server $CFG/bt-fe-nst.json
    for proto in --http1.1 --http2; do
        code=$(curl -s -o /dev/null --max-time 10 $proto \
            --cacert "$PWD/test/tls/server.crt" \
            --resolve localhost:${P61723}:127.0.0.1 -w '%{http_code}' \
            https://localhost:${P61723}/)
        [ "$code" = 200 ]
        check "backend TLS: a ticket-sending backend is relayed, not 502 (client $proto)" $?
    done
    if [ -x "$CURLH3" ]; then
        code=$("$CURLH3" --http3-only -sk -o /dev/null --max-time 10 \
            --resolve localhost:${P61723}:127.0.0.1 -w '%{http_code}' \
            https://localhost:${P61723}/)
        [ "$code" = 200 ]
        check "backend TLS: a ticket-sending backend is relayed, not 502 (h3 client)" $?
    else
        check "backend TLS: ticket-sending backend, h3 client (skipped: curl-h3 unavailable)" 0
    fi
    kill $nstp 2>/dev/null; wait $nstp 2>/dev/null
    rm -f $RUNDIR/bt_nst.log

    # --- proxy_keepalive must never park a TLS backend leg -------------------
    # A parked kTLS socket carries kernel crypto state the pool does not track,
    # and the taker sends its head with none of it set up. h1 has refused to
    # pool a TLS leg since backend TLS landed; the h2 and h3 legs had no such
    # rule, and an h3 client was observed taking a parked kTLS leg out of the
    # pool (audit-report-41). Count the BACKEND's accepts: N requests to a
    # keep-alive TLS location must open N connections, not reuse one.
    ka_probe() {   # $1 = how many requests, $2.. = the client command to repeat
        local n=$1; shift
        local before after i ok=0
        before=$(awk '/accepted connection/{c++} END{print c+0}' $RUNDIR/bt-be.log)
        for i in $(seq $n); do
            [ "$("$@")" = "BACKEND-OK" ] && ok=$((ok + 1))
        done
        sleep 0.3
        after=$(awk '/accepted connection/{c++} END{print c+0}' $RUNDIR/bt-be.log)
        echo "$ok $((after - before))"
    }

    cat > $CFG/bt-fe-tls-ka.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe-tls-ka.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61720}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61712}",
      "proxy_tls": 1, "proxy_pin": "$PIN", "proxy_sni": "localhost",
      "proxy_keepalive": 1 } ] } ] }
EOF
    start_server $CFG/bt-fe-tls-ka.json
    r=$(ka_probe 3 curl -s --http2 --cacert "$PWD/test/tls/server.crt" \
        --max-time 8 --resolve localhost:${P61720}:127.0.0.1 \
        https://localhost:${P61720}/probe.txt)
    [ "$r" = "3 3" ]
    check "backend TLS: proxy_keepalive parks no TLS leg (h2 client: 3 requests, 3 backend connections)" $?

    if [ -x "$CURLH3" ]; then
        r=$(ka_probe 3 "$CURLH3" --http3-only -sk --max-time 10 \
            --resolve localhost:${P61720}:127.0.0.1 \
            https://localhost:${P61720}/probe.txt)
        [ "$r" = "3 3" ]
        check "backend TLS: proxy_keepalive parks no TLS leg (h3 client: 3 requests, 3 backend connections)" $?
    else
        check "backend TLS: proxy_keepalive/h3 client (skipped: curl-h3 unavailable)" 0
    fi

    # the same for a proxy_h2 location, which is a TLS location too. Nothing but
    # the "connection: close" the h2 driver stamps on every synthesized response
    # was keeping these out of the pool -- incidental, and the reason the filed
    # finding did not reproduce.
    cat > $CFG/bt-fe-h2-ka.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe-h2-ka.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61721}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61712}",
      "proxy_tls": 1, "proxy_pin": "$PIN", "proxy_sni": "localhost",
      "proxy_h2": 1, "proxy_keepalive": 1 } ] } ] }
EOF
    start_server $CFG/bt-fe-h2-ka.json
    r=$(ka_probe 3 curl -s --http2 --cacert "$PWD/test/tls/server.crt" \
        --max-time 8 --resolve localhost:${P61721}:127.0.0.1 \
        https://localhost:${P61721}/probe.txt)
    [ "$r" = "3 3" ]
    check "backend h2: proxy_keepalive parks no h2 leg (3 requests, 3 backend connections)" $?

    rm -f $RUNDIR/bt_conc.txt $RUNDIR/h2_conc.txt $RUNDIR/tls_h2_conc.txt \
          "$btw/probe.txt" "$btw/big.bin"
else
    check "backend TLS e2e proxy (skipped: tls ULP or openssl unavailable)" 0
fi
