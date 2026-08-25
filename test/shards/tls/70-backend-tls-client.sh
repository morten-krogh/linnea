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

    # --- a backend that answers with HTTP/2 response TRAILERS ---------------
    # test/h2/h2c_server.py in "tls" mode is a real h2 server behind TLS 1.3 with
    # ALPN h2, so it can stand where a linnea backend cannot: /trailers answers
    # 200 with DATA that does NOT end the stream, then a TRAILER section (a
    # second HEADERS block carrying END_STREAM). RFC 9113 8.1 allows that, and
    # the linnea backend fixture cannot produce it — its last DATA frame carries
    # END_STREAM. The trailer must reach the client as NOTHING: not as a header
    # field, and not as a lost status (audit-report-42). Python also sends
    # NewSessionTickets, so this doubles as a second ticket-sending backend.
    cat > $CFG/bt-fe-tr.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe-tr.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61725}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61724}",
      "proxy_tls": 1, "proxy_pin": "$PIN", "proxy_sni": "localhost",
      "proxy_h2": 1 } ] } ] }
EOF
    start_server $CFG/bt-fe-tr.json

    # the fixture serves one connection at a time, and a TLS leg is never
    # pooled, so every request below is its own backend connection
    tr_get() {   # $1 = path, $2.. = the client command (headers on stdout)
        local path=$1; shift
        python3 test/h2/h2c_server.py ${P61724} tls >$RUNDIR/bt_tr.log 2>&1 &
        local pid=$!
        sleep 0.5
        "$@" "https://localhost:${P61725}$path" 2>/dev/null
        kill $pid 2>/dev/null; wait $pid 2>/dev/null
    }
    H1="curl -s -D- --max-time 10 --http1.1 --cacert $PWD/test/tls/server.crt \
        --resolve localhost:${P61725}:127.0.0.1"
    H2="curl -s -D- --max-time 10 --http2 --cacert $PWD/test/tls/server.crt \
        --resolve localhost:${P61725}:127.0.0.1"

    out=$(tr_get /hello $H1)
    printf '%s' "$out" | grep -q "^HTTP/1.1 200" \
        && printf '%s' "$out" | grep -q "hello from h2c"
    check "backend h2 trailers: the python h2 fixture answers through proxy_h2 (control)" $?

    for proto in H1 H2; do
        eval "cl=\$$proto"
        out=$(tr_get /trailers $cl)
        printf '%s' "$out" | grep -q " 200" \
            && printf '%s' "$out" | grep -q "hello with trailers" \
            && ! printf '%s' "$out" | grep -qi "x-checksum\|grpc-status"
        check "backend h2 trailers: 200 + body, trailer NOT relayed as a header field ($proto client)" $?
    done

    out=$(tr_get /trailers-frag $H1)
    printf '%s' "$out" | grep -q "^HTTP/1.1 200" \
        && printf '%s' "$out" | grep -q "hello with trailers" \
        && ! printf '%s' "$out" | grep -qi "x-checksum\|grpc-status"
    check "backend h2 trailers: a trailer split across HEADERS + CONTINUATION is handled the same" $?

    # a pseudo-header in a trailer is malformed (RFC 9113 8.1). It must fail the
    # exchange, not rewrite the status the initial block already gave us.
    out=$(tr_get /trailers-status $H1)
    printf '%s' "$out" | grep -q "^HTTP/1.1 502"
    check "backend h2 trailers: a pseudo-header in a trailer is refused, not honoured" $?

    # A trailer section MUST carry END_STREAM (RFC 9113 8.1). Without it the
    # block is not a trailer at all: the DATA that followed used to be appended
    # to the body and its END_STREAM completed the exchange, so a backend
    # protocol error reached the client as a response it believed was properly
    # completed (audit-report-43). Refuse it instead.
    CODE1="curl -s -o /dev/null -w %{http_code} --max-time 10 --http1.1 \
        --cacert $PWD/test/tls/server.crt --resolve localhost:${P61725}:127.0.0.1"
    CODE2="curl -s -o /dev/null -w %{http_code} --max-time 10 --http2 \
        --cacert $PWD/test/tls/server.crt --resolve localhost:${P61725}:127.0.0.1"
    for proto in CODE1 CODE2; do
        eval "cl=\$$proto"
        [ "$(tr_get /trailers-noes $cl)" = 502 ]
        check "backend h2 trailers: a trailer with no END_STREAM is refused ($proto)" $?
    done

    # and refusing it must not wedge the front: the next request still works.
    # One fixture across both, so this is the same front and the same worker.
    python3 test/h2/h2c_server.py ${P61724} tls >$RUNDIR/bt_tr.log 2>&1 &
    trpid=$!
    sleep 0.5
    c1=$($CODE1 "https://localhost:${P61725}/trailers-noes" 2>/dev/null)
    c2=$($CODE1 "https://localhost:${P61725}/hello" 2>/dev/null)
    kill $trpid 2>/dev/null; wait $trpid 2>/dev/null
    [ "$c1" = 502 ] && [ "$c2" = 200 ]
    check "backend h2 trailers: a refused trailer leaves the next request working ($c1 then $c2)" $?

    # An INFORMATIONAL response is a later header block that is NOT a trailer:
    # RFC 9113 8.1 allows zero or more 1xx blocks before the single final
    # response. Treating every later block as a trailer made a 103 backend fail
    # the exchange outright, and before that its fields leaked into the final
    # response head. Neither: the 1xx is dropped and the FINAL head is the head.
    out=$(tr_get /interim $H1)
    printf '%s' "$out" | grep -q "^HTTP/1.1 200" \
        && printf '%s' "$out" | grep -q "final after interim" \
        && ! printf '%s' "$out" | grep -qi "^link:"
    check "backend h2: a 1xx informational block is dropped and the final response is served" $?

    out=$(tr_get /interim-two $H1)
    printf '%s' "$out" | grep -q "^HTTP/1.1 200" \
        && printf '%s' "$out" | grep -q "final after interim"
    check "backend h2: two informational blocks before the final response" $?

    # ...and a 1xx block AFTER the final response is not an early response, it
    # is a trailer section carrying a pseudo-header. Classifying by the block's
    # own :status before asking what had already arrived let it be dropped as
    # "early", and the DATA after it completed the exchange with a concatenated
    # body (audit-report-44). What a block MAY be depends on what came before.
    for proto in CODE1 CODE2; do
        eval "cl=\$$proto"
        [ "$(tr_get /interim-late $cl)" = 502 ]
        check "backend h2: a 1xx block after the final response is refused ($proto)" $?
    done
    if [ -x "$CURLH3" ]; then
        code=$(tr_get /interim-late "$CURLH3" --http3-only -sk -o /dev/null \
               -w '%{http_code}' --max-time 10 \
               --resolve localhost:${P61725}:127.0.0.1)
        [ "$code" = 502 ]
        check "backend h2: a 1xx block after the final response is refused (h3 client)" $?
    else
        check "backend h2: post-final 1xx, h3 client (skipped: curl-h3 unavailable)" 0
    fi

    # Two more of the same family, found by probing the classifier rather than
    # filed: a response header section with NO :status was accepted and
    # synthesized "HTTP/1.1 000 Status" (caught downstream, but the driver has
    # callers with no such validator), and DATA arriving BEFORE the response
    # head was appended to the body — so bytes that preceded the head were
    # prepended to what the client received, under a 200.
    [ "$(tr_get /no-status $CODE1)" = 502 ]
    check "backend h2: a response header block with no :status is refused" $?
    [ "$(tr_get /data-first $CODE1)" = 502 ]
    check "backend h2: DATA before the response head is refused, not prepended" $?

    # --- control frames: PING (RFC 9113 6.7) --------------------------------
    # A PING is exactly 8 octets on stream 0. Neither was checked, and the ACK
    # builder read a full qword whatever the frame declared -- so a 7-octet PING
    # was answered with those seven bytes plus whatever followed them in the
    # leg's receive arena, echoed back to the backend (audit-report-46). The
    # fixture reports what came back in the body, so these assert the ACK itself
    # and not merely that a response arrived.
    [ "$(tr_get /ping-ok $H1 | tail -1)" = "PING-ACKED" ]
    check "backend h2 ping: a legal PING is echoed with ACK" $?
    [ "$(tr_get /ping-ack $H1 | tail -1)" = "NO-REACK" ]
    check "backend h2 ping: an ACK is consumed, never answered" $?
    # 4.1: unused flag bits are IGNORED, not refused -- the control that keeps
    # this check from being over-strict.
    [ "$(tr_get /ping-flag $H1 | tail -1)" = "PING-ACKED" ]
    check "backend h2 ping: an unused flag bit is ignored, not refused" $?
    for route in /ping7 /ping-sid; do
        [ "$(tr_get $route $CODE1)" = 502 ]
        check "backend h2 ping: $route is refused" $?
    done

    # --- the flow-controlled UPLOAD path ------------------------------------
    # Everything above sends a request head and reads a body back. This sends a
    # BODY, to a backend that will not take it all at once: the fixture
    # advertises a 1024-byte INITIAL_WINDOW_SIZE and returns credit only as it
    # drains, so linnea'"'"'s h2 body sender has to stage, block on the window, and
    # resume on each WINDOW_UPDATE. That sender had no automated coverage at all
    # until this -- the one harness that drives it, bin/linnea-h2client, is in
    # no shard (audit-report-47).
    cat > $CFG/bt-fe-up.json <<EOF
{ "log": "$PWD/$RUNDIR/bt-fe-up.log", "workers": 1,
  "servers": [ { "host": "127.0.0.1", "port": ${P61729}, "hostname": "localhost",
    "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
    "locations": [ { "prefix": "/", "proxy": "127.0.0.1:${P61728}",
      "proxy_tls": 1, "proxy_pin": "$PIN", "proxy_sni": "localhost",
      "proxy_h2": 1 } ] } ] }
EOF
    start_server $CFG/bt-fe-up.json
    python3 - "$RUNDIR/up_body.bin" <<'PY'
import sys
open(sys.argv[1], "w").write("U" * (64 * 1024))
PY
    up_probe() {   # $1 = client protocol flag; echoes the byte count returned
        python3 test/h2/h2c_server.py ${P61728} tls,throttle >/dev/null 2>&1 &
        local pid=$!
        sleep 0.5
        curl -s "$1" --cacert "$PWD/test/tls/server.crt" --max-time 30 \
            --resolve localhost:${P61729}:127.0.0.1 \
            --data-binary @$RUNDIR/up_body.bin \
            https://localhost:${P61729}/echo | wc -c
        kill $pid 2>/dev/null; wait $pid 2>/dev/null
    }
    [ "$(up_probe --http1.1)" = "$((64 * 1024))" ]
    check "backend h2 upload: a 65536-byte body crosses a 1024-byte window 64 times (h1 client)" $?
    [ "$(up_probe --http2)" = "$((64 * 1024))" ]
    check "backend h2 upload: ...and from an h2 client, whose body takes the h2p leg" $?

    # --- padded frames (RFC 9113 6.1) ---------------------------------------
    # /pad-ok is the coverage: nothing exercised padded backend frames at all,
    # so nothing said padding WORKS. The four malformed cases are controls --
    # they were already refused before the pad-length read was moved after its
    # bounds check, because the append helpers reject the negative length that
    # results (audit-report-49).
    [ "$(tr_get /pad-ok $H1 | tail -1)" = "pad-body" ]
    check "backend h2 padding: a padded HEADERS and a padded DATA relay normally" $?
    for route in /pad-h0 /pad-d0 /pad-over /prio-short; do
        [ "$(tr_get $route $CODE1)" = 502 ]
        check "backend h2 padding: $route is refused" $?
    done

    # --- control frames: SETTINGS (RFC 9113 6.5) ----------------------------
    # A connection frame on stream 0; an ACK with no payload; a non-ACK payload
    # that is a whole number of six-octet records; INITIAL_WINDOW_SIZE within
    # 2^31-1. None of it was checked (audit-report-48). /set-ok is the control.
    [ "$(tr_get /set-ok $H1 | tail -1)" = "set-body" ]
    check "backend h2 settings: a legal later SETTINGS is applied and the response relays" $?
    for route in /set-sid /set-acklen /set-len5 /set-maxwin; do
        [ "$(tr_get $route $CODE1)" = 502 ]
        check "backend h2 settings: $route is refused" $?
    done

    # 6.5.2 also gives BOUNDS for the defined identifiers, which is a different
    # rule from "ignore what you do not know": a value outside them is a
    # connection error. Only INITIAL_WINDOW_SIZE was checked (audit-report-50).
    # The legal rows are the ones that keep this from becoming a rule against
    # the identifiers themselves -- 16777215 is what real nginx advertises.
    for route in /set-push0 /set-mf-ok; do
        [ "$(tr_get $route $H1 | tail -1)" = "set-body" ]
        check "backend h2 settings: $route is accepted (legal value)" $?
    done
    for route in /set-push1 /set-push2 /set-mf-low /set-mf-high; do
        [ "$(tr_get $route $CODE1)" = 502 ]
        check "backend h2 settings: $route is refused (value out of bounds)" $?
    done

    # ...and the value rule that is not about structure at all. 6.9.2 makes a
    # change to INITIAL_WINDOW_SIZE a DELTA against every open stream's current
    # window. The fixture lets the body spend all 8192, lowers the setting to
    # 1024 and grants nothing, then reports how much arrived afterwards. The
    # answer must be none: 0 + (1024 - 8192) is negative.
    python3 test/h2/h2c_server.py ${P61728} tls,wdelta >/dev/null 2>&1 &
    wdpid=$!
    sleep 0.5
    wdout=$(curl -s --http1.1 --cacert "$PWD/test/tls/server.crt" --max-time 30 \
        --resolve localhost:${P61729}:127.0.0.1 \
        --data-binary @$RUNDIR/up_body.bin \
        https://localhost:${P61729}/echo | tr -d '"'"'\r'"'"' | tail -1)
    kill $wdpid 2>/dev/null; wait $wdpid 2>/dev/null
    [ "$wdout" = "AFTER=0" ]
    check "backend h2 settings: lowering INITIAL_WINDOW_SIZE is a delta, not an assignment ($wdout)" $?

    # --- control frames: WINDOW_UPDATE (RFC 9113 6.9) -----------------------
    # Exactly four octets, a nonzero increment, stream 0 or the request stream,
    # and a window that stays inside 2^31-1. None of it was checked: a
    # three-octet update had its fourth byte read from past the frame, an
    # update naming stream 3 credited stream 1, and the addition was unguarded
    # (audit-report-47). /win-ok is the control -- legal updates must still
    # apply and the response still relay.
    [ "$(tr_get /win-ok $H1 | tail -1)" = "win-body" ]
    check "backend h2 window: legal WINDOW_UPDATEs are applied and the response relays" $?
    for route in /win3 /win0 /win-sid /win-max; do
        [ "$(tr_get $route $CODE1)" = 502 ]
        check "backend h2 window: $route is refused" $?
    done

    # We advertise ENABLE_PUSH 0, so 8.4 makes a PUSH_PROMISE a connection
    # error rather than a frame to drop on the floor. Before we said so, the
    # default was 1 -- a backend was entitled to push and we ignored it.
    [ "$(tr_get /push $CODE1)" = 502 ]
    check "backend h2: a PUSH_PROMISE is refused after ENABLE_PUSH 0" $?

    # --- header-block FRAMING, one layer below the classifier ---------------
    # RFC 9113 6.10: a CONTINUATION may only follow a HEADERS/CONTINUATION whose
    # block is still open, on the same stream, with no frame of any kind in
    # between. The driver had no notion of a block being open, so a CONTINUATION
    # out of nowhere was decoded as the response head and a PING could sit
    # between a HEADERS and its continuation (audit-report-45). The last two
    # rows were already refused before that fix -- for the right outcome by the
    # wrong reason (the DATA-before-head rule) -- so they are controls.
    for route in /cont-first /cont-interleaved /cont-data-between /cont-wrong-stream; do
        [ "$(tr_get $route $CODE1)" = 502 ]
        check "backend h2 framing: $route is refused" $?
    done

    # refusing it must not wedge the front either
    python3 test/h2/h2c_server.py ${P61724} tls >$RUNDIR/bt_tr.log 2>&1 &
    trpid=$!
    sleep 0.5
    c1=$($CODE1 "https://localhost:${P61725}/interim-late" 2>/dev/null)
    c2=$($CODE1 "https://localhost:${P61725}/hello" 2>/dev/null)
    kill $trpid 2>/dev/null; wait $trpid 2>/dev/null
    [ "$c1" = 502 ] && [ "$c2" = 200 ]
    check "backend h2: a refused post-final 1xx leaves the next request working ($c1 then $c2)" $?

    if [ -x "$CURLH3" ]; then
        out=$(tr_get /trailers "$CURLH3" --http3-only -sk -D- --max-time 10 \
              --resolve localhost:${P61725}:127.0.0.1)
        printf '%s' "$out" | grep -q " 200" \
            && printf '%s' "$out" | grep -q "hello with trailers" \
            && ! printf '%s' "$out" | grep -qi "x-checksum\|grpc-status"
        check "backend h2 trailers: 200 + body, trailer not relayed (h3 client)" $?
    else
        check "backend h2 trailers: h3 client (skipped: curl-h3 unavailable)" 0
    fi
    rm -f $RUNDIR/bt_tr.log

    rm -f $RUNDIR/bt_conc.txt $RUNDIR/h2_conc.txt $RUNDIR/tls_h2_conc.txt \
          "$btw/probe.txt" "$btw/big.bin"
else
    check "backend TLS e2e proxy (skipped: tls ULP or openssl unavailable)" 0
fi
