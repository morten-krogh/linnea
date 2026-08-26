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
    tr_get_m() { # $1 = fixture mode, $2 = path, $3.. = the client command
        local mode=$1 path=$2; shift 2
        python3 test/h2/h2c_server.py ${P61724} $mode >$RUNDIR/bt_tr.log 2>&1 &
        local pid=$!
        sleep 0.5
        "$@" "https://localhost:${P61725}$path" 2>/dev/null
        kill $pid 2>/dev/null; wait $pid 2>/dev/null
    }
    tr_get() {   # $1 = path, $2.. = the client command (headers on stdout)
        local path=$1; shift
        tr_get_m tls "$path" "$@"
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

    # --- frame size (RFC 9113 4.2) ------------------------------------------
    # We advertise no SETTINGS_MAX_FRAME_SIZE, so 16384 bounds every frame the
    # backend may send us. What bounded it before was the receive BUFFERS --
    # 20471 and 65527 -- so a 16385-byte DATA frame the peer was never allowed
    # to send fitted in memory and was relayed (audit-report-52).
    # /fsz-ok sits exactly on the boundary and is the row that stops this
    # becoming a rule against large frames in general.
    [ "$(tr_get /fsz-ok $CODE1)" = 200 ]
    check "backend h2 framesize: a DATA frame of exactly 16384 relays" $?
    for route in /fsz-big /fsz-hdr; do
        [ "$(tr_get $route $CODE1)" = 502 ]
        check "backend h2 framesize: $route is refused" $?
    done
    # /fsz-hdr is NOT this fix's work end to end: a 20000-byte header block is
    # refused either way by the 6144-byte response-head bound, so that row is a
    # control here, not evidence. The evidence for HEADERS is below.

    # Both parsers, driven directly. Everything above reaches only the resumable
    # DRIVER through a real front; bin/linnea-h2client is the one harness that
    # also runs the blocking ORACLE, and the two are meant to agree frame for
    # frame. It is also what makes the header rows discriminating, the tool
    # having no 6144-byte head bound of its own:
    #   /fsz-hdr    one HEADERS frame of ~20000 bytes  -> refused
    #   /fsz-split  the SAME head across HEADERS + CONTINUATION, each frame
    #               under the limit                    -> relays
    # The split row is the one that keeps this from becoming a rule against
    # large header blocks: 4.2 bounds each frame, which is what CONTINUATION is
    # for, and a fix that read the limit as a block bound would fail it.
    h2c_probe() {  # $1 = path, $2.. = extra argv ("0 drv" for the driver);
                   # echoes the whole exchange, head and body
        local path=$1; shift
        python3 test/h2/h2c_server.py ${P61730} >/dev/null 2>&1 &
        local pid=$!
        sleep 0.5
        # 2>&1: the tool prints its refusal (H2C-FAIL) on stderr, so dropping
        # stderr would leave an empty string that an equality check accepts.
        timeout 10 ./bin/linnea-h2client ${P61730} "$path" GET "$@" 2>&1
        kill $pid 2>/dev/null; wait $pid 2>/dev/null
    }
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        h2c_probe /fsz-ok $argv | head -1 | grep -q "^HTTP/1.1 200"
        check "backend h2 framesize ($mode): a 16384-byte DATA frame relays" $?
        h2c_probe /fsz-split $argv | head -1 | grep -q "^HTTP/1.1 200"
        check "backend h2 framesize ($mode): a legally split header block relays" $?
        [ "$(h2c_probe /fsz-big $argv | head -1)" = "H2C-FAIL" ]
        check "backend h2 framesize ($mode): a 16385-byte DATA frame is refused" $?
        [ "$(h2c_probe /fsz-hdr $argv | head -1)" = "H2C-FAIL" ]
        check "backend h2 framesize ($mode): an oversized HEADERS frame is refused" $?
    done

    # --- stream ownership (RFC 9113 6.1, 6.2) -------------------------------
    # The leg is single-stream. A HEADERS or DATA naming stream 0, or a stream
    # we never opened, was SKIPPED as though it had not arrived, and the good
    # stream-1 response behind it relayed as a clean 200 (audit-report-53).
    #
    # Skipping is not the conservative choice it looks like. HPACK state is per
    # CONNECTION: a header block passed over rather than decoded shifts every
    # later dynamic index by one. /sid-hdr3-skew is that measured -- the
    # backend names index 63 meaning "x-b: bbb" and the pre-fix build relayed
    # "x-a: aaa" instead, status 200, no error anywhere.
    #
    # /sid-hdr3-dyn is a control, not evidence: it was refused pre-fix too,
    # because there the skew pushes the index past the END of our table and
    # HPACK fails closed. It is the same defect landing safely, which is exactly
    # why /sid-hdr3-skew exists -- an index that lands INSIDE the table is the
    # one that corrupts silently.
    #
    # /sid-dyn-ok is the control that keeps the fix honest: the same two
    # insertions and the same indices with the wrong-stream frame removed, which
    # must still decode -- 62 being the most recent insertion, "x-b: bbb" then
    # "x-a: aaa". A fix that broke dynamic indexing instead of the stream check
    # passes every refusal row above and fails this one.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        for route in /sid-hdr0 /sid-hdr3 /sid-data0 /sid-data3 /sid-hdr3-dyn \
                     /sid-hdr3-skew; do
            [ "$(h2c_probe $route $argv | head -1)" = "H2C-FAIL" ]
            check "backend h2 stream ($mode): $route is refused" $?
        done
        sid_out=$(h2c_probe /sid-dyn-ok $argv)
        printf '%s' "$sid_out" | grep -q "^HTTP/1.1 200" \
            && printf '%s' "$sid_out" | grep -q "^x-b: bbb" \
            && printf '%s' "$sid_out" | grep -q "^x-a: aaa"
        check "backend h2 stream ($mode): legal dynamic indexing still decodes" $?
    done
    for route in /sid-hdr3 /sid-data3 /sid-hdr3-skew; do
        [ "$(tr_get $route $CODE1)" = 502 ]
        check "backend h2 stream: $route is refused end to end" $?
    done

    # --- a PING read while the UPLOAD waits for credit (6.7) ----------------
    # The blocking oracle has a third frame loop, h2c_pump_window, reached only
    # when the request window is exhausted mid-upload. When the PING checks went
    # in (audit-report-46) two of its three copies were updated and this one was
    # not, so a malformed PING read there was still echoed: a 7-octet PING came
    # back as "1234567" plus a byte from PAST the frame, and an already-ACKed
    # PING was answered with another ACK. The three copies are now one helper.
    #
    # This is oracle-only -- the driver was right on all four -- and the driver
    # is what the end-to-end upload rows exercise, so nothing above could see
    # it. The two must agree, so both are asserted here.
    #
    # Note the pre-fix body carried a literal NUL (the out-of-frame byte), which
    # makes grep treat the stream as binary and print nothing at all; the helper
    # strips NUL and CR so a check cannot silently read "no output" as a pass.
    up_frames() { # $1 = fixture mode, $2 = body bytes, $3.. = extra argv
        local mode=$1 bytes=$2; shift 2
        python3 test/h2/h2c_server.py ${P61730} $mode >/dev/null 2>&1 &
        local pid=$!
        sleep 0.5
        head -c $bytes /dev/zero | tr '\0' 'U' \
            | timeout 25 ./bin/linnea-h2client ${P61730} /up POST 0 "$@" 2>&1 \
            | tr '\r\0' '  '
        kill $pid 2>/dev/null; wait $pid 2>/dev/null
    }
    pump_probe() { local mode=$1; shift; up_frames $mode 8192 "$@"; }
    cl_probe() {    # $1 = path, $2 = method, $3.. = extra argv; first line only
        local path=$1 meth=$2; shift 2
        python3 test/h2/h2c_server.py ${P61730} >/dev/null 2>&1 &
        local pid=$!
        sleep 0.5
        # </dev/null: the harness reads a request body from stdin for any
        # method that is not GET, so a HEAD probe without it inherits the
        # shard's stdin and hangs (or sends whatever it finds there).
        timeout 10 ./bin/linnea-h2client ${P61730} "$path" "$meth" "$@" \
            </dev/null 2>&1 | tr '\r\0' '  ' | head -1
        kill $pid 2>/dev/null; wait $pid 2>/dev/null
    }
    st_probe_body() { # $1 = path, $2.. = extra argv; the whole exchange
        local path=$1; shift
        python3 test/h2/h2c_server.py ${P61730} >/dev/null 2>&1 &
        local pid=$!
        sleep 0.5
        timeout 30 ./bin/linnea-h2client ${P61730} "$path" GET "$@" \
            </dev/null 2>&1 | tr '\r\0' '  '
        kill $pid 2>/dev/null; wait $pid 2>/dev/null
    }
    st_probe() {    # $1 = path, $2.. = extra argv; first line only
        local path=$1; shift
        python3 test/h2/h2c_server.py ${P61730} >/dev/null 2>&1 &
        local pid=$!
        sleep 0.5
        timeout 10 ./bin/linnea-h2client ${P61730} "$path" GET "$@" 2>&1 \
            | tr '\r\0' '  ' | head -1
        kill $pid 2>/dev/null; wait $pid 2>/dev/null
    }
    pref_probe() {  # $1 = fixture mode, $2.. = extra argv; first line only
        local mode=$1; shift
        python3 test/h2/h2c_server.py ${P61730} $mode >/dev/null 2>&1 &
        local pid=$!
        sleep 0.5
        timeout 10 ./bin/linnea-h2client ${P61730} /hello GET "$@" 2>&1 \
            | tr '\r\0' '  ' | head -1
        kill $pid 2>/dev/null; wait $pid 2>/dev/null
    }
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="drv" || argv=""
        # the control: a LEGAL ping read in the pump is still echoed, so this
        # cannot become a rule against PINGs during an upload
        pump_probe pumpok $argv | grep -q "PUMP-ACK=ABCDEFGH"
        check "backend h2 pump ping ($mode): a legal PING is echoed with ACK" $?
        [ "$(pump_probe pump7 $argv | head -1)" = "H2C-FAIL" ]
        check "backend h2 pump ping ($mode): a 7-octet PING is refused" $?
        [ "$(pump_probe pumpsid $argv | head -1)" = "H2C-FAIL" ]
        check "backend h2 pump ping ($mode): a PING naming a stream is refused" $?
        pump_probe pumpack $argv | grep -q "PUMP-ACK=NONE"
        check "backend h2 pump ping ($mode): an ACK is consumed, never answered" $?
    done

    # --- duplicate SETTINGS identifiers: LEGAL in HTTP/2 (audit-report-55) ---
    # The report asked for a duplicate identifier in one SETTINGS frame to be a
    # connection error, citing RFC 9113 6.5.2. That rule is HTTP/3's (RFC 9114
    # 7.2.4.1) and QUIC transport parameters' (RFC 9000 7.4) -- both of which
    # this server does enforce, which is very likely how the rules got crossed.
    # HTTP/2 6.5 instead says the values are processed IN ORDER, so a repeat is
    # legal and the LAST one stands. Measured against three implementations:
    # nginx 1.30.4, nghttp2 1.66.0 and our own h2 front all accept it and serve.
    #
    # So these rows pin behaviour rather than fixing any. They are not vacuous:
    # built with the report's rule wired into the driver's settings walk,
    # /set-dup-ok, /set-dup-unknown and dupwin all fail, while /set-mf-ok (the
    # same identifier in two SEPARATE frames) still passes.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        for route in /set-dup-ok /set-dup-unknown; do
            h2c_probe $route $argv | head -1 | grep -q "^HTTP/1.1 200"
            check "backend h2 settings ($mode): $route is accepted" $?
        done
        # every record is validated, not just the first for an identifier
        [ "$(h2c_probe /set-dup-2ndbad $argv | head -1)" = "H2C-FAIL" ]
        check "backend h2 settings ($mode): a repeat with an illegal value is refused" $?
    done
    # ...and the value that stands is the LAST one. The fixture puts 1024 then
    # 8192 in one frame and grants nothing until the sender stalls, so the bytes
    # that arrive first ARE the window the client believed in: 8192 means in
    # order, 1024 means first-wins, 9216 means summed.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="drv" || argv=""
        up_frames dupwin 65536 $argv | grep -q "DUPWIN=8192"
        check "backend h2 settings ($mode): a repeated value is applied in order" $?
    done
    for route in /set-dup-ok /set-dup-unknown; do
        [ "$(tr_get $route $CODE1)" = 200 ]
        check "backend h2 settings: $route is accepted end to end" $?
    done
    [ "$(tr_get /set-dup-2ndbad $CODE1)" = 502 ]
    check "backend h2 settings: a repeat with an illegal value is refused e2e" $?

    # --- the SERVER connection preface (RFC 9113 3.4) -----------------------
    # The server's preface is a SETTINGS frame and it MUST be the first frame it
    # sends. We required that of CLIENTS in the frontend from the beginning and
    # never asked it of a BACKEND, so an upstream could answer before it had
    # said what it supports (audit-report-56). Each fixture mode still sends a
    # perfectly good response behind the offending frame, so a refusal can only
    # be the missing preface.
    #
    # prefempty is the control, and it is the row a careless gate breaks: 3.4
    # allows a "potentially empty" SETTINGS, so a preface with no records at all
    # is legal and must be accepted. nghttp2 1.66.0 as a client agrees on every
    # row here -- it refuses the other four with "Remote peer returned
    # unexpected data while we expected SETTINGS frame" and accepts this one.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        for bad in prefnone prefping prefwin prefack; do
            [ "$(pref_probe $bad $argv)" = "H2C-FAIL" ]
            check "backend h2 preface ($mode): $bad is refused" $?
        done
        [ "$(pref_probe prefempty $argv)" != "H2C-FAIL" ]
        check "backend h2 preface ($mode): an EMPTY SETTINGS preface is accepted" $?
    done
    [ "$(tr_get_m tls,prefnone /hello $CODE1)" = 502 ]
    check "backend h2 preface: a response before SETTINGS is refused end to end" $?
    [ "$(tr_get_m tls,prefempty /hello $CODE1)" = 200 ]
    check "backend h2 preface: an empty SETTINGS preface serves end to end" $?

    # --- the standalone PRIORITY frame, type 0x02 (RFC 9113 6.3) ------------
    # Deprecated, still DEFINED, and its structure survives the deprecation:
    # exactly five octets, never on stream 0. The leg had no constant for 0x02
    # at all, so every malformed shape fell through the unknown-frame arm and
    # the response behind it was served (audit-report-68). The FRONTEND has
    # enforced both halves for a long time, in the same words -- the eighth
    # report running whose root is a rule this server has in one direction only.
    #
    # Distinct from the PRIORITY FLAG on a HEADERS frame: /prio-short covers
    # that one. Same five octets, different rule, and the two are kept apart
    # deliberately.
    #
    # /pri-sid0 is where we are stricter than the reference: nghttp2 refuses the
    # wrong LENGTHS with FRAME_SIZE_ERROR but serves a PRIORITY on stream 0,
    # which 6.3 makes a MUST-level PROTOCOL_ERROR. Our own frontend refuses it,
    # so this keeps the two directions in agreement.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        for bad in /pri-0 /pri-4 /pri-6 /pri-sid0; do
            [ "$(st_probe $bad $argv)" = "H2C-FAIL" ]
            check "backend h2 priority ($mode): $bad is refused" $?
        done
        st_probe /pri-ok $argv | grep -q "^HTTP/1.1 200"
        check "backend h2 priority ($mode): a legal PRIORITY is ignored, not refused" $?
    done
    [ "$(tr_get /pri-4 $CODE1)" = 502 ]
    check "backend h2 priority: a malformed PRIORITY is refused end to end" $?
    [ "$(tr_get /pri-ok $CODE1)" = 200 ]
    check "backend h2 priority: a legal one still serves end to end" $?

    # --- the :status GRAMMAR (RFC 9113 8.3.2, RFC 9110 15.1) ----------------
    # A status code is EXACTLY three digits. The h2 leg stopped at the first
    # byte that was not a digit and kept what it had, so the value was mined
    # rather than checked: "200x" and "200 " became 200, and "2000" became 200
    # by TRUNCATION -- a four-digit status relayed as a clean response
    # (audit-report-57). The h1 leg has refused "HTTP/1.1 2000" for a long time;
    # this is the same rule finally asked of h2, the one-direction-only shape
    # that also produced audit-report-56.
    #
    # /st-2x0, /st-short and /st-empty were already refused before the fix, but
    # only incidentally: they parsed to a number below 200 and died on the RANGE
    # check. Right outcome, wrong reason -- they are controls, and the rows that
    # prove the fix are the three that used to succeed.
    #
    # /st-299 is the other control: in range and unregistered, and it must still
    # be relayed. This is a grammar check, not an allowlist. nghttp2 1.66.0 as a
    # client agrees on every row -- it rejects the six with "Invalid HTTP header
    # field ... name: [:status]" and serves 200 and 299.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        for bad in /st-x /st-4 /st-sp /st-2x0 /st-short /st-empty; do
            [ "$(st_probe $bad $argv)" = "H2C-FAIL" ]
            check "backend h2 status ($mode): $bad is refused" $?
        done
        st_probe /st-200 $argv | grep -q "^HTTP/1.1 200"
        check "backend h2 status ($mode): a literal 200 still relays" $?
        st_probe /st-299 $argv | grep -q "^HTTP/1.1 299"
        check "backend h2 status ($mode): an unregistered 299 still relays" $?
    done
    [ "$(tr_get /st-x $CODE1)" = 502 ]
    check "backend h2 status: a :status of \"200x\" is refused end to end" $?
    [ "$(tr_get /st-4 $CODE1)" = 502 ]
    check "backend h2 status: a four-digit :status is refused end to end" $?
    [ "$(tr_get /st-299 $CODE1)" = 299 ]
    check "backend h2 status: an unregistered 299 is relayed end to end" $?

    # --- content-length against the DATA bytes (RFC 9113 8.1.1) -------------
    # A response whose content-length does not equal the sum of its DATA
    # payloads is malformed, and an intermediary must not forward it. The h2 leg
    # dropped the field without ever reading it -- it is not relayed, the
    # composer writes its own from the bytes it holds -- so "content-length: 1"
    # over a four-byte body came out as "content-length: 4" and the malformed
    # response was REPAIRED into a valid one (audit-report-58). Third report
    # running whose root is a rule the h1 leg has and the h2 leg does not.
    #
    # The controls are the exceptions, and they are what a careless fix breaks:
    # 1xx/204/205/304 carry no content whatever the head says (the shared
    # linnea_http_status_no_content, not a fourth copy of that list), and a HEAD
    # response carries the length a GET would have returned with no body at all.
    #
    # The HEAD pair is the row that proves the exception is implemented rather
    # than the check skipped: /cl-head sends the SAME bytes both times -- 200,
    # content-length 4, no DATA -- and it must fail for GET and serve for HEAD.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        for bad in /cl-short /cl-zero /cl-bad /cl-neg; do
            [ "$(cl_probe $bad GET $argv)" = "H2C-FAIL" ]
            check "backend h2 clen ($mode): $bad is refused" $?
        done
        cl_probe /cl-ok GET $argv | grep -q "^HTTP/1.1 200"
        check "backend h2 clen ($mode): a matching content-length relays" $?
        cl_probe /cl-304 GET $argv | grep -q "^HTTP/1.1 304"
        check "backend h2 clen ($mode): 304 may declare a length it does not send" $?
        cl_probe /cl-204 GET $argv | grep -q "^HTTP/1.1 204"
        check "backend h2 clen ($mode): 204 carries no content" $?
        [ "$(cl_probe /cl-head GET $argv)" = "H2C-FAIL" ]
        check "backend h2 clen ($mode): a length with no body is refused for GET" $?
        cl_probe /cl-head HEAD $argv | grep -q "^HTTP/1.1 200"
        check "backend h2 clen ($mode): ...and is correct for HEAD, same bytes" $?
    done
    [ "$(tr_get /cl-short $CODE1)" = 502 ]
    check "backend h2 clen: a short content-length is refused end to end" $?
    [ "$(tr_get /cl-ok $CODE1)" = 200 ]
    check "backend h2 clen: a matching content-length relays end to end" $?
    [ "$(tr_get /cl-head $CODE1 -I)" = 200 ]
    check "backend h2 clen: a HEAD through the front still serves" $?

    # --- response pseudo-headers (RFC 9113 8.3) -----------------------------
    # Three rules, all of which the REQUEST side has enforced for a long time
    # ("pseudo-header placement and repetition" in linnea_hpack.asm) and the
    # response side had none of: at most one of each name per field block, all
    # of them ahead of the regular fields, and none undefined -- :status being
    # the only one defined for a response.
    #
    # /ps-dup and /ps-dup-rev are the pair that shows what last-wins costs: the
    # SAME two values in opposite orders relayed 500 and 200 respectively, so
    # the malformed field order chose the status the client saw. /ps-dup-cont
    # splits the duplicate across HEADERS + CONTINUATION, because the field
    # block is the two COMBINED (audit-report-59; -after and -unknown were found
    # beside the filed finding, which named only the duplicate).
    #
    # The legal neighbours are the controls, and they are already above: an
    # interim 1xx followed by a final response is TWO blocks with one :status
    # each, and /trailers-frag is a legal block split across a CONTINUATION.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        for bad in /ps-dup /ps-dup-rev /ps-dup-cont /ps-after /ps-unknown \
                   /ps-upper /ps-UPPER /ps-mixed; do
            [ "$(st_probe $bad $argv)" = "H2C-FAIL" ]
            check "backend h2 pseudo ($mode): $bad is refused" $?
        done
        st_probe /ps-one $argv | grep -q "^HTTP/1.1 200"
        check "backend h2 pseudo ($mode): a single literal :status relays" $?
        st_probe /interim $argv | grep -q "^HTTP/1.1 200"
        check "backend h2 pseudo ($mode): 1xx then final is two blocks, both legal" $?
    done
    [ "$(tr_get /ps-dup $CODE1)" = 502 ]
    check "backend h2 pseudo: a repeated :status is refused end to end" $?
    [ "$(tr_get /ps-unknown $CODE1)" = 502 ]
    check "backend h2 pseudo: an undefined pseudo-header is refused end to end" $?
    [ "$(tr_get /ps-one $CODE1)" = 200 ]
    check "backend h2 pseudo: a single :status relays end to end" $?
    # RFC 9113 8.2.1 forbids uppercase in a field NAME, and a pseudo-header name
    # is one. ":Status" is not another spelling of ":status" -- and it reached
    # the status arm through a CASE-INSENSITIVE comparison that ran BEFORE the
    # validity gate, which only the ordinary-field branch calls
    # (audit-report-65). The comparison is exact now; the ci ones that remain
    # are for ordinary names, reached only after every uppercase byte has
    # already been refused. nghttp2 rejects :Status as an invalid field.
    [ "$(tr_get /ps-upper $CODE1)" = 502 ]
    check "backend h2 pseudo: an uppercase :Status is refused end to end" $?

    # --- field NAME and VALUE syntax (RFC 9113 8.2.1) -----------------------
    # A name may not be empty or carry 0x00-0x20, uppercase, 0x7f-0xff or a
    # colon; a value may not carry CR, LF or NUL, nor lead or trail with SP or
    # HTAB. A response breaking any of it is malformed and 8.1.1 forbids
    # forwarding it. Fifth report running whose root is a rule the REQUEST side
    # has (linnea_hpack.asm emit_field) and the response side did not.
    #
    # The name half was a REPAIR rather than a check -- h2c_hdrline_append
    # lowercased A-Z while copying, so "Content-Type" became "content-type" and
    # the error left no trace (audit-report-60, as filed).
    #
    # The VALUE half was not checked at all, and is the half with teeth: this
    # leg writes "name: value CRLF" into a synthesized HTTP/1 head that the
    # proxy bridge RE-PARSES. Measured end to end before the fix -- a backend
    # sending ONE field whose value contained "\r\nx-injected: yes" delivered
    # x-injected as a real header to an h1 client AND an h2 client. The e2e row
    # below asserts the ABSENCE of that header, not merely a 502: a check that
    # only looked at the status would pass on a build that still forged it.
    #
    # /fn-upper-conn is the row the report warned about: an uppercase
    # "Connection" is dropped by the case-insensitive hop-by-hop filter anyway,
    # so it must be refused for being malformed, not for being dropped.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        for bad in /fn-upper /fn-upper-conn /fn-space /fn-empty /fn-ctl \
                   /fn-colon /fn-del /fv-crlf /fv-lf /fv-nul /fv-sp; do
            [ "$(st_probe $bad $argv)" = "H2C-FAIL" ]
            check "backend h2 field ($mode): $bad is refused" $?
        done
        st_probe /fn-ok $argv | grep -q "^HTTP/1.1 200"
        check "backend h2 field ($mode): an ordinary lowercase field relays" $?
    done
    [ "$(tr_get /fv-crlf $CODE1)" = 502 ]
    check "backend h2 field: a CRLF in a value is refused end to end" $?
    inj=$(tr_get /fv-crlf $H1 | grep -ci "x-injected")
    [ "$inj" = 0 ]
    check "backend h2 field: ...and forges no header downstream ($inj lines)" $?
    [ "$(tr_get /fn-upper $CODE1)" = 502 ]
    check "backend h2 field: an uppercase name is refused end to end" $?
    [ "$(tr_get /fn-ok $CODE1)" = 200 ]
    check "backend h2 field: an ordinary field relays end to end" $?

    # --- HPACK table-size update placement (RFC 7541 4.2) -------------------
    # An update may appear only at the BEGINNING of a field block, before any
    # field representation; one after a field is a decoding error, which RFC
    # 9113 4.3 makes a connection error of type COMPRESSION_ERROR. The REQUEST
    # decoder has enforced this since its own Finding 29 -- the response-side
    # copy of the decoder never did (audit-report-61). Sixth report running
    # whose root is a rule this server has in one direction only.
    #
    # The blocks are hand-built because the point is the byte order: 0x88 is the
    # static ":status: 200" and 0x20 is an update to a maximum of zero.
    #
    # /hp-late-inc is not in the report and is the row that caught my first
    # attempt: marking only the fall-through literal form missed 0x40, literal
    # WITH indexing, which is the form an encoder actually emits. Both literal
    # forms share one label, so the mark belongs there.
    #
    # Legal placements are the controls, and there are two kinds: an update
    # before all fields, and SEVERAL in a row before all fields -- an encoder
    # signals a shrink and a restore that way, so the rule is bounded by the
    # first field, not by a count.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        for bad in /hp-late /hp-late-cont /hp-late-inc; do
            [ "$(st_probe $bad $argv)" = "H2C-FAIL" ]
            check "backend h2 hpack ($mode): $bad is refused" $?
        done
        for ok in /hp-none /hp-early /hp-two-early; do
            st_probe $ok $argv | grep -q "^HTTP/1.1 200"
            check "backend h2 hpack ($mode): $ok is accepted" $?
        done
    done
    [ "$(tr_get /hp-late $CODE1)" = 502 ]
    check "backend h2 hpack: a late table-size update is refused end to end" $?
    [ "$(tr_get /hp-early $CODE1)" = 200 ]
    check "backend h2 hpack: a legal one still serves end to end" $?

    # --- 101 is not an informational response (RFC 9113 8.6, 8.8.5) ---------
    # HTTP/2 does not support 101: there is no Upgrade-based protocol switch on
    # a stream, and 8.8.5 describes informational responses as the 1xx codes
    # OTHER than it. The classifier took the whole 100..199 range as interim, so
    # a 101 block was DROPPED and whatever came next was relayed as the answer
    # (audit-report-62). Seventh report running whose root is a rule this server
    # has in one direction only: the frontend has refused the same status from
    # an h1 upstream since its own Finding 30.
    #
    # /interim-101-es is a control, not evidence: a 101 carrying END_STREAM was
    # already refused before the fix, by the generic "a 1xx cannot end the
    # stream" rule. Right outcome, wrong reason -- the row that proves this fix
    # is /interim-101, where the block is otherwise perfectly well formed.
    #
    # The legal interim rows are the other controls: 103, and 103-then-100.
    # nghttp2 1.66.0 as a client refuses 101 with PROTOCOL_ERROR and serves 103.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        for bad in /interim-101 /interim-101-cont /interim-101-es; do
            [ "$(st_probe $bad $argv)" = "H2C-FAIL" ]
            check "backend h2 101 ($mode): $bad is refused" $?
        done
        for ok in /interim /interim-two; do
            st_probe $ok $argv | grep -q "^HTTP/1.1 200"
            check "backend h2 101 ($mode): $ok is still a legal interim" $?
        done
    done
    [ "$(tr_get /interim-101 $CODE1)" = 502 ]
    check "backend h2 101: a 101 from the backend is refused end to end" $?
    [ "$(tr_get /interim $CODE1)" = 200 ]
    check "backend h2 101: a legal 103 interim still serves end to end" $?

    # --- request-side parity sweep (after audit-report-62) ------------------
    # Reports 56-62 were each one rule the REQUEST side enforces and the
    # response side did not, found one report at a time. This block is the rest
    # of that list, swept in one pass against linnea_hpack.asm's emit_field and
    # linnea_http.asm's response-head validator.
    #
    # RFC 9113 8.2.2: "Any message containing connection-specific header fields
    # MUST be treated as malformed." These names were on the skip list, so the
    # response was quietly CLEANED UP and relayed as though the backend had
    # behaved. Dropping a field is not refusing the message -- the request side
    # has said exactly that since its own sweep. TE is the one exception the
    # section allows, and only as "trailers"; /sw-te-tr is that control and
    # nghttp2 agrees on every row here.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        # TE is here too, and by DIRECTION: 8.2.2's only exception is "the TE
        # header field, which MAY be present in an HTTP/2 REQUEST". A response
        # has none, so both values are malformed (audit-report-66, which
        # corrected this sweep -- it had kept te: trailers as an allowed value).
        # A deliberate divergence from nghttp2, which serves it.
        for bad in /sw-conn /sw-ka /sw-pconn /sw-tenc /sw-upg \
                   /sw-te-gz /sw-te-tr; do
            [ "$(st_probe $bad $argv)" = "H2C-FAIL" ]
            check "backend h2 sweep ($mode): $bad is refused (8.2.2)" $?
        done

        # RFC 9110: 1xx, 204, 205 and 304 carry no content whatever the head
        # says. A 204 whose backend sent DATA was relayed as "204 No Content"
        # with content-length: 8 AND eight bytes of body -- a response no client
        # reads as content, leaving those bytes for whatever parses next.
        for bad in /sw-204-data /sw-304-data /sw-205-data; do
            [ "$(st_probe $bad $argv)" = "H2C-FAIL" ]
            check "backend h2 sweep ($mode): $bad is refused (content on a no-content status)" $?
        done
        st_probe /sw-204-ok $argv | grep -q "^HTTP/1.1 204"
        check "backend h2 sweep ($mode): a 204 with no DATA still serves" $?
        st_probe /sw-304-ok $argv | grep -q "^HTTP/1.1 304"
        check "backend h2 sweep ($mode): a 304 with no DATA still serves" $?

        # These were already correct when the sweep ran. They are pinned so the
        # sweep's coverage is recorded rather than remembered, and so a later
        # change has to mean it.
        for bad in /sw-099 /sw-600 /sw-999 /sw-idx0 /sw-idxbig /sw-truncstr; do
            [ "$(st_probe $bad $argv)" = "H2C-FAIL" ]
            check "backend h2 sweep ($mode): $bad is refused (already correct)" $?
        done
    done
    [ "$(tr_get /sw-tenc $CODE1)" = 502 ]
    check "backend h2 sweep: transfer-encoding is refused end to end" $?
    [ "$(tr_get /sw-204-data $CODE1)" = 502 ]
    check "backend h2 sweep: content on a 204 is refused end to end" $?
    [ "$(tr_get /sw-ok $CODE1)" = 200 ]
    check "backend h2 sweep: an ordinary response still serves end to end" $?

    # --- a HEAD response has no content (RFC 9110 9.3.2) --------------------
    # The HEAD exemption added for audit-report-58 waived the content-length
    # comparison -- correctly, since a HEAD declares what a GET WOULD have
    # returned -- but never asked the other half: that the bytes must not
    # EXIST. The comment said "sends nothing" and nothing checked it
    # (audit-report-63). The body was accepted, stored, and handed back by the
    # client API with the response.
    #
    # The 2x2 is the whole rule: the same two response shapes, each legal under
    # exactly one method.
    #
    #                       asked with GET      asked with HEAD
    #   /cl-ok    (4, DATA)   legal               malformed
    #   /cl-head  (4, none)   malformed           legal
    #
    # /cl-hd-nocl is the second half of the defect: with NO content-length the
    # helper returned success from its "nothing declared" branch before the
    # method was ever considered.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        cl_probe /cl-ok GET $argv | grep -q "^HTTP/1.1 200"
        check "backend h2 head ($mode): a body for GET is legal" $?
        [ "$(cl_probe /cl-ok HEAD $argv)" = "H2C-FAIL" ]
        check "backend h2 head ($mode): ...and the same bytes for HEAD are not" $?
        [ "$(cl_probe /cl-hd-data HEAD $argv)" = "H2C-FAIL" ]
        check "backend h2 head ($mode): DATA in a HEAD response is refused" $?
        [ "$(cl_probe /cl-hd-nocl HEAD $argv)" = "H2C-FAIL" ]
        check "backend h2 head ($mode): ...even with no content-length declared" $?
        # ...and the length a HEAD DOES report is the backend's, not our
        # measurement of the body it correctly did not send. Reporting 0 here
        # destroys the one thing the method exists to ask for.
        cl_probe /cl-head HEAD $argv | grep -q "^HTTP/1.1 200"
        check "backend h2 head ($mode): a legal HEAD still serves" $?
        cl_probe /cl-head HEAD $argv >/dev/null 2>&1
        python3 test/h2/h2c_server.py ${P61730} >/dev/null 2>&1 &
        hdpid=$!
        sleep 0.5
        hdlen=$(timeout 10 ./bin/linnea-h2client ${P61730} /cl-head HEAD $argv \
                </dev/null 2>&1 | tr -d '\r' | awk -F': ' '/^content-length/{print $2}')
        kill $hdpid 2>/dev/null; wait $hdpid 2>/dev/null
        [ "$hdlen" = 4 ]
        check "backend h2 head ($mode): it reports the backend's length ($hdlen)" $?
    done
    [ "$(tr_get /cl-ok $CODE1 -I)" = 502 ]
    check "backend h2 head: a HEAD response with content is refused end to end" $?
    # head -1: $H1 already carries -D-, so adding -I makes curl print the head
    # TWICE and the value would be "4\n4" -- equal to neither 4 nor 0.
    hdlen=$(tr_get /cl-head $H1 -I | tr -d '\r' \
            | awk -F': ' '/^content-length/{print $2}' | head -1)
    [ "$hdlen" = 4 ]
    check "backend h2 head: a HEAD reports the backend's length downstream ($hdlen)" $?

    # --- the advertised receive window is a PROMISE (audit-report-64) -------
    # The leg advertised SETTINGS_INITIAL_WINDOW_SIZE = 4 MiB while its response
    # body buffer held 1 MiB, so a backend that believed us and sent 2 MiB --
    # well inside the window we had granted -- was cut off with a 502 after
    # spending the bandwidth. Same defect as the MAX_HEADER_LIST_SIZE one that
    # nginx found: an advertisement the buffers do not honour.
    #
    # The window is now tied to the cap in the header, and linnea_h2_client.asm
    # refuses to ASSEMBLE if the two ever drift -- verified by raising it and
    # watching the build fail. These rows are the runtime half: the backend
    # reports what it was promised, and the boundary is exercised at exactly
    # that size.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        adv=$(st_probe_body /fc-adv $argv | awk -F= '/^ADVWIN=/{print $2}')
        [ "$adv" = 1048576 ]
        check "backend h2 window ($mode): the backend is promised 1 MiB ($adv)" $?
        # ...and the boundary body is checked by its BYTES, not its status line.
        #
        # These rows are REGRESSION coverage, not evidence for audit-report-67,
        # and the difference is worth stating. That report's overflow -- the
        # composers writing head+body into a buffer sized for the body alone,
        # 1048646 bytes into 1048576 -- has NO black-box signature here: the
        # copy runs off the end into the very buffer it is reading from, writing
        # the correct tail there, and the caller then reads those same bytes
        # back. Byte-correct output, past the end of the object. I added distinct
        # end markers to the fixture expecting them to expose it; they do not,
        # and the pre-fix control said so by passing.
        #
        # The evidence for that fix is arithmetic (returned length > buffer size)
        # and an assembly-time guard. What these rows buy is the ability to
        # notice a future TRUNCATION, which a status-line check cannot see.
        fcout=$(st_probe_body /fc-size-1048576 $argv)
        printf '%s' "$fcout" | grep -q "^HTTP/1.1 200"
        check "backend h2 window ($mode): a body of exactly that size relays" $?
        fctail=$(printf '%s' "$fcout" | tail -c 70 | tr -d 'Z' | wc -c)
        [ "$fctail" = 0 ]
        check "backend h2 window ($mode): ...and its last bytes are its own ($fctail stray)" $?
        [ "$(st_probe /fc-huge $argv)" = "H2C-FAIL" ]
        check "backend h2 window ($mode): twice that size is refused, not truncated" $?
    done
    # The report's own finding, deliberately NOT implemented: a backend that
    # bursts past the 65535-byte CONNECTION window is still accepted. RFC 9113
    # 6.9.1 says a receiver MAY error there, and nghttp2 as a client accepts the
    # same burst with NO_ERROR. Pinned so a later reading of report 64 has to
    # mean it.
    for mode in oracle driver; do
        [ "$mode" = driver ] && argv="0 drv" || argv=""
        st_probe_body /fc-burst $argv | grep -q "^HTTP/1.1 200"
        check "backend h2 window ($mode): an over-window burst is accepted (MAY, not MUST)" $?
        st_probe_body /fc-polite $argv | grep -q "^HTTP/1.1 200"
        check "backend h2 window ($mode): ...as is the same body sent politely" $?
    done
    [ "$(tr_get /fc-size-1048576 $CODE1)" = 200 ]
    check "backend h2 window: a 1 MiB body relays end to end" $?

    # --- terminal frames: RST_STREAM (6.4) and GOAWAY (6.8) -----------------
    # These do NOT discriminate the length/stream validation added for
    # audit-report-51: a valid reset already ends the exchange in a 502, so a
    # malformed one did too. They are here because backend terminal frames had
    # no coverage at all -- nothing said a reset produces a gateway error rather
    # than a hang, which is the behaviour worth holding.
    for route in /term-rstok /term-rst3 /term-rst0 /term-gook /term-goshort /term-gosid; do
        [ "$(tr_get $route $CODE1)" = 502 ]
        check "backend h2 terminal: $route answers 502, not a hang" $?
    done
    [ "$(tr_get /hello $H1 | tail -1)" = "hello from h2c" ]
    check "backend h2 terminal: ...and the next request still works" $?

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
