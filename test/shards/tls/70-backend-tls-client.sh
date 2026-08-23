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

    rm -f $RUNDIR/bt_conc.txt "$btw/probe.txt"
else
    check "backend TLS e2e proxy (skipped: tls ULP or openssl unavailable)" 0
fi
