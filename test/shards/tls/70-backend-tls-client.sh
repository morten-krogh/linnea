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
