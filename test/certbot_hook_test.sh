#!/usr/bin/env bash
# The certbot deploy hook, exercised without root and without a renewal.
#
# It is the one piece of the deployment that runs unattended, as root, at an
# hour nobody is watching. What it now does beyond copying is TRIM the trailing
# cross-signed root off the chain, so the QUIC handshake fits inside the
# anti-amplification limit (RFC 9000 8.1) and a cold HTTP/3 connection stops
# paying an extra round trip. Trimming a certificate chain unattended is exactly
# the sort of thing that works until a CA reshuffles its hierarchy and then
# breaks TLS silently, so the property under test is not "it trims" but "it
# trims ONLY when the result still verifies, and otherwise leaves the chain
# alone".
#
# The two cases use real Let's Encrypt certificates fetched from the live
# server, because the interesting one depends on a real-world fact no synthetic
# fixture would reproduce: ISRG Root YE is not yet in trust stores, so a chain
# trimmed to leaf + intermediate does NOT verify.
#
# NOT part of ./test/run_tests.sh: it needs a real CA-issued chain from a live
# host, so it would fail on a machine with no network and go stale the moment a
# committed fixture expired. Run it by hand when the hook changes.
#
# usage: certbot_hook_test.sh [host]     (default linnea.amberbio.com)
set -u
HOST=${1:-linnea.amberbio.com}
HOOK=$(cd "$(dirname "$0")/.." && pwd)/config/certbot-deploy-hook.sh
fails=0

check() {   # check <name> <condition-result>
    if [ "$2" = 0 ]; then echo "ok   $1"; else echo "FAIL $1"; fails=$((fails + 1)); fi
}

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# The live chain, as the server sends it.
openssl s_client -connect "$HOST:443" -servername "$HOST" -showcerts </dev/null \
    2>/dev/null | awk '/BEGIN CERT/,/END CERT/' > "$tmp/live.pem"
live=$(grep -c '^-----BEGIN CERTIFICATE-----' "$tmp/live.pem" || echo 0)
if [ "$live" -lt 2 ]; then
    echo "FAIL could not fetch a chain from $HOST (got $live certs)"
    exit 1
fi
echo "note: $HOST currently serves $live certs"

# A lineage as certbot would present one. The private key is never read by the
# trimming logic -- only copied -- so a placeholder is enough.
run_hook() {   # run_hook <chain file> -> echoes the cert count it installed
    local chain=$1 lineage="$tmp/live/$HOST" out
    rm -rf "$tmp/live" "$tmp/dest"
    mkdir -p "$lineage" "$tmp/dest"
    cp "$chain" "$lineage/fullchain.pem"
    echo "placeholder" > "$lineage/privkey.pem"
    out=$(RENEWED_LINEAGE="$lineage" \
          LINNEA_CERT_DIR="$tmp/dest" \
          LINNEA_CERT_OWNER="$(id -un):$(id -gn)" \
          LINNEA_RELOAD=true \
          bash "$HOOK" 2>&1)
    echo "$out" >&2
    grep -c '^-----BEGIN CERTIFICATE-----' "$tmp/dest/$HOST/fullchain.pem" 2>/dev/null || echo 0
}

verifies() {   # verifies <chain file> -- does it chain to the system store?
    awk '/^-----BEGIN CERTIFICATE-----/ { n++ } n == 1 { print }' "$1" > "$tmp/l.pem"
    awk '/^-----BEGIN CERTIFICATE-----/ { n++ } n > 1  { print }' "$1" > "$tmp/i.pem"
    openssl verify -untrusted "$tmp/i.pem" "$tmp/l.pem" >/dev/null 2>&1
}

# --- case 1: a four-cert chain, whose trailing root IS droppable -------------
# Build one by hand if the server is already serving the trimmed three, so the
# test does not depend on which chain happens to be deployed right now.
if [ "$live" -ge 4 ]; then
    cp "$tmp/live.pem" "$tmp/four.pem"
else
    # re-add a trailing self-issued root from the system store to make a 4th
    awk '/^-----BEGIN CERTIFICATE-----/ { n++ } n <= 3 { print }' "$tmp/live.pem" > "$tmp/four.pem"
    openssl x509 -in /etc/ssl/certs/ca-certificates.crt >> "$tmp/four.pem" 2>/dev/null
fi
four=$(grep -c '^-----BEGIN CERTIFICATE-----' "$tmp/four.pem")
if [ "$four" -ge 4 ]; then
    got=$(run_hook "$tmp/four.pem")
    [ "$got" = "$((four - 1))" ]
    check "a $four-cert chain is served as $((four - 1)): the trailing root is dropped (got $got)" $?
    verifies "$tmp/dest/$HOST/fullchain.pem"
    check "...and what it installed still verifies against the system store" $?
else
    check "four-cert case (skipped: could not assemble a 4-cert chain)" 0
fi

# --- case 2: trimming would BREAK it, so the chain must be left alone --------
# leaf + YE2 + Root YE. Dropping Root YE leaves leaf + YE2, which does not
# verify, because ISRG Root YE is not in trust stores yet. The hook must notice
# and install all three. This is the case that matters: it is what stops an
# unattended renewal from serving a chain nothing can validate.
awk '/^-----BEGIN CERTIFICATE-----/ { n++ } n <= 3 { print }' "$tmp/live.pem" > "$tmp/three.pem"
three=$(grep -c '^-----BEGIN CERTIFICATE-----' "$tmp/three.pem")
if [ "$three" = 3 ]; then
    awk '/^-----BEGIN CERTIFICATE-----/ { n++ } n <= 2 { print }' "$tmp/three.pem" > "$tmp/two.pem"
    if verifies "$tmp/two.pem"; then
        # Root YE has reached this machine's trust store: the premise is gone
        check "fallback case (skipped: leaf+intermediate now verifies here)" 0
    else
        got=$(run_hook "$tmp/three.pem")
        [ "$got" = 3 ]
        check "a chain whose trim would not verify is served WHOLE (got $got of 3)" $?
        verifies "$tmp/dest/$HOST/fullchain.pem"
        check "...and what it installed verifies" $?
    fi
else
    check "fallback case (skipped: no 3-cert chain to build)" 0
fi

# --- and the key is copied, with the private one no wider than 0640 ----------
[ -s "$tmp/dest/$HOST/privkey.pem" ]
check "the private key is installed alongside the chain" $?
perm=$(stat -c %a "$tmp/dest/$HOST/privkey.pem" 2>/dev/null)
[ "$perm" = 640 ]
check "the private key is 0640, not world-readable (got $perm)" $?
perm=$(stat -c %a "$tmp/dest/$HOST/fullchain.pem" 2>/dev/null)
[ "$perm" = 644 ]
check "the chain is 0644 (got $perm)" $?

exit $((fails > 0))
