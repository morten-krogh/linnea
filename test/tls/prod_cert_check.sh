#!/usr/bin/env bash
# Load a REAL, externally issued certificate chain with the built binary.
#
# WHY THIS EXISTS. Report 114 shipped a defect that refused every real
# certificate: tbs_suffix_ok kept the [3] extensions wrapper's end in r8 across
# a der_any call, and der_any clobbers r8 in its 0x82 two-byte length path
# alone. Extensions under 256 bytes survived; extensions at 256 or more did not.
# Every fixture in this tree is under that line and every real certificate is
# over it, so a 1209-check full suite passed and the production reload was
# REJECTED (2764ba8).
#
# A synthetic fixture now holds the size line (test/tls/bigext.crt), but only a
# genuinely issued chain exercises the real thing: SCT lists, certificatePolicies,
# AIA, CRL distribution points, an issuer DN that is not our own, and a
# signature algorithm we cannot verify.
#
# HOW IT JUDGES. We do not have the private key for a production certificate --
# and must never need it. So the chain is loaded against a key we know does NOT
# match. Reaching "different identities" means every certificate in the chain
# PARSED and only the pairing failed, which is exactly the property under test.
# A chain/parse error means the loader refuses a certificate the world accepts.
#
#   usage: test/tls/prod_cert_check.sh [chain.pem ...]
#          with no argument it tries the known production chain.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 2
BIN=${BIN:-./bin/linnea}
KEY=test/tls/server.key

chains=("$@")
if [ ${#chains[@]} -eq 0 ]; then
    chains=(/etc/linnea/certs/*/fullchain.pem)
fi

found=0 bad=0
for chain in "${chains[@]}"; do
    [ -r "$chain" ] || continue
    found=$((found + 1))
    cfg=$(mktemp); trap 'rm -f "$cfg"' EXIT
    python3 - "$chain" "$KEY" > "$cfg" <<'PY'
import json, sys, os
chain, key = sys.argv[1], sys.argv[2]
json.dump({"log": os.path.join(os.getenv("TMPDIR", "/tmp"), "prodcert.log"),
           "servers": [{"host": "127.0.0.1", "port": 61443,
                        "hostname": "prod-cert-check.invalid",
                        "cert": chain, "key": key,
                        "locations": [{"prefix": "/", "root": "test/www"}]}]},
          sys.stdout)
PY
    out=$("$BIN" --config "$cfg" --test 2>&1)
    rm -f "$cfg"
    n=$(grep -c "BEGIN CERTIFICATE" "$chain")
    case "$out" in
        *"different identities"*)
            echo "  ok   $chain ($n certs): the whole chain parsed" ;;
        *"cannot load TLS certificate"*|*"not PEM"*)
            echo "  FAIL $chain ($n certs): $out"; bad=$((bad + 1)) ;;
        "")
            echo "  ok   $chain ($n certs): loaded outright" ;;
        *)
            # Anything else is a refusal on some other ground. The name warning
            # is expected here -- the hostname above deliberately matches nothing
            # -- so ignore it and judge on what remains.
            rest=$(printf '%s\n' "$out" | grep -v "presents no name matching")
            if [ -z "${rest//[[:space:]]/}" ]; then
                echo "  ok   $chain ($n certs): the whole chain parsed"
            else
                echo "  FAIL $chain ($n certs): $rest"; bad=$((bad + 1))
            fi ;;
    esac
done

if [ "$found" -eq 0 ]; then
    echo "  SKIP no real certificate chain readable on this machine"
    exit 3                       # distinct from pass and from fail
fi
exit $(( bad > 0 ))
