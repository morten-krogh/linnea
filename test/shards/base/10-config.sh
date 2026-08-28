# Config parsing and validation, plus the TLS both-or-neither rules.
# (was run_tests.sh lines 419-514, part of the every-shard preamble.)

# --- config parsing and validation ---
run_test "good config"     124 stdout "server 1: host=127.0.0.1 port=${P61090} hostname=two.test locations=3" \
    timeout 0.5 $BIN --config $CFG/listen.json
run_test "config dump"     124 stdout "config: 4 servers timeout=2 max_connections=64" \
    timeout 0.5 $BIN --config $CFG/listen.json
# the dump prints the config verbatim, and the generated configs carry
# ABSOLUTE paths so a server started in its own run directory still finds
# them — so the expected text is absolute too
run_test "location dump"   124 stdout "location 1: prefix=/sub root=$PWD/$WWW" \
    timeout 0.5 $BIN --config $CFG/listen.json
# max_body was the one limit the dump did not name — awkward for the limit
# that stands between one client and the disk, since setting it left nothing
# to check it by
run_test "max_body dumped"  124 stdout "max_body=1000000" \
    timeout 0.5 $BIN --config $CFG/listen.json
run_test "bad timeout"     1 stderr "timeout must be between 1 and 3600" \
    $BIN --config $CFG/bad-timeout.json
run_test "workers dump"    124 stdout "workers=2" \
    timeout 0.5 $BIN --config $CFG/listen.json
run_test "bad workers"     1 stderr "workers must be between 0 and 256" \
    $BIN --config $CFG/bad-workers.json
# 0 is the DEFAULT (one worker per online CPU) and used to be the one value you
# could not write: the range started at 1, so the only way to ask for the
# default was to omit the key. resolve_workers always understood it.
run_test "workers auto"    124 stdout "config:" \
    timeout 0.5 $BIN --config $CFG/workers-auto.json

# docs/config.md documents every key, its scope, default and range, plus a
# complete example. A reference that drifts from the parser is worse than
# none, so every claim in it is asserted against the binary — the example
# included, since that is what a reader copies.
python3 test/configs/doc_claims_test.py >/dev/null 2>&1
check "docs/config.md still describes the parser" $?
run_test "invalid host"    1 stderr "host must be an IPv4 or IPv6 literal" \
    $BIN --config $CFG/bad-host.json
# a hard fd limit below the configured pool is fatal: the pool could never
# fill, and accept would fail with EMFILE while the server thought it had room
run_test "fd limit too low" 1 stderr "file descriptor limit too low" \
    bash -c "ulimit -n 200; exec $BIN --config $CFG/listen.json"
# a low SOFT limit is not fatal — a process may raise its own up to the hard
# limit, so the server does that for itself rather than refusing to start
run_test "fd soft limit raised" 124 stdout "config:" \
    bash -c "ulimit -S -n 64; exec timeout 0.5 $BIN --config $CFG/listen.json"
run_test "missing argv"    1 stderr "usage:" \
    $BIN
run_test "missing file"    1 stderr "cannot open config file" \
    $BIN --config $CFG/does-not-exist.json
run_test "truncated json"  1 stderr "parse error at line" \
    $BIN --config $CFG/truncated.json
run_test "port too large"  1 stderr "port" \
    $BIN --config $CFG/bad-port-large.json
# "port": 0 is legal now and means "let the kernel choose"; what must still be
# refused is leaving the key OUT, which is what keeps a kernel-chosen port
# something the config asked for rather than something it forgot. This fixture
# used to carry the 0 and assert the opposite.
run_test "port missing"    1 stderr "requires host, port" \
    $BIN --config $CFG/bad-port-missing.json
run_test "empty servers"   1 stderr "at least one server" \
    $BIN --config $CFG/empty-servers.json
run_test "unknown key"     1 stderr "unknown key" \
    $BIN --config $CFG/unknown-key.json
run_test "escape sequence" 1 stderr "escape sequences not supported" \
    $BIN --config $CFG/escape.json
run_test "location no prefix" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN --config $CFG/location-missing-prefix.json
run_test "location root+proxy" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN --config $CFG/location-both-kinds.json
run_test "location root+redirect" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN --config $CFG/location-root-and-redirect.json
run_test "redirect dump"   124 stdout "prefix=/old redirect=https://example.com" \
    timeout 0.5 $BIN --config $CFG/listen.json
run_test "bad redirect target" 1 stderr "redirect target must start with http:// or https://" \
    $BIN --config $CFG/bad-redirect-target.json
run_test "bad proxy address" 1 stderr "invalid proxy address" \
    $BIN --config $CFG/bad-proxy-addr.json
run_test "prefix not absolute" 1 stderr "location prefix must start with '/'" \
    $BIN --config $CFG/location-bad-prefix.json
run_test "empty locations"  1 stderr "at least one location" \
    $BIN --config $CFG/empty-locations.json
# the middle server reuses the hostname on another port, which is fine;
# the clash is on the shared listener, case-insensitively
run_test "duplicate hostname" 1 stderr "duplicate hostname DUP.Test on 127.0.0.1:${P61080}" \
    $BIN --config $CFG/dup-hostname.json

# --- TLS config: "cert" and "key" are both-or-neither, and servers sharing
# --- a listener must agree (SNI picks the cert within a TLS listener,
# --- but TLS and plaintext cannot share a socket)
run_test "tls dump"        124 stdout "tls=on cert=$PWD/test/tls/server.crt" \
    timeout 0.5 $BIN --config $CFG/tls.json
run_test "sni dump"        124 stdout "hostname=sni.test tls=on cert=$PWD/test/tls/sni.crt" \
    timeout 0.5 $BIN --config $CFG/tls-sni.json
run_test "tls cert without key" 1 stderr "server needs both cert and key, or neither" \
    $BIN --config $CFG/bad-cert-only.json
run_test "tls listener mismatch" 1 stderr "servers sharing a listener must all set TLS or none" \
    $BIN --config $CFG/bad-tls-mismatch.json

# --- the certificate must be the one it claims to be, and must speak for this
# --- server's name (audit-report-119)

# A self-signed leaf carries the very key that signed it, so its own signature
# is checkable with no trust store and no chain. `openssl x509 -badsig` makes a
# file that every other check here still calls well-formed, and that the
# key/certificate pairing check still passes -- the SPKI is untouched.
run_test "cert with a forged signature" 1 stderr "signature does not verify under its own public key" \
    $BIN --config $CFG/cert-badsig.json --test
# A certificate signed by SOMEONE ELSE is left UNVERIFIED rather than refused:
# the issuer's key is not here, and is usually RSA or P-384 which this build
# cannot check at all. Deliberately silent rather than warned about -- a warning
# would fire on every boot of a perfectly good Let's Encrypt certificate.

# The name check is a WARNING, not a refusal, because serving a vhost over a
# connection authenticated for another of its names is legitimate: that is
# exactly what HTTP/2 coalescing does, and what tls-coalesce.json exercises.
run_test "cert name mismatch warns" 0 stderr "presents no name matching this server's hostname" \
    $BIN --config $CFG/cert-wrong-name.json --test
# ACCEPTANCE CONTROL. Without it a build that warned about EVERY certificate
# would sail through the check above -- the failure mode that made a green
# suite miss a constant HTTP/1.1 in the access log.
cert_name_out=$($BIN --config $CFG/tls.json --test 2>&1)
check "a matching cert name warns about nothing" \
    "$(printf '%s' "$cert_name_out" | grep -qF 'presents no name' && echo 1 || echo 0)"

# RFC 5280 4.2: a critical extension this build cannot process must be REFUSED,
# because every conforming client refuses it -- so accepting one only moves the
# failure from --test to the handshake, which is the outage a preflight exists
# to catch (audit-report-120). The fixtures carry the private arc 1.2.3.4, which
# can never become something this build implements, and are signed by
# server.key so a refusal cannot be the pairing check firing instead:
#   openssl req -new -x509 -key test/tls/server.key -subj /CN=localhost \
#     -days 3650 -addext '1.2.3.4=critical,DER:05:00' -out unknown-critical.crt
run_test "unknown critical extension refused" 1 stderr "CRITICAL X.509 extension this build does not implement" \
    $BIN --config $CFG/cert-unknown-critical.json --test
# ACCEPTANCE CONTROL, and the one that matters most here. The SAME unknown OID,
# marked non-critical, MUST still load: RFC 5280 says an unrecognised extension
# is only fatal when it is critical, so a build that refused unknown extensions
# outright would pass the check above while rejecting certificates the whole
# world ships.
$BIN --config $CFG/cert-unknown-noncritical.json --test >/dev/null 2>&1
check "the same OID non-critical still loads" $?
# The second control is basicConstraints, which is critical on EVERY certificate
# in this tree and on every real one -- leaf, intermediate and root. It had to
# join the recognised set in the same change; a set without it would refuse the
# entire corpus, which is the report-114 shape of a preflight turning a legal
# file into an outage. cert-bigext.json below and prod_cert_check.sh are what
# would catch that, so both run after this.

# A REAL certificate's extensions run to hundreds of bytes, so their SEQUENCE
# carries a two-byte (0x82) DER length -- and der_any clobbers r8 in exactly
# that path, which is where the [3] wrapper's end was being kept. Every fixture
# in this tree had extensions under 256 bytes and passed; the live Let's Encrypt
# leaf is over the line, so it was refused and a production reload rejected the
# upgrade. bigext.crt carries a 497-byte extensions block to hold that line.
$BIN --config $CFG/cert-bigext.json --test >/dev/null 2>&1
check "a 0x82-length extensions block loads (real-certificate size)" $?

# ...and the same property against a REAL, externally issued chain. bigext.crt
# holds the SIZE line synthetically; only a genuinely issued certificate carries
# the rest of what the world ships -- SCT lists, certificatePolicies, AIA, CRL
# distribution points, an issuer DN that is not ours, and a signature algorithm
# this build cannot verify. It is loaded against a key that deliberately does
# NOT match, so no private key is ever needed: reaching "different identities"
# proves every certificate in the chain parsed. SKIPPED, loudly, where no such
# chain is readable -- a skip that read as a pass is what let this ship.
prod_cert_out=$(./test/tls/prod_cert_check.sh 2>&1); prod_cert_rc=$?
if [ "$prod_cert_rc" -eq 3 ]; then
    skip "a real issued certificate chain loads (none readable on this machine)"
else
    check "a real issued certificate chain loads" "$prod_cert_rc"
    [ "$prod_cert_rc" -eq 0 ] || printf '%s\n' "$prod_cert_out"
fi

# Listener identity is the CANONICAL endpoint, not the host text (audit-report-2
# Finding 1). "::" and "0.0.0.0" are one in6addr_any endpoint, so the same
# hostname on both is a duplicate on the shared listener...
run_test "wildcard alias duplicate hostname" 1 stderr "duplicate hostname same.test" \
    $BIN --config $CFG/wildcard-dup-hostname.json
# ...and one endpoint cannot carry two different v6only settings
run_test "v6only conflict" 1 stderr "servers on one address and port must agree on v6only" \
    $BIN --config $CFG/bad-v6only-conflict.json

