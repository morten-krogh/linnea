#!/usr/bin/env bash
# Test suite for the linnea server. Run from anywhere; exits non-zero
# if any test fails.
set -u
cd "$(dirname "$0")/.."

BIN=./bin/linnea
LOG=test/linnea.log
pass=0
fail=0
rm -f "$LOG"

# run_test <name> <expected-exit> <stdout|stderr> <grep-pattern> <cmd...>
run_test() {
    local name=$1 want_rc=$2 stream=$3 pattern=$4
    shift 4
    local tmp stdout stderr rc text
    tmp=$(mktemp)
    stdout=$("$@" 2>"$tmp")
    rc=$?
    stderr=$(<"$tmp")
    rm -f "$tmp"
    if [ "$stream" = stdout ]; then text=$stdout; else text=$stderr; fi
    if [ "$rc" -eq "$want_rc" ] && printf '%s' "$text" | grep -qF "$pattern"; then
        echo "PASS: $name"
        pass=$((pass + 1))
    else
        echo "FAIL: $name (exit=$rc, wanted $want_rc; pattern: $pattern)"
        echo "  stdout: $stdout"
        echo "  stderr: $stderr"
        fail=$((fail + 1))
    fi
}

# check <name> <condition-exit-code (0 = pass)>
check() {
    if [ "$2" -eq 0 ]; then
        echo "PASS: $1"
        pass=$((pass + 1))
    else
        echo "FAIL: $1"
        fail=$((fail + 1))
    fi
}

# --- config parsing and validation ---
run_test "good config"     124 stdout "server 1: host=127.0.0.1 port=47090 hostname=two.test locations=3" \
    timeout 0.5 $BIN test/configs/listen.json
run_test "config dump"     124 stdout "config: 3 servers timeout=2 max_connections=64" \
    timeout 0.5 $BIN test/configs/listen.json
run_test "location dump"   124 stdout "location 1: prefix=/sub root=test/www" \
    timeout 0.5 $BIN test/configs/listen.json
run_test "bad timeout"     1 stderr "timeout must be between 1 and 3600" \
    $BIN test/configs/bad-timeout.json
run_test "workers dump"    124 stdout "workers=2" \
    timeout 0.5 $BIN test/configs/listen.json
run_test "bad workers"     1 stderr "workers must be between 1 and 256" \
    $BIN test/configs/bad-workers.json
run_test "invalid host"    1 stderr "invalid host address" \
    $BIN test/configs/bad-host.json
run_test "missing argv"    1 stderr "usage:" \
    $BIN
run_test "missing file"    1 stderr "cannot open config file" \
    $BIN test/configs/does-not-exist.json
run_test "truncated json"  1 stderr "parse error at line" \
    $BIN test/configs/truncated.json
run_test "port too large"  1 stderr "port" \
    $BIN test/configs/bad-port-large.json
run_test "port zero"       1 stderr "port" \
    $BIN test/configs/bad-port-zero.json
run_test "empty servers"   1 stderr "at least one server" \
    $BIN test/configs/empty-servers.json
run_test "unknown key"     1 stderr "unknown key" \
    $BIN test/configs/unknown-key.json
run_test "escape sequence" 1 stderr "escape sequences not supported" \
    $BIN test/configs/escape.json
run_test "location no prefix" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN test/configs/location-missing-prefix.json
run_test "location root+proxy" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN test/configs/location-both-kinds.json
run_test "location root+redirect" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN test/configs/location-root-and-redirect.json
run_test "redirect dump"   124 stdout "prefix=/old redirect=https://example.com" \
    timeout 0.5 $BIN test/configs/listen.json
run_test "bad redirect target" 1 stderr "redirect target must start with http:// or https://" \
    $BIN test/configs/bad-redirect-target.json
run_test "bad proxy address" 1 stderr "invalid proxy address" \
    $BIN test/configs/bad-proxy-addr.json
run_test "prefix not absolute" 1 stderr "location prefix must start with '/'" \
    $BIN test/configs/location-bad-prefix.json
run_test "empty locations"  1 stderr "at least one location" \
    $BIN test/configs/empty-locations.json
# the middle server reuses the hostname on another port, which is fine;
# the clash is on the shared listener, case-insensitively
run_test "duplicate hostname" 1 stderr "duplicate hostname DUP.Test on 127.0.0.1:47080" \
    $BIN test/configs/dup-hostname.json

# --- TLS config: "cert" and "key" are both-or-neither, and servers sharing
# --- a listener must agree (SNI picks the cert within a TLS listener,
# --- but TLS and plaintext cannot share a socket)
run_test "tls dump"        124 stdout "tls=on cert=test/tls/server.crt" \
    timeout 0.5 $BIN test/configs/tls.json
run_test "sni dump"        124 stdout "hostname=sni.test tls=on cert=test/tls/sni.crt" \
    timeout 0.5 $BIN test/configs/tls-sni.json
run_test "tls cert without key" 1 stderr "server needs both cert and key, or neither" \
    $BIN test/configs/bad-cert-only.json
run_test "tls listener mismatch" 1 stderr "servers sharing a listener must all set TLS or none" \
    $BIN test/configs/bad-tls-mismatch.json

# --- crypto self-test: known-answer vectors for the TLS primitives ---
# Runs the pre-built binary (built by `make test`/`make selftest`); the
# heavy differential/fuzz harnesses under test/crypto/ run on demand.
if [ -x ./bin/linnea-selftest ]; then
    if ./bin/linnea-selftest >/tmp/linnea_selftest.out 2>&1; then
        check "crypto selftest ($(tr '\n' ' ' </tmp/linnea_selftest.out))" 0
    else
        check "crypto selftest" 1
        cat /tmp/linnea_selftest.out
    fi
    rm -f /tmp/linnea_selftest.out
else
    check "crypto selftest (binary not built — run 'make selftest')" 1
fi

# QUIC crypto known-answer tests (RFC 9001 / 9000). Built by `make quictest`.
if [ -x ./bin/linnea-quictest ]; then
    if ./bin/linnea-quictest >/tmp/linnea_quictest.out 2>&1; then
        check "quic crypto selftest ($(tr '\n' ' ' </tmp/linnea_quictest.out))" 0
    else
        check "quic crypto selftest" 1
        cat /tmp/linnea_quictest.out
    fi
    rm -f /tmp/linnea_quictest.out
else
    check "quic crypto selftest (binary not built — run 'make quictest')" 1
fi

# QUIC on the wire: a standalone UDP receiver decrypts a real Initial packet
# built by aioquic (the QUIC/HTTP-3 reference client).
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quicserver ]; then
    timeout 10 ./bin/linnea-quicserver >/tmp/linnea_quicsrv.out 2>&1 &
    qsrv=$!
    sleep 0.4
    python3 test/quic/h3_initial.py 47500 >/dev/null 2>&1
    sleep 0.4
    wait $qsrv 2>/dev/null
    # decrypt the Initial, recover the ClientHello, and read its SNI + h3 ALPN
    grep -q "quic-initial sni=localhost alpn-h3=1" /tmp/linnea_quicsrv.out
    check "quic: decrypt aioquic Initial + parse ClientHello (SNI, h3 ALPN)" $?
    rm -f /tmp/linnea_quicsrv.out
else
    check "quic wire test (skipped: aioquic or quicserver unavailable)" 0
fi

# QUIC transport parameters (for EncryptedExtensions): aioquic parses linnea's
# encoding and the values round-trip.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quictp ]; then
    ./bin/linnea-quictp | python3 test/quic/tp_parse.py >/dev/null 2>&1
    check "quic: transport parameters parse in aioquic" $?
else
    check "quic transport-params test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC ServerHello (first message of the handshake flight): aioquic's TLS
# parser accepts it and the negotiated profile round-trips.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quicsh ]; then
    ./bin/linnea-quicsh | python3 test/quic/sh_parse.py >/dev/null 2>&1
    check "quic: ServerHello parses in aioquic (x25519, TLS 1.3)" $?
else
    check "quic ServerHello test (skipped: aioquic/binary unavailable)" 0
fi

# --- HTTP tests against a running server ---
rm -f "$LOG"
# A file spanning several pages: every other fixture fits in one, which is
# exactly what let a wrong mmap length go unnoticed.
python3 -c "open('test/www/big.txt','w').write('B'*100000)"
# Pre-compressed variants. Each one holds different text, so a test can
# tell which file was served; real deployments would compress the same
# bytes. The .gz is real gzip (curl --compressed decodes it); the .br is
# not real brotli, which linnea neither produces nor inspects.
python3 - <<'PY'
import gzip
open('test/www/enc.txt', 'w').write('plain payload')
with gzip.open('test/www/enc.txt.gz', 'wb') as f:
    f.write(b'gzip payload')
open('test/www/enc.txt.br', 'wb').write(b'br payload')
PY
python3 test/proxy_backend.py >/dev/null 2>&1 &
backend_pid=$!
$BIN test/configs/listen.json >/dev/null 2>&1 &
server_pid=$!
sleep 0.3

# check_http <name> <grep-pattern> <response-text>
check_http() {
    local name=$1 pattern=$2 resp=$3
    if printf '%s' "$resp" | grep -qF "$pattern"; then
        echo "PASS: $name"
        pass=$((pass + 1))
    else
        echo "FAIL: $name (pattern: $pattern)"
        printf '%s\n' "--- response ---" "$resp" "----------------"
        fail=$((fail + 1))
    fi
}

# raw_http <request> — send bytes, print the full response.
# printf %b keeps literal '%' in the request while expanding \r\n.
raw_http() {
    timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/47080; printf %b '$1' >&3; cat <&3"
}

# --- log file ---
grep -q "listening on 127.0.0.1:47080 (one.test)" "$LOG"
check "log listening line" $?
n=$(grep -c "listening on 127.0.0.1:47080" "$LOG")
[ "$n" -eq 1 ]
check "shared listener bound once" $?

# --- bind conflict against the running server ---
run_test "address in use"  1 stderr "cannot bind to 127.0.0.1:47080 (errno 98)" \
    $BIN test/configs/dup-bind.json

# --- static file serving ---
resp=$(curl -s --max-time 2 http://127.0.0.1:47080/hello.txt)
check_http "file txt body"     "hello from linnea" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/hello.txt)
check_http "file txt mime"     "Content-Type: text/plain" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/)
check_http "index html body"   "linnea index page" "$resp"
check_http "index html mime"   "Content-Type: text/html" "$resp"

# --- redirect location: 301 with the raw request target appended ---
resp=$(curl -si --max-time 2 http://127.0.0.1:47090/old)
check_http "redirect status"   "301 Moved Permanently" "$resp"
check_http "redirect location" "Location: https://example.com/old" "$resp"
check_http "redirect no body"  "Content-Length: 0" "$resp"
resp=$(curl -si --max-time 2 "http://127.0.0.1:47090/old/a%20b?x=1&y=2")
check_http "redirect keeps raw path+query" "Location: https://example.com/old/a%20b?x=1&y=2" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/style.css)
check_http "css mime"          "Content-Type: text/css" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/favicon.ico)
check_http "ico mime"          "Content-Type: image/x-icon" "$resp"
resp=$(curl -s --max-time 2 http://127.0.0.1:47090/sub/page.html)
check_http "subdirectory file" "subdirectory page" "$resp"

# --- location routing: 47090 has "/" -> test/www/sub and "/sub" -> test/www ---
resp=$(curl -s --max-time 2 http://127.0.0.1:47090/page.html)
check_http "location root match"  "subdirectory page" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47090/hello.txt)
check_http "location root scopes" "404 Not Found" "$resp"
# /sub/page.html matches the longer "/sub" prefix (root test/www), not "/"
resp=$(curl -s --max-time 2 http://127.0.0.1:47090/sub/page.html)
check_http "longest prefix wins"  "subdirectory page" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/no-such-file)
check_http "http 404"          "404 Not Found" "$resp"
resp=$(curl -si --max-time 2 -I http://127.0.0.1:47080/hello.txt)
check_http "HEAD length"       "Content-Length: 18" "$resp"
resp=$(curl -si --max-time 2 -X POST http://127.0.0.1:47080/hello.txt)
check_http "http 405"          "405 Method Not Allowed" "$resp"

# a file larger than one page: the mapped length must be the whole file
n=$(curl -s --max-time 5 http://127.0.0.1:47080/big.txt | wc -c)
[ "$n" -eq 100000 ]
check "large file length ($n bytes)" $?
junk=$(curl -s --max-time 5 http://127.0.0.1:47080/big.txt | tr -d 'B' | wc -c)
[ "$junk" -eq 0 ]
check "large file intact" $?

# --- caching: ETag / Last-Modified and conditional requests ---
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/hello.txt)
check_http "etag present"        "ETag: \"" "$resp"
check_http "last-modified present" "Last-Modified: " "$resp"
printf '%s' "$resp" | grep -qE '^ETag: "[0-9a-f]+-12"'
check "etag is mtime-size in hex" $?
printf '%s' "$resp" | grep -qE '^Last-Modified: [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT'
check "last-modified is an HTTP date" $?

etag=$(printf '%s' "$resp" | grep -i '^etag:' | tr -d '\r' | cut -d' ' -f2)
lastmod=$(printf '%s' "$resp" | grep -i '^last-modified:' | tr -d '\r' | cut -d' ' -f2-)

resp=$(curl -si --max-time 2 -H "If-None-Match: $etag" http://127.0.0.1:47080/hello.txt)
check_http "if-none-match 304"   "304 Not Modified" "$resp"
check_http "304 repeats etag"    "ETag: $etag" "$resp"
check_http "304 keeps alive"     "Connection: keep-alive" "$resp"
printf '%s' "$resp" | grep -qF "hello from linnea"
[ $? -ne 0 ]
check "304 carries no body" $?
# a 304 that cost a new connection each time would defeat revalidation
before=$(grep -c "accepted connection" "$LOG")
curl -s --max-time 4 -H "If-None-Match: $etag" -o /dev/null \
    http://127.0.0.1:47080/hello.txt http://127.0.0.1:47080/hello.txt
after=$(grep -c "accepted connection" "$LOG")
[ $((after - before)) -eq 1 ]
check "304 single accept" $?

resp=$(curl -si --max-time 2 -H 'If-None-Match: "stale"' http://127.0.0.1:47080/hello.txt)
check_http "stale etag 200"      "hello from linnea" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: W/$etag" http://127.0.0.1:47080/hello.txt)
check_http "weak etag 304"       "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H 'If-None-Match: *' http://127.0.0.1:47080/hello.txt)
check_http "if-none-match star"  "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: \"a\", W/\"b\", $etag" http://127.0.0.1:47080/hello.txt)
check_http "etag list 304"       "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -I -H "If-None-Match: $etag" http://127.0.0.1:47080/hello.txt)
check_http "HEAD 304"            "304 Not Modified" "$resp"

resp=$(curl -si --max-time 2 -H "If-Modified-Since: $lastmod" http://127.0.0.1:47080/hello.txt)
check_http "if-modified-since 304" "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -z "$lastmod" http://127.0.0.1:47080/hello.txt)
check_http "curl time-cond 304"  "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H "If-Modified-Since: Wed, 01 Jan 2020 00:00:00 GMT" http://127.0.0.1:47080/hello.txt)
check_http "older date 200"      "hello from linnea" "$resp"
# an unparseable date must be ignored, not treated as a condition
resp=$(curl -si --max-time 2 -H "If-Modified-Since: not a date" http://127.0.0.1:47080/hello.txt)
check_http "bad date ignored"    "hello from linnea" "$resp"
resp=$(curl -si --max-time 2 -H "If-Modified-Since: Sunday, 06-Nov-94 08:49:37 GMT" http://127.0.0.1:47080/hello.txt)
check_http "rfc850 date ignored" "hello from linnea" "$resp"
# If-None-Match wins outright when both are present
resp=$(curl -si --max-time 2 -H 'If-None-Match: "x"' -H "If-Modified-Since: $lastmod" http://127.0.0.1:47080/hello.txt)
check_http "if-none-match wins"  "hello from linnea" "$resp"

grep -qF '"GET /hello.txt" 304 0' "$LOG"
check "request log 304" $?

# --- pre-compressed variants: enc.txt has both a .br and a .gz beside it ---
# enc_of <accept-encoding> — the Content-Encoding linnea picked, if any.
# grep -a: the gzip variant's body is binary.
enc_of() {
    curl -si --max-time 2 -H "Accept-Encoding: $1" http://127.0.0.1:47080/enc.txt \
        | grep -a -io '^content-encoding: .*' | tr -d '\r' | cut -d' ' -f2
}
body_of() {
    curl -s --max-time 2 -H "Accept-Encoding: $1" http://127.0.0.1:47080/enc.txt
}
[ "$(enc_of 'gzip, br')" = "br" ]
check "br preferred over gzip" $?
[ "$(body_of 'gzip, br')" = "br payload" ]
check "br variant served" $?
[ "$(enc_of 'gzip')" = "gzip" ]
check "gzip when br unwanted" $?
[ "$(enc_of 'deflate, br')" = "br" ]
check "unknown codings skipped" $?
[ "$(enc_of 'BR')" = "br" ]
check "accept-encoding is case-insensitive" $?
[ -z "$(enc_of 'identity')" ]
check "identity gets the plain file" $?
[ "$(body_of 'identity')" = "plain payload" ]
check "plain body when no coding taken" $?
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/enc.txt)
printf '%s' "$resp" | grep -qai '^content-encoding'
[ $? -ne 0 ]
check "no accept-encoding, no coding" $?
check_http "plain body without accept-encoding" "plain payload" "$resp"
# q=0 is a refusal, and the fallback must still find the other variant
[ -z "$(enc_of 'br;q=0')" ]
check "q=0 refuses a coding" $?
[ "$(enc_of 'br;q=0, gzip')" = "gzip" ]
check "q=0 falls back to gzip" $?
[ "$(enc_of 'br;q=0.001')" = "br" ]
check "a small q still accepts" $?
[ -z "$(enc_of 'br;q=0.000')" ]
check "q=0.000 refuses too" $?
# the type comes from the name before the suffix, not from ".br"
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' http://127.0.0.1:47080/enc.txt)
check_http "type ignores the suffix" "Content-Type: text/plain" "$resp"
check_http "variant length"          "Content-Length: 10" "$resp"
check_http "variant vary"            "Vary: Accept-Encoding" "$resp"
# curl decoding the real gzip end to end
[ "$(curl -s --max-time 2 --compressed -H 'Accept-Encoding: gzip' http://127.0.0.1:47080/enc.txt)" = "gzip payload" ]
check "gzip variant decodes" $?
# a file with no variants must not claim an encoding, but still varies
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip, br' http://127.0.0.1:47080/hello.txt)
printf '%s' "$resp" | grep -qai '^content-encoding'
[ $? -ne 0 ]
check "no variant, no coding" $?
check_http "no variant still varies" "Vary: Accept-Encoding" "$resp"
check_http "no variant serves plain" "hello from linnea" "$resp"

# Each variant is its own representation: a cache must never hand one to a
# client that asked for another, so the validators have to differ.
etag_br=$(curl -si --max-time 2 -H 'Accept-Encoding: br' http://127.0.0.1:47080/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
etag_gz=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip' http://127.0.0.1:47080/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
etag_pl=$(curl -si --max-time 2 http://127.0.0.1:47080/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
[ -n "$etag_br" ] && [ "$etag_br" != "$etag_gz" ] && [ "$etag_gz" != "$etag_pl" ] && [ "$etag_br" != "$etag_pl" ]
check "each variant has its own etag" $?
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' -H "If-None-Match: $etag_br" http://127.0.0.1:47080/enc.txt)
check_http "variant revalidates 304" "304 Not Modified" "$resp"
check_http "variant 304 varies"      "Vary: Accept-Encoding" "$resp"
printf '%s' "$resp" | grep -qai '^content-encoding'
[ $? -ne 0 ]
check "variant 304 omits the coding" $?
# the br etag says nothing about the gzip or plain representations
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip' -H "If-None-Match: $etag_br" http://127.0.0.1:47080/enc.txt)
check_http "cross-variant etag 200" "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: $etag_br" http://127.0.0.1:47080/enc.txt)
check_http "variant etag vs plain 200" "plain payload" "$resp"

# --- Range requests: hello.txt is the 18 bytes "hello from linnea\n" ---
resp=$(curl -si --max-time 2 -r 0-4 http://127.0.0.1:47080/hello.txt)
check_http "range 206"           "206 Partial Content" "$resp"
check_http "range content-range" "Content-Range: bytes 0-4/18" "$resp"
check_http "range length"        "Content-Length: 5" "$resp"
printf '%s' "$resp" | grep -qF "hello from"
[ $? -ne 0 ]
check "range body is the slice" $?
check_http "range body"          "hello" "$resp"
resp=$(curl -s --max-time 2 -r 6- http://127.0.0.1:47080/hello.txt)
[ "$resp" = "from linnea" ]     # the trailing newline is byte 17
check "range open end" $?
resp=$(curl -s --max-time 2 -r -7 http://127.0.0.1:47080/hello.txt)
[ "$resp" = "linnea" ]
check "range suffix" $?
resp=$(curl -si --max-time 2 -r 0-0 http://127.0.0.1:47080/hello.txt)
check_http "range single byte"   "Content-Range: bytes 0-0/18" "$resp"
check_http "range single length" "Content-Length: 1" "$resp"
# a last past the end means "to the end"
resp=$(curl -si --max-time 2 -H 'Range: bytes=6-9999' http://127.0.0.1:47080/hello.txt)
check_http "range clamped last"  "Content-Range: bytes 6-17/18" "$resp"
# a suffix longer than the file is the whole file, still a 206
resp=$(curl -si --max-time 2 -H 'Range: bytes=-9999' http://127.0.0.1:47080/hello.txt)
check_http "range long suffix"   "Content-Range: bytes 0-17/18" "$resp"
# 200s advertise the support
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/hello.txt)
check_http "accept-ranges"       "Accept-Ranges: bytes" "$resp"
# unsatisfiable: starts at or past the end -> 416 naming the length
resp=$(curl -si --max-time 2 -H 'Range: bytes=99-' http://127.0.0.1:47080/hello.txt)
check_http "range 416"           "416 Range Not Satisfiable" "$resp"
check_http "416 content-range"   "Content-Range: bytes */18" "$resp"
check_http "416 keeps alive"     "Connection: keep-alive" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=-0' http://127.0.0.1:47080/hello.txt)
check_http "range -0 is 416"     "416 Range Not Satisfiable" "$resp"
# not understood -> ignored -> the full 200
resp=$(curl -si --max-time 2 -H 'Range: bytes=5-2' http://127.0.0.1:47080/hello.txt)
check_http "backwards range 200" "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=abc' http://127.0.0.1:47080/hello.txt)
check_http "garbage range 200"   "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: potatoes=0-4' http://127.0.0.1:47080/hello.txt)
check_http "other unit 200"      "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=0-1,3-4' http://127.0.0.1:47080/hello.txt)
check_http "several ranges 200"  "200 OK" "$resp"
check_http "several ranges full" "Content-Length: 18" "$resp"
# Range is defined for GET alone
resp=$(curl -si --max-time 2 -I -H 'Range: bytes=0-4' http://127.0.0.1:47080/hello.txt)
check_http "HEAD ignores range"  "200 OK" "$resp"
check_http "HEAD full length"    "Content-Length: 18" "$resp"
# the conditionals still win over Range
resp=$(curl -si --max-time 2 -r 0-4 -H "If-None-Match: $etag" http://127.0.0.1:47080/hello.txt)
check_http "range vs 304"        "304 Not Modified" "$resp"
# If-Range: the range only with a strong validator match
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: $etag" http://127.0.0.1:47080/hello.txt)
check_http "if-range match 206"  "206 Partial Content" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H 'If-Range: "stale"' http://127.0.0.1:47080/hello.txt)
check_http "if-range stale 200"  "200 OK" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: W/$etag" http://127.0.0.1:47080/hello.txt)
check_http "if-range weak 200"   "200 OK" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: $lastmod" http://127.0.0.1:47080/hello.txt)
check_http "if-range date 206"   "206 Partial Content" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H 'If-Range: Wed, 01 Jan 2020 00:00:00 GMT' http://127.0.0.1:47080/hello.txt)
check_http "if-range old date 200" "200 OK" "$resp"
# ranges hold on big files and on pre-compressed variants
n=$(curl -s --max-time 5 -r 90000-99999 http://127.0.0.1:47080/big.txt | tr -d 'B' | wc -c)
[ "$n" -eq 0 ] && [ "$(curl -s --max-time 5 -r 90000-99999 http://127.0.0.1:47080/big.txt | wc -c)" -eq 10000 ]
check "range into big file" $?
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' -r 0-1 http://127.0.0.1:47080/enc.txt)
check_http "variant range slices variant" "Content-Range: bytes 0-1/10" "$resp"
check_http "variant range body"  "br" "$resp"
# two ranged requests ride one keep-alive connection
before=$(grep -c "accepted connection" "$LOG")
curl -s --max-time 4 -r 0-4 \
    http://127.0.0.1:47080/hello.txt http://127.0.0.1:47080/hello.txt >/dev/null
after=$(grep -c "accepted connection" "$LOG")
[ $((after - before)) -eq 1 ]
check "206 keep-alive single accept" $?
grep -qF '"GET /hello.txt" 206 5' "$LOG"
check "request log 206" $?
grep -qF '"GET /hello.txt" 416 0' "$LOG"
check "request log 416" $?

# --- virtual hosts: 47080 is shared by one.test (default) and three.test ---
resp=$(curl -s --max-time 2 -H "Host: three.test" http://127.0.0.1:47080/page.html)
check_http "vhost three.test"  "subdirectory page" "$resp"
resp=$(curl -s --max-time 2 -H "Host: three.test:47080" http://127.0.0.1:47080/page.html)
check_http "vhost host:port"   "subdirectory page" "$resp"
resp=$(curl -s --max-time 2 -H "Host: unknown.test" http://127.0.0.1:47080/hello.txt)
check_http "vhost default"     "hello from linnea" "$resp"

# --- percent-decoding ---
resp=$(curl -s --max-time 2 'http://127.0.0.1:47080/a%20b.txt')
check_http "decode space"      "space file" "$resp"
resp=$(curl -s --max-time 2 'http://127.0.0.1:47080/sub%2Fpage.html')
check_http "decode slash"      "subdirectory page" "$resp"
check_http "encoded traversal" "400 Bad Request" "$(raw_http 'GET /%2e%2e/secret HTTP/1.1\r\nConnection: close\r\n\r\n')"
check_http "bad escape"        "400 Bad Request" "$(raw_http 'GET /%zz HTTP/1.1\r\nConnection: close\r\n\r\n')"
check_http "encoded NUL"       "400 Bad Request" "$(raw_http 'GET /%00 HTTP/1.1\r\nConnection: close\r\n\r\n')"

# --- path normalization (raw, curl normalizes dot segments itself) ---
check_http "double slash"   "hello from linnea" "$(raw_http 'GET //hello.txt HTTP/1.1\r\nConnection: close\r\n\r\n')"
check_http "dot segment"    "hello from linnea" "$(raw_http 'GET /./hello.txt HTTP/1.1\r\nConnection: close\r\n\r\n')"
check_http "dotdot resolve" "hello from linnea" "$(raw_http 'GET /sub/../hello.txt HTTP/1.1\r\nConnection: close\r\n\r\n')"
check_http "dotdot to dir"  "linnea index page" "$(raw_http 'GET /sub/.. HTTP/1.1\r\nConnection: close\r\n\r\n')"
check_http "above root"     "400 Bad Request" "$(raw_http 'GET /a/../../x HTTP/1.1\r\nConnection: close\r\n\r\n')"

# --- request bodies ---
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nContent-Length: 5\r\n\r\nXXXXXGET /hello.txt HTTP/1.1\r\nConnection: close\r\n\r\n')
n=$(printf '%s' "$resp" | grep -c "200 OK")
[ "$n" -eq 2 ]
check "body discarded, keep-alive" $?
check_http "chunked 501" "501 Not Implemented" "$(raw_http 'GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n')"
check_http "body too large 413" "413 Content Too Large" "$(raw_http 'GET / HTTP/1.1\r\nContent-Length: 9000\r\n\r\n')"

# --- protocol errors and traversal (raw, curl normalizes paths) ---
check_http "http 400" "400 Bad Request" "$(raw_http 'GARBAGE\r\n\r\n')"
check_http "http 505" "505 HTTP Version Not Supported" "$(raw_http 'GET / HTTP/1.0\r\nConnection: close\r\n\r\n')"
check_http "traversal blocked" "400 Bad Request" "$(raw_http 'GET /../secret HTTP/1.1\r\nConnection: close\r\n\r\n')"

# --- request log lines (with peer address) ---
grep -qE 'request one\.test from 127\.0\.0\.1:[0-9]+ "GET /hello\.txt" 200 18' "$LOG"
check "request log 200" $?
grep -qE 'request three\.test from 127\.0\.0\.1:[0-9]+ "GET /page\.html" 200' "$LOG"
check "request log vhost" $?
grep -qE '"GET /a%20b\.txt" 200' "$LOG"
check "request log raw target" $?
grep -qF '"GET /no-such-file" 404 0' "$LOG"
check "request log 404" $?
grep -qF '"POST /hello.txt" 405 0' "$LOG"
check "request log 405" $?
grep -qE '^\[20[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\] request' "$LOG"
check "log timestamps" $?

# --- keep-alive: two requests, one connection (count accepts in the log) ---
before=$(grep -c "accepted connection" "$LOG")
resp=$(curl -s --max-time 4 http://127.0.0.1:47080/hello.txt http://127.0.0.1:47080/index.html)
after=$(grep -c "accepted connection" "$LOG")
check_http "keep-alive body 1" "hello from linnea" "$resp"
check_http "keep-alive body 2" "linnea index page" "$resp"
[ $((after - before)) -eq 1 ]
check "keep-alive single accept" $?

# --- pipelined requests in one write ---
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\n\r\nGET /hello.txt HTTP/1.1\r\nConnection: close\r\n\r\n')
n=$(printf '%s' "$resp" | grep -c "200 OK")
[ "$n" -eq 2 ]
check "pipelined requests" $?

# --- idle timeout: configured to 2s in listen.json ---
start=$SECONDS
if timeout 6 bash -c 'exec 3<>/dev/tcp/127.0.0.1/47080; cat <&3' >/dev/null 2>&1; then
    elapsed=$((SECONDS - start))
    [ "$elapsed" -ge 1 ] && [ "$elapsed" -le 4 ]
    check "configured idle timeout (${elapsed}s)" $?
else
    check "configured idle timeout (connection not closed)" 1
fi

grep -qE 'accepted connection on 127\.0\.0\.1:47080 from 127\.0\.0\.1:[0-9]+ \(fd ' "$LOG"
check "accept log line" $?

# --- proxying: /api -> the test backend, /down -> nothing listening ---
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/simple)
check_http "proxy body"          "backend body" "$resp"
check_http "proxy status"        "200 OK" "$resp"
check_http "proxy content-length" "Content-Length: 12" "$resp"
check_http "proxy keeps alive"   "Connection: keep-alive" "$resp"

# the prefix is not stripped and the query survives: the backend echoes the target
resp=$(curl -s --max-time 3 'http://127.0.0.1:47080/api/target?x=1&y=2')
check_http "proxy target forwarded" "/api/target?x=1&y=2" "$resp"

# the client's Connection header is replaced, everything else passes through
resp=$(curl -s --max-time 3 -H 'X-Test: abc' -H 'Connection: keep-alive' \
    http://127.0.0.1:47080/api/headers)
check_http "proxy forwards headers" "X-Test: abc" "$resp"
check_http "proxy forwards host"    "Host: 127.0.0.1:47080" "$resp"
check_http "proxy closes upstream"  "Connection: close" "$resp"

resp=$(curl -s --max-time 3 -d 'hello body' http://127.0.0.1:47080/api/echo)
check_http "proxy forwards body" "hello body" "$resp"

# a HEAD response is head-only even though the backend sends Content-Length:
# waiting for that body would hang until the idle timeout
resp=$(curl -si --max-time 3 -I http://127.0.0.1:47080/api/simple)
check_http "proxy HEAD length"   "Content-Length: 12" "$resp"
check_http "proxy HEAD no hang"  "200 OK" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/204)
check_http "proxy 204 no body"   "204 No Content" "$resp"

# chunked and close-delimited bodies have no length we can pass on, so the
# client connection has to close to delimit them
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/chunked)
check_http "proxy chunked body"  "chunked body" "$resp"
check_http "proxy chunked framing" "Transfer-Encoding: chunked" "$resp"
check_http "proxy chunked closes" "Connection: close" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/eof)
check_http "proxy eof body"      "eof delimited body" "$resp"
check_http "proxy eof closes"    "Connection: close" "$resp"

# a body bigger than the relay buffer takes several upstream reads
n=$(curl -s --max-time 5 http://127.0.0.1:47080/api/big | wc -c)
[ "$n" -eq 40000 ]
check "proxy large body ($n bytes)" $?

resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/http10)
check_http "proxy 1.0 upstream"  "HTTP/1.1 200 OK" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/301)
check_http "proxy passes status" "301 Moved Permanently" "$resp"
check_http "proxy passes header" "Location: /elsewhere" "$resp"

# proxied and static requests share one keep-alive connection
before=$(grep -c "accepted connection" "$LOG")
resp=$(curl -s --max-time 4 http://127.0.0.1:47080/api/simple http://127.0.0.1:47080/hello.txt)
after=$(grep -c "accepted connection" "$LOG")
check_http "proxy then static body" "hello from linnea" "$resp"
[ $((after - before)) -eq 1 ]
check "proxy keep-alive single accept" $?

# --- proxy failures ---
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/down/x)
check_http "proxy refused 502"   "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/garbage)
check_http "proxy garbage 502"   "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/bighead)
check_http "proxy huge head 502" "502 Bad Gateway" "$resp"
# contradictory upstream framing must never reach the client: forwarding
# both would let a compromised backend split the next keep-alive response
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/tecl)
check_http "proxy TE+CL 502"     "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/cljunk)
check_http "proxy bad CL 502"    "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/clpad)
check_http "proxy CL whitespace" "valid" "$resp"
# Expect must not be forwarded: the body is already buffered, and an
# interim 100 Continue would be parsed as the response itself
resp=$(raw_http 'POST /api/expect HTTP/1.1\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nHELLO')
check_http "proxy drops Expect"  "real" "$resp"
printf '%s' "$resp" | grep -qF "100 Continue"
[ $? -ne 0 ]
check "proxy no interim 100 leak" $?
# the backend sleeps 4s; the config's timeout is 2s
start=$SECONDS
resp=$(curl -si --max-time 8 http://127.0.0.1:47080/api/slow)
elapsed=$((SECONDS - start))
check_http "proxy slow 504"      "504 Gateway Timeout" "$resp"
[ "$elapsed" -le 4 ]
check "proxy 504 on time (${elapsed}s)" $?
# a body cut short of its Content-Length must not look like a clean end
curl -s --max-time 3 http://127.0.0.1:47080/api/truncated >/dev/null 2>&1
grep -qF ': upstream closed early' "$LOG"
check "proxy truncated body" $?

# --- proxied request log lines: upstream status, relayed byte count ---
grep -qE 'request one\.test from 127\.0\.0\.1:[0-9]+ "GET /api/simple" 200 12' "$LOG"
check "proxy log 200" $?
grep -qF '"POST /api/echo" 200 10' "$LOG"
check "proxy log body bytes" $?
grep -qF '"GET /api/target?x=1&y=2" 200' "$LOG"
check "proxy log query" $?
grep -qF '"GET /down/x" 502 0' "$LOG"
check "proxy log 502" $?
grep -qF '"GET /api/slow" 504 0' "$LOG"
check "proxy log 504" $?
grep -qF '"HEAD /api/simple" 200 0' "$LOG"
check "proxy log HEAD" $?

# --- websockets: upgrade passthrough and the full-duplex tunnel ---
out=$(python3 test/ws_client.py echo)
[ "$out" = "OK" ]
check "ws echo round trips ($out)" $?
out=$(python3 test/ws_client.py pipelined)
[ "$out" = "OK" ]
check "ws client bytes before the 101 ($out)" $?
out=$(python3 test/ws_client.py push)
[ "$out" = "OK" ]
check "ws server push and 101 leftover ($out)" $?
out=$(python3 test/ws_client.py tick)
[ "$out" = "OK" ]
check "ws one-way traffic outlives idle timeout ($out)" $?
out=$(python3 test/ws_client.py silent)
[ "$out" = "OK" ]
check "ws idle tunnel times out ($out)" $?
out=$(python3 test/ws_client.py reject)
[ "$out" = "OK" ]
check "ws upgrade refusal passes through ($out)" $?
# a 101 the client never asked for must not start a tunnel
resp=$(curl -si --max-time 3 http://127.0.0.1:47080/api/101)
check_http "unrequested 101 becomes 502" "502 Bad Gateway" "$resp"
# an upgrade wish on a static location changes nothing
resp=$(curl -si --max-time 3 -H 'Connection: upgrade' -H 'Upgrade: websocket' \
    http://127.0.0.1:47080/hello.txt)
check_http "upgrade on static location" "hello from linnea" "$resp"
grep -qF '"GET /api/ws-echo" 101 0' "$LOG"
check "ws request log 101" $?
grep -qF ': upstream closed' "$LOG"
check "ws termination upstream closed" $?

# --- send timeout: a client that stops reading must not pin its slot ---
# huge.bin is sparse and far larger than any kernel socket buffering, so
# once the client's window fills the send stalls and its linked timeout
# (2s in this config) fires.
truncate -s 64M test/www/huge.bin
(exec 3<>/dev/tcp/127.0.0.1/47080
 printf 'GET /huge.bin HTTP/1.1\r\n\r\n' >&3
 sleep 6) &
stall_pid=$!
sleep 4
grep -qF ': send timeout' "$LOG"
check "termination send timeout" $?
kill $stall_pid 2>/dev/null
wait $stall_pid 2>/dev/null
# a slow but reading client must survive a transfer spanning several
# timeout windows: partial sends re-arm with a fresh timeout each time
n=$(curl -s --max-time 12 --limit-rate 16M http://127.0.0.1:47080/huge.bin | wc -c)
[ "$n" -eq 67108864 ]
check "slow reader outlives send timeout ($n bytes)" $?

# --- connection termination log lines ---
grep -qF ': close after response' "$LOG"
check "termination close-after-response" $?
grep -qF ': peer closed' "$LOG"
check "termination peer closed" $?
grep -qF ': idle timeout' "$LOG"
check "termination idle timeout" $?

kill $server_pid $backend_pid 2>/dev/null
wait $server_pid 2>/dev/null
wait $backend_pid 2>/dev/null
rm -f "$LOG" test/www/big.txt test/www/huge.bin test/www/enc.txt test/www/enc.txt.gz test/www/enc.txt.br

# --- graceful drain: SIGTERM finishes in-flight work, then exits ---
# A slow download is in flight when the master is killed; the workers
# must complete it, refuse new connections meanwhile, and exit after.
python3 -c "open('test/www/drain.bin','w').write('D' * 3000000)"
rm -f "$LOG"
$BIN test/configs/listen.json >/dev/null 2>&1 &
drain_master=$!
sleep 0.3
curl -s --max-time 30 --limit-rate 500k http://127.0.0.1:47080/drain.bin -o /tmp/drain_out &
drain_curl=$!
sleep 0.5                       # the transfer is under way
kill $drain_master              # SIGTERM: master dies, workers drain
wait $drain_master 2>/dev/null
sleep 0.5                       # accepts cancelled by now
curl -s --max-time 2 http://127.0.0.1:47080/hello.txt -o /dev/null 2>/dev/null
[ $? -ne 0 ]
check "drain refuses new connections" $?
wait $drain_curl
n=$(wc -c < /tmp/drain_out)
[ "$n" -eq 3000000 ]
check "drain finishes the in-flight response ($n bytes)" $?
sleep 0.5
! pgrep -f 'test/configs/listen.json' >/dev/null
check "drain exits after the last connection" $?
grep -qF 'worker drained' "$LOG"
check "drain logged" $?
rm -f /tmp/drain_out test/www/drain.bin "$LOG"

# --- config-check mode: `linnea -t` accepts good, rejects bad ---
$BIN -t test/configs/listen.json >/dev/null 2>&1
check "config check accepts a good config" $?
$BIN -t test/configs/bad-timeout.json >/dev/null 2>&1
[ $? -ne 0 ]
check "config check rejects a bad config" $?

# --- zero-downtime binary upgrade (SIGUSR2) ---
# The master re-execs in place: same PID, listeners adopted (never
# closed), new workers up, old workers drained. A request in flight when
# the signal lands must finish, and no new request may be refused.
rm -f "$LOG"
python3 -c "open('test/www/up.bin','w').write('U' * 3000000)"
$BIN test/configs/listen.json >/dev/null 2>&1 &
up_master=$!
sleep 0.3
old_workers=$(pgrep -P $up_master | tr '\n' ' ')
# a slow download in flight across the upgrade
curl -s --max-time 30 --limit-rate 500k http://127.0.0.1:47080/up.bin \
    -o /tmp/up_out &
up_curl=$!
# a steady stream of quick requests, counting any refusal
up_fails=0
( sleep 0.4; kill -USR2 $up_master ) &
for i in $(seq 1 60); do
    curl -s --max-time 3 http://127.0.0.1:47080/hello.txt -o /dev/null \
        || up_fails=$((up_fails + 1))
    sleep 0.03
done
kill -0 $up_master 2>/dev/null
check "upgrade keeps the master PID" $?
wait $up_curl
n=$(wc -c < /tmp/up_out)
[ "$n" -eq 3000000 ]
check "upgrade finishes the in-flight download ($n bytes)" $?
[ "$up_fails" -eq 0 ]
check "upgrade refuses no new request ($up_fails failed)" $?
sleep 1
gone=1
for w in $old_workers; do kill -0 "$w" 2>/dev/null && gone=0; done
[ "$gone" -eq 1 ]
check "upgrade drains the old workers" $?
grep -qF 'binary upgrade complete' "$LOG"
check "upgrade logged" $?
curl -s --max-time 3 http://127.0.0.1:47080/hello.txt | grep -q "hello from linnea"
check "upgraded server still serves" $?
kill $up_master 2>/dev/null
wait $up_master 2>/dev/null
rm -f /tmp/up_out test/www/up.bin "$LOG"

# --- TLS 1.3: the standalone echo server against real clients ---
# Needs the openssl CLI (cert generation + s_client) and python3 ssl,
# both already test-only dependencies. Skips cleanly if either is absent.
TLSBIN=./bin/linnea-tlstest
if [ -x "$TLSBIN" ] && command -v openssl >/dev/null 2>&1; then
    tlsdir=$(mktemp -d)
    if openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$tlsdir/k.pem" -out "$tlsdir/c.pem" -days 1 -nodes \
            -subj /CN=localhost >/dev/null 2>&1; then
        tport=47443
        "$TLSBIN" "$tlsdir/c.pem" "$tlsdir/k.pem" $tport &
        tls_pid=$!
        sleep 0.4

        # openssl s_client: full handshake + application echo
        got=$(printf 'linnea-tls' | timeout 5 openssl s_client \
              -connect 127.0.0.1:$tport -CAfile "$tlsdir/c.pem" \
              -tls1_3 -quiet 2>/dev/null)
        [ "$got" = "linnea-tls" ]
        check "tls openssl handshake + echo" $?

        # python ssl: assert protocol + cipher, echo 4B and 16KB
        timeout 8 python3 - "$tlsdir/c.pem" $tport <<'PYEOF'
import ssl, socket, sys, os
ca, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=ca)
with socket.create_connection(("127.0.0.1", port)) as raw:
    with ctx.wrap_socket(raw, server_hostname="localhost") as s:
        assert s.version() == "TLSv1.3", s.version()
        assert s.cipher()[0] == "TLS_AES_128_GCM_SHA256", s.cipher()
        s.sendall(b"ping"); assert s.recv(16) == b"ping"
        big = os.urandom(16384); s.sendall(big)
        got = b""
        while len(got) < len(big): got += s.recv(65536)
        assert got == big
PYEOF
        check "tls python ssl (TLSv1.3, AES-128-GCM, 16KB echo)" $?

        # session resumption: a NewSessionTicket from the first handshake
        # lets the second skip the certificate. python's ssl exposes the
        # PSK acceptance directly as session_reused.
        timeout 10 python3 - "$tlsdir/c.pem" $tport <<'PYEOF'
import ssl, socket, sys
ca, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=ca)
ctx.check_hostname = False           # the fixture cert is CN=localhost
# first connection: complete the handshake and collect the ticket
with socket.create_connection(("127.0.0.1", port)) as raw:
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    s.sendall(b"x"); assert s.recv(4) == b"x"
    sess = s.session               # populated once the NST arrives
    assert not s.session_reused
    s.close()
assert sess is not None, "no NewSessionTicket received"
# second connection: offer the ticket, expect resumption
with socket.create_connection(("127.0.0.1", port)) as raw:
    s = ctx.wrap_socket(raw, server_hostname="localhost", session=sess)
    assert s.version() == "TLSv1.3", s.version()
    assert s.session_reused, "server did not resume the session"
    s.sendall(b"y"); assert s.recv(4) == b"y"
    s.close()
PYEOF
        check "tls session resumption (PSK, session_reused)" $?

        # negative: plain HTTP to the TLS port -> a fatal alert record
        alert=$(timeout 3 python3 - $tport <<'PYEOF'
import socket, sys
s = socket.socket(); s.settimeout(2)
s.connect(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
d = s.recv(16)
print("alert" if d[:1] == b"\x15" else "no")
PYEOF
)
        [ "$alert" = alert ]
        check "tls plain-HTTP to TLS port -> fatal alert" $?

        # negative: a TLS 1.2-only client cannot negotiate our profile
        timeout 4 openssl s_client -connect 127.0.0.1:$tport -tls1_2 \
            </dev/null 2>&1 | grep -q "alert"
        check "tls 1.2 client rejected" $?

        # a short ClientHello fuzz: the server must survive and keep serving
        timeout 60 python3 test/tls/fuzz_clienthello.py \
            "$tlsdir/c.pem" $tport 150 >/dev/null 2>&1
        check "tls clienthello fuzz (150 cases, server survives)" $?

        kill $tls_pid 2>/dev/null
        wait $tls_pid 2>/dev/null
    else
        check "tls (openssl could not generate a P-256 cert — skipped)" 0
    fi
    rm -rf "$tlsdir"
else
    check "tls (linnea-tlstest not built or openssl absent — skipped)" 0
fi

# --- TLS end to end: the real server, handshake in userspace then kTLS ---
# Everything past the handshake is the ordinary HTTP path over a socket the
# kernel encrypts, so these tests are really asking whether the handoff left
# the connection indistinguishable from a plaintext one.
if ! grep -qw tls /proc/sys/net/ipv4/tcp_available_ulp 2>/dev/null; then
    # No kTLS: the handshake would still succeed and every request would then
    # fail, so skip rather than report a pile of misleading failures.
    check "tls e2e (kernel tls module not loaded: modprobe tls — skipped)" 0
else
    rm -f "$LOG"
    # Recreated here: the HTTP section removed its copy, and a file spanning
    # many records is the point of the large-file case below.
    python3 -c "open('test/www/big.txt','w').write('B'*100000)"
    python3 test/proxy_backend.py >/dev/null 2>&1 &
    tls_backend_pid=$!
    $BIN test/configs/tls.json >/dev/null 2>&1 &
    tls_server_pid=$!
    sleep 0.3
    CA=test/tls/server.crt
    U=https://localhost:47443

    resp=$(curl -si --max-time 5 --cacert $CA $U/hello.txt)
    check_http "tls static body"   "hello from linnea" "$resp"
    check_http "tls static status" "200 OK" "$resp"

    # One connection, two requests: keep-alive has to survive the handoff.
    # -w reports per transfer, so sum it: the second request must open no
    # new connection (and so must not repeat the handshake).
    n=$(curl -s --max-time 5 --cacert $CA -o /dev/null -o /dev/null \
        -w '%{num_connects}\n' $U/hello.txt $U/index.html | awk '{t += $1} END {print t}')
    [ "$n" = "1" ]
    check "tls keep-alive reuses one connection" $?

    # A file spanning many records exercises the kTLS TX path against an
    # mmap'd send, where the kernel does the fragmenting.
    n=$(curl -s --max-time 10 --cacert $CA $U/big.txt | wc -c)
    [ "$n" = "100000" ]
    check "tls large file intact ($n bytes)" $?

    resp=$(curl -si --max-time 5 --cacert $CA $U/api/simple)
    check_http "tls proxy body"   "backend body" "$resp"
    check_http "tls proxy status" "200 OK" "$resp"

    timeout 8 python3 - "$CA" 47443 <<'PYEOF'
import ssl, socket, sys
ctx = ssl.create_default_context(cafile=sys.argv[1])
with socket.create_connection(("localhost", int(sys.argv[2])), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname="localhost") as s:
        assert s.version() == "TLSv1.3", s.version()
        assert s.cipher()[0] == "TLS_AES_128_GCM_SHA256", s.cipher()
        s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        # The head and the mmap'd body are separate sends, so under kTLS
        # they are separate records: read until the body turns up rather
        # than assuming one recv holds the whole response.
        buf = b""
        while b"hello from linnea" not in buf:
            d = s.recv(4096)
            assert d, f"connection closed after {buf!r}"
            buf += d
        assert b"200 OK" in buf, buf
PYEOF
    check "tls python ssl (TLSv1.3, AES-128-GCM)" $?

    # kTLS reports the peer's close_notify as -EIO rather than a 0-length
    # read, so an orderly shutdown must not be logged as a recv error.
    curl -s --max-time 5 --cacert $CA $U/hello.txt >/dev/null
    sleep 0.3
    grep -q "closed connection on 127.0.0.1:47443 .*: peer closed" "$LOG"
    check "tls close_notify logs as peer closed" $?
    ! grep -q "recv error" "$LOG"
    check "tls orderly close is not a recv error" $?

    # resumption over the real kTLS server: the ticket from connection one
    # must let connection two resume (openssl prints "Reused"), and a byte
    # must still flow — proving the app-key handoff used the right sequence
    # (the NST went out at seq 0, so the kernel starts at seq 1). The first
    # connection makes a full request and reads to EOF (-ign_eof), so the
    # post-handshake ticket is received before -sess_out writes it.
    req=$'GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'
    printf '%s' "$req" | timeout 5 openssl s_client -connect 127.0.0.1:47443 \
        -CAfile $CA -tls1_3 -ign_eof -sess_out "$LOG.sess" >/dev/null 2>&1
    reused=$(printf '%s' "$req" | timeout 5 openssl s_client \
        -connect 127.0.0.1:47443 -CAfile $CA -tls1_3 -ign_eof \
        -sess_in "$LOG.sess" 2>/dev/null | grep -c '^Reused')
    [ "$reused" -eq 1 ]
    check "tls resumption over kTLS (Reused)" $?
    rm -f "$LOG.sess"

    # ALPN: this server (47443) has a proxy location, and proxy-over-h2 is
    # not implemented, so it must keep speaking http/1.1 even with h2 on by
    # default. Offering nothing gets no ALPN extension back.
    echo | timeout 5 openssl s_client -connect 127.0.0.1:47443 -CAfile $CA \
        -tls1_3 -alpn h2,http/1.1 2>/dev/null | grep -q "ALPN protocol: http/1.1"
    check "alpn: proxy vhost stays http/1.1 (h2 gated off)" $?
    echo | timeout 5 openssl s_client -connect 127.0.0.1:47443 -CAfile $CA \
        -tls1_3 2>/dev/null | grep -q "No ALPN negotiated"
    check "alpn absent when not offered" $?

    # HTTP/2 connection bring-up: a separate http2:1 server. ALPN selects
    # h2; preface + SETTINGS + PING exchange; a request draws GOAWAY.
    $BIN test/configs/tls-h2.json >/dev/null 2>&1 &
    h2_pid=$!
    sleep 0.3
    timeout 10 python3 test/tls/h2_bringup.py $CA 47446 >/dev/null 2>&1
    check "http2 connection bring-up (preface, settings, ping, goaway)" $?

    # M16/M17: a real HTTP/2 client (curl's nghttp2 — genuine HPACK with
    # Huffman + the static table) has its HEADERS decoded and the named
    # static file served back over h2. Serving the right file end to end is
    # the proof the :path decoded correctly.
    rl="--resolve localhost:47446:127.0.0.1"
    u="https://localhost:47446"
    body=$(curl -s --http2 --cacert $CA $rl "$u/hello.txt")
    [ "$body" = "hello from linnea" ]
    check "http2 serves a static file (HPACK decode -> file)" $?
    # status line, content-type and content-length over h2
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null "$u/hello.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 200' \
        && echo "$hdrs" | grep -qi '^content-type: text/plain' \
        && echo "$hdrs" | grep -qi '^content-length: 18'
    check "http2 response headers (status, content-type, content-length)" $?
    ver=$(curl -s -o /dev/null --http2 --cacert $CA $rl \
        -w '%{http_version}' "$u/hello.txt")
    [ "$ver" = "2" ]
    check "http2 request uses HTTP/2 (not downgraded)" $?
    ct=$(curl -s -o /dev/null --http2 --cacert $CA $rl \
        -w '%{content_type}' "$u/style.css")
    [ "$ct" = "text/css" ]
    check "http2 content-type from extension (css)" $?
    # a body larger than the initial flow-control window (100000 > 65535):
    # exercises DATA chunking and WINDOW_UPDATE-driven resumption
    n=$(curl -s --http2 --cacert $CA $rl "$u/big.txt" | wc -c)
    junk=$(curl -s --http2 --cacert $CA $rl "$u/big.txt" | tr -d 'B' | wc -c)
    [ "$n" -eq 100000 ] && [ "$junk" -eq 0 ]
    check "http2 flow control: 100000-byte body, exact + intact" $?
    # keep-alive with a Huffman-coded custom header (decoder must parse+skip)
    two=$(curl -s --http2 --cacert $CA $rl \
        -H "x-linnea-probe: a-huffman-coded-header-value-98765" \
        "$u/hello.txt" "$u/big.txt" | wc -c)
    [ "$two" -eq 100018 ]
    check "http2 keep-alive: two requests, one connection" $?
    # HEAD: headers only, no body
    hb=$(curl -s --http2 -I --cacert $CA $rl "$u/hello.txt" | grep -ci .)
    hd=$(curl -s --http2 -I --cacert $CA $rl "$u/hello.txt" | grep -qi 'content-length: 18' && echo ok)
    [ "$hd" = "ok" ]
    check "http2 HEAD: headers with content-length, no body" $?
    # a directory maps to index.html
    dc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' "$u/")
    [ "$dc" = "200" ]
    check "http2 directory serves index.html" $?
    # missing file -> 404, disallowed method -> 405
    c404=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' "$u/nope.txt")
    c405=$(curl -s -o /dev/null --http2 --cacert $CA $rl -X DELETE -w '%{http_code}' "$u/hello.txt")
    [ "$c404" = "404" ] && [ "$c405" = "405" ]
    check "http2 error statuses (404 missing, 405 method)" $?
    # path traversal above the root is refused
    ct400=$(curl -s -o /dev/null --http2 --cacert $CA $rl --path-as-is \
        -w '%{http_code}' "$u/../../../etc/passwd")
    [ "$ct400" = "400" ]
    check "http2 path traversal refused (400)" $?

    # M18: multiplexing — concurrent streams with interleaved DATA, the
    # rapid-reset (CVE-2023-44487) defense, and stream-pool exhaustion.
    timeout 30 python3 test/tls/h2_multiplex.py $CA 47446 >/dev/null 2>&1
    check "http2 multiplexing (concurrent streams, rapid-reset, pool cap)" $?

    # M19: fuzz the frame layer and HPACK decoder — malformed streams must
    # never crash the worker; a live h2 GET still serves between batches.
    timeout 60 python3 test/tls/fuzz_h2.py $CA 47446 120 >/dev/null 2>&1
    check "http2 fuzz (malformed frames + HPACK survive, server serves)" $?

    # M20: strict stream-id validation + honouring SETTINGS_INITIAL_WINDOW_SIZE.
    timeout 20 python3 test/tls/h2_conformance.py $CA 47446 >/dev/null 2>&1
    check "http2 conformance (stream-id rules, initial window size)" $?

    kill $h2_pid 2>/dev/null
    wait $h2_pid 2>/dev/null
    # (h2 graceful drain — GOAWAY(last-stream) then finish open streams — is
    # exercised by test/tls/h2_drain.py against a running worker; it is not in
    # the automated suite because reliably retiring one worker of a forked
    # multi-process server without the master's supervision reaping the
    # draining worker is timing-fragile. The hot-upgrade path keeps other
    # workers alive, so old workers drain cleanly there.)

    timeout 30 python3 test/tls/oversized_record.py $CA 47443 \
        test/tls/clienthello_seed.bin >/dev/null 2>&1
    check "tls oversized record refused (msg_buf bound)" $?

    # Records pipelined behind the Finished, including one split the way an
    # MSS boundary would split it — the case loopback never produces.
    timeout 40 python3 test/tls/pipelined_early.py $CA 47443 >/dev/null 2>&1
    check "tls pipelined early records (whole and split)" $?

    # A tunnelled upgrade over TLS: the tunnel has its own recv path, so it
    # needs the close_notify handling too, and the relay must stay blind to
    # the fact that the kernel is encrypting underneath it.
    timeout 10 python3 - "$CA" 47443 <<'PYEOF' >/dev/null 2>&1
import base64, os, socket, ssl, sys
ctx = ssl.create_default_context(cafile=sys.argv[1])
raw = socket.create_connection(("localhost", int(sys.argv[2])), timeout=5)
s = ctx.wrap_socket(raw, server_hostname="localhost")
key = base64.b64encode(os.urandom(16)).decode()
s.sendall(f"GET /api/ws-echo HTTP/1.1\r\nHost: localhost\r\n"
          f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
          f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
resp = b""
while b"\r\n\r\n" not in resp:
    d = s.recv(4096)
    assert d, "closed before the 101"
    resp += d
assert b"101 Switching Protocols" in resp, resp[:60]
s.sendall(b"tunnel-bytes-over-tls")          # linnea never parses frames
assert s.recv(64) == b"tunnel-bytes-over-tls"
s.close()
PYEOF
    check "tls websocket tunnel (101 + blind relay)" $?

    kill $tls_server_pid $tls_backend_pid 2>/dev/null
    wait $tls_server_pid 2>/dev/null
    wait $tls_backend_pid 2>/dev/null
    rm -f "$LOG" test/www/big.txt

    # --- SNI: two TLS vhosts share 127.0.0.1:47444, each with its own cert
    $BIN test/configs/tls-sni.json >/dev/null 2>&1 &
    sni_server_pid=$!
    sleep 0.3
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:47444 \
        -servername sni.test 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=sni.test"
    check "sni selects the named vhost cert" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:47444 \
        -servername localhost 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "sni selects the owner cert by name" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:47444 \
        -noservername 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "no sni falls back to the listener owner" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:47444 \
        -servername unknown.test 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "unknown sni falls back to the listener owner" $?
    # h2 is on by default (tls-sni.json sets no "http2" key): a static vhost
    # negotiates h2.
    echo | timeout 5 openssl s_client -connect 127.0.0.1:47444 -CAfile test/tls/sni.crt \
        -servername sni.test -tls1_3 -alpn h2,http/1.1 2>/dev/null \
        | grep -q "ALPN protocol: h2"
    check "alpn: h2 on by default (static vhost)" $?
    # a full request via the SNI vhost: curl verifies against the sni.test
    # cert AND the Host routing must land on the sni.test docroot (which
    # holds page.html; the listener owner does not). h2 is on by default now,
    # so this also exercises SNI vhost routing over HTTP/2.
    resp=$(curl -s --max-time 5 --cacert test/tls/sni.crt \
        --resolve sni.test:47444:127.0.0.1 https://sni.test:47444/page.html)
    check_http "sni end to end (cert + vhost routing)" "subdirectory page" "$resp"
    kill $sni_server_pid 2>/dev/null
    wait $sni_server_pid 2>/dev/null
    rm -f "$LOG"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
