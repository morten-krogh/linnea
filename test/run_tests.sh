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
run_test "good config"     124 stdout "server 1: host=127.0.0.1 port=47090 hostname=two.test locations=2" \
    timeout 0.5 $BIN test/configs/listen.json
run_test "config dump"     124 stdout "config: 3 servers timeout=2 max_connections=64" \
    timeout 0.5 $BIN test/configs/listen.json
run_test "location dump"   124 stdout "location 1: prefix=/sub root=test/www" \
    timeout 0.5 $BIN test/configs/listen.json
run_test "bad timeout"     1 stderr "timeout must be between 1 and 3600" \
    $BIN test/configs/bad-timeout.json
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
run_test "location no prefix" 1 stderr "location requires prefix and exactly one of root or proxy" \
    $BIN test/configs/location-missing-prefix.json
run_test "location root+proxy" 1 stderr "location requires prefix and exactly one of root or proxy" \
    $BIN test/configs/location-both-kinds.json
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
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/style.css)
check_http "css mime"          "Content-Type: text/css" "$resp"
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

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
