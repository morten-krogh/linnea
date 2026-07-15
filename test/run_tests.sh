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
run_test "good config"     124 stdout "server 1: host=127.0.0.1 port=47090 hostname=two.test root=test/www" \
    timeout 0.5 $BIN test/configs/listen.json
run_test "config dump"     124 stdout "config: 3 servers timeout=2 max_connections=64" \
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

# --- HTTP tests against a running server ---
rm -f "$LOG"
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
resp=$(curl -si --max-time 2 http://127.0.0.1:47080/no-such-file)
check_http "http 404"          "404 Not Found" "$resp"
resp=$(curl -si --max-time 2 -I http://127.0.0.1:47080/hello.txt)
check_http "HEAD length"       "Content-Length: 18" "$resp"
resp=$(curl -si --max-time 2 -X POST http://127.0.0.1:47080/hello.txt)
check_http "http 405"          "405 Method Not Allowed" "$resp"

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

# --- connection termination log lines ---
grep -qF ': close after response' "$LOG"
check "termination close-after-response" $?
grep -qF ': peer closed' "$LOG"
check "termination peer closed" $?
grep -qF ': idle timeout' "$LOG"
check "termination idle timeout" $?

kill $server_pid 2>/dev/null
wait $server_pid 2>/dev/null
rm -f "$LOG"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
