#!/usr/bin/env bash
# Test suite for the linnea config loader. Run from anywhere; exits non-zero
# if any test fails.
set -u
cd "$(dirname "$0")/.."

BIN=./bin/linnea
pass=0
fail=0

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

# The server blocks after binding its listeners, so success cases run under
# timeout (exit 124) and use dedicated high ports to avoid collisions.
run_test "good config"     124 stdout "server 1: host=127.0.0.1 port=47090 hostname=two.test" \
    timeout 0.5 $BIN test/configs/listen.json
run_test "listen log"      124 stdout "listening on 127.0.0.1:47090 (two.test)" \
    timeout 0.5 $BIN test/configs/listen.json
run_test "invalid host"    1 stderr "invalid host address" \
    $BIN test/configs/bad-host.json
run_test "address in use"  1 stderr "cannot bind to 127.0.0.1:47100 (errno 98)" \
    $BIN test/configs/dup-bind.json
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

# HTTP tests against a running server.
server_log=$(mktemp)
$BIN test/configs/listen.json >"$server_log" 2>&1 &
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

# raw_http <request> — send bytes, print the full response
raw_http() {
    timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/47080; printf '$1' >&3; cat <&3"
}

resp=$(curl -s --max-time 2 http://127.0.0.1:47080/hello)
check_http "http 200 server"  "server: one.test" "$resp"
check_http "http 200 method"  "method: GET" "$resp"
check_http "http 200 target"  "target: /hello" "$resp"
check_http "http 200 host"    "host: 127.0.0.1:47080" "$resp"

resp=$(curl -s --max-time 2 -H "Host: custom.example" http://127.0.0.1:47090/x)
check_http "http host header" "host: custom.example" "$resp"
check_http "http second port" "server: two.test" "$resp"

check_http "http 400" "400 Bad Request" "$(raw_http 'GARBAGE\r\n\r\n')"
check_http "http 505" "505 HTTP Version Not Supported" "$(raw_http 'GET / HTTP/1.0\r\n\r\n')"
check_http "http no host" "host: -" "$(raw_http 'GET / HTTP/1.1\r\n\r\n')"

sleep 0.2
if grep -q "accepted connection on 127.0.0.1:47080 (fd " "$server_log"; then
    echo "PASS: accept log"
    pass=$((pass + 1))
else
    echo "FAIL: accept log"
    cat "$server_log"
    fail=$((fail + 1))
fi
kill $server_pid 2>/dev/null
wait $server_pid 2>/dev/null
rm -f "$server_log"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
