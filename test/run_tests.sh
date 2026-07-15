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

# The event loop must accept a TCP connection and (for now) close it:
# reading from the socket must return EOF quickly rather than blocking,
# and the server must log the accepted connection.
server_log=$(mktemp)
$BIN test/configs/listen.json >"$server_log" 2>&1 &
server_pid=$!
sleep 0.3
if (exec 3<>/dev/tcp/127.0.0.1/47080) 2>/dev/null &&
   timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/47080; cat <&3' >/dev/null; then
    echo "PASS: tcp connect and server close"
    pass=$((pass + 1))
else
    echo "FAIL: tcp connect and server close"
    fail=$((fail + 1))
fi
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
