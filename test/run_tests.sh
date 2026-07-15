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

run_test "good config"     0 stdout "server 1: host=127.0.0.1 port=9000 hostname=internal.example.com" \
    $BIN config/linnea.json
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

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
