# The assembly websocket backend (direct + tunnelled), the send timeout, and connection-termination log lines.

# --- the assembly websocket backend, direct and through the tunnel ---
# The same battery both ways: RFC 6455 handshake, framing, unmasking, the
# broadcast, and the protocol errors. Passing directly but failing proxied
# would put the fault in linnea's tunnel rather than in the backend.
# The /api backend, which had no coverage at all until a read of it turned up
# five faults — including one that stopped the whole server indefinitely. It is
# spoken to directly: linnea's side of /api is exercised by the proxy tests.
./bin/linnea-api ${P61703} >/dev/null 2>&1 &
api_pid=$!
for _ in $(seq 1 60); do
    (echo > /dev/tcp/127.0.0.1/${P61703}) >/dev/null 2>&1 && break
    sleep 0.1
done
if extensive; then
    api_out=$(python3 test/api/api_backend_test.py ${P61703} 2>&1)
    [ $? -eq 0 ]
    check "the /api backend" $?
    # Inside the guard, because it READS what the guard assigns. Left outside it
    # this line met `set -u` on a fast run, and the shell it died in was the one
    # holding the rest of the block: five later checks failed against a server
    # that was no longer there. A skipped check is a variable that was never
    # set, which is the same hazard as a skipped fixture wearing different
    # clothes.
    printf '%s\n' "$api_out" | grep -q "^FAIL" && printf '%s\n' "$api_out" | sed -n 's/^FAIL /  api: /p'
else
    skip "the /api backend -- 10s"
fi
kill $api_pid 2>/dev/null

ws_direct_out=$(python3 test/api/ws_backend_test.py ${P61701} 2>&1)
[ $? -eq 0 ]
check "websocket backend, spoken to directly" $?
ws_proxy_out=$(python3 test/api/ws_backend_test.py ${P61080} /ws 2>&1)
[ $? -eq 0 ]
check "websocket backend, through linnea's tunnel" $?
for out in "$ws_direct_out" "$ws_proxy_out"; do
    printf '%s\n' "$out" | grep -q "^FAIL" && printf '%s\n' "$out" | sed -n 's/^FAIL /  ws: /p'
done
# an upgrade wish on a static location changes nothing
resp=$(curl -si --max-time 3 -H 'Connection: upgrade' -H 'Upgrade: websocket' \
    http://127.0.0.1:${P61080}/hello.txt)
check_http "upgrade on static location" "hello from linnea" "$resp"
grep -qF '"GET /api/ws-echo HTTP/1.1" 101 0' "$LOG"
check "ws request log 101" $?
grep -qF ': upstream closed' "$LOG"
check "ws termination upstream closed" $?

# --- send timeout: a client that stops reading must not pin its slot ---
# huge.bin is sparse and far larger than any kernel socket buffering, so
# once the client's window fills the send stalls and its linked timeout
# (2s in this config) fires.
truncate -s 64M $WWW/huge.bin
(exec 3<>/dev/tcp/127.0.0.1/${P61080}
 printf 'GET /huge.bin HTTP/1.1\r\nHost: one.test\r\n\r\n' >&3
 sleep 6) &
stall_pid=$!
sleep 4
grep -qF ': send timeout' "$LOG"
check "termination send timeout" $?
kill $stall_pid 2>/dev/null
wait $stall_pid 2>/dev/null
# a slow but reading client must survive a transfer spanning several
# timeout windows: partial sends re-arm with a fresh timeout each time
n=$(curl -s --max-time 12 --limit-rate 16M http://127.0.0.1:${P61080}/huge.bin | wc -c)
[ "$n" -eq 67108864 ]
check "slow reader outlives send timeout ($n bytes)" $?
# ...and a client that RESETS mid-response is not an error at all. ECONNRESET
# and EPIPE on the sending side are what a closed tab looks like from this end;
# the receive side learned that in 911e0b9 while the send side filed all of it
# as "send error", 49 times in the production log with no errno to say which
# write failed. huge.bin is still here and is larger than any socket buffer, so
# a client that reads one byte and then closes with SO_LINGER 0 leaves a send in
# flight for the RST to break. Verified against 8d67ffd~1, which calls the same
# scenario "send error".
out8=$(timeout 60 python3 test/send_reset_test.py ${P61080} "$LOG" "peer reset" plain 2>&1)
case "$out8" in ok*) true ;; *) false ;; esac
check "a reset mid-response is peer reset, not a send error ($out8)" $?

# --- connection termination log lines ---
grep -qF ': close after response' "$LOG"
check "termination close-after-response" $?
grep -qF ': peer closed' "$LOG"
check "termination peer closed" $?
# A client that hangs up abruptly (RST) is ECONNRESET, which is what a browser
# closing a tab looks like — routine, and told apart from a real read failure
# rather than logged as "recv error" with the errno thrown away.
python3 - <<'RST'
import os, socket, struct, time
_PB = int(os.environ.get("LINNEA_TEST_PORT_BASE", 61000))
s = socket.create_connection(("127.0.0.1", _PB + 80), timeout=5)
s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n")   # unfinished
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
s.close()
time.sleep(0.6)
RST
grep -qF ': peer reset' "$LOG"
check "termination peer reset (RST is not an error)" $?
! grep -qF 'recv failed, errno 104' "$LOG"
check "a reset does not log an errno line" $?
grep -qF ': idle timeout' "$LOG"
check "termination idle timeout" $?

