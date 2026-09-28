# Proxy capacity: how many proxied streams one HTTP/2 connection relays at
# once, what a worker reserves per connection slot, and that an exhausted slot
# pool fails the one request rather than the connection or the worker.
#
# Vefruna holds one server-sent-events stream per browser tab, and a browser
# shares one h2 connection per origin across its tabs. Until the slot pool, an
# h2 connection relayed at most 8 proxied streams (LINNEA_H2P_SLOTS) though it
# advertised SETTINGS_MAX_CONCURRENT_STREAMS 100, and every connection slot
# reserved ~11.4 MiB of address space up front, so a worker could not start at
# max_connections 3000 on a 16 GB host.

cap_sock="$PWD/$RUNDIR/cap-sse.sock"
cap_events="$PWD/$RUNDIR/cap-sse-events.log"
: > "$cap_events"
python3 test/sse_backend.py "$cap_sock" "$cap_events" >/dev/null 2>&1 &
cap_be=$!
for _ in $(seq 1 50); do [ -S "$cap_sock" ] && break; sleep 0.1; done
cap_port=$((PORTBASE + 496))

# cap_config <file> <max_connections> <max_upstream> [http3]
cap_config() {
    cat > "$1" <<EOF
{ "log": "$PWD/$RUNDIR/capacity.log", "timeout": 30, "proxy_timeout": 20,
  "workers": 1, "max_connections": $2, "max_upstream": $3, "http3": ${4:-0},
  "servers": [ { "host": "127.0.0.1", "port": $cap_port, "hostname": "localhost",
      "cert": "$PWD/test/tls/server.crt", "key": "$PWD/test/tls/server.key",
      "locations": [ { "prefix": "/sse", "proxy": "unix:$cap_sock" },
                     { "prefix": "/", "root": "$PWD/$WWW" } ] } ] }
EOF
}

# cap_start <config> -- start it, wait for a worker; sets cap_pid, cap_w
cap_start() {
    $BIN --config "$1" >"$RUNDIR/capacity.err" 2>&1 &
    cap_pid=$!
    cap_w=""
    for _ in $(seq 1 50); do
        cap_w=$(workers_of $cap_pid | awk '{print $1}')
        [ -n "$cap_w" ] && curl -sk -o /dev/null --max-time 2 \
            "https://127.0.0.1:$cap_port/hello.txt" && break
        sleep 0.1
    done
}

cap_stop() {
    kill $cap_pid 2>/dev/null
    wait $cap_pid 2>/dev/null
}

# --- one connection carries as many proxied streams as it advertises -------
# 100 event streams on ONE connection, each held open until it has delivered
# an event, so they were concurrent rather than served in turn; then the 101st,
# past SETTINGS_MAX_CONCURRENT_STREAMS, is refused and the 100 are unharmed.
cap=$CFG/capacity-streams.json
cap_config "$cap" 1024 256 1
cap_start "$cap"
out=$(timeout 60 python3 test/h2_many_streams.py $cap_port 100 100 0 2>&1)
check "capacity: 100 concurrent proxied event streams on one h2 connection (was 8) -- ${out%% (*}" $?
out=$(timeout 60 python3 test/h2_many_streams.py $cap_port 101 100 1 2>&1)
check "capacity: stream 101 is refused, the other 100 are served -- ${out%% (*}" $?
# ...and the HTTP/3 twin, which allowed 100 all along: held to the same number
# by the same check. Each of its relays borrows a connection-pool slot.
out=$(timeout 60 python3 test/h3_many_streams.py $cap_port 100 2>&1)
rc=$?
if [ $rc -eq 2 ]; then
    skip "capacity: 100 concurrent proxied event streams on one h3 connection ($out)"
else
    check "capacity: 100 concurrent proxied event streams on one h3 connection -- $out" $rc
fi
cap_stop

# --- an exhausted pool fails the one stream, and recovers ----------------------
# max_upstream 2 and max_connections 4 give a pool of 6 relay slots. Ten event
# streams on one connection: 2 are served, the rest are answered 503 (the
# upstream ceiling) or refused REFUSED_STREAM (the slot pool) -- and nothing
# else: no GOAWAY, no dead worker, and the connection serves a request after.
# Twice over, so slots that were not handed back would show on the second run.
cap=$CFG/capacity-pool.json
cap_config "$cap" 4 2
cap_start "$cap"
cap_w0=$cap_w
out1=$(timeout 60 python3 test/h2_many_streams.py $cap_port 10 2 any 2>&1)
rc1=$?
out2=$(timeout 60 python3 test/h2_many_streams.py $cap_port 10 2 any 2>&1)
rc2=$?
[ $rc1 -eq 0 ] && [ $rc2 -eq 0 ] && [ "$(workers_of $cap_pid | awk '{print $1}')" = "$cap_w0" ] \
    && echo "$out1" | grep -q '^ok: 2 of 10' && echo "$out2" | grep -q '^ok: 2 of 10' \
    && echo "$out2" | grep -Eq '\(([1-9][0-9]*) REFUSED_STREAM'
check "capacity: a full slot pool refuses the stream, not the connection, and recovers -- ${out2%% (MAX*}" $?
cap_stop

# --- a large max_connections costs address space, not memory ------------------
# A worker must start and serve at max_connections 16384 (the pre-pool layout
# asked for 16384 x 11.4 MiB and could not), and idle, having served a proxied
# request over h1 and over h2, it must still be small: the connection pool is
# touched only as far as it has been used, and the relay slots and backend-leg
# arenas are borrowed per request.
hard=$(ulimit -Hn)
if [ "$hard" = unlimited ] || [ "$hard" -ge 17000 ]; then
    cap=$CFG/capacity-big.json
    cap_config "$cap" 16384 256
    cap_start "$cap"
    h1=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --http1.1 \
        "https://127.0.0.1:$cap_port/sse/events?n=1&gap=0")
    h2=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --http2 \
        "https://127.0.0.1:$cap_port/sse/events?n=1&gap=0")
    rss=$(awk '/^VmRSS/{print $2}' /proc/$cap_w/status 2>/dev/null)
    vsz=$(awk '/^VmSize/{print $2}' /proc/$cap_w/status 2>/dev/null)
    [ "$h1" = 200 ] && [ "$h2" = 200 ] && [ -n "$rss" ] && [ "$rss" -lt 32768 ]
    check "capacity: a worker serves at max_connections 16384 (h1 $h1, h2 $h2; idle RSS ${rss:-?} KiB, virtual ${vsz:-?} KiB)" $?
    cap_stop
else
    skip "capacity: max_connections 16384 (hard RLIMIT_NOFILE $hard is below 17000)"
fi

kill $cap_be 2>/dev/null
wait $cap_be 2>/dev/null
rm -f "$CFG"/capacity-*.json "$RUNDIR/capacity.err"
