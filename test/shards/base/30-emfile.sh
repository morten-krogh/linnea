# accept(2) under a standing EMFILE must back off, not spin.
# (was run_tests.sh lines 5206-5262, the every-shard tail before reporting.)

# --- accept(2) that keeps failing must back off, not spin ---
# A multishot accept the kernel disarms with an error used to be re-armed
# immediately, so a standing EMFILE burned a whole core and wrote a log line
# per failure (millions in seconds). The fd limit is reached before the
# connection pool fills, which is what makes this reachable at all.
emf=$CFG/emfile.json
cat > $emf <<EOF
{
  "log": "$LOG",
  "timeout": 30, "head_timeout": 30, "workers": 1,
  "max_connections": 1024, "max_per_ip": 4096,
  "servers": [ { "host": "127.0.0.1", "port": ${P61671}, "hostname": "localhost",
      "locations": [ { "prefix": "/", "root": "$WWW" } ] } ]
}
EOF
# The startup check now makes an EMFILE from the *configured* pool impossible,
# so squeeze the running worker instead — which is the case that remains real:
# a system-wide ENFILE, or an operator lowering the limit under a live process.
$BIN --config $emf >$RUNDIR/emfile.err 2>&1 &
emf_pid=$!
sleep 0.6
emf_w=$(workers_of $emf_pid | awk '{print $1}')
[ -n "$emf_w" ] && prlimit --pid $emf_w --nofile=48:524288 2>/dev/null
python3 - <<'PY' &
import os, socket, time
_PB = int(os.environ.get("LINNEA_TEST_PORT_BASE", 61000))
socks = []
for _ in range(200):
    try:
        socks.append(socket.create_connection(("127.0.0.1", _PB + 671), timeout=2))
    except OSError:
        pass
time.sleep(6)
for s in socks:
    s.close()
PY
emf_flood=$!
sleep 1.5
if [ -n "$emf_w" ] && [ -r /proc/$emf_w/stat ]; then
    t0=$(awk '{print $14+$15}' /proc/$emf_w/stat)
    sleep 3
    t1=$(awk '{print $14+$15}' /proc/$emf_w/stat)
    ticks=$((t1 - t0))
else
    ticks=-1
fi
wait $emf_flood 2>/dev/null
sleep 1
# a spin is ~300 ticks per 3s (one full core); the backoff leaves it near 0
lines=$(wc -l < $RUNDIR/emfile.err)
[ "$ticks" -ge 0 ] && [ "$ticks" -lt 100 ] && [ "$lines" -lt 1000 ] \
    && [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            http://127.0.0.1:${P61671}/hello.txt)" = 200 ]
check "accept: a standing EMFILE backs off instead of spinning (${ticks} ticks, ${lines} log lines)" $?
kill $emf_pid 2>/dev/null
wait $emf_pid 2>/dev/null
rm -f $emf $RUNDIR/emfile.err "$LOG"
