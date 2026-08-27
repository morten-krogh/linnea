# HTTP/1 proxying: /api backend, proxy failures, proxy_timeout, the split error_log, and rate_limit metering.

# --- proxying: /api -> the test backend, /down -> nothing listening ---
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/simple)
check_http "proxy body"          "backend body" "$resp"
check_http "proxy status"        "200 OK" "$resp"
check_http "proxy content-length" "Content-Length: 12" "$resp"
check_http "proxy keeps alive"   "Connection: keep-alive" "$resp"

# the prefix is not stripped and the query survives: the backend echoes the target
resp=$(curl -s --max-time 3 "http://127.0.0.1:${P61080}/api/target?x=1&y=2")
check_http "proxy target forwarded" "/api/target?x=1&y=2" "$resp"

# the client's Connection header is replaced, everything else passes through
resp=$(curl -s --max-time 3 -H 'X-Test: abc' -H 'Connection: keep-alive' \
    http://127.0.0.1:${P61080}/api/headers)
check_http "proxy forwards headers" "X-Test: abc" "$resp"
check_http "proxy forwards host"    "Host: 127.0.0.1:${P61080}" "$resp"
check_http "proxy closes upstream"  "Connection: close" "$resp"

resp=$(curl -s --max-time 3 -d 'hello body' http://127.0.0.1:${P61080}/api/echo)
check_http "proxy forwards body" "hello body" "$resp"

# ...but a field the client's own Connection names is hop-by-hop and MUST be
# removed before forwarding (RFC 9110 7.6.1). Only Connection and Expect were
# dropped, so a client could mark any field hop-by-hop and have it delivered to
# the backend anyway — the header-smuggling shape that rule exists to close.
if extensive; then
    timeout 60 python3 test/tls/h1_proxy_hop_by_hop.py ${P61080} >/dev/null 2>&1
    check "proxy removes hop-by-hop fields, both directions" $?
else
    skip "proxy removes hop-by-hop fields, both directions -- 20s"
fi

# RFC 9110 7.6.3 MUST: a proxy names itself and the protocol it received on, in
# each message it forwards. Without it a proxied request is indistinguishable
# from a direct one — no loop detection, and no way to tell which hop
# transformed a message.
timeout 60 python3 test/tls/proxy_via.py ${P61080} >/dev/null 2>&1
check "proxy adds Via to the request and the response" $?

# RFC 9112 3.2.2 MUST: with an absolute-form target, a proxy ignores the received
# Host and replaces it with the target's authority. The parser already ROUTED on
# the target -- that half was right -- but the rewrite copied the client's Host
# line verbatim, so a request that selected this vhost as one.test reached the
# backend claiming other.test (audit-report-75). On the proxy_h2 leg that field
# becomes the sole :authority, which RFC 9113 8.3.1 requires to come from the
# request's control data. The origin-form row is the control: there the
# effective authority IS the Host value, so nothing changes.
timeout 60 python3 test/tls/h1_absolute_form.py ${P61080} >/dev/null 2>&1
check "proxy replaces Host from an absolute-form target" $?

# RFC 9110 5.6.7 MUST: all three HTTP-date formats parse. Only IMF-fixdate did,
# so a conditional request carrying an obsolete form was answered
# unconditionally — the client got the whole body instead of its 304.
timeout 60 python3 test/tls/http_date_formats.py ${P61080} >/dev/null 2>&1
check "all three HTTP-date formats are accepted" $?

# RFC 9110 13.1.1 / 13.1.4: If-Match and If-Unmodified-Since were never read, so
# a request carrying one was answered as though it had no condition at all —
# the lost update those fields exist to prevent. 13.2.2 also fixes the order:
# a failing If-Match is a 412 even when an If-None-Match would have said 304.
timeout 60 python3 test/tls/preconditions.py ${P61080} >/dev/null 2>&1
check "If-Match and If-Unmodified-Since are evaluated" $?

# RFC 9112 9.1: Connection is a token LIST and `close` may sit anywhere in it.
# Only a value that was entirely "close" counted, so `keep-alive, close` was
# answered `Connection: keep-alive` and the socket held to the idle timeout.
if extensive; then
    timeout 60 python3 test/tls/connection_close_token.py ${P61080} >/dev/null 2>&1
    check "Connection: close is honoured anywhere in the list" $?
else
    skip "Connection: close is honoured anywhere in the list -- 8s"
fi

# RFC 9110 6.6.1: Date on everything outside 1xx/5xx. The canned blobs are
# assembled ahead of time, so they shipped without one while every dynamically
# built response had it. RFC 9112 9.6: and a response that closes must say so —
# the OPTIONS * blob closed while claiming, in a comment, that it did not.
timeout 60 python3 test/tls/canned_response_headers.py ${P61080} >/dev/null 2>&1
check "canned responses carry Date and announce a close" $?

# RFC 9110 10.1.1 MUST: answer a 100-continue expectation with 100 or a final
# status. The field was never inspected, so the server waited for a body the
# client was withholding while the client waited for permission to send it —
# a full second added to every such request, for clients that recover at all.
timeout 60 python3 test/tls/expect_continue.py ${P61080} >/dev/null 2>&1
check "Expect: 100-continue is answered" $?

# Chunked request bodies (RFC 9112 7.1 MUST). Any Transfer-Encoding at all used
# to be 501, so every client that sends a body of unknown length up front was
# refused: curl -T -, fetch() with a ReadableStream, most libraries handed a
# stream. The arrival-pattern cases are the ones that matter — a body comes in
# as many reads as the network likes.
if extensive; then
    timeout 120 python3 test/tls/h1_chunked_request.py ${P61080} >/dev/null 2>&1
    check "h1 decodes chunked request bodies" $?
else
    skip "h1 decodes chunked request bodies -- 20s, a sweep of arrival patterns"
fi

# a HEAD response is head-only even though the backend sends Content-Length:
# waiting for that body would hang until the idle timeout
resp=$(curl -si --max-time 3 -I http://127.0.0.1:${P61080}/api/simple)
check_http "proxy HEAD length"   "Content-Length: 12" "$resp"
check_http "proxy HEAD no hang"  "200 OK" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/204)
check_http "proxy 204 no body"   "204 No Content" "$resp"
# The backend sends "Content-Length: 12" on that 204, which RFC 9110 8.6 forbids
# outright, and the proxy relayed it on every protocol. It is not a cosmetic
# field: curl's HTTP/3 leg answered the relayed version with ERR_CLOSING and
# never completed the response (audit-report-9 Finding 2). Dropped, not
# rewritten to 0 -- "no length" and "a length of zero" are different answers.
check_http "proxy 204 drops the forbidden length" "none" \
    "$(printf '%s' "$resp" | grep -i '^content-length:' || echo none)"

# chunked and close-delimited bodies have no length we can pass on, so the
# client connection has to close to delimit them
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/chunked)
check_http "proxy chunked body"  "chunked body" "$resp"
check_http "proxy chunked framing" "Transfer-Encoding: chunked" "$resp"
check_http "proxy chunked closes" "Connection: close" "$resp"

# ...and that relay judges the framing it forwards. The cross-protocol matrix
# covers the case where head and body arrive together, which is a 502 like h2
# and h3 give; this is the other half, where the head has already gone out and
# all h1 can do is decline to finish the message (audit-report-24).
out=$(timeout 30 python3 test/h1_chunk_relay.py ${P61080} 2>&1 | tail -1)
[ "$out" = "OK" ]
check "a chunked relay that goes wrong late or across a read does not complete ($out)" $?
grep -qF '"GET /api/chunkkeepalive HTTP/1.1" 200' "$LOG"
check "a chunked response that ends at its terminal chunk is logged as served" $?
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/eof)
check_http "proxy eof body"      "eof delimited body" "$resp"
check_http "proxy eof closes"    "Connection: close" "$resp"

# a body bigger than the relay buffer takes several upstream reads
n=$(curl -s --max-time 5 http://127.0.0.1:${P61080}/api/big | wc -c)
[ "$n" -eq 40000 ]
check "proxy large body ($n bytes)" $?

resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/http10)
check_http "proxy 1.0 upstream"  "HTTP/1.1 200 OK" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/301)
check_http "proxy passes status" "301 Moved Permanently" "$resp"
check_http "proxy passes header" "Location: /elsewhere" "$resp"

# proxied and static requests share one keep-alive connection
before=$(grep -c "accepted connection" "$LOG")
resp=$(curl -s --max-time 4 http://127.0.0.1:${P61080}/api/simple http://127.0.0.1:${P61080}/hello.txt)
after=$(grep -c "accepted connection" "$LOG")
check_http "proxy then static body" "hello from linnea" "$resp"
[ $((after - before)) -eq 1 ]
check "proxy keep-alive single accept" $?

# --- proxy failures ---
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/down/x)
check_http "proxy refused 502"   "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/garbage)
check_http "proxy garbage 502"   "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/bighead)
check_http "proxy huge head 502" "502 Bad Gateway" "$resp"
# contradictory upstream framing must never reach the client: forwarding
# both would let a compromised backend split the next keep-alive response
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/tecl)
check_http "proxy TE+CL 502"     "502 Bad Gateway" "$resp"

# The upstream deadline is its own key. One `timeout` governed both halves, so
# a deployment could not hold a client connection open longer than it was
# willing to wait for a backend -- or the reverse, which is the common one.
# This fixture is the case that could not be expressed: timeout 2, backend
# deadline 10, against /api/slow, which sleeps 4s. Before proxy_timeout the
# client idle timeout cut it at 2s and the answer was a 504.
start_server $CFG/proxy-timeout.json
ptmo_pid=$SRV_PID
ptmo=$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' \
       http://127.0.0.1:${P61466}/api/slow)
[ "$ptmo" = "200" ]
check "proxy_timeout outlives a shorter client timeout ($ptmo, backend sleeps 4s)" $?
# ...and the ordinary path through the same server still answers, so the check
# above cannot pass on a build that simply stopped timing anything out.
ptmo2=$(curl -s --max-time 10 http://127.0.0.1:${P61466}/api/simple)
[ "$ptmo2" = "backend body" ]
check "proxy_timeout fixture serves an ordinary proxied request ($ptmo2)" $?
kill $ptmo_pid 2>/dev/null
wait $ptmo_pid 2>/dev/null

# error_log splits the diagnostics from the request record. One file held both,
# so the stream you want when something is wrong was interleaved with thousands
# of access lines an hour. The split is nginx's: access_log is the requests,
# error_log is everything else.
rm -f $RUNDIR/linnea-split-acc.log $RUNDIR/linnea-split-err.log
start_server $CFG/error-log.json
elog_pid=$SRV_PID
# BOTH protocols this fixture speaks. h1 and h2 write their access records
# through different code, and marking only one of them is exactly how this
# shipped broken the first time: the manual check used h2, so h1's own writer
# went unnoticed until the suite ran.
curl -s -o /dev/null --max-time 5 --http1.1 https://localhost:${P61467}/hello.txt --cacert $CA --resolve localhost:${P61467}:127.0.0.1
curl -s -o /dev/null --max-time 5 --http2  https://localhost:${P61467}/nope     --cacert $CA --resolve localhost:${P61467}:127.0.0.1
sleep 0.3
# the access log holds the request records and NOTHING else
# `grep -c` PRINTS 0 and EXITS 1 when nothing matches, so "|| echo 0" appends a
# second zero and the variable becomes "0\n0" -- which fails every comparison
# and truncates the label. "|| true" keeps grep's own count.
#
# And the property, not the count: start_server makes its own readiness request,
# so how many records land here is the harness's business. What must hold is
# that the access log contains request records and NOTHING else, from both
# protocols.
acc_req=$(grep -c "request localhost" $RUNDIR/linnea-split-acc.log 2>/dev/null || true)
acc_other=$(grep -vc "request localhost" $RUNDIR/linnea-split-acc.log 2>/dev/null || true)
acc_protos=$(grep -oE "HTTP/[0-9.]+" $RUNDIR/linnea-split-acc.log 2>/dev/null | sort -u | tr '\n' ' ')
[ "${acc_req:-0}" -ge 2 ] && [ "${acc_other:-1}" = "0" ] && [ "$acc_protos" = "HTTP/1.1 HTTP/2 " ]
check "error_log: the access log holds only request records, from both protocols ($acc_req req, $acc_other other: $acc_protos)" $?
# ...and the diagnostics went to the other file, with no request lines in it
err_life=$(grep -c "accepted connection" $RUNDIR/linnea-split-err.log 2>/dev/null || true)
err_req=$(grep -c "request localhost" $RUNDIR/linnea-split-err.log 2>/dev/null || true)
[ "${err_life:-0}" -ge 2 ] && [ "${err_req:-1}" = "0" ]
check "error_log: the diagnostics went to the other file ($err_life lifecycle, $err_req req)" $?

# A dead worker must say HOW it died. wait4 hands the master the status and the
# master used to log only the pid, so nine worker deaths in one day (2026-08-14)
# could not be told from nine clean exits -- and those want opposite
# investigations. The worker's OWN fatal message went to stderr, which under
# systemd is a journal an unprivileged operator cannot read, on a unit whose
# AmbientCapabilities also forbid a core dump. Both halves are asserted here
# because either alone leaves the cause unreadable.
elog_worker=$(workers_of_now $elog_pid | awk '{print $1}')
kill -9 $elog_worker 2>/dev/null
for i in $(seq 1 40); do
    grep -q "exited on signal" $RUNDIR/linnea-split-err.log 2>/dev/null && break
    sleep 0.1
done
grep -q "worker $elog_worker exited on signal 9, respawning" $RUNDIR/linnea-split-err.log
check "a worker killed by a signal is logged with that signal" $?
# ...on the error stream, where diagnostics live -- not among the request records
! grep -q "exited on signal" $RUNDIR/linnea-split-acc.log 2>/dev/null
check "a worker death is a diagnostic, not an access record" $?
# A memory fault must report WHERE, not merely that it happened. The master's
# line gives the signal; this gives the instruction. Without it a segfault on
# this unit is unattributable -- AmbientCapabilities clears the dumpable flag,
# so production cannot leave a core however LimitCORE is set, and seven
# segfaults on 2026-08-14 produced none.
#
# Asserted because the install can fail SILENTLY: the first attempt at wiring
# it never inserted the call at all (the target line ended in a continuation
# backslash), the handler never ran, and the only symptom was a missing line
# that nothing was looking for.
elog_worker3=$(workers_of_now $elog_pid | awk '{print $1}')
kill -11 $elog_worker3 2>/dev/null
for i in $(seq 1 40); do
    grep -q "fatal: SIGSEGV" $RUNDIR/linnea-split-err.log 2>/dev/null && break
    sleep 0.1
done
crash_line=$(grep "fatal: SIGSEGV" $RUNDIR/linnea-split-err.log 2>/dev/null | tail -1)
case "$crash_line" in
    *"fatal: SIGSEGV addr=0x"*"rip=0x"*"rsp=0x"*) true ;;
    *) false ;;
esac
check "a memory fault reports addr, rip and rsp before dying (${crash_line:-nothing logged})" $?
# and the rip must be a real code address -- a zero or a truncated field would
# satisfy the shape above while naming nothing
crash_rip=$(printf '%s' "$crash_line" | grep -oE "rip=0x[0-9a-f]{16}" | cut -d= -f2)
[ -n "$crash_rip" ] && [ "$crash_rip" != "0x0000000000000000" ]
check "the reported rip is a real address ($crash_rip)" $?
# the handler must not CHANGE the outcome: the worker still dies of signal 11
for i in $(seq 1 40); do
    grep -q "exited on signal 11" $RUNDIR/linnea-split-err.log 2>/dev/null && break
    sleep 0.1
done
grep -q "worker $elog_worker3 exited on signal 11, respawning" $RUNDIR/linnea-split-err.log
check "a reported fault still kills the worker with its own signal" $?

sleep 1.3
# The control: a worker that exits of its own accord must read DIFFERENTLY, or
# the line cannot answer the only question it exists to answer.
#
# Wait out the master's spawn-storm guard first. A worker that exits WITHOUT a
# signal within one second of being spawned is treated as a startup error that
# would repeat for ever, so the master gives up (.storm) instead of logging and
# respawning -- and the worker respawned a moment ago by the kill -9 above is
# well inside that window. Sending the SIGTERM immediately makes the master
# exit and produces no status line at all, which is the server behaving
# correctly and the test asking the wrong question.
sleep 1.3
elog_worker2=$(workers_of_now $elog_pid | awk '{print $1}')
kill -TERM $elog_worker2 2>/dev/null
for i in $(seq 1 40); do
    grep -q "exited with status" $RUNDIR/linnea-split-err.log 2>/dev/null && break
    sleep 0.1
done
grep -q "worker $elog_worker2 exited with status 0, respawning" $RUNDIR/linnea-split-err.log
check "a worker that exits on its own is logged with its status, not a signal" $?

kill $elog_pid 2>/dev/null
wait $elog_pid 2>/dev/null

# rate_limit meters REQUESTS, which is what max_per_ip cannot: h2 and h3 allow
# 100 streams per connection, so a connection cap barely bounds the request
# rate. Every protocol must be metered -- a limit two of the three walk past is
# a control with a hole, and it is the same address either way, so all three
# share ONE bucket. Exact counts are timing (the bucket refills while the loop
# runs), so this asserts the property: some allowed, some refused, on each.
rm -f $RUNDIR/linnea-rl.log
start_server $CFG/rate-limit.json
rl_pid=$SRV_PID
rl_burst "h1" curl -sS -o /dev/null -w '%{http_code}' --max-time 5 --http1.1 \
    --cacert $CA --resolve localhost:${P61468}:127.0.0.1 https://localhost:${P61468}/hello.txt
rl_burst "h2" curl -sS -o /dev/null -w '%{http_code}' --max-time 5 --http2 \
    --cacert $CA --resolve localhost:${P61468}:127.0.0.1 https://localhost:${P61468}/hello.txt
if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
    rl_burst "h3" "$CURLH3" --http3-only -s -o /dev/null -w '%{http_code}' --max-time 15 \
        --cacert $CA --resolve localhost:${P61468}:127.0.0.1 https://localhost:${P61468}/hello.txt
else
    check "rate_limit meters h3 (skipped: no HTTP/3 curl)" 0
fi
# What the SERVER recorded, not what the client saw. The client's view cannot
# tell 429 from 431, and it was 431 in the log on the first cut: the wire
# response was parameterised and the access line left hardcoded. h3 was worse —
# it wrote the access line from the SHARED log block, so a refusal carried the
# previous request's method and target.
rl_logged=$(grep -cE '"- - HTTP/[0-9.]+" 429 ' $RUNDIR/linnea-rl.log 2>/dev/null || true)
rl_wrong=$(grep -cE ' (431|200) $' /dev/null 2>/dev/null || true)
rl_mislabelled=$(grep -c ' 431 ' $RUNDIR/linnea-rl.log 2>/dev/null || true)
[ "${rl_logged:-0}" -ge 2 ] && [ "${rl_mislabelled:-1}" = "0" ]
check "rate_limit logs a refusal as 429, with no method or target ($rl_logged recorded, $rl_mislabelled mislabelled 431)" $?

# ...and it recovers: a client that waits is served again rather than stuck
sleep 1.3
rl_again=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 --cacert $CA \
    --resolve localhost:${P61468}:127.0.0.1 https://localhost:${P61468}/hello.txt)
[ "$rl_again" = "200" ]
check "rate_limit refills: a client that waits is served again ($rl_again)" $?
kill $rl_pid 2>/dev/null
wait $rl_pid 2>/dev/null
# The control, and the one that matters for every deployment that has not asked
# for this: with the key unset nothing is metered at all. The fixture above is
# the only one in the suite that sets it, so any other server serving a burst
# would do -- assert it explicitly rather than by implication.
start_server $CFG/error-log.json      # no rate_limit key
rlctl_pid=$SRV_PID
rlctl=0
for i in $(seq 1 25); do
    c=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 --cacert $CA \
        --resolve localhost:${P61467}:127.0.0.1 https://localhost:${P61467}/hello.txt)
    [ "$c" = "200" ] && rlctl=$((rlctl+1))
done
[ "$rlctl" = "25" ]
check "rate_limit unset meters nothing ($rlctl/25 served)" $?
kill $rlctl_pid 2>/dev/null
wait $rlctl_pid 2>/dev/null
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/cljunk)
check_http "proxy bad CL 502"    "502 Bad Gateway" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/clpad)
check_http "proxy CL whitespace" "valid" "$resp"
# Expect must not be forwarded: the body is already buffered, and an
# interim 100 Continue would be parsed as the response itself
resp=$(raw_http 'POST /api/expect HTTP/1.1\r\nHost: one.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nHELLO')
check_http "proxy drops Expect"  "real" "$resp"
printf '%s' "$resp" | grep -qF "100 Continue"
[ $? -ne 0 ]
check "proxy no interim 100 leak" $?
# the backend sleeps 4s; the config's timeout is 2s
start=$SECONDS
resp=$(curl -si --max-time 8 http://127.0.0.1:${P61080}/api/slow)
elapsed=$((SECONDS - start))
check_http "proxy slow 504"      "504 Gateway Timeout" "$resp"
[ "$elapsed" -le 4 ]
check "proxy 504 on time (${elapsed}s)" $?
# a body cut short of its Content-Length must not look like a clean end
curl -s --max-time 3 http://127.0.0.1:${P61080}/api/truncated >/dev/null 2>&1
grep -qF ': upstream closed early' "$LOG"
check "proxy truncated body" $?

# --- a Unix-domain backend (docs/design/unix-backend-plan.md) -----------
# The whole point is that reachability is a FILE PERMISSION rather than "any
# process on this host", so the socket lives in the run's own directory: two
# concurrent shard jobs must not share one, which is why genports.py moves it
# the way it moves every other run-local path.
usock="$PWD/$RUNDIR/be.sock"
LINNEA_BACKEND_UNIX="$usock" python3 test/proxy_backend.py >/dev/null 2>&1 &
ub_pid=$!
for _ in $(seq 1 50); do [ -S "$usock" ] && break; sleep 0.1; done
check "unix backend: the fixture created its socket" $([ -S "$usock" ] && echo 0 || echo 1)
# sun_path is 108 including its NUL. Assert the path we actually generated
# fits, or a failure below would be about the run directory, not the feature.
check "unix backend: the generated path fits sun_path (${#usock} <= 107)" \
      $([ ${#usock} -le 107 ] && echo 0 || echo 1)

start_server $CFG/unix-backend.json
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61081}/api/simple)
check_http "unix backend: proxied GET"            "backend body" "$resp"
check_http "unix backend: ...with the real status" "200 OK" "$resp"
resp=$(curl -s --max-time 3 "http://127.0.0.1:${P61081}/api/target?x=1&y=2")
check_http "unix backend: target and query forwarded" "/api/target?x=1&y=2" "$resp"
resp=$(curl -s --max-time 3 -d 'hello over a socket' http://127.0.0.1:${P61081}/api/echo)
check_http "unix backend: request body forwarded" "hello over a socket" "$resp"
# the control: a static location on the same server is untouched by any of it
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:${P61081}/hello.txt)
check_http "unix backend: static location still served" "200" "$code"

# A socket path with nothing at it is a 502, and the log must say WHICH of the
# three connect failures it was -- naming it is the reason the errno is carried
# at all. Asserting only the 502 would pass on a build that says nothing.
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:${P61081}/gone)
check_http "unix backend: an absent socket is 502" "502" "$code"
ulog="$RUNDIR/unix-backend.log"
grep -q "connect failed (no such socket path)" "$ulog"
check "unix backend: ...logged as 'no such socket path', not a bare failure" $?

kill $ub_pid 2>/dev/null

# ...and the REAL backend, not only the fixture: linnea-api itself can listen on
# a socket, which is what makes any of this usable in production rather than
# only in this suite. It also owns the socket FILE -- it unlinks a stale one
# before binding -- so a restart onto its own leftover must work, which is the
# case a service restart actually hits.
apisock="$PWD/$RUNDIR/api-unix.sock"
: > "$RUNDIR/api-unix.out"
./bin/linnea-api "unix:$apisock" "$PWD/$RUNDIR" > "$RUNDIR/api-unix.out" 2>&1 &
au_pid=$!
for _ in $(seq 1 50); do [ -S "$apisock" ] && break; sleep 0.1; done
check "linnea-api: listens on a unix socket" $([ -S "$apisock" ] && echo 0 || echo 1)
# the startup line named "127.0.0.1:0" in unix mode until it was taught not to:
# a log naming an address nothing is bound to is worse than no line at all.
grep -q "listening on unix:$apisock" "$RUNDIR/api-unix.out"
check "linnea-api: ...and says where, not '127.0.0.1:0'" $?
kill $au_pid 2>/dev/null; wait $au_pid 2>/dev/null
# the socket file outlives the process; the restart must bind over it
: > "$RUNDIR/api-unix.out"
./bin/linnea-api "unix:$apisock" "$PWD/$RUNDIR" > "$RUNDIR/api-unix.out" 2>&1 &
au_pid=$!
for _ in $(seq 1 50); do grep -q "listening on unix:" "$RUNDIR/api-unix.out" && break; sleep 0.1; done
grep -q "listening on unix:$apisock" "$RUNDIR/api-unix.out"
check "linnea-api: restarts over its own stale socket file" $?
kill $au_pid 2>/dev/null
