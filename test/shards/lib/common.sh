# Shared setup, fixtures and helpers. Sourced ONCE by test/shards/run.sh before
# any shard's files, so it defines and sets up in the runner's own shell. This
# was the preamble of the monolithic run_tests.sh; the shard-gating math and the
# union check it needed are gone -- coverage is now "every file in every shard
# directory runs", which is self-evident and needs no reference to verify.
set -u
# Repo root from THIS file's own location (test/shards/lib/), not $0: the runner
# that sources us lives elsewhere and $0 would point at it, not at the tree.
cd "$(dirname "${BASH_SOURCE[0]}")/../../.." || { echo "common.sh: cannot find repo root" >&2; exit 1; }

BIN=./bin/linnea

# --- ports -------------------------------------------------------------------
# Every port this suite binds is derived from ONE base, so two runs can go at
# once by giving them different bases. Fixed numbers could not do that however
# carefully they were chosen: above the ephemeral range they are safe from an
# unrelated process stealing one as its SOURCE port, but a second copy of this
# suite asks for exactly the same numbers and collides on every one of them.
#
# The default base is 61000, so an ordinary run gets precisely the numbers the
# config templates already carry and nothing observable changes. The generated
# configs go to test/configs/run/ (gitignored); the templates stay put.
#
# LINNEA_TEST_PORT_BASE is exported because the Python helpers derive their own
# ports from the same rule -- one source of truth for "which run is this".
PORTBASE=${LINNEA_TEST_PORT_BASE:-61000}
export LINNEA_TEST_PORT_BASE=$PORTBASE
# Everything this run WRITES lives here, so two runs at different bases share
# no file either -- ports were only half the problem. The logs they grep, the
# uploads they echo back, and the document root they generate into and delete
# from were all shared, and two runs would have crossed every one of them.
RUNDIR=test/run-$PORTBASE
export LINNEA_TEST_RUNDIR=$RUNDIR
rm -rf "$RUNDIR"
mkdir -p "$RUNDIR"
CFG=$RUNDIR/configs
# The HTTP/3 curl (ngtcp2 + nghttp3), used by several blocks below and defined
# once here so a block that runs before the independent-client section does not
# silently take its "skipped" branch against an unset name. See that section
# for how to build one and why it is worth having.
CURLH3=${LINNEA_CURL_H3:-$HOME/curl-h3/bin/curl}
# The suite's CA, likewise defined once up here. It was set partway down, in
# the TLS section, so a block added above that point named a variable that did
# not exist yet -- `set -u` stops the run there, which is the good outcome;
# without it the curl would simply have gone unverified.
CA=test/tls/server.crt
# test/www is a template now, like test/configs: a run copies it and is free to
# generate into and delete from its own. 8 MB, so the copy costs nothing.
WWW=$RUNDIR/www
cp -a test/www "$WWW"
python3 test/configs/genports.py "$PORTBASE" "$CFG" "$RUNDIR" >/dev/null || {
    echo "FATAL: could not generate the configs for port base $PORTBASE" >&2
    exit 1
}
P61000=$((PORTBASE + 0))
P61080=$((PORTBASE + 80))
P61090=$((PORTBASE + 90))
P61100=$((PORTBASE + 100))
P61466=$((PORTBASE + 466))
P61467=$((PORTBASE + 467))
P61468=$((PORTBASE + 468))
P61469=$((PORTBASE + 469))
P61470=$((PORTBASE + 470))
P61481=$((PORTBASE + 481))
P61482=$((PORTBASE + 482))
P61483=$((PORTBASE + 483))
P61484=$((PORTBASE + 484))
P61485=$((PORTBASE + 485))
P61486=$((PORTBASE + 486))
P61487=$((PORTBASE + 487))
P61488=$((PORTBASE + 488))
P61489=$((PORTBASE + 489))
P61490=$((PORTBASE + 490))
P61491=$((PORTBASE + 491))
P61493=$((PORTBASE + 493))
P61494=$((PORTBASE + 494))
P61443=$((PORTBASE + 443))
P61444=$((PORTBASE + 444))
P61446=$((PORTBASE + 446))
P61452=$((PORTBASE + 452))
P61453=$((PORTBASE + 453))
P61454=$((PORTBASE + 454))
P61455=$((PORTBASE + 455))
P61456=$((PORTBASE + 456))
P61457=$((PORTBASE + 457))
P61459=$((PORTBASE + 459))
P61461=$((PORTBASE + 461))
P61462=$((PORTBASE + 462))
P61463=$((PORTBASE + 463))
P61464=$((PORTBASE + 464))
P61465=$((PORTBASE + 465))
P61470=$((PORTBASE + 470))
P61481=$((PORTBASE + 481))
P61482=$((PORTBASE + 482))
P61483=$((PORTBASE + 483))
P61484=$((PORTBASE + 484))
P61485=$((PORTBASE + 485))
P61486=$((PORTBASE + 486))
P61487=$((PORTBASE + 487))
P61488=$((PORTBASE + 488))
P61489=$((PORTBASE + 489))
P61490=$((PORTBASE + 490))
P61491=$((PORTBASE + 491))
P61493=$((PORTBASE + 493))
P61494=$((PORTBASE + 494))
P61492=$((PORTBASE + 492))
P61495=$((PORTBASE + 495))
P61498=$((PORTBASE + 498))
P61500=$((PORTBASE + 500))
P61501=$((PORTBASE + 501))
P61671=$((PORTBASE + 671))
P61701=$((PORTBASE + 701))
P61702=$((PORTBASE + 702))
P61703=$((PORTBASE + 703))
P61704=$((PORTBASE + 704))   # the fast suite's short-interval websocket backend
P61710=$((PORTBASE + 710))   # backend-TLS client handshake test (openssl s_server)
P61711=$((PORTBASE + 711))   # backend-TLS client handshake test, HRR server
# -----------------------------------------------------------------------------
LOG=$RUNDIR/linnea.log
# What actually reached a proxy backend, appended to by test/proxy_backend.py.
# A RUNDIR-derived path shared by every shard that starts a backend (h1 and
# tls both do), so it lives here rather than in one shard's setup -- the tls
# shard reads it without running the h1 shard's startup. Each shard truncates
# it before use.
SEEN=$RUNDIR/linnea_backend_seen.log
pass=0
fail=0
rm -f "$LOG"

# --- fast and extensive runs -------------------------------------------------
# Measured 2026-08-16, timestamping every result line of a full run: 675 checks
# and 834 seconds, of which THIRTEEN checks are 452 s. The other 433 checks
# under a tenth of a second each come to 5.4 s TOTAL. The suite is not slow
# because it is broad; it is slow because a handful of checks wait out a real
# deadline (a 30 s ping and its 15 s grace), soak a path for a fixed span, or
# sweep every size in a range.
#
# So the split is by COST, not by area: LINNEA_SUITE=fast (the default) skips
# the two dozen most expensive checks and keeps the rest, which is ~96% of the
# checks in under a third of the time. LINNEA_SUITE=full runs everything.
#
# WHAT IS GUARDED IS THE CHECK, NEVER THE FIXTURE. Every server still starts,
# is used and is stopped in exactly the order it always was, because the time
# is in the tests and not in the setup -- and because this script is linear and
# stateful, so a skipped start_server would leave a later block reading a
# $SRV_PORT belonging to a server that was never started. That failure does not
# announce itself: the block would quietly test the previous fixture and pass.
SUITE=${LINNEA_SUITE:-fast}
case "$SUITE" in
    fast|full) ;;
    *) echo "FATAL: LINNEA_SUITE must be 'fast' or 'full', not '$SUITE'" >&2; exit 1 ;;
esac
skipped=0
# Used as: if extensive; then <the slow thing>; check "..." $?; else skip "..."; fi
extensive() { [ "$SUITE" = full ]; }

skip() {
    echo "SKIP: $1"
    skipped=$((skipped + 1))
}

# run_test <name> <expected-exit> <stdout|stderr> <grep-pattern> <cmd...>
run_test() {
    local name=$1 want_rc=$2 stream=$3 pattern=$4
    shift 4
    local tmp stdout stderr rc text
    tmp=$(mktemp)
    # Bounded, because every caller here expects the command to EXIT. A config
    # fixture that the parser starts accepting does not fail this check, it
    # starts serving and never returns -- the whole run then hangs on it with
    # no output at all, which is how a deliberate change to the port rule cost
    # 26 minutes and looked like a slow suite. A timeout turns that into one
    # loud failure, and 30s is far longer than any of these take.
    stdout=$(timeout 30 "$@" 2>"$tmp")
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

# workers_of <master-pid>: the sorted worker PIDs of a running server. A crash
# is invisible through a fresh request because the master respawns the worker,
# so an attack test compares this before and after: any change is a crash.
workers_of() { pgrep -P "$1" 2>/dev/null | sort | tr '\n' ' '; }

# Every long-running server this run starts, so none is left behind. A server
# that outlives its run holds its port, the NEXT run's server then cannot bind
# and exits at once, and that run's tests quietly exercise the stale server
# instead -- passing, while any check that inspects the process measures a pid
# that is already gone. The condition sustains itself once it starts, so the
# cure is not leaving them in the first place.
SERVERS=""
cleanup_servers() {
    local p
    for p in $SERVERS; do kill $p 2>/dev/null; done
}
trap cleanup_servers EXIT

# start_server <config> — start a long-running test server and PROVE it is ours.
# Sets SRV_PID, which callers assign to their own variable.
#
# A server that cannot bind exits immediately, and everything downstream then
# runs against whoever already holds the port. The requests succeed, so the block
# looks healthy, while workers_of returns empty, worker-count comparisons compare
# nothing, and a signal to "the master" goes to a dead pid. A silent wrong answer
# is worse than a failure, so this stops the run and says why.
start_server() {
    local cfg=$1 err i j pf rp
    err=$(mktemp)
    # env -C runs it with the RUN's directory as its working directory, which
    # is what gives each run its own "linnea-qdbg". That trigger is a filename
    # the server resolves against its CWD, so two runs sharing one working
    # directory shared the QUIC trace switch: one run's persistent-congestion
    # test turned tracing on in the other run's servers. $! is still the
    # server, which a subshell-and-cd would have cost. Every path in the
    # generated configs is absolute for the same reason.
    env -C "$RUNDIR" "$PWD/${BIN#./}" --config "$PWD/$cfg" >"$err" 2>&1 &
    SRV_PID=$!
    SERVERS="$SERVERS $SRV_PID"
    for i in $(seq 1 60); do
        kill -0 "$SRV_PID" 2>/dev/null || break        # it exited: report below
        if [ -n "$(pgrep -P "$SRV_PID" 2>/dev/null)" ]; then
            rm -f "$err"                               # master up, workers forked
            # A fixture that asked the kernel for its port says so in a
            # port_file, written before the fork. Callers take SRV_PORT the
            # way they take SRV_PID.
            SRV_PORT=""
            pf=$(sed -n 's/.*"port_file": *"\([^"]*\)".*/\1/p' "$cfg" | head -1)
            if [ -n "$pf" ]; then
                for j in $(seq 1 60); do
                    if [ -s "$pf" ]; then
                        SRV_PORT=$(awk 'NR==1{print $3}' "$pf")
                        break
                    fi
                    sleep 0.1
                done
                if [ -z "$SRV_PORT" ]; then
                    echo "FATAL: $cfg never reported its port in $pf" >&2
                    exit 1
                fi
            fi
            # ...and a worker has SERVED something, not merely forked.
            #
            # Callers used to follow this with "sleep 0.5" — a guess about how
            # long a worker takes to arm its listeners, right on an idle
            # machine and wrong the moment anything else runs, which is how
            # every check that flaked under two concurrent suites came to be
            # standing behind one.
            #
            # It has to be a COMPLETED REQUEST. A TCP connect proves nothing:
            # the master creates and listens on the socket before it forks, so
            # the kernel finishes the handshake into the listen backlog whether
            # or not any worker has reached accept(). A reply can only come
            # from a worker inside its event loop, which is also the loop that
            # armed the QUIC recv in the same submit -- so this covers h3 too.
            # Any status will do, 404 and 421 included: what is being proved is
            # that someone answered.
            rp=$SRV_PORT
            [ -n "$rp" ] || rp=$(sed -n 's/.*"port": *\([0-9][0-9]*\).*/\1/p' "$cfg" | head -1)
            if [ -n "$rp" ] && [ "$rp" != 0 ]; then
                local scheme=http
                grep -q '"cert"' "$cfg" && scheme=https
                for j in $(seq 1 200); do
                    curl -sk -o /dev/null --max-time 2 "$scheme://127.0.0.1:$rp/" \
                        2>/dev/null && break
                    sleep 0.05
                done
            fi
            return 0
        fi
        sleep 0.1
    done
    echo >&2
    echo "FATAL: the server for $cfg never came up." >&2
    if [ -s "$err" ]; then
        echo "  it said:" >&2
        sed 's/^/    /' "$err" >&2
    fi
    echo "  The usual cause is a server an earlier run left behind still holding" >&2
    echo "  the port. Such a server would go on answering these tests, so the run" >&2
    echo "  stops here rather than report on the wrong process. Find them with:" >&2
    echo "    ps -eo pid,ppid,comm,args | awk '\$3==\"linnea\" && \$0 ~ /test\\/configs/'" >&2
    echo "  and kill the ones whose parent is 1." >&2
    echo >&2
    rm -f "$err"
    exit 1
}

# ...and refuse to start at all if such a server is already running: every port
# this suite uses would be answered by it.
# Any test server already running, whoever started it. This deliberately does NOT
# filter on ppid == 1: a server started from a shell that is still alive has that
# shell as its parent, and looking only for orphans misses exactly the case that
# bites -- a server left behind by hand a moment ago. Workers are excluded by
# taking only processes whose parent is not itself a linnea.
stray_servers() {
    local pids
    # Keyed on THIS run's config directory, which does two jobs. It still
    # catches a server an earlier run at this base left behind — the thing the
    # FATAL below exists for. And it cannot see a run going on beside this one
    # at a different base, which would otherwise be reported as a stray and
    # abort a perfectly good run.
    #
    # It matched /test\/configs/ until the configs moved to test/run-<base>/
    # and that substring stopped existing, so the guard silently matched
    # nothing. A guard that has stopped guarding looks exactly like a clean
    # machine, which is why this is pinned to $CFG rather than to any literal.
    pids=$(ps -eo pid,comm,args --no-headers 2>/dev/null \
        | awk -v cfg="$CFG" '$2 == "linnea" && index($0, cfg) { print $1 }' | tr '\n' ' ')
    local p ppid
    for p in $pids; do
        ppid=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
        case " $pids " in
            *" $ppid "*) ;;              # a worker: its master is in the list
            *) echo "$p" ;;
        esac
    done
}
# Every port this suite binds is above 61000, and deliberately so: this box's
# ephemeral range is 32768-60999 (/proc/sys/net/ipv4/ip_local_port_range), and
# the fixtures used to sit inside it. An outgoing client socket — the suite
# makes thousands — could take a fixture's port as its SOURCE port, and the
# fixture would then fail to bind with EADDRINUSE while nothing was listening
# on it. That surfaced as the FATAL below accusing a leftover server that did
# not exist. Keep new fixtures above 61000 too — and write them through the
# PORTBASE block at the top rather than as literals, or they will be the one
# number two concurrent runs fight over. Above the ephemeral range stops an
# unrelated process taking a port; only the base stops a second copy of THIS
# suite taking it.
# drain_workers <master pid> — start a graceful drain and stop the master.
# The drain lives on SIGQUIT, which is what kill_old_workers sends the
# generation a hot upgrade retires; SIGTERM is an immediate stop that drops
# whatever is open. The master is SIGTERMed afterwards so it cannot respawn
# the workers, and a worker already draining ignores the SIGTERM its
# PR_SET_PDEATHSIG delivers when the master goes.
# workers_of_now <master> — the worker pids, captured WHILE the master is still
# alive to name them. The drain tests kill the master themselves, and once it is
# gone its workers are reparented to init, so pgrep -P finds nothing; a worker
# already draining also ignores the SIGTERM that PR_SET_PDEATHSIG delivers, so
# it can outlive the test holding the port. That left a pattern match on the
# config path as the only handle — and a pattern cannot tell this suite's
# server from one running beside it, which is how two concurrent runs came to
# kill each other's servers mid-test. Take the pids first and there is nothing
# to match against.
workers_of_now() { pgrep -P "$1" 2>/dev/null | tr '\n' ' '; }

# reap_workers <pids...> — kill exactly those, no pattern.
reap_workers() { local w; for w in "$@"; do kill -9 "$w" 2>/dev/null; done; }

# workers_gone <pids...> — wait until none of them is alive. The drain is
# supposed to END; polling for that is the assertion, where a fixed sleep
# followed by a check was only ever a guess about how long it takes.
workers_gone() {
    local i w still
    for i in $(seq 1 100); do
        still=""
        for w in "$@"; do kill -0 "$w" 2>/dev/null && still="$still $w"; done
        [ -z "$still" ] && return 0
        sleep 0.1
    done
    return 1
}

drain_workers() {
    local m=$1 w
    for w in $(pgrep -P "$m"); do kill -QUIT "$w" 2>/dev/null; done
    kill "$m" 2>/dev/null
}

strays=$(stray_servers)
if [ -n "$strays" ]; then
    echo "FATAL: test servers from an earlier run are still running:" >&2
    ps -o pid,args -p $(echo $strays | tr ' ' ',') >&2
    echo "  They hold this suite's ports, so its own servers cannot bind and its" >&2
    echo "  results would describe the old ones. Kill them and re-run:" >&2
    echo "    kill $(echo $strays | tr '\n' ' ')" >&2
    exit 1
fi

# ...and a backend from an earlier run, which is worse than it sounds. The
# suite starts its own on 61100 at the point it needs one, and until then
# nothing should answer there: several tests turn on a proxied path being
# UNREACHABLE. A leftover backend makes /api/anything a 404 from the backend
# rather than a 502 from a dead upstream, and the failure names the wrong
# thing entirely. Cheap to detect, and it has caught real confusion twice.
if (echo > /dev/tcp/127.0.0.1/${P61100}) >/dev/null 2>&1; then
    echo "FATAL: something is already listening on 127.0.0.1:${P61100}." >&2
    echo "  That is this suite's proxy backend port, and it starts its own" >&2
    echo "  later — tests that need an UNREACHABLE upstream would pass or" >&2
    echo "  fail for the wrong reason. Probably a leftover:" >&2
    ps -eo pid,args | grep "[p]roxy_backend" >&2
    exit 1
fi

# Same reasoning for the websocket backend's two ports: a leftover linnea-ws
# holding one of them would answer with a counter at some arbitrary value, and
# the checks that read the count would fail with numbers that look like a
# framing bug.
for wsport in ${P61701} ${P61702}; do
    if (echo > /dev/tcp/127.0.0.1/$wsport) >/dev/null 2>&1; then
        echo "FATAL: something is already listening on 127.0.0.1:$wsport." >&2
        echo "  That is this suite's websocket backend port. Probably a leftover:" >&2
        ps -eo pid,args | grep "[l]innea-ws" >&2
        exit 1
    fi
done

# ...and the /api backend's, for the same reason: a leftover would answer, and
# the checks below would be reporting on a binary nobody built.
if (echo > /dev/tcp/127.0.0.1/${P61703}) >/dev/null 2>&1; then
    echo "FATAL: something is already listening on 127.0.0.1:${P61703}." >&2
    echo "  That is this suite's /api backend port. Probably a leftover:" >&2
    ps -eo pid,args | grep "[l]innea-api" >&2
    exit 1
fi

# --- shared helpers used by more than one shard (were hoisted out of region 1) ---
backend_ready() {
    for _ in $(seq 1 60); do
        (echo > /dev/tcp/127.0.0.1/${P61100}) >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    echo >&2
    echo "FATAL: the proxy backend never came up on ${P61100}." >&2
    echo "  Every proxied request in this block would answer 502 and the failures" >&2
    echo "  would point everywhere except here, so the run stops instead. Check for" >&2
    echo "  a backend an earlier run left behind:" >&2
    echo "    ps -eo pid,args | grep [p]roxy_backend" >&2
    echo >&2
    exit 1
}

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

raw_http() {
    # See test/raw_http.py: the bash /dev/tcp one-liner this replaces gave the
    # connect, the write and the read a single two-second budget, and `cat` only
    # ever escaped a keep-alive response by being killed at the deadline. Under
    # load the deadline beat the response and the test saw an empty string with
    # its stderr discarded — a flake that cost this suite a different test on
    # three separate runs and reproduced on none of them in isolation.
    python3 test/raw_http.py "$1"
}

enc_of() {
    curl -si --max-time 2 -H "Accept-Encoding: $1" http://127.0.0.1:${P61080}/enc.txt \
        | grep -a -io '^content-encoding: .*' | tr -d '\r' | cut -d' ' -f2
}

body_of() {
    curl -s --max-time 2 -H "Accept-Encoding: $1" http://127.0.0.1:${P61080}/enc.txt
}

mime_probe() {                 # mime_probe <ext> <expected type>
    printf 'x' > "$WWW/probe.$1"
    resp=$(raw_http "GET /probe.$1 HTTP/1.1\r\nHost: one.test\r\n\r\n")
    check_http "mime: .$1 is $2" "Content-Type: $2" "$resp"
    rm -f "$WWW/probe.$1"
}

rl_burst() {   # $1 = label, rest = the curl that prints a status
    local lbl=$1; shift
    local ok=0 ref=0 i c
    sleep 1.3                       # let the bucket refill before each protocol
    for i in $(seq 1 12); do
        c=$("$@" 2>/dev/null)
        [ "$c" = "200" ] && ok=$((ok+1))
        [ "$c" = "429" ] && ref=$((ref+1))
    done
    [ "$ok" -ge 1 ] && [ "$ref" -ge 1 ]
    check "rate_limit meters $lbl ($ok served, $ref refused of 12)" $?
}
