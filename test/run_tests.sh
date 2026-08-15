#!/usr/bin/env bash
# Test suite for the linnea server. Run from anywhere; exits non-zero
# if any test fails.
set -u
cd "$(dirname "$0")/.."

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
P61470=$((PORTBASE + 470))
P61492=$((PORTBASE + 492))
P61495=$((PORTBASE + 495))
P61498=$((PORTBASE + 498))
P61500=$((PORTBASE + 500))
P61501=$((PORTBASE + 501))
P61671=$((PORTBASE + 671))
P61701=$((PORTBASE + 701))
P61702=$((PORTBASE + 702))
P61703=$((PORTBASE + 703))
# -----------------------------------------------------------------------------
LOG=$RUNDIR/linnea.log
pass=0
fail=0
rm -f "$LOG"

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

# --- config parsing and validation ---
run_test "good config"     124 stdout "server 1: host=127.0.0.1 port=${P61090} hostname=two.test locations=3" \
    timeout 0.5 $BIN --config $CFG/listen.json
run_test "config dump"     124 stdout "config: 3 servers timeout=2 max_connections=64" \
    timeout 0.5 $BIN --config $CFG/listen.json
# the dump prints the config verbatim, and the generated configs carry
# ABSOLUTE paths so a server started in its own run directory still finds
# them — so the expected text is absolute too
run_test "location dump"   124 stdout "location 1: prefix=/sub root=$PWD/$WWW" \
    timeout 0.5 $BIN --config $CFG/listen.json
# max_body was the one limit the dump did not name — awkward for the limit
# that stands between one client and the disk, since setting it left nothing
# to check it by
run_test "max_body dumped"  124 stdout "max_body=1000000" \
    timeout 0.5 $BIN --config $CFG/listen.json
run_test "bad timeout"     1 stderr "timeout must be between 1 and 3600" \
    $BIN --config $CFG/bad-timeout.json
run_test "workers dump"    124 stdout "workers=2" \
    timeout 0.5 $BIN --config $CFG/listen.json
run_test "bad workers"     1 stderr "workers must be between 0 and 256" \
    $BIN --config $CFG/bad-workers.json
# 0 is the DEFAULT (one worker per online CPU) and used to be the one value you
# could not write: the range started at 1, so the only way to ask for the
# default was to omit the key. resolve_workers always understood it.
run_test "workers auto"    124 stdout "config:" \
    timeout 0.5 $BIN --config $CFG/workers-auto.json

# docs/config.md documents every key, its scope, default and range, plus a
# complete example. A reference that drifts from the parser is worse than
# none, so every claim in it is asserted against the binary — the example
# included, since that is what a reader copies.
python3 test/configs/doc_claims_test.py >/dev/null 2>&1
check "docs/config.md still describes the parser" $?
run_test "invalid host"    1 stderr "host must be an IPv4 literal" \
    $BIN --config $CFG/bad-host.json
# a hard fd limit below the configured pool is fatal: the pool could never
# fill, and accept would fail with EMFILE while the server thought it had room
run_test "fd limit too low" 1 stderr "file descriptor limit too low" \
    bash -c "ulimit -n 200; exec $BIN --config $CFG/listen.json"
# a low SOFT limit is not fatal — a process may raise its own up to the hard
# limit, so the server does that for itself rather than refusing to start
run_test "fd soft limit raised" 124 stdout "config:" \
    bash -c "ulimit -S -n 64; exec timeout 0.5 $BIN --config $CFG/listen.json"
run_test "missing argv"    1 stderr "usage:" \
    $BIN
run_test "missing file"    1 stderr "cannot open config file" \
    $BIN --config $CFG/does-not-exist.json
run_test "truncated json"  1 stderr "parse error at line" \
    $BIN --config $CFG/truncated.json
run_test "port too large"  1 stderr "port" \
    $BIN --config $CFG/bad-port-large.json
# "port": 0 is legal now and means "let the kernel choose"; what must still be
# refused is leaving the key OUT, which is what keeps a kernel-chosen port
# something the config asked for rather than something it forgot. This fixture
# used to carry the 0 and assert the opposite.
run_test "port missing"    1 stderr "requires host, port" \
    $BIN --config $CFG/bad-port-missing.json
run_test "empty servers"   1 stderr "at least one server" \
    $BIN --config $CFG/empty-servers.json
run_test "unknown key"     1 stderr "unknown key" \
    $BIN --config $CFG/unknown-key.json
run_test "escape sequence" 1 stderr "escape sequences not supported" \
    $BIN --config $CFG/escape.json
run_test "location no prefix" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN --config $CFG/location-missing-prefix.json
run_test "location root+proxy" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN --config $CFG/location-both-kinds.json
run_test "location root+redirect" 1 stderr "location requires prefix and exactly one of root, proxy or redirect" \
    $BIN --config $CFG/location-root-and-redirect.json
run_test "redirect dump"   124 stdout "prefix=/old redirect=https://example.com" \
    timeout 0.5 $BIN --config $CFG/listen.json
run_test "bad redirect target" 1 stderr "redirect target must start with http:// or https://" \
    $BIN --config $CFG/bad-redirect-target.json
run_test "bad proxy address" 1 stderr "invalid proxy address" \
    $BIN --config $CFG/bad-proxy-addr.json
run_test "prefix not absolute" 1 stderr "location prefix must start with '/'" \
    $BIN --config $CFG/location-bad-prefix.json
run_test "empty locations"  1 stderr "at least one location" \
    $BIN --config $CFG/empty-locations.json
# the middle server reuses the hostname on another port, which is fine;
# the clash is on the shared listener, case-insensitively
run_test "duplicate hostname" 1 stderr "duplicate hostname DUP.Test on 127.0.0.1:${P61080}" \
    $BIN --config $CFG/dup-hostname.json

# --- TLS config: "cert" and "key" are both-or-neither, and servers sharing
# --- a listener must agree (SNI picks the cert within a TLS listener,
# --- but TLS and plaintext cannot share a socket)
run_test "tls dump"        124 stdout "tls=on cert=$PWD/test/tls/server.crt" \
    timeout 0.5 $BIN --config $CFG/tls.json
run_test "sni dump"        124 stdout "hostname=sni.test tls=on cert=$PWD/test/tls/sni.crt" \
    timeout 0.5 $BIN --config $CFG/tls-sni.json
run_test "tls cert without key" 1 stderr "server needs both cert and key, or neither" \
    $BIN --config $CFG/bad-cert-only.json
run_test "tls listener mismatch" 1 stderr "servers sharing a listener must all set TLS or none" \
    $BIN --config $CFG/bad-tls-mismatch.json

# --- crypto self-test: known-answer vectors for the TLS primitives ---
# Build the unit-test binaries here rather than trusting what is on disk. `make`
# does not produce them, and the checks below only test for existence — so a tree
# that has been cleaned reports a failure that looks like a real one, while a
# STALE binary is worse: it passes, silently testing code that no longer exists.
make -s bin/linnea-selftest bin/linnea-quictest bin/linnea-rtxtest >/dev/null 2>&1
if [ -x ./bin/linnea-selftest ]; then
    if ./bin/linnea-selftest >$RUNDIR/linnea_selftest.out 2>&1; then
        check "crypto selftest ($(tr '\n' ' ' <$RUNDIR/linnea_selftest.out))" 0
    else
        check "crypto selftest" 1
        cat $RUNDIR/linnea_selftest.out
    fi
    rm -f $RUNDIR/linnea_selftest.out
else
    check "crypto selftest (binary not built — run 'make selftest')" 1
fi

# QUIC crypto known-answer tests (RFC 9001 / 9000). Built by `make quictest`.
if [ -x ./bin/linnea-quictest ]; then
    if ./bin/linnea-quictest >$RUNDIR/linnea_quictest.out 2>&1; then
        check "quic crypto selftest ($(tr '\n' ' ' <$RUNDIR/linnea_quictest.out))" 0
    else
        check "quic crypto selftest" 1
        cat $RUNDIR/linnea_quictest.out
    fi
    rm -f $RUNDIR/linnea_quictest.out
else
    check "quic crypto selftest (binary not built — run 'make quictest')" 1
fi

# QUIC on the wire: a standalone UDP receiver decrypts a real Initial packet
# built by aioquic (the QUIC/HTTP-3 reference client).
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quicserver ]; then
    timeout 10 ./bin/linnea-quicserver ${P61500} >$RUNDIR/linnea_quicsrv.out 2>&1 &
    qsrv=$!
    sleep 0.4
    python3 test/quic/h3_initial.py ${P61500} >/dev/null 2>&1
    sleep 0.4
    wait $qsrv 2>/dev/null
    # decrypt the Initial, recover the ClientHello, and read its SNI + h3 ALPN
    grep -q "quic-initial sni=localhost alpn-h3=1" $RUNDIR/linnea_quicsrv.out
    check "quic: decrypt aioquic Initial + parse ClientHello (SNI, h3 ALPN)" $?
    rm -f $RUNDIR/linnea_quicsrv.out
else
    check "quic wire test (skipped: aioquic or quicserver unavailable)" 0
fi

# QUIC transport parameters (for EncryptedExtensions): aioquic parses linnea's
# encoding and the values round-trip.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quictp ]; then
    ./bin/linnea-quictp | python3 test/quic/tp_parse.py >/dev/null 2>&1
    check "quic: transport parameters parse in aioquic" $?
else
    check "quic transport-params test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC ServerHello (first message of the handshake flight): aioquic's TLS
# parser accepts it and the negotiated profile round-trips.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quicsh ]; then
    ./bin/linnea-quicsh | python3 test/quic/sh_parse.py >/dev/null 2>&1
    check "quic: ServerHello parses in aioquic (x25519, TLS 1.3)" $?
else
    check "quic ServerHello test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC EncryptedExtensions (h3 ALPN + transport parameters): aioquic's TLS
# parser reads the ALPN and the transport-parameters extension decodes.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quicee ]; then
    ./bin/linnea-quicee | python3 test/quic/ee_parse.py >/dev/null 2>&1
    check "quic: EncryptedExtensions parse in aioquic (h3 + transport params)" $?
else
    check "quic EncryptedExtensions test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC Certificate message: the real test chain, framed and parsed by aioquic.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quiccert ]; then
    ./bin/linnea-quiccert | python3 test/quic/cert_parse.py >/dev/null 2>&1
    check "quic: Certificate message parses in aioquic" $?
else
    check "quic Certificate test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC CertificateVerify: the ECDSA signature verifies against the test cert.
if python3 -c 'import aioquic, cryptography' 2>/dev/null && [ -x ./bin/linnea-quiccv ]; then
    ./bin/linnea-quiccv | python3 test/quic/cv_verify.py >/dev/null 2>&1
    check "quic: CertificateVerify signature verifies against the cert" $?
else
    check "quic CertificateVerify test (skipped: deps unavailable)" 0
fi

# QUIC Finished: the HMAC verify_data matches an independent computation.
if python3 -c 'import aioquic, cryptography' 2>/dev/null && [ -x ./bin/linnea-quicfin ]; then
    ./bin/linnea-quicfin | python3 test/quic/fin_verify.py >/dev/null 2>&1
    check "quic: Finished verify_data matches the reference HMAC" $?
else
    check "quic Finished test (skipped: deps unavailable)" 0
fi

# QUIC handshake on the wire: linnea replies to a client Initial with a
# coalesced Initial (ACK + ServerHello) and Handshake packet (EE, Certificate,
# CertificateVerify, Finished); aioquic completes the TLS 1.3 handshake.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/hs_test.py ${P61501} >/dev/null 2>&1
    check "quic: full handshake completes in aioquic (h3 negotiated)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "quic handshake test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC handshake confirmation: the client sends its Finished; linnea decrypts
# the Handshake packet, verifies the MAC (prints CFIN-OK), and replies with
# HANDSHAKE_DONE in a 1-RTT packet. cfin_test.py asserts aioquic accepts it and
# confirms the handshake — both server-side auth and the 1-RTT keys.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    cfinlog=$(mktemp)
    timeout 10 ./bin/linnea-quichs ${P61501} >"$cfinlog" 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/cfin_test.py ${P61501} >/dev/null 2>&1
    cfinrc=$?
    sleep 0.3
    if [ $cfinrc -eq 0 ] && grep -q CFIN-OK "$cfinlog"; then cfinok=0; else cfinok=1; fi
    check "quic: client Finished verified + HANDSHAKE_DONE confirms handshake" $cfinok
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
    rm -f "$cfinlog"
else
    check "quic handshake-confirm test (skipped: aioquic/binary unavailable)" 0
fi

# QUIC connection pool: allocation, exhaustion, the idle sweep and slot reuse.
if [ -x ./bin/linnea-pooltest ]; then
    out=$(./bin/linnea-pooltest)
    rc=$?
    check "quic pool selftest ($out)" $rc
else
    check "quic pool selftest (skipped: binary unavailable)" 0
fi

# io_uring submission accounting: when the kernel consumes fewer sqes than it was
# told (a batch with an sqe it cannot init), the remainder must still be offered
# again rather than trailing our tail for the life of the process.
if [ -x ./bin/linnea-ringtest ]; then
    out=$(./bin/linnea-ringtest)
    rc=$?
    check "io_uring partial-submission recovery selftest ($out)" $rc
else
    check "io_uring partial-submission selftest (skipped: binary unavailable)" 0
fi

# QUIC 1-RTT loss recovery: the sent-packet ring (record/ack-range/inflight) and
# the ACK-frame range decoder, in isolation and together.
if [ -x ./bin/linnea-rtxtest ]; then
    out=$(./bin/linnea-rtxtest)
    rc=$?
    check "quic loss-recovery selftest ($out)" $rc
else
    check "quic loss-recovery selftest (skipped: binary unavailable)" 0
fi

# 0-RTT anti-replay: the strike register accepts a fresh binder, rejects a replay
# within the window, reuses expired slots, and fails closed when full.
if [ -x ./bin/linnea-replaytest ]; then
    out=$(./bin/linnea-replaytest)
    rc=$?
    check "quic 0-RTT anti-replay + ticket-lifetime + ack-delay selftest ($out)" $rc
else
    check "quic 0-RTT anti-replay selftest (skipped: binary unavailable)" 0
fi

# QPACK decode: field sections encoded by pylsqpack (static + literals + Huffman,
# zero dynamic table) decode to the right HTTP/3 request pseudo-headers.
if python3 -c 'import pylsqpack' 2>/dev/null && [ -x ./bin/linnea-qpacktest ]; then
    python3 test/quic/qpack_test.py >/dev/null 2>&1
    check "qpack: HTTP/3 request headers decode (static, literal, Huffman)" $?
else
    check "qpack decode test (skipped: pylsqpack/binary unavailable)" 0
fi

# The response ENCODER's output bound. It assembled a field section into a
# 768-byte buffer with no limit at all, while the proxy-relay encoder beside it
# in the same file had carried one all along -- and a redirect's Location is the
# configured target plus the CLIENT's request target, so a long path ran a
# couple of thousand bytes past the end. Nothing observed it: the bytes landed
# in a neighbouring buffer nothing read again. Only a canary can fail on that,
# which is what this asserts, alongside a control that a section which FITS is
# still produced (or the checks would pass on an encoder that wrote nothing).
if [ -x ./bin/linnea-qpacktest ]; then
    out=$(./bin/linnea-qpacktest encode 2>&1)
    [ "${out%% *}" = "qpack-encode" ] && [ "${out##* }" = "6/6" ]
    check "qpack: the response encoder refuses to write past its buffer ($out)" $?
else
    check "qpack encoder bound (skipped: binary unavailable)" 0
fi

# HTTP/3 request framing: linnea walks the request-stream frames, skips
# DATA/unknown frames, and QPACK-decodes the HEADERS frame to the request.
if python3 -c 'import pylsqpack' 2>/dev/null && [ -x ./bin/linnea-h3test ]; then
    python3 test/quic/h3_test.py >/dev/null 2>&1
    check "h3: request HEADERS frame parsed and decoded (skips GREASE/unknown)" $?
else
    check "h3 framing test (skipped: pylsqpack/binary unavailable)" 0
fi

# HTTP/3 response building: linnea frames a HEADERS (QPACK-encoded status,
# content-type, content-length) + DATA response that pylsqpack decodes.
if python3 -c 'import pylsqpack' 2>/dev/null && [ -x ./bin/linnea-h3resp ]; then
    python3 test/quic/h3resp_test.py >/dev/null 2>&1
    check "h3: response HEADERS+DATA built and QPACK-decodes (status/ct/cl)" $?
else
    check "h3 response test (skipped: pylsqpack/binary unavailable)" 0
fi

# End-to-end HTTP/3: complete the handshake, send an h3 GET, and check linnea
# replies with a 200 HEADERS+DATA response over the request stream.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_e2e_test.py ${P61501} >/dev/null 2>&1
    check "h3: serves real static files over QUIC (MIME, index, 404)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "h3 end-to-end test (skipped: deps unavailable)" 0
fi

# Several HTTP/3 requests on one connection: three GETs on three streams arrive
# coalesced in one packet; linnea answers each on its own stream.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_multi_test.py ${P61501} >/dev/null 2>&1
    check "h3: multiple requests on one connection, each on its own stream" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "h3 multi-stream test (skipped: deps unavailable)" 0
fi

# NewSessionTicket over QUIC: after the handshake the server sends a ticket (in a
# CRYPTO frame coalesced with HANDSHAKE_DONE) carrying the early_data extension
# with max_early_data_size = 0xffffffff, so the client can resume / send 0-RTT.
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_ticket_test.py ${P61501} >/dev/null 2>&1
    check "h3: server issues a NewSessionTicket (early_data for 0-RTT)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "h3 NewSessionTicket test (skipped: deps unavailable)" 0
fi

# Session resumption: a second connection presents the first's ticket as a PSK;
# the server opens it, verifies the binder, resumes with a pre_shared_key
# ServerHello and a certificate-free flight (materially fewer bytes).
if python3 -c 'import aioquic' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 12 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_resume_test.py ${P61501} >/dev/null 2>&1
    check "h3: resumes from a ticket (PSK, binder, no certificate)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "h3 resumption test (skipped: deps unavailable)" 0
fi

# 0-RTT early data: a resuming client sends its GET coalesced with the
# ClientHello; the server decrypts the 0-RTT packet, accepts (EE early_data),
# and serves the buffered request once the 1-RTT keys are up.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 12 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_0rtt_test.py ${P61501} >/dev/null 2>&1
    check "h3: serves a 0-RTT request (early data accepted)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "h3 0-RTT test (skipped: deps unavailable)" 0
fi

# HTTP/3 through the real server: linnea binds a UDP listener for its TLS
# server and drives the QUIC handler from the io_uring loop, so h3 is served by
# the production binary from the config's document root — while TCP keeps
# serving HTTP/1.1 and HTTP/2 on the same port. The config runs four workers,
# so this also covers SO_REUSEPORT steering.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    python3 test/mk_test_image.py $WWW/linnea.png >/dev/null    # served over h3
    start_server $CFG/tls-h3.json
    P61452=$SRV_PORT
    h3_pid=$SRV_PID
    python3 test/quic/h3_e2e_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): real server serves static files over QUIC" $?

    python3 test/quic/h3_etag_test.py ${P61452} >/dev/null 2>&1
    check "h3 validators, date + server headers, conditional 304s" $?

    python3 test/quic/h3_range_test.py ${P61452} >/dev/null 2>&1
    check "h3 range 206/416, if-range, cache-control, chunked slice" $?

    python3 test/quic/h3_enc_test.py ${P61452} >/dev/null 2>&1
    check "h3 pre-compressed variants (br/gzip, vary, variant etag 304)" $?

    python3 test/quic/h3_qpack_err_test.py ${P61452} >/dev/null 2>&1
    check "h3 undecodable field section ends the connection (0x200)" $?
    python3 test/quic/h3_multi_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): several requests on one connection" $?
    python3 test/quic/h3_conns_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): two interleaved connections" $?
    # the idle timeout is the MINIMUM of the two advertised max_idle_timeouts
    # (RFC 9000 10.1), so a client that will forget us in a second must not hold
    # a pool slot for our 30; the paired control keeps that from being any
    # connection simply going idle
    timeout 60 python3 test/quic/h3_idle_tp_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): the client's max_idle_timeout is honoured (and only it)" $?
    # several workers each bind the QUIC port with SO_REUSEPORT; the kernel
    # steers by 4-tuple so a connection always reaches the worker holding it
    python3 test/quic/h3_workers_test.py ${P61452} 8 >/dev/null 2>&1
    check "h3 (io_uring): connections spread across workers are all served" $?

    python3 test/quic/h3_ack_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): replies acknowledge received packets" $?

    # loss recovery: drop the server's reply and it must retransmit (under a
    # fresh packet number) once its probe timeout fires
    python3 test/quic/h3_rtx_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a dropped reply is retransmitted after the PTO" $?

    # control streams: the server opens its control stream (SETTINGS first) and
    # the QPACK encoder/decoder streams once the handshake completes
    python3 test/quic/h3_control_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): server opens control + QPACK streams with SETTINGS" $?

    # receive side: a client control stream that opens with SETTINGS is accepted
    # and served; one whose first frame is not SETTINGS is closed (H3_MISSING_SETTINGS)
    python3 test/quic/h3_settings_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): client control stream validated (SETTINGS-first enforced)" $?

    # and the rest of the control stream's frame sequence, not just its first two
    # bytes: DATA/HEADERS/PUSH_PROMISE, the reserved HTTP/2 types and a second
    # SETTINGS end the connection, GREASE and the control frames are skipped by
    # length, and a header split across STREAM frames still parses
    timeout 180 python3 test/quic/h3_ctrl_frames_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): control-stream frames walked and validated" $?

    # request bodies: POST is a 405 now, but the body must still be reassembled
    # whole and the stream answered, with its flow-control credit settled
    python3 test/quic/h3_body_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a multi-packet request body is consumed and answered" $?

    # large responses: a 600 KB file streams as ack-clocked STREAM-frame chunks
    # (each datagram under the 1200-byte floor); one dropped chunk is rebuilt
    # from the file after the PTO; a small GET is answered mid-transfer; a
    # client whose flow-control window cannot take the file gets a 503
    python3 test/quic/h3_big_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): large response streamed in chunks (loss + interleave + 503)" $?

    # four large (chunked) responses requested at once: all stream concurrently,
    # interleaved by the pump over the shared congestion window, none refused —
    # each arrives byte-exact. This is a full browser page load (a 503 on a
    # concurrent large request made Firefox abandon h3 for h2).
    python3 test/quic/h3_queue_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): four concurrent large responses, all intact" $?

    # concurrent large responses through an emulated lossy, REORDERING network
    # (both directions), across several seeds — the conditions a real browser hits
    # and that lockstep tests miss. Exercises ack-based fast retransmit and the
    # priority pump; every stream must arrive byte-exact on every seed.
    python3 test/quic/h3_stress_test.py ${P61452} 6 6 3 >/dev/null 2>&1
    check "h3 (io_uring): concurrent responses survive loss + reordering" $?

    # RFC 9218 priority: default (non-incremental) responses are served to
    # completion in arrival order — sequentially, so complete images appear sooner
    # — and a `priority: u=0` request jumps ahead of default-urgency ones.
    python3 test/quic/h3_priority_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): responses scheduled by RFC 9218 priority" $?

    # static files answer GET and HEAD (and h3's own POST echo); every other
    # method used to fall through and be SERVED AS A GET, body and all, where
    # h1 and h2 both answer 405. The method is matched case-sensitively.
    timeout 200 python3 test/quic/h3_method_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): unknown methods get 405, not the file" $?

    # and the client can change its mind afterwards: a PRIORITY_UPDATE on the
    # control stream reprioritises a response already streaming, and one that
    # overtakes the request it names is kept and applied when that stream opens
    timeout 300 python3 test/quic/h3_priority_update_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): PRIORITY_UPDATE reprioritises a response" $?

    # a size/boundary/request-style matrix: every response, from 0 bytes through
    # the inline/chunked threshold and exact chunk multiples to 200 KB, must
    # terminate (deliver a FIN) — sequentially reusing one connection, all at once
    # under the priority scheduler, and as a HEAD. A request that never finishes
    # fails here.
    python3 test/quic/h3_matrix_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): size/boundary/HEAD/concurrent matrix all terminate" $?

    # connection reuse: far more than the advertised 100 bidi streams on ONE
    # connection (a browser reusing it across refreshes) — the server must raise
    # the peer's limit with MAX_STREAMS or new requests can't be sent (images stop
    # loading, h2 fallback after ~30s).
    python3 test/quic/h3_reuse_test.py ${P61452} 250 >/dev/null 2>&1
    check "h3 (io_uring): reused connection past 100 streams (MAX_STREAMS)" $?

    # under load: many concurrent connections (browser tabs / refreshes) plus a
    # burst of open-load-close churn — every request completes and the workers stay
    # alive with no descriptor leak.
    python3 test/quic/h3_load_test.py ${P61452} 12 4 >/dev/null 2>&1
    check "h3 (io_uring): concurrent connections + churn under load" $?

    # browser reloads on one reused connection: each reload cancels the previous
    # page's in-flight downloads (STOP_SENDING). The server must tear a cancelled
    # stream down or its abandoned chunks pin the congestion window and, after
    # enough reloads, the connection stalls (hang, then h2 fallback).
    python3 test/quic/h3_reload_test.py ${P61452} 10 >/dev/null 2>&1
    check "h3 (io_uring): reload-cancel (STOP_SENDING) does not stall the connection" $?

    # connection-level credit (MAX_DATA) must be read from every packet, including
    # the ones that arrive while no response stream is open — which is exactly what a
    # reload's cancels leave behind. The peer sends each value once (its packet is
    # acknowledged), so a raise the server misses is gone for good: the server then
    # stalls at a window the peer has long since widened, with nothing in flight.
    python3 test/quic/h3_maxdata_test.py ${P61452} 8 >/dev/null 2>&1
    check "h3 (io_uring): MAX_DATA is absorbed with no response stream open" $?

    # a request whose ack is lost is retransmitted by the client; the server must
    # ack the retransmit, not serve the stream a second time — a duplicate response
    # slot resends the whole body and pins the shared congestion window (the real-
    # browser wedge). Several chunked streams over one connection, ack-loss forced.
    python3 test/quic/h3_dup_request_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): retransmitted request is not served twice (no duplicate wedge)" $?

    # an Initial's header carries the token a client echoes from a Retry, and the
    # server copies that header into a fixed scratch buffer to authenticate the
    # packet. The token is client-supplied, so an oversized one must be refused
    # rather than copied over whatever follows the buffer — a worker that dies here
    # is a remote, pre-handshake stack overwrite with attacker-chosen bytes.
    python3 test/quic/h3_initial_token_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): oversized Initial token refused, not copied past its buffer" $?

    # a flood of Initials that are never answered must not fill the connection pool
    # and lock real clients out: once enough slots are held by unvalidated peers the
    # server demands a Retry token, which only a client at a real address can echo.
    # Runs late and settles afterwards — it deliberately leaves the pool under
    # pressure, and the pool needs a moment to reclaim the forged slots.
    python3 test/quic/h3_retry_test.py ${P61452} 300 >/dev/null 2>&1
    check "h3 (io_uring): forged-Initial flood does not lock out real clients" $?
    sleep 6

    # a spoofed packet from a different source, carrying a valid connection id but
    # no valid AEAD tag, must NOT redirect the server's sends (RFC 9000 9.3): the
    # peer address is adopted only from an authenticated packet.
    python3 test/quic/h3_migration_spoof_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): unauthenticated source does not redirect the connection" $?

    # and the replayed half: a captured 1-RTT datagram resent from another source
    # carries a VALID tag, so authenticity alone cannot gate the address change.
    # RFC 9000 12.3 (discard an already-processed packet number) + 9.3 (only the
    # highest-numbered packet may move the address) are what close it.
    python3 test/quic/h3_replay_spoof_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): replayed packet does not redirect the connection" $?

    # the server's own first flight must survive being lost. There was no loss
    # recovery for the Initial or Handshake spaces at all, so dropping that one
    # ~1150-byte datagram ended the handshake and the client fell back to TCP.
    python3 test/quic/h3_hs_rtx_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a lost handshake flight is retransmitted" $?

    # Frames coalesced ahead of a request must not hide it (RFC 9000 12.4). Six
    # scanners each carried a partial frame-length table and stopped at the first
    # type theirs did not list, so a CONNECTION_CLOSE hid what followed it and an
    # unknown type hid the rest of the packet from all six — silently, with the
    # packet acknowledged, so the client never retried.
    python3 test/quic/h3_frame_walk_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): coalesced frames do not hide the rest of the packet" $?

    # the same field rules over HTTP/3 (RFC 9114 4.2, 4.3.1) — one shared
    # decoder, and this side had it worse: the connection-specific names were
    # matched only inside the proxy rebuild, which HTTP/3 never enters at all.
    python3 test/quic/h3_field_rules_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): request field rules" $?

    # The server must not name a protocol the client never offered (RFC 7301
    # 3.2): build_ee wrote "h3" into EncryptedExtensions without ever reading
    # the client's list, so a doq or hq-interop client was told it had h3.
    python3 test/quic/h3_alpn_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): ALPN is checked, not assumed" $?

    # ...and a refusal must SAY SO (RFC 9001 4.8): the TLS alert becomes a QUIC
    # error of 0x0100+description in a CONNECTION_CLOSE. Every handshake-space
    # refusal used to be silent, because the only close path needed 1-RTT keys
    # that do not exist that early, so the client could not tell "refused" from
    # "lost" and simply retransmitted its ClientHello until it gave up.
    python3 test/quic/h3_hs_close_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a refused handshake closes with the TLS alert" $?

    # RESET_STREAM's Final Size is OURS, not the peer's (RFC 9000 19.4). Resetting
    # a malformed request reported the client's request length, so the peer held
    # connection-level credit for data it would never be sent — and one large
    # enough obliges a conforming client to close with FLOW_CONTROL_ERROR.
    python3 test/quic/h3_reset_final_size_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): RESET_STREAM reports our own final size" $?

    # ...and the code that reset carries has to say WHICH thing went wrong: a
    # truncated last frame is a connection error (7.1), a stream that never
    # carried HEADERS is H3_REQUEST_INCOMPLETE so the client may retry (4.1),
    # and only a request that decodes and then breaks a rule is MESSAGE_ERROR.
    python3 test/quic/h3_stream_codes_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a failed request stream names its fault" $?

    # ...and the same preconditions over h3, so the answer does not depend on
    # which protocol carried the request (RFC 9110 13.1.1, 13.1.4, 13.2.2).
    python3 test/quic/h3_preconditions_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): If-Match and If-Unmodified-Since" $?

    # RFC 9114 6.2: a critical stream must not be closed BY ANY MEANS. Only a
    # FIN was noticed, so a peer could RESET_STREAM its control stream and the
    # connection carried on as though it still had one.
    python3 test/quic/h3_critical_reset_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): resetting a critical stream is detected" $?

    # h3-8: the QPACK encoder stream must be read, not ignored. We advertise
    # capacity 0, so the only legal instruction is Set Dynamic Table Capacity
    # to 0; an insert or another capacity means the peer's table state and
    # ours have silently diverged — QPACK_ENCODER_STREAM_ERROR. Also: a FIN
    # on a LATER frame of a QPACK stream is a critical-stream closure too.
    python3 test/quic/h3_qpack_enc_stream_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): QPACK encoder-stream instructions are policed" $?

    # h3-6: control-stream enforcement must survive reordering. A STREAM frame
    # delivered (and acked) ahead of the walked prefix used to be dropped, and
    # since a reordered frame comes only once, the hole was permanent — every
    # control-stream rule quietly stopped being enforced there. Held now, and
    # legal reordering must still close nothing.
    python3 test/quic/h3_ctrl_reorder_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): control-stream rules survive reordering" $?

    # An ack-eliciting packet MUST be acknowledged (RFC 9000 13.2.1). An ACK was
    # only built when the server had something of its own to send, so a lone PING
    # (a browser keepalive) or a lone stream reset drew nothing and the peer
    # resent it with a doubling timeout for the life of the connection.
    python3 test/quic/h3_ack_eliciting_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): a packet with nothing to answer is still acked" $?

    # the same for the handshake flights: no long-header packet authenticates its
    # sender, so neither a replayed Initial nor a forged Handshake may move the
    # peer address (RFC 9000 9 — no migration before the handshake is confirmed)
    python3 test/quic/h3_longhdr_spoof_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): spoofed long-header packets do not redirect the connection" $?

    # the client initiates a 1-RTT key update mid-transfer (RFC 9001 §6); the server
    # must derive the next key generation and follow, or it can no longer decrypt the
    # client's packets and the transfer wedges.
    python3 test/quic/h3_key_update_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): follows a client-initiated 1-RTT key update" $?

    # quic-8: after sending a CONNECTION_CLOSE the server keeps the closing state
    # for a while (RFC 9000 10.2), re-sending the close in response to the peer's
    # packets — so the peer learns the real error even if the first close is lost,
    # instead of the stateless reset a freed connection id would draw.
    python3 test/quic/h3_closing_state_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): closing state re-sends the close, no stateless reset" $?

    # quic-11: once the handshake is confirmed the server discards its Initial and
    # Handshake keys (RFC 9001 4.9/4.9.1) and drops any long-header packet rather
    # than AEAD-processing it under keys that are supposed to be gone. A burst of
    # such packets on an established connection must not disturb it.
    python3 test/quic/h3_post_handshake_long.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): long-header packets after confirmation are dropped" $?

    # a 1-RTT packet for a connection id we hold no state for gets a stateless reset
    # (RFC 9000 §10.3), so the peer fails fast instead of waiting out its idle timeout.
    python3 test/quic/h3_stateless_reset_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): stateless reset for an unknown connection id" $?

    # a peer that sends more request-stream data than the advertised window commits a
    # flow-control violation; the server closes with a transport CONNECTION_CLOSE
    # (FLOW_CONTROL_ERROR) rather than silently dropping (RFC 9000 §4.1 / §10.2).
    python3 test/quic/h3_flow_violation_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): flow-control violation closes with a transport error" $?

    # a long-header packet with an unsupported version draws a Version Negotiation
    # packet listing the versions we speak (RFC 9000 §6.1), so the client can retry.
    python3 test/quic/h3_version_negotiation_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): unsupported version draws Version Negotiation" $?

    # a full QUIC v2 (RFC 9369) handshake — different Initial salt, "quicv2" labels
    # and remapped long-header packet types — serving HTTP/3 byte-exact.
    python3 test/quic/h3_v2_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): QUIC v2 handshake serves HTTP/3" $?

    # a client whose Initials start above packet number 0 (Chrome starts at 1): the
    # ServerHello ACK must cover the real [min,max] range, not [0,max] — acking an
    # unsent packet is invalid and a strict client aborts to h2 (QUIC_INVALID_ACK_DATA).
    python3 test/quic/h3_pn_offset_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): ACK covers only received Initials (Chrome starts pn at 1)" $?

    # a real binary asset: a PNG served with the right MIME type, byte-exact,
    # over the chunked h3 path
    python3 test/quic/h3_image_test.py ${P61452} $WWW >/dev/null 2>&1
    check "h3 (io_uring): PNG image served intact (image/png, chunked)" $?

    # a ClientHello too large for one Initial packet (as a browser's post-quantum
    # key share makes it) is reassembled across Initials by the client's original
    # DCID; a ClientHello with no x25519 share is refused without crashing
    python3 test/quic/h3_bigch_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): multi-packet ClientHello reassembled; no-x25519 refused" $?

    # ngtcp2/curl fragments the ClientHello into many small CRYPTO frames sent out
    # of offset order, several per packet; the reassembly must place each at its
    # offset, not assume order (this is what made real browsers fall back to h2)
    python3 test/quic/h3_frag_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): out-of-order multi-frame ClientHello reassembled" $?

    # the request-stream reassembler: a request too big for one packet, with the
    # datagrams reversed and shuffled, so a hole opens and later fills. Every
    # other h3 test sends a request that fits one packet, which never exercises
    # the arrived-bytes map at all
    timeout 120 python3 test/quic/h3_reorder_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): multi-packet request reassembled out of order" $?

    # a header section past our bound is our resource limit, not the peer's
    # encoder misbehaving: it must be answered on its own stream (431), not
    # reported as a decompression failure that takes the whole connection down
    timeout 60 python3 test/quic/h3_bigheaders_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): oversized header list gets 431, connection survives" $?

    # a malformed request whose stream has already ended is answered with a
    # reset; it used to be dropped, leaving the client waiting on a response
    # that could never come
    timeout 60 python3 test/quic/h3_malformed_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): malformed complete request is reset, not dropped" $?

    # QUIC TRANSPORT frames, which h3_malformed_test.py does not reach — it
    # covers HTTP/3 application frames one layer up. These are the parsers in
    # src/lib/linnea_quic.asm walking raw bytes from an UNAUTHENTICATED peer:
    # Initial keys come from the connection id, so none of this needs a
    # handshake. Every length in them is a varint that can claim up to 2^62,
    # and the whole of their safety is bounds checks. Deterministic seed, so a
    # failure is reproducible. Passing is not "it refused" — refusing is the
    # point — it is that every worker survived and the port still serves.
    #
    # ON A SERVER OF ITS OWN, which cost a suite run to learn: five hundred
    # half-open connections from five hundred unrelated connection ids leave a
    # pool nothing like the one the other h3 tests expect, and run against the
    # shared fixture this broke the 0-RTT test forty lines later. Ordering it
    # last would have worked until someone appended a test after it.
    if python3 -c 'import cryptography' 2>/dev/null; then
        start_server $CFG/tls-h3-fuzz.json
        P61456=$SRV_PORT
        fuzz_pid=$SRV_PID
        sleep 0.4
        timeout 120 python3 test/quic/fuzz_quic_frames.py ${P61456} 500 "$fuzz_pid" \
            >/dev/null 2>&1
        check "quic transport frames: 500 malformed Initials leave it serving" $?
        kill $fuzz_pid 2>/dev/null
        wait $fuzz_pid 2>/dev/null
    else
        check "quic frame fuzz (skipped: cryptography unavailable)" 0
    fi

    # session resumption: the real server issues a NewSessionTicket with the
    # early_data extension once the handshake completes
    python3 test/quic/h3_ticket_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): server issues a NewSessionTicket (early_data)" $?

    # and accepts it back: a second connection resumes with the ticket (PSK), so
    # the server skips the certificate
    python3 test/quic/h3_resume_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): resumes from a ticket (no certificate re-sent)" $?

    # 0-RTT: a resuming client's GET, sent as early data with the ClientHello, is
    # decrypted and served
    python3 test/quic/h3_0rtt_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): serves a 0-RTT request (early data)" $?

    # quic-6b: the same over QUIC v2. RFC 9369 shifts every long-header type up
    # by one, so the 0-RTT packet is 0x20 rather than 0x10 -- the walk that hunts
    # for it used to look for the v1 type only, so a v2 client's early data was
    # silently ignored and its request went unanswered until it resent it at
    # 1-RTT. One byte different on the wire, same assertions.
    python3 test/quic/h3_0rtt_test.py ${P61452} 2 >/dev/null 2>&1
    check "h3 (io_uring): serves a 0-RTT request over QUIC v2 (RFC 9369 types)" $?

    # quic-6: the 0-RTT packet shares the Application pn space with 1-RTT and MUST
    # be acknowledged (RFC 9000 13.2.1); the server used to discard its number, so
    # the early request was never acked. The qlog must show the server ack cover
    # the packet number the client sent its 0-RTT on.
    python3 test/quic/h3_0rtt_ack_test.py ${P61452} >/dev/null 2>&1
    check "h3 (io_uring): the 0-RTT packet is acknowledged" $?

    # BPF connection-ID steering: a connection survives the client migrating to a
    # fresh source port. Needs CAP_BPF on the binary (a rebuild drops the file
    # capability), so it is skipped when the steering program could not load.
    if getcap "$BIN" 2>/dev/null | grep -q cap_bpf; then
        python3 test/quic/h3_migrate_test.py ${P61452} >/dev/null 2>&1
        check "h3 (io_uring): connection survives client migration (BPF CID steering)" $?
    else
        check "h3 (io_uring): CID steering (skipped: binary lacks CAP_BPF)" 0
    fi

    # Alt-Svc: the TCP responses advertise HTTP/3 on this port, which is how a
    # browser discovers it at all
    hdrs=$(curl -si --http1.1 --cacert test/tls/server.crt \
                --resolve localhost:${P61452}:127.0.0.1 \
                https://localhost:${P61452}/hello.txt)
    echo "$hdrs" | grep -qi "alt-svc: h3=\":${P61452}\""
    check "h3 (io_uring): HTTP/1.1 advertises Alt-Svc for h3" $?
    hdrs=$(curl -si --http2 --cacert test/tls/server.crt \
                --resolve localhost:${P61452}:127.0.0.1 \
                https://localhost:${P61452}/hello.txt)
    echo "$hdrs" | grep -qi "alt-svc: h3=\":${P61452}\""
    check "h3 (io_uring): HTTP/2 advertises Alt-Svc for h3" $?

    # the UDP listener must not disturb TCP on the same host and port
    body=$(curl -s --http2 --cacert test/tls/server.crt \
                 --resolve localhost:${P61452}:127.0.0.1 \
                 https://localhost:${P61452}/hello.txt)
    [ "$body" = "hello from linnea" ]
    check "h3 (io_uring): HTTP/2 over TCP still served on the same port" $?

    # a pre-auth malformed Initial (long-header Length rewritten to 0) must not
    # underflow the AEAD ciphertext length and crash a worker; the workers must
    # be the same processes afterwards, and normal h3 must still be served
    ulw_before=$(workers_of $h3_pid)
    python3 test/quic/h3_length_underflow_test.py ${P61452} >/dev/null 2>&1
    sleep 0.5
    python3 test/quic/h3_e2e_test.py ${P61452} >/dev/null 2>&1
    ulw_ok=$?
    ulw_after=$(workers_of $h3_pid)
    [ -n "$ulw_before" ] && [ "$ulw_before" = "$ulw_after" ] && [ $ulw_ok -eq 0 ]
    check "h3 (io_uring): malformed Length Initial crashes no worker (pre-auth)" $?

    # a resumption offer whose PskIdentity is longer than a real ticket must be
    # rejected before the AEAD: the open writes identity_len-28 bytes into a
    # 48-byte stack slot, so an oversized identity overwrote the return address
    # of a pre-auth path. Real resumption must keep working afterwards.
    pio_before=$(workers_of $h3_pid)
    python3 test/quic/h3_psk_id_overflow_test.py ${P61452} >/dev/null 2>&1
    sleep 0.5
    python3 test/quic/h3_resume_test.py ${P61452} >/dev/null 2>&1
    pio_ok=$?
    pio_after=$(workers_of $h3_pid)
    [ -n "$pio_before" ] && [ "$pio_before" = "$pio_after" ] && [ $pio_ok -eq 0 ]
    check "h3 (io_uring): oversized PskIdentity crashes no worker (pre-auth)" $?

    kill $h3_pid 2>/dev/null
    wait $h3_pid 2>/dev/null
else
    check "h3 io_uring tests (skipped: deps unavailable)" 0
fi

# h3 routes to locations. A vhost with a proxy location used to be barred from
# h3 altogether, and when another vhost on the same port owned the listener its
# requests were answered from THAT vhost's document root, under that vhost's
# certificate — 404s over h3 for paths that served 200 over h2. The fixture is
# that exact shape, with disjoint roots so the fall-through cannot pass quietly.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-mixed.json
    mixed_pid=$SRV_PID
    out=$(python3 test/quic/h3_locations_test.py ${P61461} 2>&1)
    [ "$out" = "OK" ]
    check "h3 routes to locations: own root, longest prefix, 502 on proxy ($out)" $?
    # the same paths over h2, which has always routed: the two must agree
    body=$(curl -s --http2 --max-time 6 --cacert test/tls/server.crt \
                https://localhost:${P61461}/page.html)
    case "$body" in *"subdirectory page"*) true ;; *) false ;; esac
    check "h3/h2 agree on the mixed vhost's own root" $?
    kill $mixed_pid 2>/dev/null
    wait $mixed_pid 2>/dev/null
else
    check "h3 location routing (skipped: deps unavailable)" 0
fi

# Dual-stack IPv6: one AF_INET6 listener (host "::", IPV6_V6ONLY off) serves both
# families. A full h3 GET must complete over native IPv6 (::1) AND over IPv4
# (127.0.0.1) against that single listener — the native-v6 peer also exercises the
# 28-byte sockaddr_in6 handling on the receive, conn.peer and sendto-reply paths.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-v6.json
    P61455=$SRV_PORT
    v6_pid=$SRV_PID
    python3 test/quic/h3_ipv6_test.py ${P61455} >/dev/null 2>&1
    check "h3 (io_uring): dual-stack — served over native IPv6 (::1) and IPv4" $?
    # TCP too: the same dual-stack socket answers HTTP/2 over native IPv6
    body=$(curl -s --http2 --cacert test/tls/server.crt \
                 --resolve localhost:${P61455}:[::1] \
                 https://localhost:${P61455}/hello.txt)
    [ "$body" = "hello from linnea" ]
    check "h3 (io_uring): dual-stack — HTTP/2 over TCP served on native IPv6" $?
    kill $v6_pid 2>/dev/null
    wait $v6_pid 2>/dev/null
    rm -f $RUNDIR/linnea.log
else
    check "dual-stack IPv6 test (skipped: deps unavailable)" 0
fi

# Q134: a trailing HEADERS frame (trailers) must not merge into the request
# and change the response — a trailer "range: bytes=0-4" used to turn a
# whole-file GET into a 206.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-drain.json
    P61453=$SRV_PORT
    tr_master=$SRV_PID
    tr_workers=$(workers_of_now $tr_master)
    timeout 60 python3 test/quic/h3_trailer_test.py ${P61453} >/dev/null 2>&1
    check "h3 (io_uring): trailers do not influence the response" $?
    # Q136: frames illegal on a request stream (reserved h2 types, control/push
    # frames, DATA before HEADERS) are a connection error H3_FRAME_UNEXPECTED,
    # not silently ignored; GREASE/unknown stay ignored.
    timeout 90 python3 test/quic/h3_frame_reject_test.py ${P61453} >/dev/null 2>&1
    check "h3 (io_uring): illegal request-stream frames rejected (0x105)" $?
    kill $tr_master 2>/dev/null
    wait $tr_master 2>/dev/null
    reap_workers $tr_workers
    rm -f $RUNDIR/linnea.log
fi

# HTTP/3 GOAWAY on drain: a worker told to drain sends GOAWAY on its control
# stream so the client opens no new requests, then exits. A single-worker config
# keeps the signalling deterministic; the test kills the master itself.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-drain.json
    P61453=$SRV_PORT
    ga_master=$SRV_PID
    ga_workers=$(workers_of_now $ga_master)
    python3 test/quic/h3_goaway_test.py ${P61453} $ga_master >/dev/null 2>&1
    check "h3 (io_uring): drain sends GOAWAY on the control stream" $?
    # Q120: the request that test served must be in the access log
    grep -qE 'request localhost from [0-9.:]+ "GET /hello.txt HTTP/3" 200 ' $RUNDIR/linnea.log
    check "h3 request access-logged" $?
    wait $ga_master 2>/dev/null
    reap_workers $ga_workers
    rm -f $RUNDIR/linnea.log
else
    check "h3 GOAWAY drain test (skipped: deps unavailable)" 0
fi

# A STOP must tell h3 peers, not merely vanish. SIGTERM exits at once — there
# is nothing to drain — but a QUIC connection that goes silent leaves its peer
# to an idle timeout, and a browser reads repeated unexplained losses as the
# origin's h3 being unreliable. One CONNECTION_CLOSE each fixes that without
# making the stop slower.
if python3 -c 'import aioquic' 2>/dev/null; then
    start_server $CFG/tls-h3-drain.json
    P61453=$SRV_PORT
    sc_master=$SRV_PID
    out=$(timeout 40 python3 test/quic/h3_stop_close_test.py ${P61453} $sc_master 2>&1)
    case "$out" in OK*) true ;; *) false ;; esac
    check "h3 (io_uring): a stop closes peers instead of vanishing ($out)" $?
    kill -9 $sc_master 2>/dev/null
    wait $sc_master 2>/dev/null
else
    check "h3 stop-close test (skipped: deps unavailable)" 0
fi

# Drain with an in-flight h3 response (Q117): the drain-exit test used to count
# only TCP connections, so a worker whose work was all QUIC exited the moment
# the drain began (and stopped re-arming the datagram recv besides) — the peer
# hung mid-download with nothing on the wire to tell it. Now the worker keeps
# receiving, finishes the response, says goodbye with CONNECTION_CLOSE
# (H3_NO_ERROR), and only then exits.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-drain.json
    P61453=$SRV_PORT
    di_master=$SRV_PID
    di_workers=$(workers_of_now $di_master)
    timeout 40 python3 test/quic/h3_drain_inflight_test.py ${P61453} $di_master >/dev/null 2>&1
    check "h3 (io_uring): drain finishes the in-flight response, then closes" $?
    wait $di_master 2>/dev/null
    # the drain must END: wait for OUR workers to go, by pid. A pattern here
    # asserted that no such server exists anywhere, which a suite running
    # beside this one falsified while draining perfectly correctly.
    workers_gone $di_workers
    check "h3 drain exits after the last QUIC connection" $?
    rm -f $RUNDIR/linnea.log
else
    check "h3 in-flight drain test (skipped: deps unavailable)" 0
fi

# GOAWAY must stop processing what it disowns (h3-7, RFC 9114 5.2): on a
# draining connection a request at/above the GOAWAY's stream id draws
# RESET_STREAM(H3_REQUEST_REJECTED), not a response — else a client that
# retried it elsewhere (as the GOAWAY instructs) runs it twice. The window
# only exists on a connection the drain sweep left alive, so the test holds a
# stalled response in flight across the drain, then checks the disowned
# stream is rejected AND the in-flight response still completes.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-drain.json
    P61453=$SRV_PORT
    gr_master=$SRV_PID
    gr_workers=$(workers_of_now $gr_master)
    timeout 60 python3 test/quic/h3_goaway_reject_test.py ${P61453} $gr_master >/dev/null 2>&1
    check "h3 (io_uring): drain rejects disowned streams (0x10b), serves owned" $?
    kill $gr_master 2>/dev/null
    wait $gr_master 2>/dev/null
    reap_workers $gr_workers
    rm -f $RUNDIR/linnea.log
else
    check "h3 GOAWAY reject test (skipped: deps unavailable)" 0
fi

# Steering handoff across a hot upgrade (Q118): a master handed the previous
# generation's bpf map+program in LINNEA_UPGRADE stamps its connection ids from
# the other half of the index space (base 64), so the draining generation's
# connections keep steering to their workers; unusable inherited fds cost only
# the steering. The script plays the old master itself (inherited listener,
# zombie old-worker pid, pipe fds standing in for the bpf pair).
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    timeout 30 python3 test/quic/h3_steer_base_test.py \
        $CFG/tls-h3-drain.json ${P61453} >/dev/null 2>&1
    check "h3 (io_uring): upgrade handoff stamps the other steering half" $?
    rm -f $RUNDIR/linnea.log
else
    check "h3 steering handoff test (skipped: deps unavailable)" 0
fi

# Drain with an in-flight h2 response and a slow reader (Q117): the connection
# was freed once the last body byte reached the kernel, and close(2) with the
# client's unread WINDOW_UPDATEs queued answered with an RST that discarded
# the untransmitted tail of the send buffer — ~90% of the body arrived, then a
# reset. The lingering close (shutdown the write side, drain reads until the
# peer closes) delivers every byte.
rm -f $RUNDIR/linnea.log
python3 -c "open('$WWW/h2drain.bin','wb').write(bytes(3000000))"
start_server $CFG/tls-h3-drain.json
P61453=$SRV_PORT
h2d_master=$SRV_PID
timeout 60 python3 test/tls/h2_drain_slow.py test/tls/server.crt ${P61453} $h2d_master >/dev/null 2>&1
check "http2 drain delivers the whole in-flight body to a slow reader" $?
wait $h2d_master 2>/dev/null
rm -f $RUNDIR/linnea.log $WWW/h2drain.bin

# Large certificate chain (~5.2 KB, seven certs — over the old ~3.9 KB cap) on
# both transports. On h3 the flight is both larger than one datagram (QUIC forbids
# IP fragmentation, so the Certificate CRYPTO is split across <=MTU Handshake
# packets) and larger than the 3x amplification budget (RFC 9000 s8.1, so the tail
# is withheld until the client's address is validated, then resumed): the test
# confirms the first burst stays within 3x, no datagram breaches the 1200-byte
# floor, and the handshake completes. That the server even boots with this chain
# exercises the raised cap; the curl check confirms the same chain over h2/TCP.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    rm -f $RUNDIR/linnea.log
    start_server $CFG/tls-h3-bigcert.json
    P61454=$SRV_PORT
    bc_pid=$SRV_PID
    sleep 0.6
    python3 test/quic/h3_bigcert_test.py ${P61454} >/dev/null 2>&1
    check "h3 (io_uring): large flight segmented + held to the 3x amp budget" $?
    body=$(curl -s --http2 --cacert test/tls/bigchain.crt \
                --resolve localhost:${P61454}:127.0.0.1 https://localhost:${P61454}/hello.txt)
    [ "$body" = "hello from linnea" ]
    check "h2 (kTLS): large certificate chain over TCP (past the old cap)" $?
    kill $bc_pid 2>/dev/null
    wait $bc_pid 2>/dev/null
    rm -f $RUNDIR/linnea.log
else
    check "h3 handshake segmentation/amplification test (skipped: deps unavailable)" 0
fi

# Acknowledgements: our reply must acknowledge the request packet, or the peer
# keeps retransmitting work already done.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_ack_test.py ${P61501} >/dev/null 2>&1
    check "quic: replies acknowledge the packets we received" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "quic ack test (skipped: deps unavailable)" 0
fi

# Connection churn: more connections than the pool has slots, each closing
# cleanly, must all be served — the slot has to come back on CONNECTION_CLOSE.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 60 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_churn_test.py ${P61501} 100 >/dev/null 2>&1
    check "quic: 100 connections through a 64-slot pool (close frees the slot)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "quic churn test (skipped: deps unavailable)" 0
fi

# Connection pool: two connections whose handshakes and requests are fully
# interleaved must not share keys, transcript, connection ids or packet numbers.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null && [ -x ./bin/linnea-quichs ]; then
    timeout 10 ./bin/linnea-quichs ${P61501} >/dev/null 2>&1 &
    hspid=$!
    sleep 0.4
    python3 test/quic/h3_conns_test.py ${P61501} >/dev/null 2>&1
    check "quic: two interleaved connections keep separate state (pool demux)" $?
    kill $hspid 2>/dev/null
    wait $hspid 2>/dev/null
else
    check "quic connection-pool test (skipped: deps unavailable)" 0
fi

# --- HTTP tests against a running server ---
rm -f "$LOG"
# A file spanning several pages: every other fixture fits in one, which is
# exactly what let a wrong mmap length go unnoticed.
python3 -c "open('$WWW/big.txt','w').write('B'*100000)"
# Pre-compressed variants. Each one holds different text, so a test can
# tell which file was served; real deployments would compress the same
# bytes. The .gz is real gzip (curl --compressed decodes it); the .br is
# not real brotli, which linnea neither produces nor inspects.
python3 - "$WWW" <<'PY'
import gzip, sys
W = sys.argv[1]                      # the run's own document root
open(W + '/enc.txt', 'w').write('plain payload')
with gzip.open(W + '/enc.txt.gz', 'wb') as f:
    f.write(b'gzip payload')
open(W + '/enc.txt.br', 'wb').write(b'br payload')
PY
# The suite runs two backends in turn, both on 61100: one for the plain-HTTP
# block and a second for the TLS block. SO_REUSEADDR lets the second past a
# TIME_WAIT, but not past a first that is still listening — and the backend's
# output goes to /dev/null, so a failed bind is invisible until every proxied
# request in the rest of the run answers 502. Seen once: 23 failures, all
# proxy, none reproducible. Wait for it to actually accept.
# It used to WARN and carry on. That is how ten proxy tests come to fail at once
# with 502s that say nothing about the cause: every proxied request in the block
# is answered by a server with no backend behind it. Same rule as start_server --
# a fixture that did not come up makes every result after it meaningless, so stop.
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

SEEN=$RUNDIR/linnea_backend_seen.log       # what actually reached a backend
rm -f "$SEEN"
python3 test/proxy_backend.py >/dev/null 2>&1 &
backend_pid=$!
backend_ready
# The websocket backend, twice: 61701 is spoken to directly, 61702 sits behind
# linnea's /ws location. Two instances rather than one, so the counter each
# battery sees is its own and the two runs cannot perturb each other.
./bin/linnea-ws ${P61701} >/dev/null 2>&1 &
ws_direct_pid=$!
./bin/linnea-ws ${P61702} >/dev/null 2>&1 &
ws_proxy_pid=$!
for _ in $(seq 1 60); do
    (echo > /dev/tcp/127.0.0.1/${P61701}) >/dev/null 2>&1 && \
    (echo > /dev/tcp/127.0.0.1/${P61702}) >/dev/null 2>&1 && break
    sleep 0.1
done
start_server $CFG/listen.json
server_pid=$SRV_PID
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
# The request carries literal \r\n escapes; raw_http.py expands them.
raw_http() {
    # See test/raw_http.py: the bash /dev/tcp one-liner this replaces gave the
    # connect, the write and the read a single two-second budget, and `cat` only
    # ever escaped a keep-alive response by being killed at the deadline. Under
    # load the deadline beat the response and the test saw an empty string with
    # its stderr discarded — a flake that cost this suite a different test on
    # three separate runs and reproduced on none of them in isolation.
    python3 test/raw_http.py "$1"
}

# --- log file ---
grep -q "listening on 127.0.0.1:${P61080} (one.test)" "$LOG"
check "log listening line" $?
n=$(grep -c "listening on 127.0.0.1:${P61080}" "$LOG")
[ "$n" -eq 1 ]
check "shared listener bound once" $?

# --- bind conflict against the running server ---
run_test "address in use"  1 stderr "cannot bind to 127.0.0.1:${P61080} (errno 98)" \
    $BIN --config $CFG/dup-bind.json

# --- static file serving ---
resp=$(curl -s --max-time 2 http://127.0.0.1:${P61080}/hello.txt)
check_http "file txt body"     "hello from linnea" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/hello.txt)
check_http "file txt mime"     "Content-Type: text/plain" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/)
check_http "index html body"   "linnea index page" "$resp"
check_http "index html mime"   "Content-Type: text/html" "$resp"

# --- redirect location: 301 with the raw request target appended ---
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61090}/old)
check_http "redirect status"   "301 Moved Permanently" "$resp"
check_http "redirect location" "Location: https://example.com/old" "$resp"
check_http "redirect no body"  "Content-Length: 0" "$resp"
resp=$(curl -si --max-time 2 "http://127.0.0.1:${P61090}/old/a%20b?x=1&y=2")
check_http "redirect keeps raw path+query" "Location: https://example.com/old/a%20b?x=1&y=2" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/style.css)
check_http "css mime"          "Content-Type: text/css" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/favicon.ico)
check_http "ico mime"          "Content-Type: image/x-icon" "$resp"
resp=$(curl -s --max-time 2 http://127.0.0.1:${P61090}/sub/page.html)
check_http "subdirectory file" "subdirectory page" "$resp"

# --- location routing: 61090 has "/" -> test/www/sub and "/sub" -> test/www ---
resp=$(curl -s --max-time 2 http://127.0.0.1:${P61090}/page.html)
check_http "location root match"  "subdirectory page" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61090}/hello.txt)
check_http "location root scopes" "404 Not Found" "$resp"
# /sub/page.html matches the longer "/sub" prefix (root test/www), not "/"
resp=$(curl -s --max-time 2 http://127.0.0.1:${P61090}/sub/page.html)
check_http "longest prefix wins"  "subdirectory page" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/no-such-file)
check_http "http 404"          "404 Not Found" "$resp"
resp=$(curl -si --max-time 2 -I http://127.0.0.1:${P61080}/hello.txt)
check_http "HEAD length"       "Content-Length: 18" "$resp"
resp=$(curl -si --max-time 2 -X POST http://127.0.0.1:${P61080}/hello.txt)
check_http "http 405"          "405 Method Not Allowed" "$resp"

# a file larger than one page: the mapped length must be the whole file
n=$(curl -s --max-time 5 http://127.0.0.1:${P61080}/big.txt | wc -c)
[ "$n" -eq 100000 ]
check "large file length ($n bytes)" $?
junk=$(curl -s --max-time 5 http://127.0.0.1:${P61080}/big.txt | tr -d 'B' | wc -c)
[ "$junk" -eq 0 ]
check "large file intact" $?

# --- caching: ETag / Last-Modified and conditional requests ---
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/hello.txt)
check_http "etag present"        "ETag: \"" "$resp"
check_http "last-modified present" "Last-Modified: " "$resp"
printf '%s' "$resp" | grep -qE '^ETag: "[0-9a-f]+-12"'
check "etag is mtime-size in hex" $?
printf '%s' "$resp" | grep -qE '^Last-Modified: [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT'
check "last-modified is an HTTP date" $?
check_http "server header"       "Server: linnea" "$resp"
printf '%s' "$resp" | grep -qE '^Date: [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT'
check "date is an HTTP date" $?
check_http "cache-control from config" "Cache-Control: max-age=60" "$resp"
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/no-such-file)
check_http "404 server header"   "Server: linnea" "$resp"

resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/hello.txt)
etag=$(printf '%s' "$resp" | grep -i '^etag:' | tr -d '\r' | cut -d' ' -f2)
lastmod=$(printf '%s' "$resp" | grep -i '^last-modified:' | tr -d '\r' | cut -d' ' -f2-)

resp=$(curl -si --max-time 2 -H "If-None-Match: $etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-none-match 304"   "304 Not Modified" "$resp"
check_http "304 repeats etag"    "ETag: $etag" "$resp"
check_http "304 keeps alive"     "Connection: keep-alive" "$resp"
check_http "304 server header"   "Server: linnea" "$resp"
check_http "304 date header"     "Date: " "$resp"
check_http "304 repeats cache-control" "Cache-Control: max-age=60" "$resp"
printf '%s' "$resp" | grep -qF "hello from linnea"
[ $? -ne 0 ]
check "304 carries no body" $?
# a 304 that cost a new connection each time would defeat revalidation
before=$(grep -c "accepted connection" "$LOG")
curl -s --max-time 4 -H "If-None-Match: $etag" -o /dev/null \
    http://127.0.0.1:${P61080}/hello.txt http://127.0.0.1:${P61080}/hello.txt
after=$(grep -c "accepted connection" "$LOG")
[ $((after - before)) -eq 1 ]
check "304 single accept" $?

resp=$(curl -si --max-time 2 -H 'If-None-Match: "stale"' http://127.0.0.1:${P61080}/hello.txt)
check_http "stale etag 200"      "hello from linnea" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: W/$etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "weak etag 304"       "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H 'If-None-Match: *' http://127.0.0.1:${P61080}/hello.txt)
check_http "if-none-match star"  "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: \"a\", W/\"b\", $etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "etag list 304"       "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -I -H "If-None-Match: $etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "HEAD 304"            "304 Not Modified" "$resp"

resp=$(curl -si --max-time 2 -H "If-Modified-Since: $lastmod" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-modified-since 304" "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -z "$lastmod" http://127.0.0.1:${P61080}/hello.txt)
check_http "curl time-cond 304"  "304 Not Modified" "$resp"
resp=$(curl -si --max-time 2 -H "If-Modified-Since: Wed, 01 Jan 2020 00:00:00 GMT" http://127.0.0.1:${P61080}/hello.txt)
check_http "older date 200"      "hello from linnea" "$resp"
# an unparseable date must be ignored, not treated as a condition
resp=$(curl -si --max-time 2 -H "If-Modified-Since: not a date" http://127.0.0.1:${P61080}/hello.txt)
check_http "bad date ignored"    "hello from linnea" "$resp"
# An rfc850 date now PARSES (RFC 9110 5.6.7); 1994 is simply older than the
# file, so the body is still what comes back. The name said "ignored" when the
# format was rejected outright — the outcome is the same, the reason is not.
resp=$(curl -si --max-time 2 -H "If-Modified-Since: Sunday, 06-Nov-94 08:49:37 GMT" http://127.0.0.1:${P61080}/hello.txt)
check_http "rfc850 date parses, and 1994 is older" "hello from linnea" "$resp"
# If-None-Match wins outright when both are present
resp=$(curl -si --max-time 2 -H 'If-None-Match: "x"' -H "If-Modified-Since: $lastmod" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-none-match wins"  "hello from linnea" "$resp"

grep -qF '"GET /hello.txt HTTP/1.1" 304 0' "$LOG"
check "request log 304" $?

# --- pre-compressed variants: enc.txt has both a .br and a .gz beside it ---
# enc_of <accept-encoding> — the Content-Encoding linnea picked, if any.
# grep -a: the gzip variant's body is binary.
enc_of() {
    curl -si --max-time 2 -H "Accept-Encoding: $1" http://127.0.0.1:${P61080}/enc.txt \
        | grep -a -io '^content-encoding: .*' | tr -d '\r' | cut -d' ' -f2
}
body_of() {
    curl -s --max-time 2 -H "Accept-Encoding: $1" http://127.0.0.1:${P61080}/enc.txt
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
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/enc.txt)
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
# h1-14: RFC 9110 5.3 makes repeated field lines equivalent to the comma-joined
# value, so a client may split its codings over several Accept-Encoding lines.
# Taking only the first dropped every coding after it — "identity" then "br"
# served the plain file. Each line is now its own span and a coding is taken if
# any of them accepts it, which is the answer joining them would have given.
enc_of2() {
    curl -si --max-time 2 -H "Accept-Encoding: $1" -H "Accept-Encoding: $2" \
        http://127.0.0.1:${P61080}/enc.txt \
        | grep -ai '^content-encoding' | tr -d '\r' | sed 's/.*: //'
}
[ "$(enc_of2 'identity' 'br')" = "br" ]
check "split accept-encoding: the second line is honoured" $?
[ "$(enc_of2 'identity' 'gzip')" = "gzip" ]
check "split accept-encoding: gzip on the second line" $?
[ "$(enc_of2 'gzip' 'br')" = "br" ]
check "split accept-encoding: br still preferred over gzip" $?
# the type comes from the name before the suffix, not from ".br"
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' http://127.0.0.1:${P61080}/enc.txt)
check_http "type ignores the suffix" "Content-Type: text/plain" "$resp"
check_http "variant length"          "Content-Length: 10" "$resp"
check_http "variant vary"            "Vary: Accept-Encoding" "$resp"
# h1-15: a variant with no plain file beside it is served to whoever takes the
# encoding and 404s everyone else, so the miss is content-negotiated too. If
# that 404 omits Vary, a shared cache stores it under the bare URL and then
# hands it to the very clients the variant was for — the 200 becomes
# unreachable through the cache. Both answers must agree on Vary.
printf 'br only payload' > $WWW/varonly.txt.br
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' http://127.0.0.1:${P61080}/varonly.txt)
check_http "variant-only file served to a br client" "HTTP/1.1 200" "$resp"
check_http "variant-only 200 varies"                 "Vary: Accept-Encoding" "$resp"
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: identity' http://127.0.0.1:${P61080}/varonly.txt)
check_http "variant-only 404s a client that cannot take it" "HTTP/1.1 404" "$resp"
check_http "that 404 varies too (h1-15)"                    "Vary: Accept-Encoding" "$resp"
rm -f $WWW/varonly.txt.br
# curl decoding the real gzip end to end
[ "$(curl -s --max-time 2 --compressed -H 'Accept-Encoding: gzip' http://127.0.0.1:${P61080}/enc.txt)" = "gzip payload" ]
check "gzip variant decodes" $?
# a file with no variants must not claim an encoding, but still varies
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip, br' http://127.0.0.1:${P61080}/hello.txt)
printf '%s' "$resp" | grep -qai '^content-encoding'
[ $? -ne 0 ]
check "no variant, no coding" $?
check_http "no variant still varies" "Vary: Accept-Encoding" "$resp"
check_http "no variant serves plain" "hello from linnea" "$resp"

# Each variant is its own representation: a cache must never hand one to a
# client that asked for another, so the validators have to differ.
etag_br=$(curl -si --max-time 2 -H 'Accept-Encoding: br' http://127.0.0.1:${P61080}/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
etag_gz=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip' http://127.0.0.1:${P61080}/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
etag_pl=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/enc.txt | grep -ai '^etag:' | tr -d '\r' | cut -d' ' -f2)
[ -n "$etag_br" ] && [ "$etag_br" != "$etag_gz" ] && [ "$etag_gz" != "$etag_pl" ] && [ "$etag_br" != "$etag_pl" ]
check "each variant has its own etag" $?
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' -H "If-None-Match: $etag_br" http://127.0.0.1:${P61080}/enc.txt)
check_http "variant revalidates 304" "304 Not Modified" "$resp"
check_http "variant 304 varies"      "Vary: Accept-Encoding" "$resp"
printf '%s' "$resp" | grep -qai '^content-encoding'
[ $? -ne 0 ]
check "variant 304 omits the coding" $?
# the br etag says nothing about the gzip or plain representations
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: gzip' -H "If-None-Match: $etag_br" http://127.0.0.1:${P61080}/enc.txt)
check_http "cross-variant etag 200" "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H "If-None-Match: $etag_br" http://127.0.0.1:${P61080}/enc.txt)
check_http "variant etag vs plain 200" "plain payload" "$resp"

# --- Range requests: hello.txt is the 18 bytes "hello from linnea\n" ---
resp=$(curl -si --max-time 2 -r 0-4 http://127.0.0.1:${P61080}/hello.txt)
check_http "range 206"           "206 Partial Content" "$resp"
check_http "range content-range" "Content-Range: bytes 0-4/18" "$resp"
check_http "range length"        "Content-Length: 5" "$resp"
printf '%s' "$resp" | grep -qF "hello from"
[ $? -ne 0 ]
check "range body is the slice" $?
check_http "range body"          "hello" "$resp"
resp=$(curl -s --max-time 2 -r 6- http://127.0.0.1:${P61080}/hello.txt)
[ "$resp" = "from linnea" ]     # the trailing newline is byte 17
check "range open end" $?
resp=$(curl -s --max-time 2 -r -7 http://127.0.0.1:${P61080}/hello.txt)
[ "$resp" = "linnea" ]
check "range suffix" $?
resp=$(curl -si --max-time 2 -r 0-0 http://127.0.0.1:${P61080}/hello.txt)
check_http "range single byte"   "Content-Range: bytes 0-0/18" "$resp"
check_http "range single length" "Content-Length: 1" "$resp"
# a last past the end means "to the end"
resp=$(curl -si --max-time 2 -H 'Range: bytes=6-9999' http://127.0.0.1:${P61080}/hello.txt)
check_http "range clamped last"  "Content-Range: bytes 6-17/18" "$resp"
# a suffix longer than the file is the whole file, still a 206
resp=$(curl -si --max-time 2 -H 'Range: bytes=-9999' http://127.0.0.1:${P61080}/hello.txt)
check_http "range long suffix"   "Content-Range: bytes 0-17/18" "$resp"
# 200s advertise the support
resp=$(curl -si --max-time 2 http://127.0.0.1:${P61080}/hello.txt)
check_http "accept-ranges"       "Accept-Ranges: bytes" "$resp"
# unsatisfiable: starts at or past the end -> 416 naming the length
resp=$(curl -si --max-time 2 -H 'Range: bytes=99-' http://127.0.0.1:${P61080}/hello.txt)
check_http "range 416"           "416 Range Not Satisfiable" "$resp"
check_http "416 content-range"   "Content-Range: bytes */18" "$resp"
check_http "416 keeps alive"     "Connection: keep-alive" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=-0' http://127.0.0.1:${P61080}/hello.txt)
check_http "range -0 is 416"     "416 Range Not Satisfiable" "$resp"
# not understood -> ignored -> the full 200
resp=$(curl -si --max-time 2 -H 'Range: bytes=5-2' http://127.0.0.1:${P61080}/hello.txt)
check_http "backwards range 200" "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=abc' http://127.0.0.1:${P61080}/hello.txt)
check_http "garbage range 200"   "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: potatoes=0-4' http://127.0.0.1:${P61080}/hello.txt)
check_http "other unit 200"      "200 OK" "$resp"
resp=$(curl -si --max-time 2 -H 'Range: bytes=0-1,3-4' http://127.0.0.1:${P61080}/hello.txt)
check_http "several ranges 200"  "200 OK" "$resp"
check_http "several ranges full" "Content-Length: 18" "$resp"
# Range is defined for GET alone
resp=$(curl -si --max-time 2 -I -H 'Range: bytes=0-4' http://127.0.0.1:${P61080}/hello.txt)
check_http "HEAD ignores range"  "200 OK" "$resp"
check_http "HEAD full length"    "Content-Length: 18" "$resp"
# the conditionals still win over Range
resp=$(curl -si --max-time 2 -r 0-4 -H "If-None-Match: $etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "range vs 304"        "304 Not Modified" "$resp"
# If-Range: the range only with a strong validator match
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: $etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-range match 206"  "206 Partial Content" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H 'If-Range: "stale"' http://127.0.0.1:${P61080}/hello.txt)
check_http "if-range stale 200"  "200 OK" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: W/$etag" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-range weak 200"   "200 OK" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H "If-Range: $lastmod" http://127.0.0.1:${P61080}/hello.txt)
check_http "if-range date 206"   "206 Partial Content" "$resp"
resp=$(curl -si --max-time 2 -r 0-4 -H 'If-Range: Wed, 01 Jan 2020 00:00:00 GMT' http://127.0.0.1:${P61080}/hello.txt)
check_http "if-range old date 200" "200 OK" "$resp"
# ranges hold on big files and on pre-compressed variants
n=$(curl -s --max-time 5 -r 90000-99999 http://127.0.0.1:${P61080}/big.txt | tr -d 'B' | wc -c)
[ "$n" -eq 0 ] && [ "$(curl -s --max-time 5 -r 90000-99999 http://127.0.0.1:${P61080}/big.txt | wc -c)" -eq 10000 ]
check "range into big file" $?
resp=$(curl -si --max-time 2 -H 'Accept-Encoding: br' -r 0-1 http://127.0.0.1:${P61080}/enc.txt)
check_http "variant range slices variant" "Content-Range: bytes 0-1/10" "$resp"
check_http "variant range body"  "br" "$resp"
# two ranged requests ride one keep-alive connection
before=$(grep -c "accepted connection" "$LOG")
curl -s --max-time 4 -r 0-4 \
    http://127.0.0.1:${P61080}/hello.txt http://127.0.0.1:${P61080}/hello.txt >/dev/null
after=$(grep -c "accepted connection" "$LOG")
[ $((after - before)) -eq 1 ]
check "206 keep-alive single accept" $?
grep -qF '"GET /hello.txt HTTP/1.1" 206 5' "$LOG"
check "request log 206" $?
grep -qF '"GET /hello.txt HTTP/1.1" 416 0' "$LOG"
check "request log 416" $?

# --- virtual hosts: 61080 is shared by one.test (default) and three.test ---
resp=$(curl -s --max-time 2 -H "Host: three.test" http://127.0.0.1:${P61080}/page.html)
check_http "vhost three.test"  "subdirectory page" "$resp"
resp=$(curl -s --max-time 2 -H "Host: three.test:${P61080}" http://127.0.0.1:${P61080}/page.html)
check_http "vhost host:port"   "subdirectory page" "$resp"
resp=$(curl -s --max-time 2 -H "Host: unknown.test" http://127.0.0.1:${P61080}/hello.txt)
check_http "vhost default"     "hello from linnea" "$resp"

# --- percent-decoding ---
resp=$(curl -s --max-time 2 "http://127.0.0.1:${P61080}/a%20b.txt")
check_http "decode space"      "space file" "$resp"
resp=$(curl -s --max-time 2 "http://127.0.0.1:${P61080}/sub%2Fpage.html")
check_http "decode slash"      "subdirectory page" "$resp"
check_http "encoded traversal" "400 Bad Request" "$(raw_http 'GET /%2e%2e/secret HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "bad escape"        "400 Bad Request" "$(raw_http 'GET /%zz HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "encoded NUL"       "400 Bad Request" "$(raw_http 'GET /%00 HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# --- path normalization (raw, curl normalizes dot segments itself) ---
check_http "double slash"   "hello from linnea" "$(raw_http 'GET //hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dot segment"    "hello from linnea" "$(raw_http 'GET /./hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dotdot resolve" "hello from linnea" "$(raw_http 'GET /sub/../hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "dotdot to dir"  "linnea index page" "$(raw_http 'GET /sub/.. HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"
check_http "above root"     "400 Bad Request" "$(raw_http 'GET /a/../../x HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# --- request bodies ---
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nContent-Length: 5\r\n\r\nXXXXXGET /hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')
n=$(printf '%s' "$resp" | grep -c "200 OK")
[ "$n" -eq 2 ]
check "body discarded, keep-alive" $?
# Chunked bodies used to be 501 and this test asserted it. Receiving and
# decoding the coding is a MUST (RFC 9112 7.1), so the expectation moves with
# the behaviour: a complete chunked body is served, and a coding we genuinely do
# not implement is what keeps the 501.
check_http "chunked body decoded and served" "200 OK" "$(raw_http 'GET / HTTP/1.1\r\nHost: one.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n')"
check_http "an unimplemented coding is still 501" "501 Not Implemented" "$(raw_http 'GET / HTTP/1.1\r\nHost: one.test\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n')"
# A static location cannot stream a body, so one it cannot buffer with the
# head is refused; a proxy location streams the same body instead (below).
check_http "body too large 413" "413 Content Too Large" "$(raw_http 'GET / HTTP/1.1\r\nHost: one.test\r\nContent-Length: 20000\r\n\r\n')"

# --- protocol errors and traversal (raw, curl normalizes paths) ---
check_http "http 400" "400 Bad Request" "$(raw_http 'GARBAGE\r\n\r\n')"
# h1-11: HTTP/1.0 is SERVED, not refused. 505 is defined for a MAJOR version the
# server does not support (RFC 9110 15.6.6) and 1.0 shares major version 1 with
# 1.1, so refusing it was both a misuse of the code and an operational trap --
# health checkers and `curl -0` speak 1.0, and a 505 reads like a protocol fault
# rather than a version default. Only a major version we do not implement is 505
# now; a higher MINOR version is processed as 1.1, which is what RFC 9112 2.5
# asks for.
check_http "http/1.0 served" "200 OK" "$(raw_http 'GET /hello.txt HTTP/1.0\r\nHost: one.test\r\n\r\n')"
check_http "http/1.0 without Host served" "200 OK" "$(raw_http 'GET /hello.txt HTTP/1.0\r\n\r\n')"
check_http "http/1.1 without Host still 400" "400 Bad Request" "$(raw_http 'GET /hello.txt HTTP/1.1\r\n\r\n')"
check_http "http/1.2 processed as 1.1" "200 OK" "$(raw_http 'GET /hello.txt HTTP/1.2\r\nHost: one.test\r\n\r\n')"
check_http "http 505" "505 HTTP Version Not Supported" "$(raw_http 'GET / HTTP/2.0\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# 1.0 has no persistent connections unless the client asks for one, and "close"
# wins wherever it appears in the list (9.1) -- applying the tokens in order
# would let `close, keep-alive` reopen a connection the client had finished with.
check_http "http/1.0 defaults to close" "Connection: close" "$(raw_http 'GET /hello.txt HTTP/1.0\r\nHost: one.test\r\n\r\n')"
check_http "http/1.0 keep-alive honoured" "Connection: keep-alive" "$(raw_http 'GET /hello.txt HTTP/1.0\r\nHost: one.test\r\nConnection: keep-alive\r\n\r\n')"
check_http "http/1.0 close beats keep-alive whatever the order" "Connection: close" "$(raw_http 'GET /hello.txt HTTP/1.0\r\nHost: one.test\r\nConnection: close, keep-alive\r\n\r\n')"
check_http "http/1.1 close beats keep-alive whatever the order" "Connection: close" "$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close, keep-alive\r\n\r\n')"

# two requests on one 1.0 connection, which only works if keep-alive was real
ka10=$(raw_http 'GET /hello.txt HTTP/1.0\r\nHost: one.test\r\nConnection: keep-alive\r\n\r\nGET /hello.txt HTTP/1.0\r\nHost: one.test\r\nConnection: close\r\n\r\n')
[ "$(printf '%s' "$ka10" | grep -c '^HTTP/1.1 200')" = "2" ]
check "http/1.0 keep-alive serves a second request on the same connection" $?

# RFC 9110 10.1.1: a 100 (Continue) MUST NOT be sent to a 1.0 client, which would
# read the interim status as the final one. 1.1 must still get it.
exp11=$(raw_http 'POST /hello.txt HTTP/1.1\r\nHost: one.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n')
printf '%s' "$exp11" | grep -q '100 Continue'
check "http/1.1 Expect still draws 100 Continue" $?
# `grep -qv` would be the wrong test here: it asks "is there a line that does not
# match", which is FALSE for the empty response that passing actually produces --
# a 1.0 client gets nothing at all and the server waits for the body.
exp10=$(raw_http 'POST /hello.txt HTTP/1.0\r\nHost: one.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n')
! printf '%s' "$exp10" | grep -q '100 Continue'
check "http/1.0 Expect draws no 100 Continue" $?
check_http "traversal blocked" "400 Bad Request" "$(raw_http 'GET /../secret HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')"

# --- video MIME types (Q129): a .mp4 served as application/octet-stream is
# not played by a browser's <video> element, so the type is what makes a
# media file usable at all. Range handling is exercised elsewhere; what is
# checked here is the type, on a plain GET and on a 206.
printf 'not really a video' > $WWW/clip.mp4
resp=$(raw_http 'GET /clip.mp4 HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "mime: .mp4 is video/mp4" "Content-Type: video/mp4" "$resp"

# Q130: the types a modern site cannot do without. The first three are hard
# failures rather than cosmetics — WebAssembly refuses to instantiate without
# application/wasm, an ES module served as octet-stream is rejected outright
# under the nosniff we send, and a .htm answered as octet-stream downloads
# instead of rendering. Both tables are checked, since h1 and h2/h3 keep
# separate ones and a type added to only one is the likely mistake.
mime_probe() {                 # mime_probe <ext> <expected type>
    printf 'x' > "$WWW/probe.$1"
    resp=$(raw_http "GET /probe.$1 HTTP/1.1\r\nHost: one.test\r\n\r\n")
    check_http "mime: .$1 is $2" "Content-Type: $2" "$resp"
    rm -f "$WWW/probe.$1"
}
mime_probe wasm        application/wasm
mime_probe mjs         text/javascript
mime_probe htm         text/html
mime_probe woff2       font/woff2
mime_probe webp        image/webp
mime_probe avif        image/avif
mime_probe mp3         audio/mpeg
mime_probe pdf         application/pdf
mime_probe webmanifest application/manifest+json
mime_probe js          text/javascript
# Q131: the text types declare UTF-8. A page carries <meta charset> and is
# fine either way, but a .txt or .csv without it is left to whatever the
# browser guesses. Not on application/json: RFC 8259 defines JSON as UTF-8
# and its media type has no charset parameter at all.
mime_probe txt  'text/plain; charset=utf-8'
mime_probe csv  'text/csv; charset=utf-8'
mime_probe css  'text/css; charset=utf-8'
resp=$(raw_http 'GET /probe.json HTTP/1.1\r\nHost: one.test\r\n\r\n')
printf 'x' > $WWW/probe.json
resp=$(raw_http 'GET /probe.json HTTP/1.1\r\nHost: one.test\r\n\r\n')
printf '%s' "$resp" | grep -qi 'charset' && json_charset=1 || json_charset=0
[ "$json_charset" = 0 ]
check "mime: application/json carries no charset" $?
rm -f $WWW/probe.json
resp=$(raw_http 'GET /clip.mp4 HTTP/1.1\r\nHost: one.test\r\nRange: bytes=0-3\r\n\r\n')
check_http "mime: a 206 keeps the video type" "Content-Type: video/mp4" "$resp"
check_http "mime: the 206 is a real partial" "206 Partial Content" "$resp"
rm -f $WWW/clip.mp4

# --- request-target forms (Q127, RFC 9112 3.2). Only origin-form used to
# survive: absolute-form and "OPTIONS *" reached the path normalizer and came
# back 400. A server MUST accept absolute-form, and the authority it carries
# — not the Host header — identifies the resource.
resp=$(raw_http 'GET http://one.test/hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form served" "hello from linnea" "$resp"
resp=$(raw_http 'GET https://one.test/hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form (https scheme) served" "hello from linnea" "$resp"
resp=$(raw_http 'GET http://one.test HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form with no path is the root" "200 OK" "$resp"
# the target's authority wins over Host: three.test has its own root, which
# holds no hello.txt, so routing by it is visible as a 404
resp=$(raw_http 'GET http://three.test/hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form authority beats Host" "404" "$resp"
resp=$(raw_http 'GET http:///hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: absolute-form with an empty authority is 400" "400 Bad Request" "$resp"
# an HTTP/1.1 client must still send Host, even in absolute-form
resp=$(raw_http 'GET http://one.test/hello.txt HTTP/1.1\r\n\r\n')
check_http "target: absolute-form still requires a Host line" "400 Bad Request" "$resp"
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: OPTIONS * answered" "200 OK" "$resp"
check_http "target: OPTIONS * lists the methods" "Allow: GET, HEAD, OPTIONS" "$resp"
resp=$(raw_http 'GET * HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "target: asterisk with any other method is 400" "400 Bad Request" "$resp"
# the asterisk form used to be answered before the Host rules ran, so it was the
# one request that could arrive with no Host or two of them and still get a 200
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\n\r\n')
check_http "target: OPTIONS * without a Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\nHost: one.test\r\nHost: evil.test\r\n\r\n')
check_http "target: OPTIONS * with two Hosts is 400" "400 Bad Request" "$resp"
# ...and the same here: the body is decoded, so OPTIONS * answers about the
# server as it always should have. The 501 was the coding being refused.
resp=$(raw_http 'OPTIONS * HTTP/1.1\r\nHost: one.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n')
check_http "target: OPTIONS * with a chunked body is answered" "200 OK" "$resp"

# --- the method is a token (RFC 9110 9.1). The request-line parse only bounded
# it to printable ASCII, so every delimiter got through — including the double
# quote, which the access line writes the method inside, splitting its own
# quoted field. An unknown but well-formed method still parses as a method.
#
# Its ANSWER is 501, not 405: 15.6.2 makes 501 "the appropriate response when
# the server does not recognize the request method", where 405 says the method
# is known and merely not allowed here. These checks asserted 405 for both,
# which told a client PROPFIND was a real method this resource declines.
resp=$(raw_http 'PROPFIND /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: an unknown token method is 501, not 400" "501 Not Implemented" "$resp"
# RFC 9110 15.5.6: a 405 must name what the resource does take — so it is asked
# with a method we DO recognise
resp=$(raw_http 'POST /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a known method gets 405" "405 Method Not Allowed" "$resp"
check_http "method: the 405 carries Allow" "Allow: GET, HEAD" "$resp"
resp=$(raw_http '!#$%&\x27*+-.^_`|~ /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: every tchar punctuation is still a method" "501 Not Implemented" "$resp"
resp=$(raw_http 'GE"T /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a double quote is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GE/T /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a delimiter is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GE\x1bT /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: a control byte is 400" "400 Bad Request" "$resp"
# a method is case-sensitive (RFC 9110 9.1), so "get" is not GET — and not a
# method we recognise at all, which is 501
resp=$(raw_http 'get /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "method: lowercase get is 501, not a served file" "501 Not Implemented" "$resp"
# None of those reached the access log, which is what the quote could break.
# Matched through cat -v so the ESC shows as ^[, and with -F so the quote and
# the brackets are literal — "GE alone would match every ordinary GET line.
! cat -v "$LOG" | grep -qF -e '"GE"T' -e '"GE/T' -e '"GE^[T'
check "method: no malformed method reaches the access log" $?

# --- Host header rules (Q123, RFC 9112 3.2): every request we accept is
# HTTP/1.1, so exactly one Host field line is mandatory and its value must
# look like an authority. A missing or repeated Host used to be served
# normally — and a second Host is a smuggling primitive, since an
# intermediary may route on the other one.
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n')
check_http "host: one Host serves"  "200 OK" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\n\r\n')
check_http "host: missing Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nHost: evil.test\r\n\r\n')
check_http "host: duplicate Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\nHost: one.test\r\n\r\n')
check_http "host: repeated identical Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost:\r\n\r\n')
check_http "host: empty Host is 400" "400 Bad Request" "$resp"
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one test\r\n\r\n')
check_http "host: Host with a space is 400" "400 Bad Request" "$resp"
resp=$(raw_http "GET /hello.txt HTTP/1.1\r\nHost: one.test:${P61080}\r\n\r\n")
check_http "host: Host with a port serves" "200 OK" "$resp"
resp=$(raw_http "GET /hello.txt HTTP/1.1\r\nHost: [::1]:${P61080}\r\n\r\n")
check_http "host: IPv6-literal Host serves" "200 OK" "$resp"
# the trailing OWS a field value may carry is trimmed before validation
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\t\r\n\r\n')
check_http "host: trailing OWS trimmed, not rejected" "200 OK" "$resp"
# a proxied location is routed only after the Host check
resp=$(raw_http 'GET /api/simple HTTP/1.1\r\n\r\n')
check_http "host: missing Host on a proxy location is 400" "400 Bad Request" "$resp"

# --- request log lines (with peer address) ---
grep -qE 'request one\.test from 127\.0\.0\.1:[0-9]+ "GET /hello\.txt HTTP/1\.1" 200 18' "$LOG"
check "request log 200" $?
grep -qE 'request three\.test from 127\.0\.0\.1:[0-9]+ "GET /page\.html HTTP/1\.1" 200' "$LOG"
check "request log vhost" $?
grep -qE '"GET /a%20b\.txt HTTP/1\.1" 200' "$LOG"
check "request log raw target" $?
grep -qF '"GET /no-such-file HTTP/1.1" 404 0' "$LOG"
check "request log 404" $?
grep -qF '"POST /hello.txt HTTP/1.1" 405 0' "$LOG"
check "request log 405" $?
grep -qE '^\[20[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\] request' "$LOG"
check "log timestamps" $?

# --- keep-alive: two requests, one connection (count accepts in the log) ---
before=$(grep -c "accepted connection" "$LOG")
resp=$(curl -s --max-time 4 http://127.0.0.1:${P61080}/hello.txt http://127.0.0.1:${P61080}/index.html)
after=$(grep -c "accepted connection" "$LOG")
check_http "keep-alive body 1" "hello from linnea" "$resp"
check_http "keep-alive body 2" "linnea index page" "$resp"
[ $((after - before)) -eq 1 ]
check "keep-alive single accept" $?

# --- pipelined requests in one write ---
resp=$(raw_http 'GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\nGET /hello.txt HTTP/1.1\r\nHost: one.test\r\nConnection: close\r\n\r\n')
n=$(printf '%s' "$resp" | grep -c "200 OK")
[ "$n" -eq 2 ]
check "pipelined requests" $?

# --- idle timeout: configured to 2s in listen.json ---
start=$SECONDS
if timeout 6 bash -c "exec 3<>/dev/tcp/127.0.0.1/${P61080}; cat <&3" >/dev/null 2>&1; then
    elapsed=$((SECONDS - start))
    [ "$elapsed" -ge 1 ] && [ "$elapsed" -le 4 ]
    check "configured idle timeout (${elapsed}s)" $?
else
    check "configured idle timeout (connection not closed)" 1
fi

grep -qE "accepted connection on 127\.0\.0\.1:${P61080} from 127\.0\.0\.1:[0-9]+ \(fd " "$LOG"
check "accept log line" $?

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
timeout 60 python3 test/tls/h1_proxy_hop_by_hop.py ${P61080} >/dev/null 2>&1
check "proxy removes hop-by-hop fields, both directions" $?

# RFC 9110 7.6.3 MUST: a proxy names itself and the protocol it received on, in
# each message it forwards. Without it a proxied request is indistinguishable
# from a direct one — no loop detection, and no way to tell which hop
# transformed a message.
timeout 60 python3 test/tls/proxy_via.py ${P61080} >/dev/null 2>&1
check "proxy adds Via to the request and the response" $?

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
timeout 60 python3 test/tls/connection_close_token.py ${P61080} >/dev/null 2>&1
check "Connection: close is honoured anywhere in the list" $?

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
timeout 120 python3 test/tls/h1_chunked_request.py ${P61080} >/dev/null 2>&1
check "h1 decodes chunked request bodies" $?

# a HEAD response is head-only even though the backend sends Content-Length:
# waiting for that body would hang until the idle timeout
resp=$(curl -si --max-time 3 -I http://127.0.0.1:${P61080}/api/simple)
check_http "proxy HEAD length"   "Content-Length: 12" "$resp"
check_http "proxy HEAD no hang"  "200 OK" "$resp"
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/204)
check_http "proxy 204 no body"   "204 No Content" "$resp"

# chunked and close-delimited bodies have no length we can pass on, so the
# client connection has to close to delimit them
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/chunked)
check_http "proxy chunked body"  "chunked body" "$resp"
check_http "proxy chunked framing" "Transfer-Encoding: chunked" "$resp"
check_http "proxy chunked closes" "Connection: close" "$resp"
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

# --- large uploads: a body too large to buffer with the head is captured in
# full (on disk, past what fits in memory) and only then forwarded, so it is
# bounded by max_body rather than by in_buf ---
python3 -c "
import random, sys
random.seed(11)
open('$WWW/upload.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
want=$(md5sum < $WWW/upload.bin | cut -d' ' -f1)
curl -s --max-time 30 --data-binary @$WWW/upload.bin \
    http://127.0.0.1:${P61080}/api/echo > $RUNDIR/upload_echo.bin
[ "$(md5sum < $RUNDIR/upload_echo.bin | cut -d' ' -f1)" = "$want" ]
check "proxy captures a 300000-byte request body (byte-exact)" $?
rm -f $RUNDIR/upload_echo.bin

# The point of capturing rather than relaying: a client that abandons its
# upload must leave the backend with NOTHING — not a truncated request it
# cannot distinguish from a complete one, and may already have acted on.
# Asserted against the backend's own record of what reached it, and the
# control below proves that record is being written.
python3 test/upload_abort.py >/dev/null
sleep 0.5
! grep -q ' /api/abandoned ' "$SEEN"
check "abandoned upload reaches the backend not at all" $?
grep -q ' /api/echo 300000$' "$SEEN"
check "backend record control (the completed upload IS in it)" $?

# --- chunked uploads too large to buffer: captured and decoded as they
# arrive, then forwarded as an ordinary counted request. Before this they were
# a 413 outright, since only the counted path could stream. ---
for m in big head bad abort cap flood twice; do
    out=$(python3 test/upload_chunked.py $m)
    [ "$out" = "OK" ]
    case $m in
      big)   check "chunked upload captured byte-exact through ragged framing ($out)" $? ;;
      head)  check "chunked upload reaches the backend counted, not chunked ($out)" $? ;;
      bad)   check "chunked upload with a bad chunk size is 400 ($out)" $? ;;
      abort) check "abandoned chunked upload reaches the backend not at all ($out)" $? ;;
      cap)   check "chunked upload past max_body is 413, not a reset ($out)" $? ;;
      flood) check "endless chunked trailers hit max_body too ($out)" $? ;;
      twice) check "two chunked captures on one kept-alive connection ($out)" $? ;;
    esac
done

# The rewritten upstream head goes into up_buf behind ONE up-front bound, and
# .append is an unchecked rep movsb — so a head that clears the bound but whose
# rewrite outgrows it runs off the end of the slot into the next connection.
# The bound has ~24 bytes of margin over everything the rewrite adds (Via, the
# Connection line, a Content-Length when a chunked one was dropped); this walks
# a head across the boundary in both framings and expects only 200 or 431.
out=$(python3 test/h1_upbuf_test.py ${P61080} 2>&1 | tail -1)
[ "$out" = "OK" ]
check "a proxied head at the up_buf boundary is served or refused ($out)" $?

# The same, counted: two captures on one connection. The bodies must DIFFER —
# with identical ones a second upload served out of the first one's file looks
# perfectly correct.
python3 -c "
import random
random.seed(31); open('$WWW/up1.bin','wb').write(bytes(random.getrandbits(8) for _ in range(200000)))
random.seed(41); open('$WWW/up2.bin','wb').write(bytes(random.getrandbits(8) for _ in range(250000)))"
curl -s --max-time 30 -o $RUNDIR/up1_echo.bin --data-binary @$WWW/up1.bin http://127.0.0.1:${P61080}/api/echo \
     --next -s --max-time 30 -o $RUNDIR/up2_echo.bin --data-binary @$WWW/up2.bin http://127.0.0.1:${P61080}/api/echo
[ "$(md5sum < $RUNDIR/up1_echo.bin | cut -d' ' -f1)" = "$(md5sum < $WWW/up1.bin | cut -d' ' -f1)" ] &&
[ "$(md5sum < $RUNDIR/up2_echo.bin | cut -d' ' -f1)" = "$(md5sum < $WWW/up2.bin | cut -d' ' -f1)" ]
check "two counted captures on one kept-alive connection" $?
rm -f $RUNDIR/up1_echo.bin $RUNDIR/up2_echo.bin $WWW/up1.bin $WWW/up2.bin

# max_body is what stands between one client and the filesystem, so it is
# refused on the declared length — before a byte of it is written anywhere.
resp=$(raw_http "POST /api/toobig HTTP/1.1\r\nHost: one.test\r\nContent-Length: 99999999999\r\n\r\n")
check_http "upload past max_body is 413" "413 Content Too Large" "$resp"
! grep -q ' /api/toobig ' "$SEEN"
check "the refused upload never reached the backend" $?

# --- proxied request log lines: upstream status, relayed byte count ---
grep -qE 'request one\.test from 127\.0\.0\.1:[0-9]+ "GET /api/simple HTTP/1\.1" 200 12' "$LOG"
check "proxy log 200" $?
grep -qF '"POST /api/echo HTTP/1.1" 200 10' "$LOG"
check "proxy log body bytes" $?
grep -qF '"GET /api/target?x=1&y=2 HTTP/1.1" 200' "$LOG"
check "proxy log query" $?
grep -qF '"GET /down/x HTTP/1.1" 502 0' "$LOG"
check "proxy log 502" $?
grep -qF '"GET /api/slow HTTP/1.1" 504 0' "$LOG"
check "proxy log 504" $?
grep -qF '"HEAD /api/simple HTTP/1.1" 200 0' "$LOG"
check "proxy log HEAD" $?

# --- websockets: upgrade passthrough and the full-duplex tunnel ---
out=$(python3 test/ws_client.py echo)
[ "$out" = "OK" ]
check "ws echo round trips ($out)" $?
out=$(python3 test/ws_client.py pipelined)
[ "$out" = "OK" ]
check "ws client bytes before the 101 ($out)" $?
out=$(python3 test/ws_client.py push)
[ "$out" = "OK" ]
check "ws server push and 101 leftover ($out)" $?
out=$(python3 test/ws_client.py tick)
[ "$out" = "OK" ]
check "ws one-way traffic outlives idle timeout ($out)" $?
out=$(python3 test/ws_client.py silent)
[ "$out" = "OK" ]
check "ws idle tunnel times out ($out)" $?
out=$(python3 test/ws_client.py reject)
[ "$out" = "OK" ]
check "ws upgrade refusal passes through ($out)" $?
# a 101 the client never asked for must not start a tunnel
resp=$(curl -si --max-time 3 http://127.0.0.1:${P61080}/api/101)
check_http "unrequested 101 becomes 502" "502 Bad Gateway" "$resp"
# ...and nothing open may hold up a stop. These two run their own servers,
# because they stop them — 61080 is serving the rest of the suite. The second
# waits out the 30s drain deadline, and is the slowest check in the file.
# linnea-ws heartbeats its clients rather than letting the proxy reap them on
# silence. Both halves are checked, and each is the other's control: a server
# that never reaped, and one that dropped everyone, each pass exactly one of
# them. ~50s, which is the price of a real 30s ping and its 15s grace.
hb=$(timeout 120 python3 test/ws_heartbeat_test.py ${P61701} 2>&1)
[ "$hb" = "OK" ]
check "ws: clients that answer the ping live, silent ones are dropped ($hb)" $?

out=$(python3 test/ws_drain_test.py)
[ "$out" = "OK" ]
check "a stop is immediate whatever is open ($out)" $?
out=$(python3 test/reload_deadline_test.py)
case "$out" in OK*) true ;; *) false ;; esac
check "a reload retires an old worker a tunnel pins ($out)" $?

# --- the upload capture lands on the filesystem spill_dir names -----------
# doc_claims_test covers the parsing and validation of the key. What it cannot
# see is the two open() sites going back to a hardcoded "/tmp" — silent, and
# its only symptom is uploads held in RAM instead of on disk. An O_TMPFILE has
# no directory entry, so the descriptor in /proc is the only evidence there is.
mkdir -p test/spill
python3 test/proxy_backend.py >/dev/null 2>&1 &
spill_backend_pid=$!
backend_ready
start_server $CFG/tls-h3-big.json
P61498=$SRV_PORT
h3big_pid=$SRV_PID
sleep 0.3
start_server $CFG/spill-dir.json
P61495=$SRV_PORT
spill_pid=$SRV_PID
sleep 0.3
out=$(timeout 60 python3 test/spill_dir_test.py ${P61495} test/spill $spill_pid 2>&1)
case "$out" in ok*) true ;; *) false ;; esac
check "the upload capture file is created under spill_dir ($out)" $?
# h3 uploads whose body goes straight to the capture file, at two sizes that
# fail for two different reasons. Every OTHER h3 upload check in the suite uses
# a body under 7 KB, which keeps the whole request on the RAM path -- so none of
# them reaches this code at all, and 635/0 said nothing about the case the
# direct-to-file change was FOR.
#
# 40000 is the one that pins the bug. Inside a payload the granted ceiling is
# capped at the payload's end, and a grant smaller than RA_GRANT (16 KiB) was
# suppressed as not worth a packet -- so the last step up to that cap was never
# sent and the peer stalled a few bytes short of a body it had already declared.
# The broken band was payloads from RA_BUF (where the file path engages) up to
# where the final step reaches RA_GRANT: 34000..49000 hung every time, 33000 and
# 50000 never did. It is deterministic and answers in ~0.1s, so it is the cheap
# guard; if only this one fails, the grant floor has come back.
#
# 16000000 crosses RA_WINDOW (4 MiB) instead, where the ceiling has to keep
# following body_hi across many grants rather than being set once. It is slow
# (~8s) but it is the only check that exercises a payload longer than the window.
#
# A NOTE ON MEASURING THESE, which cost most of a day: the leftover that
# triggered the stall is just the payload end modulo how far body_hi happened to
# jump between grant evaluations, so at a size near the band edge one run hangs
# and the next does not. 8 MB completed three times and then hung on the same
# binary, and a bisect read that as a tidy "2 x RA_WINDOW" threshold that never
# existed. Sizes inside the band above are deterministic; sizes outside it are
# not evidence of anything.
for n in 40000 16000000; do
    out2=$(timeout 120 python3 test/quic/h3_upload_big.py localhost $n ${P61498} 2>&1)
    case "$out2" in ok*) true ;; *) false ;; esac
    check "h3 upload of $n bytes goes to the capture file and echoes back ($out2)" $?
done
# A stream ENDED at exactly the flow-control limit, in an empty frame of its
# own, while a gap remains in the payload. Inside a payload the limit we grant
# IS the payload's end, and the reassembly base stays pinned at its start, so
# that offset looked a whole payload past a 32 KiB window: the connection was
# closed with FLOW_CONTROL_ERROR against a peer that had done nothing wrong.
# The check also sends 64 bytes PAST the end, which must STILL be refused --
# without that half it would pass just as well against a server that stopped
# checking the bound at all.
out3=$(timeout 120 python3 test/quic/h3_fin_at_limit_test.py ${P61498} 2>&1)
case "$out3" in ok*) true ;; *) false ;; esac
check "h3 a stream ended at the flow-control limit is not a violation ($out3)" $?
# An upload in progress survives other connections ending. A teardown releases
# all RA_CTXS contexts and closes any descriptor they hold, but "holds one" was
# spelled != -1 while a freshly allocated connection slot is ZEROED -- so every
# connection that ended closed fd 0 once per unused context, and fd 0 is
# routinely another request's capture file (the worker closes stdin). That
# upload then died with a 413 naming no method and no path.
out4=$(timeout 120 python3 test/quic/h3_capture_fd_test.py ${P61498} 2>&1)
case "$out4" in ok*) true ;; *) false ;; esac
check "h3 an upload survives other connections being torn down ($out4)" $?
# A body split across several DATA frames, where a non-final one is big enough
# to take the capture-file path. Closing a payload region leaves through the
# done-check with nothing to feed, and the grant lived only on the feed's tail
# -- so the peer was left holding a ceiling equal to the base, with no credit
# for the next frame's header, and both sides waited for ever. Every other h3
# upload check sends ONE DATA frame, which is what hid it.
out5=$(timeout 120 python3 test/quic/h3_multi_data_test.py ${P61498} 2>&1)
case "$out5" in ok*) true ;; *) false ;; esac
check "h3 a body in several DATA frames keeps its credit ($out5)" $?
# Several uploads at once on ONE connection. Every other upload check runs one
# request at a time, so nothing asked what happens when the RA_CTXS (6)
# reassembly contexts are all in use -- which a browser posting several files
# does immediately. Six must be served byte-exact (the bodies differ in length,
# so a reassembly landing in the wrong context cannot pass), and past six the
# rest must be REFUSED with H3_REQUEST_REJECTED rather than dropped: that is
# what makes a limit of six acceptable, because the client is told it may
# retry. A stream ending in NEITHER a response nor a reset is the regression.
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    out7=$(timeout 200 python3 test/quic/h3_concurrent_uploads_test.py ${P61498} 2>&1 | tail -1)
    case "$out7" in ok*) true ;; *) false ;; esac
    check "h3 six concurrent uploads on one connection ($out7)" $?
else
    check "h3 concurrent uploads (skipped: aioquic/pylsqpack unavailable)" 0
fi
# A peer that says it is blocked must be told the window again. MAX_DATA rides
# whatever 1-RTT packet is going out, and for an uploading peer that is usually
# a bare ACK -- which this server emits UNTRACKED, so a lost one is never
# retransmitted, and the next grant only fires when more data arrives, which is
# what a blocked peer cannot send. DATA_BLOCKED is the peer's own remedy under
# RFC 9000 4.1 and was parsed only to be stepped over.
if python3 -c 'import aioquic' 2>/dev/null; then
    outb=$(timeout 90 python3 test/quic/h3_data_blocked_test.py ${P61498} 2>&1)
    case "$outb" in ok*) true ;; *) false ;; esac
    check "h3 DATA_BLOCKED re-advertises the connection window ($outb)" $?
else
    check "h3 DATA_BLOCKED (skipped: aioquic unavailable)" 0
fi
# A body the server CANNOT CAPTURE must not be reported as one the client sent
# too much of. Opening the capture file, writing it, a full filesystem and a
# payload fragmented past the range list all returned a bare -1, and the caller
# turned every -1 into the same verdict as a body past max_body: 413. The
# access line carries no method and no path (the head never parsed), so a
# failed write and an oversized upload were indistinguishable in the log too --
# which is how a capture file closed by another connection went unattributed.
# The check walks 200 -> 413 -> 500 -> 200, the last so that a server which
# answered 500 for ever afterwards could not pass it.
mkdir -p test/spill_fail
start_server $CFG/tls-h3-spillfail.json
P61492=$SRV_PORT
h3sf_pid=$SRV_PID
sleep 0.3
if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
    out6=$(timeout 200 python3 test/quic/h3_capture_fail_test.py ${P61492} test/spill_fail 2>&1)
    case "$out6" in ok*|skipped*) true ;; *) false ;; esac
    check "h3 an uncapturable body is a 500, not the client's fault ($out6)" $?
else
    check "h3 uncapturable body (skipped: aioquic/pylsqpack unavailable)" 0
fi
kill $h3sf_pid 2>/dev/null
wait $h3sf_pid 2>/dev/null
chmod 755 test/spill_fail 2>/dev/null
kill $spill_pid $h3big_pid $spill_backend_pid 2>/dev/null
wait $spill_pid 2>/dev/null
wait $spill_backend_pid 2>/dev/null

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
api_out=$(python3 test/api/api_backend_test.py ${P61703} 2>&1)
[ $? -eq 0 ]
check "the /api backend" $?
printf '%s\n' "$api_out" | grep -q "^FAIL" && printf '%s\n' "$api_out" | sed -n 's/^FAIL /  api: /p'
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

kill $server_pid $backend_pid $ws_direct_pid $ws_proxy_pid 2>/dev/null
# the next block binds 61100 again, so let this one's listener go first
for _ in $(seq 1 60); do
    (echo > /dev/tcp/127.0.0.1/${P61100}) >/dev/null 2>&1 || break
    sleep 0.1
done
wait $server_pid 2>/dev/null
wait $backend_pid 2>/dev/null
wait $ws_direct_pid $ws_proxy_pid 2>/dev/null
rm -f "$LOG" $WWW/big.txt $WWW/upload.bin $WWW/upload2.bin $WWW/h2range.bin $WWW/huge.bin $WWW/enc.txt $WWW/enc.txt.gz $WWW/enc.txt.br

# --- connection limits: slow-head deadline and the per-address cap ---
# One host must not be able to hold the server open. The idle timeout cannot stop
# it: every byte rearms it, so a trickled request head keeps its slot forever.
# limits.json sets a long idle timeout on purpose, so only the head deadline can
# be what closes the trickling connection.
start_server $CFG/limits.json
P61470=$SRV_PORT
limits_pid=$SRV_PID
python3 test/limits_test.py ${P61470} >/dev/null 2>&1
check "connection limits: slow head cut off, per-address cap holds" $?
kill $limits_pid 2>/dev/null
wait $limits_pid 2>/dev/null

# --- the head deadline also bounds the TLS handshake (slowloris on 443) ---
# A client dribbling ClientHello bytes rearms only the per-op idle timeout; the
# head deadline (stamped at accept) must cut it, while a real handshake serves.
if python3 -c 'import ssl' 2>/dev/null; then
    start_server $CFG/tls-slowhead.json
    P61455=$SRV_PORT
    slowhs_pid=$SRV_PID
    timeout 40 python3 test/tls/tls_slow_handshake.py test/tls/server.crt ${P61455} 3 \
        >/dev/null 2>&1
    check "tls handshake slowloris cut at the head deadline" $?
    kill $slowhs_pid 2>/dev/null
    wait $slowhs_pid 2>/dev/null
fi

# --- graceful drain: SIGQUIT finishes in-flight work, then exits ---
# A slow download is in flight when the drain starts; the workers must
# complete it, refuse new connections meanwhile, and exit after.
#
# SIGQUIT, not SIGTERM: a stop is immediate now and would drop this download
# on purpose (see "a stop is immediate whatever is open"). The drain is what a
# hot upgrade does to the generation it retires, and kill_old_workers signals
# the workers, so the test does the same.
python3 -c "open('$WWW/drain.bin','w').write('D' * 3000000)"
rm -f "$LOG"
start_server $CFG/listen.json
drain_master=$SRV_PID
sleep 0.3
curl -s --max-time 30 --limit-rate 500k http://127.0.0.1:${P61080}/drain.bin -o $RUNDIR/drain_out &
drain_curl=$!
sleep 0.5                       # the transfer is under way
drain_workers $drain_master     # SIGQUIT to the workers, then the master
wait $drain_master 2>/dev/null
sleep 0.5                       # accepts cancelled by now
curl -s --max-time 2 http://127.0.0.1:${P61080}/hello.txt -o /dev/null 2>/dev/null
[ $? -ne 0 ]
check "drain refuses new connections" $?
wait $drain_curl
n=$(wc -c < $RUNDIR/drain_out)
[ "$n" -eq 3000000 ]
check "drain finishes the in-flight response ($n bytes)" $?
# Poll rather than assert a fixed deadline: this check is about WHETHER the
# drain ends once the last connection is gone, not how fast -- promptness has
# its own timed check above ("sigterm: workers exit with an idle connection
# open"). curl exiting does not mean the worker has already noticed the close,
# freed the connection and left, and on a loaded box that gap can exceed half a
# second; it went red once in this suite for exactly that reason and would not
# reproduce standalone (0 in 10).
drain_gone=1
for _ in $(seq 1 20); do
    sleep 0.25
    pgrep -f "$CFG/listen.json" >/dev/null || { drain_gone=0; break; }
done
drain_left=$(pgrep -af "$CFG/listen.json" | tr '\n' '|')
[ "$drain_gone" -eq 0 ]
check "drain exits after the last connection (${drain_left:-none left})" $?
grep -qF 'worker drained' "$LOG"
check "drain logged" $?
rm -f $RUNDIR/drain_out $WWW/drain.bin "$LOG"

# --- accepts spread across the workers (Q122): each worker owns its own
# SO_REUSEPORT listener set, so the kernel hashes connections across them.
# Before, every accept landed on one worker's ring and multi-core TCP
# scaling was theoretical. 24 held connections must reach BOTH workers.
rm -f "$LOG"
start_server $CFG/listen.json
spread_master=$SRV_PID
sleep 0.3
spread_workers=$(pgrep -P $spread_master | sort | tr '\n' ' ')
python3 - <<'PYEOF2' &
import os, socket, time
_PB = int(os.environ.get("LINNEA_TEST_PORT_BASE", 61000))
socks = []
for i in range(24):
    s = socket.create_connection(("127.0.0.1", _PB + 80), timeout=5)
    s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: one.test\r\n\r\n")
    s.recv(200)
    socks.append(s)
time.sleep(2.5)
for s in socks:
    s.close()
PYEOF2
spread_holder=$!
sleep 1.2
spread_ok=1
for w in $spread_workers; do
    n=$(ls /proc/$w/fd 2>/dev/null | wc -l)
    [ "$n" -gt 12 ] || spread_ok=0
done
[ "$spread_ok" = 1 ] && [ -n "$spread_workers" ]
check "accepts spread across the workers (all above baseline)" $?
wait $spread_holder
kill $spread_master 2>/dev/null
wait $spread_master 2>/dev/null

# --- config-check mode: `linnea -t` accepts good, rejects bad ---
$BIN --test --config $CFG/listen.json >/dev/null 2>&1
check "config check accepts a good config" $?
$BIN --test --config $CFG/bad-timeout.json >/dev/null 2>&1
[ $? -ne 0 ]
check "config check rejects a bad config" $?

# --- the command line -------------------------------------------------
# The configuration is named by -c/--config and nothing else. Every spelling of
# a config check must agree, and every malformed command line — an unknown
# option, a flag with no value, a config named twice, a bare path — must be a
# usage error rather than something the server guesses its way through.
for form in "--test --config $CFG/listen.json" \
            "-t -c $CFG/listen.json" \
            "--config=$CFG/listen.json --test" \
            "--config $CFG/listen.json -t"; do
    $BIN $form >/dev/null 2>&1
    check "cli: '$form' checks the config" $?
done
# --help goes to stdout and exits 0; a usage error goes to stderr and exits 1
out=$($BIN --help 2>/dev/null); rc=$?
[ $rc -eq 0 ] && printf '%s' "$out" | grep -q -- "--bpf-probe"
check "cli: --help prints the options to stdout, exit 0" $?
$BIN -h >/dev/null 2>&1
check "cli: -h is the same as --help" $?
# --bpf-probe must SAY something: which step refused and with what errno, or the
# program fd it loaded. It used to answer "FAILED err=1" for all six causes,
# which reads as EPERM whatever actually happened. Runs unprivileged here, so
# the map create is refused; on a box with CAP_BPF it succeeds instead, and both
# shapes are accepted — what is asserted is that the message carries a cause.
out=$($BIN --bpf-probe 2>&1)
# the last line goes into a variable first: a command substitution inside the
# check's message argument would overwrite the $? being reported (see the
# no-Content-Length upload check for what that hides)
bpf_last=$(printf '%s' "$out" | tail -1)
printf '%s' "$out" | grep -Eq "ok prog fd=[0-9]+|FAILED at [a-zA-Z_ ]+: errno=[0-9]+|FAILED: loaded and attached, but a datagram did not steer"
check "cli: --bpf-probe names its outcome ($bpf_last)" $?

# "port": 0 — the kernel picks the port and port_file reports it. This is the
# one fixture that needs no port of its own, so it cannot collide with another
# run: everything else here holds a fixed number above the ephemeral range,
# which stops an unrelated process stealing it but does nothing about a second
# copy of this suite.
#
# Three things have to hold together, and each is worthless alone: the file
# must appear, the port in it must actually serve, and every worker must be on
# THAT port -- a listener set whose members bound different ports would still
# answer here, through whichever one the file happened to name.
pf=$RUNDIR/port-zero.ports
rm -f "$pf" $RUNDIR/linnea-p0.log
start_server $CFG/port-zero.json
p0pid=$SRV_PID
p0port=""
for _ in $(seq 1 40); do
    [ -s "$pf" ] && { p0port=$(awk '$1=="auto.test"{print $3}' "$pf"); break; }
    sleep 0.1
done
if [ -n "$p0port" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: auto.test' \
           "http://127.0.0.1:$p0port/" 2>/dev/null)
    [ "$code" = "200" ]
    check "port 0: the kernel-chosen port in port_file serves ($p0port -> $code)" $?
    # workers=2, so two listeners must sit on the same chosen port
    n=$(ss -lnt 2>/dev/null | grep -c ":$p0port ")
    [ "$n" = "2" ]
    check "port 0: both workers bound the same chosen port ($n listeners)" $?
    grep -q "listening on 127.0.0.1:$p0port (auto.test)" $RUNDIR/linnea-p0.log
    check "port 0: the log reports the real port, not 0" $?
else
    check "port 0: port_file never appeared" 1
fi
kill $p0pid 2>/dev/null; wait $p0pid 2>/dev/null
rm -f "$pf" $RUNDIR/linnea-p0.log
for bad in "--bogus x" "-x x" "--config" "-c" "--config=" "-" \
           "$CFG/listen.json" \
           "-t $CFG/listen.json" \
           "--config $CFG/listen.json $CFG/listen.json" \
           "-c $CFG/listen.json --config $CFG/listen.json"; do
    $BIN $bad >/dev/null 2>&1
    [ $? -eq 1 ]
    check "cli: '$bad' is a usage error" $?
done
$BIN 2>&1 >/dev/null | grep -q "usage: linnea"
check "cli: no arguments prints usage on stderr" $?
timeout 0.5 $BIN --config $CFG/listen.json >/dev/null 2>&1
[ $? -eq 124 ]
check "cli: --config starts the server" $?

# --- stop is prompt: an idle keep-alive connection must not hold it ---
# SIGTERM closes connections that are merely parked, so a stop takes about
# as long as the work in flight, not as long as the idle timeout. SIGQUIT
# is the patient drain used for the hot upgrade, where the new generation
# is already serving; it leaves those connections alone.
rm -f "$LOG"
start_server $CFG/listen.json
stop_master=$SRV_PID
sleep 0.3
stop_workers=$(pgrep -P $stop_master | tr '\n' ' ')
# hold an idle keep-alive connection open across the stop
python3 test/keepalive_holder.py ${P61080} 20 &
stop_holder=$!
sleep 0.5
start=$SECONDS
kill -TERM $stop_master $stop_workers 2>/dev/null
gone=0
for _ in $(seq 1 60); do
    still=0
    for w in $stop_workers; do kill -0 "$w" 2>/dev/null && still=1; done
    [ "$still" -eq 0 ] && { gone=1; break; }
    sleep 0.1
done
elapsed=$((SECONDS - start))
[ "$gone" -eq 1 ]
check "sigterm: workers exit with an idle connection open (${elapsed}s)" $?
kill $stop_holder 2>/dev/null
wait $stop_holder 2>/dev/null
wait $stop_master 2>/dev/null

# --- log rotation (SIGHUP) ---
# Every process holds its own descriptor for the log, so after a rotation
# they must be told to reopen it: without that they keep filling the renamed
# inode and the fresh file stays empty.
rm -f "$LOG" "$LOG.rot"
start_server $CFG/listen.json
rot_master=$SRV_PID
sleep 0.3
curl -s --max-time 3 http://127.0.0.1:${P61080}/hello.txt -o /dev/null
sleep 0.2
mv "$LOG" "$LOG.rot"
curl -s --max-time 3 http://127.0.0.1:${P61080}/hello.txt -o /dev/null
sleep 0.2
rotated_before=$(wc -l < "$LOG.rot")
kill -HUP $rot_master
sleep 0.5
curl -s --max-time 3 http://127.0.0.1:${P61080}/index.html -o /dev/null
sleep 0.3
kill -0 $rot_master 2>/dev/null
check "sighup: the server survives it" $?
[ -s "$LOG" ]
check "sighup: reopens the log (new file has lines)" $?
grep -q '"GET /index.html HTTP/1.1"' "$LOG"
check "sighup: post-rotate requests log to the new file" $?
[ "$(wc -l < "$LOG.rot")" -eq "$rotated_before" ]
check "sighup: the rotated file stops growing" $?
kill $rot_master 2>/dev/null
wait $rot_master 2>/dev/null
rm -f "$LOG.rot"

# --- zero-downtime binary upgrade (SIGUSR2) ---
# The master re-execs in place: same PID, listeners adopted (never
# closed), new workers up, old workers drained. A request in flight when
# the signal lands must finish, and no new request may be refused.
rm -f "$LOG"
python3 -c "open('$WWW/up.bin','w').write('U' * 3000000)"
start_server $CFG/listen.json
up_master=$SRV_PID
sleep 0.3
old_workers=$(pgrep -P $up_master | tr '\n' ' ')
# a slow download in flight across the upgrade
curl -s --max-time 30 --limit-rate 500k http://127.0.0.1:${P61080}/up.bin \
    -o $RUNDIR/up_out &
up_curl=$!
# a steady stream of quick requests, counting any refusal
up_fails=0
up_why=""
( sleep 0.4; kill -USR2 $up_master ) &
for i in $(seq 1 60); do
    # record HOW a request failed, not just that it did: this check has gone
    # red about once in a dozen runs and never under a targeted repro (seven
    # runs, two of them under CPU load, zero refusals), so the next red run
    # should say whether the server refused (curl 7) or the client simply ran
    # out of its 3s patience on a loaded box (curl 28).
    #
    # Take curl's status into up_rc on the very next line. Reading $? inside
    # the `if` body gets the status of the counter assignment -- which is
    # always 0 -- so this diagnostic used to record "curl0" for every failure
    # and answer none of the question it was added to answer.
    curl -s --max-time 3 http://127.0.0.1:${P61080}/hello.txt -o /dev/null
    up_rc=$?
    if [ $up_rc -ne 0 ]; then
        up_fails=$((up_fails + 1))
        up_why="$up_why $i:curl$up_rc"
    fi
    sleep 0.03
done
kill -0 $up_master 2>/dev/null
check "upgrade keeps the master PID" $?
wait $up_curl
n=$(wc -c < $RUNDIR/up_out)
[ "$n" -eq 3000000 ]
check "upgrade finishes the in-flight download ($n bytes)" $?
[ "$up_fails" -eq 0 ]
check "upgrade refuses no new request ($up_fails failed:${up_why:- none})" $?
sleep 1
gone=1
for w in $old_workers; do kill -0 "$w" 2>/dev/null && gone=0; done
[ "$gone" -eq 1 ]
check "upgrade drains the old workers" $?
grep -qF 'binary upgrade complete' "$LOG"
check "upgrade logged" $?
curl -s --max-time 3 http://127.0.0.1:${P61080}/hello.txt | grep -q "hello from linnea"
check "upgraded server still serves" $?
kill $up_master 2>/dev/null
wait $up_master 2>/dev/null
rm -f $RUNDIR/up_out $WWW/up.bin "$LOG"

# The same handover under real concurrency. One-at-a-time curl caught the
# drain's resets about once in a dozen suite runs, which is not enough signal
# to tell a fix from luck; 40 clients in flight fill the accept queue and make
# it deterministic. Every attempt must be answered — a reset here means the
# drain threw away a connection it had already taken, or the listener close
# purged the queue behind it.
# The previous instance's WORKERS can outlive its master by a moment and they
# hold the listener, so starting straight on top of it fails the bind and the
# new master exits immediately -- leaving this test signalling a pid that is
# already gone. Wait for the port to go quiet, then confirm we are up.
for _ in $(seq 1 40); do
    (echo > /dev/tcp/127.0.0.1/${P61080}) >/dev/null 2>&1 || break
    sleep 0.25
done
start_server $CFG/listen.json
burst_master=$SRV_PID
for _ in $(seq 1 40); do
    curl -s --max-time 1 http://127.0.0.1:${P61080}/hello.txt -o /dev/null && break
    sleep 0.25
done
burst_out=$(timeout 60 python3 test/upgrade_burst.py $burst_master ${P61080} 2>&1)
burst_rc=$?
kill $burst_master 2>/dev/null
wait $burst_master 2>/dev/null
# One retry, and only on failure. Leaving the reuseport group means closing the
# listening socket, and the sweep that empties its accept queue first cannot be
# atomic with that close -- a connection can still land in the gap between the
# sweep coming up empty and the close on the next instruction. Measured at 2
# lost in ~34k attempts on a loaded box (and 0 in 386k on an idle one), so a
# single strict run flakes now and then. A real regression fails both attempts:
# pre-Q177 lost 6-18 per round, every round.
if [ $burst_rc -ne 0 ]; then
    for _ in $(seq 1 40); do
        (echo > /dev/tcp/127.0.0.1/${P61080}) >/dev/null 2>&1 || break
        sleep 0.25
    done
    start_server $CFG/listen.json
    burst_master=$SRV_PID
    for _ in $(seq 1 40); do
        curl -s --max-time 1 http://127.0.0.1:${P61080}/hello.txt -o /dev/null && break
        sleep 0.25
    done
    burst_out="$burst_out; retry: $(timeout 60 python3 test/upgrade_burst.py $burst_master ${P61080} 2>&1)"
    burst_rc=$?
    kill $burst_master 2>/dev/null
    wait $burst_master 2>/dev/null
fi
check "upgrade under load loses no connection ($burst_out)" $burst_rc
rm -f "$LOG"

# --- TLS 1.3: the standalone echo server against real clients ---
# Needs the openssl CLI (cert generation + s_client) and python3 ssl,
# both already test-only dependencies. Skips cleanly if either is absent.
TLSBIN=./bin/linnea-tlstest
# Build it here rather than trusting whatever is on disk. It links src/linnea_tls.o
# but `make` alone does not produce it, so an out-of-date binary sits there looking
# perfectly runnable and quietly exercises the PREVIOUS TLS code — every check below
# passing against a build that no longer matches the source.
make -s tlstest >/dev/null 2>&1
if [ -x "$TLSBIN" ] && command -v openssl >/dev/null 2>&1; then
    tlsdir=$(mktemp -d)
    if openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$tlsdir/k.pem" -out "$tlsdir/c.pem" -days 1 -nodes \
            -subj /CN=localhost >/dev/null 2>&1; then
        tport=${P61443}
        "$TLSBIN" "$tlsdir/c.pem" "$tlsdir/k.pem" $tport &
        tls_pid=$!
        sleep 0.4

        # openssl s_client: full handshake + application echo
        got=$(printf 'linnea-tls' | timeout 5 openssl s_client \
              -connect 127.0.0.1:$tport -CAfile "$tlsdir/c.pem" \
              -tls1_3 -quiet 2>/dev/null)
        [ "$got" = "linnea-tls" ]
        check "tls openssl handshake + echo" $?

        # An ALPN mismatch SHALL be a fatal no_application_protocol alert (RFC
        # 7301 3.2). The handshake used to complete with no protocol selected and
        # the server then spoke HTTP/1 at whatever arrived.
        timeout 30 python3 test/tls/alpn_mismatch.py "$tlsdir/c.pem" $tport >/dev/null 2>&1
        check "tls ALPN mismatch is a fatal alert" $?

        # HelloRetryRequest (RFC 8446 4.1.4). OpenSSL sends a key_share for its
        # FIRST -groups entry only, so a client listing P-256 ahead of x25519
        # supports our group but guessed wrong about it. That MUST draw a retry;
        # it used to draw a fatal handshake_failure, locking the client out.
        got=$(printf 'linnea-hrr' | timeout 8 openssl s_client \
              -connect 127.0.0.1:$tport -CAfile "$tlsdir/c.pem" \
              -groups P-256:X25519 -tls1_3 -quiet 2>/dev/null)
        [ "$got" = "linnea-hrr" ]
        check "tls HelloRetryRequest: P-256-first client completes" $?

        # the same with several groups ahead of x25519, so the retry is not an
        # artefact of the two-group case
        got=$(printf 'linnea-hrr2' | timeout 8 openssl s_client \
              -connect 127.0.0.1:$tport -CAfile "$tlsdir/c.pem" \
              -groups P-521:P-384:P-256:X25519 -tls1_3 -quiet 2>/dev/null)
        [ "$got" = "linnea-hrr2" ]
        check "tls HelloRetryRequest: several groups before x25519" $?

        # a session must still resume across a retry. The binder is computed over
        # message_hash || HRR || Truncate(ClientHello2); hashing ClientHello2 on
        # its own fails it silently, and since such a client is retried on every
        # connection it would never resume at all.
        #
        # Hold stdin open past the handshake: s_client exits the moment stdin
        # hits EOF, and if NewSessionTicket has not landed by then -sess_out
        # writes NO FILE AT ALL and the resume below cannot succeed. That is a
        # race in the test, not the server -- it cost this check about 1 run in
        # 13, and a no-retry control flaked at the same rate, so it never had
        # anything to do with the retry. -ign_eof also fixes it but waits out
        # the full 8s timeout, since the echo server closes only when we do.
        { printf 'x'; sleep 0.5; } | timeout 8 openssl s_client \
              -connect 127.0.0.1:$tport \
              -CAfile "$tlsdir/c.pem" -groups P-256:X25519 -tls1_3 \
              -sess_out "$tlsdir/s.pem" >/dev/null 2>&1
        printf 'x' | timeout 8 openssl s_client -connect 127.0.0.1:$tport \
              -CAfile "$tlsdir/c.pem" -groups P-256:X25519 -tls1_3 \
              -sess_in "$tlsdir/s.pem" 2>&1 | grep -q 'Reused, TLSv1.3'
        check "tls session resumes across a HelloRetryRequest" $?

        # a client that genuinely cannot do x25519 must still be refused: a
        # retry would ask for a group it has already declined, and 4.1.4 allows
        # exactly one, so looping is not an option either
        timeout 8 openssl s_client -connect 127.0.0.1:$tport \
              -CAfile "$tlsdir/c.pem" -groups P-256 -tls1_3 \
              </dev/null >/dev/null 2>&1
        [ $? -ne 0 ]
        check "tls no shared group is still a handshake failure" $?

        # python ssl: assert protocol + cipher, echo 4B and 16KB
        timeout 8 python3 - "$tlsdir/c.pem" $tport <<'PYEOF'
import ssl, socket, sys, os
ca, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=ca)
with socket.create_connection(("127.0.0.1", port)) as raw:
    with ctx.wrap_socket(raw, server_hostname="localhost") as s:
        assert s.version() == "TLSv1.3", s.version()
        assert s.cipher()[0] == "TLS_AES_128_GCM_SHA256", s.cipher()
        s.sendall(b"ping"); assert s.recv(16) == b"ping"
        big = os.urandom(16384); s.sendall(big)
        got = b""
        while len(got) < len(big): got += s.recv(65536)
        assert got == big
PYEOF
        check "tls python ssl (TLSv1.3, AES-128-GCM, 16KB echo)" $?

        # session resumption: a NewSessionTicket from the first handshake
        # lets the second skip the certificate. python's ssl exposes the
        # PSK acceptance directly as session_reused.
        timeout 10 python3 - "$tlsdir/c.pem" $tport <<'PYEOF'
import ssl, socket, sys
ca, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.create_default_context(cafile=ca)
ctx.check_hostname = False           # the fixture cert is CN=localhost
# first connection: complete the handshake and collect the ticket
with socket.create_connection(("127.0.0.1", port)) as raw:
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    s.sendall(b"x"); assert s.recv(4) == b"x"
    sess = s.session               # populated once the NST arrives
    assert not s.session_reused
    s.close()
assert sess is not None, "no NewSessionTicket received"
# second connection: offer the ticket, expect resumption
with socket.create_connection(("127.0.0.1", port)) as raw:
    s = ctx.wrap_socket(raw, server_hostname="localhost", session=sess)
    assert s.version() == "TLSv1.3", s.version()
    assert s.session_reused, "server did not resume the session"
    s.sendall(b"y"); assert s.recv(4) == b"y"
    s.close()
PYEOF
        check "tls session resumption (PSK, session_reused)" $?

        # negative: plain HTTP to the TLS port -> a fatal alert record
        alert=$(timeout 3 python3 - $tport <<'PYEOF'
import socket, sys
s = socket.socket(); s.settimeout(2)
s.connect(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
d = s.recv(16)
print("alert" if d[:1] == b"\x15" else "no")
PYEOF
)
        [ "$alert" = alert ]
        check "tls plain-HTTP to TLS port -> fatal alert" $?

        # negative: a TLS 1.2-only client cannot negotiate our profile
        timeout 4 openssl s_client -connect 127.0.0.1:$tport -tls1_2 \
            </dev/null 2>&1 | grep -q "alert"
        check "tls 1.2 client rejected" $?

        # a short ClientHello fuzz: the server must survive and keep serving
        timeout 60 python3 test/tls/fuzz_clienthello.py \
            "$tlsdir/c.pem" $tport 150 >/dev/null 2>&1
        check "tls clienthello fuzz (150 cases, server survives)" $?

        kill $tls_pid 2>/dev/null
        wait $tls_pid 2>/dev/null
    else
        check "tls (openssl could not generate a P-256 cert — skipped)" 0
    fi
    rm -rf "$tlsdir"
else
    check "tls (linnea-tlstest not built or openssl absent — skipped)" 0
fi

# --- TLS end to end: the real server, handshake in userspace then kTLS ---
# Everything past the handshake is the ordinary HTTP path over a socket the
# kernel encrypts, so these tests are really asking whether the handoff left
# the connection indistinguishable from a plaintext one.
if ! grep -qw tls /proc/sys/net/ipv4/tcp_available_ulp 2>/dev/null; then
    # No kTLS: the handshake would still succeed and every request would then
    # fail, so skip rather than report a pile of misleading failures.
    check "tls e2e (kernel tls module not loaded: modprobe tls — skipped)" 0
else
    rm -f "$LOG"
    # Recreated here: the HTTP section removed its copy, and a file spanning
    # many records is the point of the large-file case below.
    python3 -c "open('$WWW/big.txt','w').write('B'*100000)"
    python3 test/proxy_backend.py >/dev/null 2>&1 &
    tls_backend_pid=$!
    backend_ready
    start_server $CFG/tls.json
    P61443=$SRV_PORT
    tls_server_pid=$SRV_PID
    sleep 0.3
    CA=test/tls/server.crt
    U=https://localhost:${P61443}

    resp=$(curl -si --http1.1 --max-time 5 --cacert $CA $U/hello.txt)
    check_http "tls static body"   "hello from linnea" "$resp"
    check_http "tls static status" "200 OK" "$resp"

    # One connection, two requests: keep-alive has to survive the handoff.
    # -w reports per transfer, so sum it: the second request must open no
    # new connection (and so must not repeat the handshake).
    n=$(curl -s --max-time 5 --cacert $CA -o /dev/null -o /dev/null \
        -w '%{num_connects}\n' $U/hello.txt $U/index.html | awk '{t += $1} END {print t}')
    [ "$n" = "1" ]
    check "tls keep-alive reuses one connection" $?

    # A file spanning many records exercises the kTLS TX path against an
    # mmap'd send, where the kernel does the fragmenting.
    n=$(curl -s --max-time 10 --cacert $CA $U/big.txt | wc -c)
    [ "$n" = "100000" ]
    check "tls large file intact ($n bytes)" $?

    resp=$(curl -si --http1.1 --max-time 5 --cacert $CA $U/api/simple)
    check_http "tls proxy body"   "backend body" "$resp"
    check_http "tls proxy status" "200 OK" "$resp"

    # A captured upload over TLS: the capture window is filled by the kTLS
    # recvmsg path rather than a plain recv, which is a different arm.
    python3 -c "
import random
random.seed(13)
open('$WWW/tlsupload.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
    curl -s --max-time 30 --cacert $CA --data-binary @$WWW/tlsupload.bin \
        $U/api/echo > $RUNDIR/tls_upload_echo.bin
    [ "$(md5sum < $RUNDIR/tls_upload_echo.bin | cut -d' ' -f1)" = \
      "$(md5sum < $WWW/tlsupload.bin | cut -d' ' -f1)" ]
    check "tls proxy captures a 300000-byte request body (byte-exact)" $?
    rm -f $RUNDIR/tls_upload_echo.bin $WWW/tlsupload.bin

    timeout 8 python3 - "$CA" ${P61443} <<'PYEOF'
import ssl, socket, sys
ctx = ssl.create_default_context(cafile=sys.argv[1])
with socket.create_connection(("localhost", int(sys.argv[2])), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname="localhost") as s:
        assert s.version() == "TLSv1.3", s.version()
        assert s.cipher()[0] == "TLS_AES_128_GCM_SHA256", s.cipher()
        s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        # The head and the mmap'd body are separate sends, so under kTLS
        # they are separate records: read until the body turns up rather
        # than assuming one recv holds the whole response.
        buf = b""
        while b"hello from linnea" not in buf:
            d = s.recv(4096)
            assert d, f"connection closed after {buf!r}"
            buf += d
        assert b"200 OK" in buf, buf
PYEOF
    check "tls python ssl (TLSv1.3, AES-128-GCM)" $?

    # configured security headers ride every response this vhost builds
    hdrs=$(curl -si --http1.1 --max-time 5 --cacert $CA $U/hello.txt)
    check_http "hsts header (h1)"     "Strict-Transport-Security: max-age=31536000" "$hdrs"
    check_http "nosniff header (h1)"  "X-Content-Type-Options: nosniff" "$hdrs"
    hdrs=$(curl -si --http1.1 --max-time 5 --cacert $CA $U/no-such-file)
    check_http "hsts on a 404 (h1)"   "Strict-Transport-Security:" "$hdrs"
    # a proxy failure answers from the same canned blobs, but used to send them
    # straight from rodata — so a 502 from a dead upstream, often the first
    # thing a client ever sees from the origin, carried no policy at all
    hdrs=$(curl -si --http1.1 --max-time 5 --cacert $CA $U/down/x)
    check_http "hsts on a proxy 502 (h1)"    "Strict-Transport-Security:" "$hdrs"
    check_http "nosniff on a proxy 502 (h1)" "X-Content-Type-Options: nosniff" "$hdrs"

    # This vhost has a REDIRECT location, and that used to keep it off h3
    # entirely — no listener, no registration — because "QPACK has no Location
    # header to emit". That was never true: RFC 9204's static table has
    # "location" at index 12. Since h3 serves redirects, the vhost belongs on
    # h3 like any other and must say so, because Alt-Svc migration is
    # per-origin: withholding it is what cost every OTHER location on this
    # server its h3. The curl-h3 block at the end of this section follows the
    # advertisement and checks that h3 really answers /old.
    hdrs=$(curl -si --max-time 5 --cacert $CA $U/hello.txt)
    echo "$hdrs" | grep -qi 'alt-svc'
    check "h3 advertised by a redirect vhost (alt-svc present)" $?

    # HTTP/3 proxying end to end, against the backend already listening on
    # 61100. A proxied h3 request has no client socket to answer on: the leg
    # borrows a connection slot for its upstream half, captures the response
    # whole, and streams it out of a response-stream slot like a file. Every
    # part of that is checked here — status and body, the target and query, a
    # client header reaching the backend, chunked de-chunked and re-lengthed,
    # a close-delimited body, 40000 bytes streamed past a single packet,
    # hop-by-hop fields stopped in both directions, a POST body forwarded, and
    # an unreachable upstream answered 502 rather than left silent.
    # Its own log file, deliberately: these clients hang up hard (a raw socket
    # closed the moment the field block is read, a QUIC client that stops
    # answering), and the close_notify checks further down grep $LOG for the
    # absence of "recv error". Sharing a log would have this block decide that.
    rm -f $RUNDIR/linnea-h3p.log
    start_server $CFG/tls-h3-proxy.json
    P61462=$SRV_PORT
    h3p_pid=$SRV_PID
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        out=$(timeout 120 python3 test/quic/h3_proxy_test.py ${P61462} 2>&1)
        [ "$out" = "OK" ]
        check "h3 proxies to an HTTP/1.1 upstream ($out)" $?

        # How a request stream ends, and what becomes of one that never does:
        # a FIN on a frame carrying no bytes, and contexts left claimed by
        # clients that walked away. Both are consequences of consuming a stream
        # as it arrives, and both were silent — the client simply waited.
        out=$(timeout 150 python3 test/quic/h3_stream_end_test.py ${P61462} 2>&1)
        [ "$out" = "OK" ]
        check "h3 request streams end and are reclaimed ($out)" $?

        # An upload abandoned midway leaves a capture file behind. Closing that
        # descriptor is the only thing that returns the space, and PrivateTmp
        # makes the space RAM — so the count has to come back DOWN once the
        # connections are reaped, not merely stop climbing. Counted on the
        # worker, since the master opens none of them.
        # Not the peak, which races the idle sweep — whether the count comes
        # back DOWN. Eight of them, so a server that keeps them is unmistakable:
        # before the fix all eight were still open minutes later, and it is the
        # count settling at the baseline that says the descriptor and its tmpfs
        # pages went back.
        h3p_worker=$(pgrep -P "$h3p_pid" | head -1)
        fd_deleted() { ls -l /proc/"$1"/fd 2>/dev/null | grep -c '(deleted)'; }
        before=$(fd_deleted "$h3p_worker")
        timeout 120 python3 test/quic/h3_abandon_upload.py ${P61462} 8 >/dev/null 2>&1
        after=$(fd_deleted "$h3p_worker")
        for _ in $(seq 1 75); do          # the reap runs ~30 s in; leave room
            [ "$after" -le "$before" ] && break
            sleep 1
            after=$(fd_deleted "$h3p_worker")
        done
        [ "$after" -le "$before" ]
        check "h3 abandoned uploads release their capture file (${before} -> ${after} after 8)" $?
    else
        check "h3 proxying (skipped: aioquic/pylsqpack unavailable)" 0
        check "h3 request streams end and are reclaimed (skipped)" 0
        check "h3 abandoned uploads release their capture file (skipped)" 0
    fi
    # RFC 9002 7.6: a path that stops delivering for longer than 3x the PTO is
    # persistent congestion, and the window must go to its floor rather than
    # merely halve. It is the ONLY thing answering a dead path now that a PTO
    # expiry no longer reduces cwnd (7.6.1 forbids that, and obeying it is what
    # unstalled large downloads) -- so this shows it FIRING, by going deaf for a
    # second mid-transfer, and shows the transfer finishing anyway. A floor with
    # ssthresh left above it recovers in slow start; that is the difference
    # between a pause and a dead connection. Verified against 1077793, which
    # does not declare it.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        truncate -s 32M $WWW/pcbig.bin
        outpc=$(timeout 200 python3 test/quic/h3_persistent_congestion_test.py \
                  ${P61462} /pcbig.bin $RUNDIR/linnea-h3p.log 2>&1 | tail -1)
        case "$outpc" in ok*) true ;; *) false ;; esac
        check "h3 persistent congestion is declared, and recovered from ($outpc)" $?
        rm -f $WWW/pcbig.bin
    else
        check "h3 persistent congestion (skipped: aioquic unavailable)" 0
    fi
    # the same path over h2, which has proxied since Q86: the two must agree
    b2=$(curl -s --http2 --max-time 6 --cacert test/tls/server.crt \
              https://localhost:${P61462}/api/simple)
    [ "$b2" = "backend body" ]
    check "h3/h2 agree on the proxied body" $?

    # ...and they must agree about REFUSING one. A response carrying both
    # Transfer-Encoding: chunked and Content-Length is contradictory (RFC 9112
    # 6.3) and h1 has always answered 502 -- "forwarding both would let a
    # compromised backend split the next keep-alive response". h2 and h3 each
    # picked a side and relayed instead, so one backend answer produced three
    # different client-visible outcomes: 502 on h1, a 200 on h2 declaring the
    # upstream's content-length over a de-chunked body of a different length
    # (which the client rejects as PROTOCOL_ERROR), and a clean 200 on h3 with
    # the chunked length restated. Which one a client saw came down to the
    # protocol it happened to negotiate.
    tc2=$(curl -s --http2 -o /dev/null -w '%{http_code}' --max-time 6 \
          --cacert test/tls/server.crt https://localhost:${P61462}/api/tecl)
    [ "$tc2" = "502" ]
    check "h2 refuses a proxied response framed both ways ($tc2)" $?
    if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
        tc3=$("$CURLH3" --http3-only -s -o /dev/null -w '%{http_code}' --max-time 15 \
              --cacert test/tls/server.crt https://localhost:${P61462}/api/tecl)
        [ "$tc3" = "502" ]
        check "h3 refuses the same response h1 and h2 refuse ($tc3)" $?
    else
        check "h3 refuses a doubly-framed proxied response (skipped: no HTTP/3 curl)" 0
    fi
    # The control, and it is the one that matters: a legitimately chunked
    # response carries no Content-Length and must still relay. Without it the
    # two checks above would pass on a build that had simply stopped
    # de-chunking anything.
    ch2=$(curl -s --http2 --max-time 6 --cacert test/tls/server.crt \
          https://localhost:${P61462}/api/chunked)
    [ "$ch2" = "chunked body" ]
    check "h2 still relays an ordinary chunked response ($ch2)" $?

    # RFC 9110 7.6.1 / RFC 9113 8.2.2: the backend's connection fields describe
    # its connection to us, and a message carrying one is malformed on h2. Six
    # names were dropped and TE was not — the one a backend is most likely to
    # send back for an ordinary reason — so the same answer travelled
    # differently over h1 (which drops it) and h2. Checked by decoding the
    # field block: a substring search finds "te" inside "content-length".
    timeout 60 python3 test/tls/h2_proxy_hop_by_hop.py test/tls/server.crt ${P61462} \
        >/dev/null 2>&1
    check "h2 does not relay hop-by-hop response fields" $?

    # A request BODY spanning packets, delivered out of order and duplicated,
    # echoed back and compared by checksum. h3_reorder_test.py covers a field
    # SECTION the same way; this covers the bytes a body is made of, where a
    # misplacement is silent rather than a parse failure. Both matter more once
    # the buffer starts sliding out from under a stream as it is consumed.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        out=$(timeout 180 python3 test/quic/h3_reorder_body_test.py ${P61462} 2>&1)
        [ "$out" = "OK" ]
        check "h3 request body reassembled out of order and duplicated ($out)" $?
    else
        check "h3 body reassembly (skipped: deps unavailable)" 0
    fi

    # max_body bounds an upload on h1, and did nothing at all on h2: a body
    # with a Content-Length streams through the slot FIFO to the backend, and
    # nothing compared the declared length against the cap. Lowering max_body
    # to bound uploads therefore left the one protocol browsers use uncapped.
    # The fixture's max_body is 200000.
    rm -f "$SEEN"
    code=$(head -c 199000 /dev/zero | tr '\0' 'a' | curl -s -o /dev/null \
           -w '%{http_code}' --http2 --max-time 20 --cacert test/tls/server.crt \
           -X POST --data-binary @- https://localhost:${P61462}/api/echo)
    [ "$code" = "200" ]
    check "h2 upload under max_body is served ($code)" $?
    code=$(head -c 400000 /dev/zero | tr '\0' 'b' | curl -s -o /dev/null \
           -w '%{http_code}' --http2 --max-time 20 --cacert test/tls/server.crt \
           -X POST --data-binary @- https://localhost:${P61462}/api/echo)
    [ "$code" = "413" ]
    check "h2 upload past max_body is 413 ($code)" $?
    # and the point of a cap: the bytes never land
    ! grep -q ' 400000$' "$SEEN"
    check "the refused h2 upload never reached the backend" $?
    # TWO uploads on ONE connection. Every other h2 upload check is its own
    # curl, i.e. its own connection, and that shape is what let a026f0d ship:
    # every SECOND upload on a connection was refused 413 at 8192 bytes however
    # large max_body was, because the first left an exclusive claim behind and
    # the second fell to the bounded collect path. Verified against the parent
    # of a026f0d, which answers 200 then 413 here.
    up1=$(mktemp); up2=$(mktemp); upf=$(mktemp)
    head -c 50000 /dev/zero | tr '\0' 'x' > "$upf"
    codes=$(curl -sS --http2 --cacert test/tls/server.crt \
              -o "$up1" -w '%{http_code} ' -X POST --data-binary @"$upf" \
              https://localhost:${P61462}/api/echo \
              --next --http2 --cacert test/tls/server.crt \
              -o "$up2" -w '%{http_code}' -X POST --data-binary @"$upf" \
              https://localhost:${P61462}/api/echo)
    [ "$codes" = "200 200" ] && cmp -s "$up1" "$upf" && cmp -s "$up2" "$upf"
    check "h2 a second upload on the same connection is served ($codes)" $?
    # ...and it really WAS one connection. Without this the check quietly stops
    # testing anything the day curl decides not to reuse: two 200s from two
    # connections is exactly what the broken build would also have produced.
    reused=$(grep 'POST /api/echo HTTP/2' $RUNDIR/linnea-h3p.log | tail -2 |
             sed 's/.*from [0-9.]*:\([0-9]*\) .*/\1/' | sort -u | wc -l)
    [ "$reused" = "1" ]
    check "...and both of those really shared one connection" $?
    rm -f "$up1" "$up2" "$upf"
    kill $h3p_pid 2>/dev/null
    wait $h3p_pid 2>/dev/null

    # A canned h3 error must describe ITSELF. The QPACK encoder reads
    # content-encoding, the validators, content-range, location and
    # cache-control out of .bss globals that only linnea_h3_serve clears — and
    # they are per WORKER, so every connection it holds shares them. Responses
    # built anywhere else inherited the last request's: the reader's
    # 413/421/431/500, answered before a request has routed at all, and the
    # proxy's 502/503/504, built on a completion long after the serve that
    # parked it returned. One static hit was enough to make the next 413 go out
    # as content-encoding: gzip over a plain-text body — undecodable to any
    # client that honours it — with that file's etag and its location's
    # Cache-Control, which made a transient failure storable for as long as the
    # static content was. A separate fixture because it needs workers:1, an
    # upstream timeout short enough to fire while a second request runs, and a
    # location carrying a cache_control.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        rm -f $RUNDIR/linnea-h3canned.log
        start_server $CFG/tls-h3-canned.json
        P61464=$SRV_PORT
        h3cn_pid=$SRV_PID
        # a pre-compressed variant to arm the encoding, beside a plain file so
        # the negotiation is real rather than a .gz served to everyone
        printf 'canned plain payload' > $WWW/canned.txt
        python3 -c "
import gzip, sys
with gzip.open(sys.argv[1], 'wb') as f:
    f.write(b'canned gzip payload')" "$WWW/canned.txt.gz"
        out=$(timeout 90 python3 test/quic/h3_canned_fields_test.py ${P61464} 2>&1)
        [ "$out" = "OK" ]
        check "h3 canned errors carry no other request's field section ($out)" $?
        rm -f $WWW/canned.txt $WWW/canned.txt.gz
        kill $h3cn_pid 2>/dev/null
        wait $h3cn_pid 2>/dev/null
    else
        check "h3 canned error field sections (skipped: aioquic unavailable)" 0
    fi

    # The response buffers must fit the LARGEST head the documented config can
    # produce, not a typical one. hsts and cache_control are each up to 255
    # bytes, which is 510 of the old 512-byte per-connection head buffer on
    # their own — so a vhost setting both at their documented maxima could not
    # serve ANY file over LINNEA_H3_INLINE_MAX over h3: the head failed the
    # bound and the stream was RESET, with no status and no body, while h1 and
    # h2 served the same file normally. Silent, and invisible to every other
    # check here because they all use short header values.
    rm -f $RUNDIR/linnea-h3maxhdr.log
    start_server $CFG/tls-h3-maxhdr.json
    P61465=$SRV_PORT
    h3mx_pid=$SRV_PID
    python3 -c "
import sys
open(sys.argv[1],'wb').write(bytes(range(256))*40)" "$WWW/maxhdr.bin"     # 10240 bytes
    # the independent-client block below sets this too; both want it, and the
    # assignment is idempotent
    CURLH3=${LINNEA_CURL_H3:-$HOME/curl-h3/bin/curl}
    if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
        got=$("$CURLH3" --http3-only -s --max-time 20 --cacert $CA \
              --resolve localhost:${P61465}:127.0.0.1 \
              -o $RUNDIR/maxhdr.out -w '%{http_code}' \
              https://localhost:${P61465}/maxhdr.bin)
        [ "$got" = "200" ] && cmp -s $RUNDIR/maxhdr.out "$WWW/maxhdr.bin"
        check "h3 serves a chunked response with max-length hsts+cache_control ($got)" $?
        rm -f $RUNDIR/maxhdr.out
    else
        check "h3 max-length header response (skipped: no HTTP/3 curl)" 0
    fi
    # h2 is the control: it always could, so a failure above is h3's buffer
    # and not the config being rejected somewhere earlier.
    g2=$(curl -s --http2 --max-time 20 --cacert $CA \
         --resolve localhost:${P61465}:127.0.0.1 \
         -o $RUNDIR/maxhdr2.out -w '%{http_code}' \
         https://localhost:${P61465}/maxhdr.bin)
    [ "$g2" = "200" ] && cmp -s $RUNDIR/maxhdr2.out "$WWW/maxhdr.bin"
    check "h2 serves the same max-length-header response ($g2)" $?
    rm -f $RUNDIR/maxhdr2.out $WWW/maxhdr.bin
    kill $h3mx_pid 2>/dev/null
    wait $h3mx_pid 2>/dev/null

    # A cancelled h3 request must let its upstream leg go rather than run it to
    # completion. Dropping the answer at delivery was always correct, but the
    # leg held a connection slot and an upstream socket for as long as the
    # backend took — one of each per abandoned request. The fixture sets
    # max_upstream to 1, so a leg that was not released blocks the next proxied
    # request with a 503; that is the observable, and it is checked for a reset
    # STREAM and a closed CONNECTION separately, since they reach the leg by
    # different paths. The third case keeps the fix honest: a leg nobody
    # cancelled must STILL hold its slot.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        rm -f $RUNDIR/linnea-h3c.log
        start_server $CFG/tls-h3-cancel.json
        P61463=$SRV_PORT
        h3c_pid=$SRV_PID
        out=$(timeout 120 python3 test/quic/h3_cancel_test.py ${P61463} 2>&1)
        [ "$out" = "OK" ]
        check "h3 cancel releases the upstream leg ($out)" $?
        kill $h3c_pid 2>/dev/null
        wait $h3c_pid 2>/dev/null
    else
        check "h3 cancel releases the upstream leg (skipped: deps unavailable)" 0
    fi

    # kTLS reports the peer's close_notify as -EIO rather than a 0-length
    # read, so an orderly shutdown must not be logged as a recv error.
    curl -s --max-time 5 --cacert $CA $U/hello.txt >/dev/null
    sleep 0.3
    grep -q "closed connection on 127.0.0.1:${P61443} .*: peer closed" "$LOG"
    check "tls close_notify logs as peer closed" $?
    ! grep -q "recv error" "$LOG"
    check "tls orderly close is not a recv error" $?

    # resumption over the real kTLS server: the ticket from connection one
    # must let connection two resume (openssl prints "Reused"), and a byte
    # must still flow — proving the app-key handoff used the right sequence
    # (the NST went out at seq 0, so the kernel starts at seq 1). The first
    # connection makes a full request and reads to EOF (-ign_eof), so the
    # post-handshake ticket is received before -sess_out writes it.
    req=$'GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'
    printf '%s' "$req" | timeout 5 openssl s_client -connect 127.0.0.1:${P61443} \
        -CAfile $CA -tls1_3 -ign_eof -sess_out "$LOG.sess" >/dev/null 2>&1
    reused=$(printf '%s' "$req" | timeout 5 openssl s_client \
        -connect 127.0.0.1:${P61443} -CAfile $CA -tls1_3 -ign_eof \
        -sess_in "$LOG.sess" 2>/dev/null | grep -c '^Reused')
    [ "$reused" -eq 1 ]
    check "tls resumption over kTLS (Reused)" $?
    rm -f "$LOG.sess"

    # ALPN: since Q86 a proxy location is served over h2 too, so this
    # server (61443, which has proxy locations) offers h2 like any other.
    # Offering nothing gets no ALPN extension back.
    echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61443} -CAfile $CA \
        -tls1_3 -alpn h2,http/1.1 2>/dev/null | grep -q "ALPN protocol: h2"
    check "alpn: proxy vhost offers h2 (proxy-over-h2)" $?

    # security headers over h2, on static, error and proxied responses
    sec() { timeout 10 curl -s --http2 -D - -o /dev/null --cacert $CA \
        --resolve localhost:${P61443}:127.0.0.1 "$1"; }
    h=$(sec "https://localhost:${P61443}/hello.txt")
    echo "$h" | grep -qi '^strict-transport-security: max-age=31536000' \
        && echo "$h" | grep -qi '^x-content-type-options: nosniff'
    check "http2 security headers (static)" $?
    h=$(sec "https://localhost:${P61443}/nope")
    echo "$h" | grep -qi '^strict-transport-security:' \
        && echo "$h" | grep -qi '^x-content-type-options:'
    check "http2 security headers (404)" $?
    h=$(sec "https://localhost:${P61443}/api/simple")
    echo "$h" | grep -qi '^strict-transport-security:' \
        && echo "$h" | grep -qi '^x-content-type-options:'
    check "http2 security headers (proxied response)" $?

    # h2/h3 hand the whole :path to the normalizer, where h1 first cut the query
    # off and, for a directory, put back the slash normalize consumed. Without
    # that, every URL carrying a query and every directory but "/" 404'd on h2.
    q() { timeout 10 curl -s -o /dev/null -w '%{http_code}' --http2 --cacert $CA \
              --resolve localhost:${P61443}:127.0.0.1 "https://localhost:${P61443}$1"; }
    [ "$(q '/index.html?v=1')" = 200 ] && [ "$(q '/hello.txt?a=b&c=d')" = 200 ]
    check "http2: a query string is not part of the file name" $?
    # (a directory without the trailing slash 404s on h1 too — no redirect)
    [ "$(q '/sub/')" = 200 ] && [ "$(q '/sub/.')" = 200 ] && [ "$(q '/sub')" = 404 ]
    check "http2: a directory serves its index.html" $?
    # a control byte in the path truncates the name at open(2) while the MIME
    # lookup reads past it, and CR/LF forges a request line in a proxied head
    [ "$(q '/hello.txt%00.html')" = 400 ] && [ "$(q '/api%0d%0aX:%201')" = 400 ]
    check "http2: an encoded control byte in the path is rejected" $?

    # --- proxy over HTTP/2 (Q86): each stream runs its own HTTP/1.1 upstream
    # exchange, so the backend still only ever speaks h1 (and WebSocket).
    h2p() { timeout 10 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 "$@"; }
    P=https://localhost:${P61443}
    [ "$(h2p "$P/api/simple")" = "backend body" ]
    check "http2 proxy: counted body relayed" $?
    v=$(h2p -o /dev/null -w '%{http_version}' "$P/api/simple")
    [ "$v" = "2" ]
    check "http2 proxy: served over h2 (not downgraded)" $?
    [ "$(h2p -d 'hello body' "$P/api/echo")" = "hello body" ]
    check "http2 proxy: POST request body forwarded" $?
    [ "$(h2p "$P/api/target?q=1&x=2")" = "/api/target?q=1&x=2" ]
    check "http2 proxy: raw target incl. query forwarded" $?
    [ "$(h2p "$P/api/chunked")" = "chunked body" ]
    check "http2 proxy: chunked upstream de-chunked" $?
    [ "$(h2p "$P/api/eof")" = "eof delimited body" ]
    check "http2 proxy: close-delimited body relayed" $?
    n=$(h2p "$P/api/big" | wc -c)
    [ "$n" -eq 40000 ]
    check "http2 proxy: large body through flow control ($n bytes)" $?
    # a stream pool slot that once served a proxied stream keeps its .up unless
    # the static path clears it, which sent the scheduler to the upstream branch
    # and left the file body unsent (200 with an empty body, slot never reaped)
    sz=$(timeout 15 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
             -o /dev/null -o /dev/null -o /dev/null -o /dev/null \
             -w '%{size_download} ' \
             "$P/api/simple" "$P/index.html" "$P/api/simple" "$P/index.html")
    [ "$sz" = "12 335 12 335 " ]
    check "http2: static body still served after a proxied stream reuses the slot" $?
    # request-body bytes are debited from the connection window on arrival and
    # credited only once they go upstream, so a reset mid-upload used to strand
    # them: four ~16KB rounds exhausted the 65535 window for the connection's life
    python3 test/tls/h2_upload_credit.py $CA ${P61443} >/dev/null 2>&1
    check "http2: an aborted upload returns its connection flow control" $?
    # tearing an h2 connection down while the other direction still has an op in
    # flight now shuts the socket down and defers the free until it completes,
    # so the kernel cannot write into a recycled buffer. Confirm the deferral
    # always resolves: fds must come back to the baseline, not accumulate.
    w1=$(workers_of $tls_server_pid | awk '{print $1}')
    fd0=$(ls /proc/$w1/fd 2>/dev/null | wc -l)
    for _ in $(seq 1 30); do
        timeout 5 curl -s --http2 --max-time 0.05 --cacert $CA \
            --resolve localhost:${P61443}:127.0.0.1 -o /dev/null \
            "https://localhost:${P61443}/api/big" 2>/dev/null
        timeout 5 curl -s --http2 --max-time 0.05 --cacert $CA \
            --resolve localhost:${P61443}:127.0.0.1 -o /dev/null \
            "https://localhost:${P61443}/big.txt" 2>/dev/null
    done
    sleep 3
    fd1=$(ls /proc/$w1/fd 2>/dev/null | wc -l)
    [ -n "$fd0" ] && [ "$fd0" -gt 0 ] && [ "$fd1" -le $((fd0 + 2)) ] \
        && [ "$(h2p -o /dev/null -w '%{http_code}' "$P/index.html")" = 200 ]
    check "http2: aborted mid-transfer connections are freed, not leaked ($fd0 -> $fd1 fds)" $?
    # the rewritten upstream request: Host from :authority, client headers
    # forwarded, Content-Length re-derived, Connection: close ours
    head=$(h2p -H 'X-Probe: abc' "$P/api/headers")
    echo "$head" | grep -qi "^Host: localhost:${P61443}" \
        && echo "$head" | grep -qi '^x-probe: abc' \
        && echo "$head" | grep -qi '^Connection: close' \
        && ! echo "$head" | grep -qi '^:'
    check "http2 proxy: request rewritten for the h1 backend" $?
    # response headers translated, hop-by-hop dropped
    hdrs=$(h2p -D - -o /dev/null "$P/api/simple")
    echo "$hdrs" | grep -qi '^HTTP/2 200' \
        && echo "$hdrs" | grep -qi '^content-length: 12' \
        && ! echo "$hdrs" | grep -qi '^connection:'
    check "http2 proxy: response head translated (no hop-by-hop)" $?
    # a dead backend fails the stream, not the connection
    code=$(h2p -o /dev/null -w '%{http_code}' "$P/down/x")
    [ "$code" = "502" ]
    check "http2 proxy: dead upstream answers 502" $?
    # static and proxied streams multiplexed on ONE connection
    out=$(timeout 15 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
        -w '%{num_connects}\n' -o /dev/null "$P/hello.txt" \
        -w '%{num_connects}\n' -o /dev/null "$P/api/simple" | awk '{t += $1} END {print t}')
    [ "$out" = "1" ]
    check "http2 proxy: static + proxied share one connection" $?
    # several proxied streams in flight at once (the slot pool)
    S=$(mktemp -d)
    timeout 20 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 --parallel \
        -o "$S/a" "$P/api/simple" -o "$S/b" "$P/api/chunked" \
        -o "$S/c" "$P/api/big" -o "$S/d" "$P/api/eof"
    [ "$(cat "$S/a")" = "backend body" ] && [ "$(cat "$S/b")" = "chunked body" ] \
        && [ "$(wc -c < "$S/c")" -eq 40000 ] && [ "$(cat "$S/d")" = "eof delimited body" ]
    check "http2 proxy: four concurrent upstream exchanges" $?
    rm -rf "$S"
    # a page's worth of concurrent API calls (six, the usual browser cap)
    codes=$(timeout 20 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 --parallel \
        -w '%{http_code} ' -o /dev/null "$P/api/simple" -o /dev/null "$P/api/simple" \
        -o /dev/null "$P/api/simple" -o /dev/null "$P/api/simple" \
        -o /dev/null "$P/api/simple" -o /dev/null "$P/api/simple")
    [ "$(echo $codes | tr ' ' '\n' | grep -c '^200$')" -eq 6 ]
    check "http2 proxy: six concurrent proxied streams all answered" $?
    # a large upload over h2: the body streams through the flow-control
    # window instead of being collected, so it is not capped by a buffer
    python3 -c "
import random
random.seed(13)
open('$WWW/upload2.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
uwant=$(md5sum < $WWW/upload2.bin | cut -d' ' -f1)
timeout 60 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
    --data-binary @$WWW/upload2.bin "https://localhost:${P61443}/api/echo" \
    > $RUNDIR/upload2_echo.bin
[ "$(md5sum < $RUNDIR/upload2_echo.bin | cut -d' ' -f1)" = "$uwant" ]
check "http2 captures a 300000-byte counted request body (byte-exact)" $?
rm -f $RUNDIR/upload2_echo.bin
# Two bodies that used to miss the streaming buffer and fall to a collecting
# path capped at 8 KiB whatever max_body said: one with no usable
# Content-Length, and the second of two uploads running at the same time on one
# connection. Every body is captured now, so neither is a special case any
# more -- they stay because they are still the two shapes most likely to break.
#
# curl cannot express the concurrent case at all -- --parallel opens a second
# connection, so it measures two independent uploads and proves nothing --
# hence the hand-rolled client. Against the pre-fix binary it reports
# "stream 3: status 413".
timeout 60 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
    -o /dev/null -w '%{http_code}' -X POST -T - \
    "https://localhost:${P61443}/api/echo" < $WWW/upload2.bin > $RUNDIR/upl_nocl.txt
# NB: the status is read into a variable BEFORE the test. Writing it as
# `check "... ($(cat f))" $?` reads correctly and is broken: bash expands the
# command substitution before calling check, and that expansion overwrites the
# $? the test just set, so the check reported whether CAT succeeded. It passed
# unconditionally, and it hid a real 408 here for as long as it took to notice
# the number printed inside a line that said PASS.
upl_nocl=$(cat $RUNDIR/upl_nocl.txt)
[ "$upl_nocl" = "200" ]
check "http2 captures a 300000-byte body with no Content-Length ($upl_nocl)" $?
rm -f $RUNDIR/upl_nocl.txt
out=$(timeout 90 python3 test/h2_concurrent_upload.py ${P61443} 200000 2>&1)
check "http2: two 200000-byte uploads at once on one connection ($out)" $?
# A body with a Content-Length, byte-exact, PAST the advertised window. Every
# other counted-body check here is 300000 bytes, which fits inside one slot
# plus a little spill and is nowhere near the 4 MiB window; the one case that
# does go past it sends no Content-Length, so it was always on the capture path
# and cannot speak for the path that a counted body now takes.
dd if=/dev/urandom of=$RUNDIR/upload6.bin bs=1M count=6 2>/dev/null
u6=$(md5sum < $RUNDIR/upload6.bin | cut -d' ' -f1)
timeout 120 curl -s --http2 --max-time 110 --cacert $CA \
    --resolve localhost:${P61443}:127.0.0.1 \
    --data-binary @$RUNDIR/upload6.bin "https://localhost:${P61443}/api/echo" \
    > $RUNDIR/upload6_echo.bin
[ "$(md5sum < $RUNDIR/upload6_echo.bin | cut -d' ' -f1)" = "$u6" ]
check "http2: a 6 MiB counted body past the stream window is byte-exact" $?
rm -f $RUNDIR/upload6.bin $RUNDIR/upload6_echo.bin
# ...and the point of capturing it at all: the backend is not touched until the
# body is in, so a request on another stream of the same connection is answered
# while the upload is still arriving. The backend for this one is SERIAL (the
# test brings its own), because a threaded backend answers the second request
# regardless and both builds would pass. See the header of the script.
out=$(timeout 120 python3 test/h2_upload_blocking.py ${P61443} 4000000 1500000 2>&1)
check "http2: a proxied GET is answered while an upload is still arriving ($out)" $?
# ...and how many times the upload had to STOP to be given more window. A
# ROUND-TRIP COUNT, because it is the half of this that loopback can see: the
# frame handler cannot run while a client send is in flight, so every batch of
# WINDOW_UPDATEs is a pause in reading the body -- free here, one RTT each on a
# real link. Crediting per DATA frame instead of per GRANT_MIN took a real
# client from 4.4 MB/s to 1.4 MB/s with every loopback check in this file green.
out=$(timeout 120 python3 test/h2_upload_grants.py ${P61443} 8000000 2>&1)
check "http2: an upload's window grants stay batched ($out)" $?
# ...and one PAST the advertised stream window. This size is the point: a
# collected body is credited back as it is consumed, and crediting only the
# CONNECTION window was enough while such a body could not exceed 8 KiB. With
# the cap lifted, an upload stalled for ever at exactly
# SETTINGS_INITIAL_WINDOW_SIZE (4 MiB) with the stream window at zero and the
# connection window wide open. Every other upload check here is under that, so
# none of them can catch it — keep this one above LINNEA_H2_INITIAL_WINDOW.
dd if=/dev/urandom of=$RUNDIR/upload5.bin bs=1M count=5 2>/dev/null
u5=$(md5sum < $RUNDIR/upload5.bin | cut -d' ' -f1)
timeout 90 curl -s --http2 --max-time 80 --cacert $CA \
    --resolve localhost:${P61443}:127.0.0.1 -X POST -T - \
    "https://localhost:${P61443}/api/echo" < $RUNDIR/upload5.bin > $RUNDIR/upload5_echo.bin
[ "$(md5sum < $RUNDIR/upload5_echo.bin | cut -d' ' -f1)" = "$u5" ]
check "http2: a 5 MiB no-Content-Length body past the stream window completes" $?
rm -f $RUNDIR/upload5.bin $RUNDIR/upload5_echo.bin
# and over TLS HTTP/1.1, where the client pipelines it behind the handshake
timeout 60 curl -s --http1.1 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
    --data-binary @$WWW/upload2.bin "https://localhost:${P61443}/api/echo" \
    > $RUNDIR/upload3_echo.bin
[ "$(md5sum < $RUNDIR/upload3_echo.bin | cut -d' ' -f1)" = "$uwant" ]
check "tls http1.1 relays a 300000-byte request body (byte-exact)" $?
rm -f $RUNDIR/upload3_echo.bin

    # A streamed upload must leave the connection consistent: the request
    # head stays in place (so the access log can still name it) and the
    # keep-alive bookkeeping never sees in_len below head_len — that
    # underflowed into a gigabyte-scale copy off the end of the connection
    # pool, killing the worker.
    timeout 60 curl -s --http1.1 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
        -o /dev/null -w '%{http_code}' --data-binary @$WWW/upload2.bin \
        "https://localhost:${P61443}/api/echo" > $RUNDIR/upl_code.txt
    timeout 60 curl -s --http1.1 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
        -o /dev/null -w '%{num_connects} %{http_code}' --data-binary @$WWW/upload2.bin \
        "https://localhost:${P61443}/api/echo" --next --http1.1 --cacert $CA \
        --resolve localhost:${P61443}:127.0.0.1 -o /dev/null \
        -w ' %{num_connects} %{http_code}' "https://localhost:${P61443}/hello.txt" \
        > $RUNDIR/upl_ka.txt
    [ "$(cat $RUNDIR/upl_ka.txt)" = "1 200 0 200" ]
    check "tls upload: keep-alive survives a streamed body" $?
    grep -q '"POST /api/echo HTTP/1.1" 200' "$LOG"
    check "tls upload: the streamed request is logged with its target" $?
    # the worker must still be the one that started (no crash + respawn).
    # Match ", respawning" and not the whole old sentence: the line now carries
    # the exit cause between the pid and that word ("exited on signal 9,
    # respawning"), so the former pattern would never match again and this
    # assertion would pass whatever happened.
    ! grep -q ", respawning" "$LOG"
    check "tls upload: no worker died" $?
    rm -f $RUNDIR/upl_code.txt $RUNDIR/upl_ka.txt

    # a HEAD is bodiless, and its slot must come back: more sequential
    # bodiless requests than there are slots, all on one connection
    args=""
    for i in $(seq 12); do args="$args -I -o /dev/null $P/api/simple"; done
    codes=$(timeout 20 curl -s --http2 --cacert $CA --resolve localhost:${P61443}:127.0.0.1 \
        -w '%{http_code}\n' $args)
    [ "$(echo "$codes" | grep -c '^200$')" -eq 12 ]
    check "http2 proxy: bodiless HEAD responses free their slot" $?
    # ...and the Via entry names HTTP/2 there, since that is what the request
    # arrived on, while the response says 1.1 — what the backend answered on.
    body=$(h2p "$P/api/headers")
    echo "$body" | grep -qi '^Via: 2 linnea' \
        && h2p -D - -o /dev/null "$P/api/simple" | grep -qi '^via: 1.1 linnea'
    check "http2 proxy: Via names h2 upstream and 1.1 downstream" $?

    # a redirect location over h2 (also newly reachable: h2 used to 404 it)
    hdrs=$(h2p -D - -o /dev/null "$P/old/page.html")
    echo "$hdrs" | grep -qi '^HTTP/2 301' \
        && echo "$hdrs" | grep -qi '^location: https://example.com/old/page.html'
    check "http2 redirect location (301 + Location)" $?
    echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61443} -CAfile $CA \
        -tls1_3 2>/dev/null | grep -q "No ALPN negotiated"
    check "alpn absent when not offered" $?

    # HTTP/2 connection bring-up: a separate http2:1 server. ALPN selects
    # h2; preface + SETTINGS + PING exchange; a request draws GOAWAY.
    start_server $CFG/tls-h2.json
    P61446=$SRV_PORT
    h2_pid=$SRV_PID
    sleep 0.3
    timeout 10 python3 test/tls/h2_bringup.py $CA ${P61446} >/dev/null 2>&1
    check "http2 connection bring-up (preface, settings, ping, goaway)" $?

    # M16/M17: a real HTTP/2 client (curl's nghttp2 — genuine HPACK with
    # Huffman + the static table) has its HEADERS decoded and the named
    # static file served back over h2. Serving the right file end to end is
    # the proof the :path decoded correctly.
    # tls-8 / tls-9: the alert DESCRIPTION the server sends. Refusing correctly
    # but naming the wrong reason sends a client to fix the wrong thing --
    # handshake_failure for a version mismatch tells an old client to change its
    # cipher list. Six cases, one of them a control that must NOT move, and one
    # (bad_record_mac) read out of a record sealed under the server's handshake
    # key. 5 of the 6 report the wrong code before the fix.
    timeout 60 python3 test/tls/alert_codes.py ${P61446} >/dev/null 2>&1
    check "tls alert codes name the actual fault (tls-8, tls-9)" $?

    # ...and the log has to say WHICH of them happened. "tls handshake failed"
    # was the single largest close reason in the production log -- 4018 in
    # eighteen days -- with nothing whatever to tell a bad ClientHello from an
    # unsupported version from a client that walked away. The alert we already
    # send the client names the fault exactly; it was simply never written
    # down. The six cases above must leave at least four distinct codes.
    alerts=$(grep -c 'tls handshake failed, alert ' "$LOG" 2>/dev/null || echo 0)
    distinct=$(grep -oE 'tls handshake failed, alert [0-9]+' "$LOG" 2>/dev/null |
               sort -u | wc -l)
    [ "$alerts" -ge 4 ] && [ "$distinct" -ge 4 ]
    check "tls a failed handshake records which alert it sent ($alerts lines, $distinct distinct)" $?

    # RFC 8446 7.4.2 MUST: a low-order X25519 key share drives the ECDHE
    # product to all-zero whatever the server's private key is, and the
    # handshake must be abandoned rather than keyed from a secret both sides
    # could name in advance. All eight of Curve25519's low-order points, plus
    # the non-canonical encodings p, p+1 and p-1 — which is why the check is on
    # the computed secret and not a blocklist of inputs. Every one of them was
    # accepted before the check existed.
    timeout 60 python3 test/tls/low_order_share.py 127.0.0.1 ${P61446} >/dev/null 2>&1
    check "a low-order x25519 share is refused, not keyed from (RFC 8446 7.4.2)" $?

    # linnea-probe is a SHIPPED product whose purpose is pointing at servers
    # someone else runs, and it appended every handshake message a server sent
    # into fixed .bss buffers with a rep movsb and no bound. A 22 KB chain
    # walked over tr_len, th_buf, every TLS secret and both key schedules:
    # SIGSEGV on TLS and on QUIC alike. h3buf had the same shape at one of its
    # two reassembly sites — 875154c had bounded only the other. The assertion
    # is exit 2 (the "larger than this prober can hold" diagnostic), never 139,
    # and never 0, which would mean a silently truncated transcript reporting a
    # handshake fault that was not the server's.
    timeout 200 python3 test/tls/probe_bigchain.py ./bin/linnea-probe \
        test/tls/server.crt test/tls/bigchain.crt test/tls/server.key \
        >/dev/null 2>&1
    check "linnea-probe survives an oversized certificate chain" $?

    # tls-4: a mid-connection KeyUpdate (RFC 8446 4.6.3). The peer derives the
    # next generation of its traffic secret and switches to it; a receiver that
    # cannot follow loses the connection. kTLS reports the KeyUpdate record by
    # attaching a control message, which a plain recv cannot carry -- such a read
    # fails with -EIO AND CONSUMES THE RECORD -- so this is also what proves the
    # receive path is reading with RECVMSG.
    #
    # openssl s_client's 'k' sends one. TWO TRAPS, both of which make a broken
    # server look healthy:
    #   -ign_eof DISABLES the interactive commands, so 'k' is sent as request
    #     data and no KeyUpdate ever reaches the wire;
    #   one KeyUpdate does not prove the secret was ADVANCED -- deriving the same
    #     generation twice would still serve the second request. Hence two.
    ku_req() { printf 'GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n'; }
    ku_n=$({ ku_req; sleep 0.6; sleep 0.6; ku_req; sleep 1; } | timeout 15 \
        openssl s_client -connect 127.0.0.1:${P61446} -alpn http/1.1 2>/dev/null \
        | grep -c '^HTTP/1.1')
    [ "$ku_n" = "2" ]
    check "tls control: two requests on one kTLS connection" $?

    ku_n=$({ ku_req; sleep 0.6; echo k; sleep 0.6; ku_req; sleep 0.6; echo k; \
             sleep 0.6; ku_req; sleep 1; } | timeout 20 \
        openssl s_client -connect 127.0.0.1:${P61446} -alpn http/1.1 2>/dev/null \
        | grep -c '^HTTP/1.1')
    [ "$ku_n" = "3" ]
    check "tls survives two mid-connection KeyUpdates (kTLS rekey)" $?

    # ...and the other half of 4.6.3: update_requested obliges US to send a
    # KeyUpdate of our own before our next application record, which means
    # switching the transmit key underneath it. 'K' asks for that; two of them
    # prove our sending secret advances as well as our receiving one.
    ku_n=$({ ku_req; sleep 0.6; echo K; sleep 0.6; ku_req; sleep 0.6; echo K; \
             sleep 0.6; ku_req; sleep 1; } | timeout 25 \
        openssl s_client -connect 127.0.0.1:${P61446} -alpn http/1.1 2>/dev/null \
        | grep -c '^HTTP/1.1')
    [ "$ku_n" = "3" ]
    check "tls answers an update_requested KeyUpdate (both directions rekey)" $?

    # the KeyUpdate must be OURS, on the wire, not merely survived: -msg prints
    # both directions, so two lines mean the peer's and the answer to it
    ku_m=$({ ku_req; sleep 0.6; echo K; sleep 0.6; ku_req; sleep 1; } | timeout 20 \
        openssl s_client -connect 127.0.0.1:${P61446} -alpn http/1.1 -msg 2>&1 \
        | grep -ac 'KeyUpdate')
    [ "$ku_m" = "2" ]
    check "tls sends its own KeyUpdate in answer ($ku_m records)" $?

    # the deferred path: a KeyUpdate landing while a large response is still
    # streaming cannot rekey immediately -- switching the transmit key with a
    # send in flight would encrypt data under a key the peer is not expecting --
    # so it waits for the socket to go quiet. Both responses must still arrive.
    # Its own fixture, generated here. This asked for /h3s11.bin, which NOTHING
    # in the suite produces: h3_stress_test.py makes h3s0..h3s5 at 70000+i*12000,
    # so index 11 would be 202000 bytes even if it existed. The 690000-byte file
    # on disk was a fossil from an older version of that test, and this check had
    # been passing on it — on a clean checkout it failed, which is how it was
    # found. A test that borrows another's artefact is one refactor from silently
    # asserting nothing.
    python3 -c "
import sys
open(sys.argv[1], 'wb').write(bytes((i * 131 + (i >> 8) * 17) & 0xFF
                                    for i in range(690000)))" "$WWW/kuflow.bin"
    ku_out=$({ printf 'GET /kuflow.bin HTTP/1.1\r\nHost: localhost\r\n\r\n'; \
               sleep 0.03; echo K; sleep 3; ku_req; sleep 2; } | timeout 30 \
        openssl s_client -connect 127.0.0.1:${P61446} -alpn http/1.1 2>/dev/null \
        | grep -ac -e 'Content-Length: 690000' -e 'hello from linnea')
    [ "$ku_out" = "2" ]
    check "tls KeyUpdate mid-stream: the response and the next request survive" $?

    rl="--resolve localhost:${P61446}:127.0.0.1"
    u="https://localhost:${P61446}"
    body=$(curl -s --http2 --cacert $CA $rl "$u/hello.txt")
    [ "$body" = "hello from linnea" ]
    check "http2 serves a static file (HPACK decode -> file)" $?
    # status line, content-type and content-length over h2
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null "$u/hello.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 200' \
        && echo "$hdrs" | grep -qi '^content-type: text/plain' \
        && echo "$hdrs" | grep -qi '^content-length: 18'
    check "http2 response headers (status, content-type, content-length)" $?
    # validators, date and server over h2 — and revalidation draws a 304
    h2etag=$(echo "$hdrs" | grep -i '^etag:' | tr -d '\r' | cut -d' ' -f2)
    echo "$hdrs" | grep -qiE '^etag: "[0-9a-f]+-12"' \
        && echo "$hdrs" | grep -qiE '^last-modified: [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT' \
        && echo "$hdrs" | grep -qiE '^date: [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT' \
        && echo "$hdrs" | grep -qi '^server: linnea'
    check "http2 validators, date and server headers" $?
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null \
        -H "If-None-Match: $h2etag" "$u/hello.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 304' \
        && echo "$hdrs" | grep -qi "^etag: $h2etag" \
        && ! echo "$hdrs" | grep -qi '^content-length:'
    check "http2 if-none-match 304 (etag repeated, no body)" $?
    sc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'If-None-Match: "stale"' "$u/hello.txt")
    [ "$sc" = "200" ]
    check "http2 stale etag 200" $?

    # If-Match / If-Unmodified-Since over h2 (RFC 9110 13.1.1, 13.1.4). h1 got
    # these in Q187; until h2 and h3 followed, the same request got a different
    # answer depending on which protocol carried it.
    sc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H "If-Match: $h2etag" "$u/hello.txt")
    sc2=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'If-Match: "0000000000000000"' "$u/hello.txt")
    sc3=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'If-Unmodified-Since: Wed, 01 Jan 2020 00:00:00 GMT' "$u/hello.txt")
    # 13.2.2: a failing If-Match wins over an If-None-Match that would say 304
    sc4=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'If-Match: "0000000000000000"' -H "If-None-Match: $h2etag" \
        "$u/hello.txt")
    [ "$sc" = "200" ] && [ "$sc2" = "412" ] && [ "$sc3" = "412" ] && [ "$sc4" = "412" ]
    check "http2 preconditions: If-Match/If-Unmodified-Since ($sc/$sc2/$sc3/$sc4)" $?
    h2lm=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null "$u/hello.txt" \
        | grep -i '^last-modified:' | tr -d '\r' | cut -d' ' -f2-)
    sc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H "If-Modified-Since: $h2lm" "$u/hello.txt")
    [ "$sc" = "304" ]
    check "http2 if-modified-since 304" $?
    # accept-ranges + configured cache-control on the 200
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null "$u/hello.txt")
    echo "$hdrs" | grep -qi '^accept-ranges: bytes' \
        && echo "$hdrs" | grep -qi '^cache-control: max-age=60'
    check "http2 accept-ranges + cache-control headers" $?
    # a single byte range: 206, the exact slice, content-range names it
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null -r 5-9 "$u/hello.txt")
    body=$(curl -s --http2 --cacert $CA $rl -r 5-9 "$u/hello.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 206' \
        && echo "$hdrs" | grep -qi '^content-range: bytes 5-9/18' \
        && echo "$hdrs" | grep -qi '^content-length: 5' \
        && [ "$body" = " from" ]
    check "http2 range 206 (slice + content-range)" $?
    # suffix and open-ended forms
    b1=$(curl -s --http2 --cacert $CA $rl -r -5 "$u/hello.txt")
    b2=$(curl -s --http2 --cacert $CA $rl -r 12- "$u/hello.txt")
    [ "$b1" = "nnea" ] && [ "$b2" = "innea" ]
    check "http2 range suffix + open-ended" $?
    # a large mid-file slice streams through flow control byte-exact
    python3 -c "
d = bytearray()
i = 0
while len(d) < 100000: d += (b'%07d\n' % i); i += 1
open('$WWW/h2range.bin','wb').write(d[:100000])"
    want=$(python3 -c "
import hashlib
print(hashlib.md5(open('$WWW/h2range.bin','rb').read()[25000:75000]).hexdigest())")
    got=$(curl -s --http2 --cacert $CA $rl -r 25000-74999 "$u/h2range.bin" | md5sum | cut -d' ' -f1)
    [ "$got" = "$want" ]
    check "http2 range: 50000-byte mid-file slice byte-exact" $?
    # unsatisfiable: bodiless 416 naming the actual length
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null -r 999999-1000000 "$u/hello.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 416' \
        && echo "$hdrs" | grep -qi '^content-range: bytes \*/18'
    check "http2 unsatisfiable range 416" $?
    # If-Range: strong match applies the range; a stale validator serves it all
    sc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -r 5-9 -H "If-Range: $h2etag" "$u/hello.txt")
    sc2=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -r 5-9 -H 'If-Range: "stale"' "$u/hello.txt")
    [ "$sc" = "206" ] && [ "$sc2" = "200" ]
    check "http2 if-range gates the 206" $?
    # a 304 repeats the cache policy
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null \
        -H "If-None-Match: $h2etag" "$u/hello.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 304' \
        && echo "$hdrs" | grep -qi '^cache-control: max-age=60'
    check "http2 304 repeats cache-control" $?
    # pre-compressed variants: enc.txt has both a .br and a .gz beside it
    python3 - "$WWW" <<'PY'
import gzip, sys
W = sys.argv[1]                      # the run's own document root
open(W + '/enc.txt', 'w').write('plain payload')
with gzip.open(W + '/enc.txt.gz', 'wb') as f:
    f.write(b'gzip payload')
open(W + '/enc.txt.br', 'wb').write(b'br payload')
PY
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null \
        -H 'Accept-Encoding: gzip, br' "$u/enc.txt")
    body=$(curl -s --http2 --cacert $CA $rl -H 'Accept-Encoding: gzip, br' "$u/enc.txt")
    echo "$hdrs" | grep -qi '^content-encoding: br' \
        && echo "$hdrs" | grep -qi '^vary: Accept-Encoding' \
        && [ "$body" = "br payload" ]
    check "http2 pre-compressed br preferred (+ vary)" $?
    gz=$(curl -s --http2 --compressed --cacert $CA $rl -H 'Accept-Encoding: gzip' "$u/enc.txt")
    [ "$gz" = "gzip payload" ]
    check "http2 gzip variant (curl decodes it)" $?
    body=$(curl -s --http2 --cacert $CA $rl "$u/enc.txt")
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null "$u/enc.txt")
    [ "$body" = "plain payload" ] && ! echo "$hdrs" | grep -qi '^content-encoding' \
        && echo "$hdrs" | grep -qi '^vary: Accept-Encoding'
    check "http2 no accept-encoding: plain, vary still set" $?
    # the variant's etag revalidates: 304 keeps vary, no content-encoding
    enctag=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null \
        -H 'Accept-Encoding: br' "$u/enc.txt" | grep -i '^etag:' | tr -d '\r' | cut -d' ' -f2)
    hdrs=$(curl -s --http2 -D - --cacert $CA $rl -o /dev/null \
        -H 'Accept-Encoding: br' -H "If-None-Match: $enctag" "$u/enc.txt")
    echo "$hdrs" | grep -qi '^HTTP/2 304' \
        && echo "$hdrs" | grep -qi '^vary: Accept-Encoding' \
        && ! echo "$hdrs" | grep -qi '^content-encoding'
    check "http2 variant etag 304 (vary kept, coding not restated)" $?
    ver=$(curl -s -o /dev/null --http2 --cacert $CA $rl \
        -w '%{http_version}' "$u/hello.txt")
    [ "$ver" = "2" ]
    check "http2 request uses HTTP/2 (not downgraded)" $?
    ct=$(curl -s -o /dev/null --http2 --cacert $CA $rl \
        -w '%{content_type}' "$u/style.css")
    [ "$ct" = "text/css; charset=utf-8" ]
    check "http2 content-type from extension (css)" $?
    # a body larger than the initial flow-control window (100000 > 65535):
    # exercises DATA chunking and WINDOW_UPDATE-driven resumption
    n=$(curl -s --http2 --cacert $CA $rl "$u/big.txt" | wc -c)
    junk=$(curl -s --http2 --cacert $CA $rl "$u/big.txt" | tr -d 'B' | wc -c)
    [ "$n" -eq 100000 ] && [ "$junk" -eq 0 ]
    check "http2 flow control: 100000-byte body, exact + intact" $?
    # keep-alive with a Huffman-coded custom header (decoder must parse+skip)
    two=$(curl -s --http2 --cacert $CA $rl \
        -H "x-linnea-probe: a-huffman-coded-header-value-98765" \
        "$u/hello.txt" "$u/big.txt" | wc -c)
    [ "$two" -eq 100018 ]
    check "http2 keep-alive: two requests, one connection" $?
    # RFC 9218 `priority` request header (u=, i): a browser sends it on EVERY
    # request, so capturing it must not corrupt the request. It once overwrote the
    # h2 stream-id stack local, resetting the connection — every browser page blank.
    pc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'priority: u=3, i' "$u/big.txt")
    [ "$pc" = "200" ]
    check "http2 priority header served (RFC 9218, no stream-id corruption)" $?
    # HPACK dynamic table: a client may index into its own table before it
    # has processed our SETTINGS(HEADER_TABLE_SIZE=0), and does exactly that
    # when it opens several streams at once. Without a decoder-side table
    # those references cost a GOAWAY and every in-flight request with it, so
    # hammer the case: six parallel streams on a fresh connection, repeatedly.
    hpack_fail=0
    for _ in 1 2 3 4 5 6 7 8; do
        codes=$(timeout 15 curl -s --http2 --cacert $CA $rl --parallel -w '%{http_code}\n' \
            -o /dev/null "$u/hello.txt" -o /dev/null "$u/index.html" \
            -o /dev/null "$u/style.css" -o /dev/null "$u/hello.txt" \
            -o /dev/null "$u/index.html" -o /dev/null "$u/style.css" 2>/dev/null)
        [ "$(echo "$codes" | grep -c '^200$')" -eq 6 ] || hpack_fail=$((hpack_fail + 1))
    done
    [ "$hpack_fail" -eq 0 ]
    check "http2 HPACK dynamic table (8x six parallel streams)" $?

    # a full browser-like header set (many headers, incl. priority + sec-fetch-*)
    bc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' \
        -H 'user-agent: Mozilla/5.0 Firefox/128.0' -H 'accept: text/html,*/*' \
        -H 'accept-language: en-US' -H 'accept-encoding: gzip, br' \
        -H 'priority: u=0, i' -H 'sec-fetch-dest: document' \
        -H 'sec-fetch-mode: navigate' -H 'te: trailers' "$u/hello.txt")
    [ "$bc" = "200" ]
    check "http2 browser-like header set served" $?
    # several resources multiplexed on one connection (a page load), each with a
    # priority header, all 200 (per-URL -o so bodies do not leak into -w output)
    mpd=$(mktemp -d)
    mc=$(curl -s --http2 --cacert $CA $rl --parallel -H 'priority: u=3, i' \
        -w '%{http_code}\n' \
        "$u/hello.txt" -o "$mpd/a" \
        "$u/big.txt" -o "$mpd/b" \
        "$u/style.css" -o "$mpd/c" | sort -u | tr -d '\n')
    rm -rf "$mpd"
    [ "$mc" = "200" ]
    check "http2 concurrent multiplexed requests with priority (page load)" $?
    # HEAD: headers only, no body
    hb=$(curl -s --http2 -I --cacert $CA $rl "$u/hello.txt" | grep -ci .)
    hd=$(curl -s --http2 -I --cacert $CA $rl "$u/hello.txt" | grep -qi 'content-length: 18' && echo ok)
    [ "$hd" = "ok" ]
    check "http2 HEAD: headers with content-length, no body" $?
    # a directory maps to index.html
    dc=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' "$u/")
    [ "$dc" = "200" ]
    check "http2 directory serves index.html" $?
    # missing file -> 404, disallowed method -> 405
    c404=$(curl -s -o /dev/null --http2 --cacert $CA $rl -w '%{http_code}' "$u/nope.txt")
    c405=$(curl -s -o /dev/null --http2 --cacert $CA $rl -X DELETE -w '%{http_code}' "$u/hello.txt")
    [ "$c404" = "404" ] && [ "$c405" = "405" ]
    check "http2 error statuses (404 missing, 405 method)" $?
    # path traversal above the root is refused
    ct400=$(curl -s -o /dev/null --http2 --cacert $CA $rl --path-as-is \
        -w '%{http_code}' "$u/../../../etc/passwd")
    [ "$ct400" = "400" ]
    check "http2 path traversal refused (400)" $?

    # M18: multiplexing — concurrent streams with interleaved DATA, the
    # rapid-reset (CVE-2023-44487) defense, and stream-pool exhaustion.
    timeout 30 python3 test/tls/h2_multiplex.py $CA ${P61446} >/dev/null 2>&1
    check "http2 multiplexing (concurrent streams, rapid-reset, pool cap)" $?

    # A whole docroot over ONE connection, every body compared to the file:
    # the ordinary case a browser performs and the one no other h2 test did.
    # It is what caught the round-robin cursor wrapping with a power-of-two
    # mask — raise MAX_STREAMS to anything else and most slots became
    # unreachable, so their streams were accepted, logged 200, and never sent
    # a byte. The single-stream and six-stream tests all passed throughout.
    out=$(timeout 90 python3 test/tls/h2_page_load.py $CA ${P61446} $WWW 2>&1)
    case "$out" in ok*) true ;; *) false ;; esac
    check "http2 page load: every body byte-exact ($out)" $?

    # RFC 9218 scheduling, the same policy h3's pump applies: the default
    # priority is NON-incremental, so concurrent responses complete one at a
    # time in arrival order; u=0 jumps the queue; i opts back in to sharing the
    # window. h2 parsed the priority field and then ignored it entirely.
    timeout 200 python3 test/tls/h2_priority.py $CA ${P61446} >/dev/null 2>&1
    check "http2 responses scheduled by RFC 9218 priority" $?

    # M19: fuzz the frame layer and HPACK decoder — malformed streams must
    # never crash the worker; a live h2 GET still serves between batches.
    # 150s, not 60: since unknown frame types are discarded rather than drawing
    # a GOAWAY (RFC 9113 4.1), the server no longer ends a fuzzed connection
    # early, so the client waits out its own timeout on more cases. The run is
    # slower by design — it measures ~80s — and a crash still shows as a
    # non-zero exit rather than as the timeout.
    timeout 150 python3 test/tls/fuzz_h2.py $CA ${P61446} 120 >/dev/null 2>&1
    check "http2 fuzz (malformed frames + HPACK survive, server serves)" $?

    # M20: strict stream-id validation + honouring SETTINGS_INITIAL_WINDOW_SIZE.
    # A connection error must carry the code RFC 9113 names for it. Every fault
    # reported PROTOCOL_ERROR, because the reason was never threaded through to
    # the single site that writes the GOAWAY.
    timeout 30 python3 test/tls/h2_error_codes.py $CA ${P61446} >/dev/null 2>&1
    check "http2 connection errors carry the RFC's code" $?

    # RFC 9113 8.1.1: content-length must equal the sum of the DATA payloads.
    # An over-long body was already refused; one that stopped SHORT was not
    # noticed at all — the request sat holding an upstream slot until the body
    # clock timed it out, reporting a timeout for a framing fault visible at
    # once. Runs against the proxy vhost, which is where bodies go.
    timeout 60 python3 test/tls/h2_content_length.py $CA ${P61443} >/dev/null 2>&1
    check "http2 content-length is reconciled with the DATA sent" $?

    timeout 20 python3 test/tls/h2_conformance.py $CA ${P61446} >/dev/null 2>&1
    check "http2 conformance (stream-id rules, initial window size)" $?

    # A biggish cookie load (4.8 KB) fits the Q121 limits and must be SERVED —
    # whole, not with the overflowing fields silently dropped (the Q100 bug),
    # and certainly not by killing the connection (the pre-Q121 behaviour).
    bigck=$(python3 -c "print('a'*4800)")
    code=$(timeout 10 curl -s -o /dev/null -w '%{http_code}' --http2 --cacert $CA \
        --resolve localhost:${P61446}:127.0.0.1 -H "Cookie: $bigck" \
        https://localhost:${P61446}/hello.txt 2>/dev/null)
    [ "$code" = 200 ]
    check "http2 big-but-legal cookie served (fits the raised limits)" $?

    # Q121: an oversized header block answers the stream 431 (the connection
    # survives and keeps serving), and SETTINGS advertises the real
    # MAX_HEADER_LIST_SIZE so clients can trim before hitting it.
    timeout 30 python3 test/tls/h2_big_headers.py $CA ${P61446} >/dev/null 2>&1
    check "http2 oversized header block: stream 431, connection survives" $?

    # wrong-length PING / WINDOW_UPDATE are a connection error, not an over-read
    # (a zero-length PING used to echo 8 stale in_buf bytes to the peer)
    timeout 20 python3 test/tls/h2_frame_size.py $CA ${P61446} >/dev/null 2>&1
    check "http2 control-frame size validated (no PING over-read/echo)" $?

    kill $h2_pid 2>/dev/null
    wait $h2_pid 2>/dev/null
    # (h2 graceful drain — GOAWAY(last-stream) then finish open streams — is
    # exercised by test/tls/h2_drain.py against a running worker; it is not in
    # the automated suite because reliably retiring one worker of a forked
    # multi-process server without the master's supervision reaping the
    # draining worker is timing-fragile. The hot-upgrade path keeps other
    # workers alive, so old workers drain cleanly there.)

    # This used to go red in full runs and was put down to suite STATE. It was
    # not: the test itself refused a prompt server. It pushes 8000 bytes at a
    # server that rejects the record on its 5-byte header, so the reset lands
    # while sendall is still writing, and only the recv was wrapped to expect
    # it — measured at ~10-20% under load, on this code and on the code before
    # it. Fixed in the test. The probe below stays, because the one failure
    # worth chasing is still the same one: on failure ask the same server for
    # an ordinary page — if that answers, the server is healthy and the 2s
    # reply deadline was simply missed; if it does not, a worker is wedged.
    timeout 30 python3 test/tls/oversized_record.py $CA ${P61443} \
        test/tls/clienthello_seed.bin >/dev/null 2>&1
    ovr_rc=$?
    if [ $ovr_rc -ne 0 ]; then
        ovr_probe=$(timeout 5 curl -s -o /dev/null -w '%{http_code}' --cacert $CA \
            --resolve localhost:${P61443}:127.0.0.1 https://localhost:${P61443}/hello.txt 2>&1)
        echo "  (oversized-record failed; the same server answers /hello.txt with: ${ovr_probe:-nothing})"
    fi
    [ $ovr_rc -eq 0 ]
    check "tls oversized record refused (msg_buf bound)" $?

    # Q125: a ClientHello split across records must still complete. A
    # handshake message is a byte stream carried by records, so a client may
    # fragment it at will — and one over 2^14 bytes has no choice. Every
    # fragmented hello used to draw a fatal alert.
    timeout 60 python3 test/tls/fragmented_ch.py ${P61443} >/dev/null 2>&1
    check "tls fragmented ClientHello completes the handshake" $?

    # Records pipelined behind the Finished, including one split the way an
    # MSS boundary would split it — the case loopback never produces.
    timeout 40 python3 test/tls/pipelined_early.py $CA ${P61443} >/dev/null 2>&1
    check "tls pipelined early records (whole and split)" $?

    # A tunnelled upgrade over TLS: the tunnel has its own recv path, so it
    # needs the close_notify handling too, and the relay must stay blind to
    # the fact that the kernel is encrypting underneath it.
    timeout 10 python3 - "$CA" ${P61443} <<'PYEOF' >/dev/null 2>&1
import base64, os, socket, ssl, sys
ctx = ssl.create_default_context(cafile=sys.argv[1])
raw = socket.create_connection(("localhost", int(sys.argv[2])), timeout=5)
s = ctx.wrap_socket(raw, server_hostname="localhost")
key = base64.b64encode(os.urandom(16)).decode()
s.sendall(f"GET /api/ws-echo HTTP/1.1\r\nHost: localhost\r\n"
          f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
          f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
resp = b""
while b"\r\n\r\n" not in resp:
    d = s.recv(4096)
    assert d, "closed before the 101"
    resp += d
assert b"101 Switching Protocols" in resp, resp[:60]
s.sendall(b"tunnel-bytes-over-tls")          # linnea never parses frames
assert s.recv(64) == b"tunnel-bytes-over-tls"
s.close()
PYEOF
    check "tls websocket tunnel (101 + blind relay)" $?

    # RST_STREAM must crash no worker: resetting a proxied stream whose upstream
    # is live and in flight (h2p_kill closing it with a syscall), and RST on
    # stream 0 (a connection error, not a lookup that re-frees a reaped slot).
    prst_before=$(workers_of $tls_server_pid)
    timeout 60 python3 test/tls/h2_proxy_rst.py $CA ${P61443} >/dev/null 2>&1
    sleep 0.5
    resp=$(curl -si --http2 --max-time 5 --cacert $CA $U/hello.txt)
    prst_after=$(workers_of $tls_server_pid)
    [ -n "$prst_before" ] && [ "$prst_before" = "$prst_after" ] \
        && printf '%s' "$resp" | grep -qF "hello from linnea"
    check "http2 proxied-stream RST + RST-stream-0 crash no worker" $?

    # Q124: the authority rules — :authority is h2's Host, and a duplicate,
    # a Host contradicting it, a misplaced pseudo-header or a missing
    # authority must fail THAT STREAM (the connection keeps serving), while
    # a Host standing in for :authority still works.
    timeout 90 python3 test/tls/h2_authority.py $CA ${P61443} >/dev/null 2>&1
    check "http2 authority rules (stream errors, connection survives)" $?

    # RFC 9113 5.1.1: a client's stream id is odd and above the floor, and
    # breaking either is a CONNECTION error. Both were checked AFTER the
    # malformed-request tests, so a malformed request on an even id drew only a
    # stream reset and stamped the floor with an even number. The last case
    # guards the other side: a malformed request on a VALID id must still fail
    # only its stream.
    timeout 60 python3 test/tls/h2_stream_id.py $CA ${P61443} >/dev/null 2>&1
    check "http2 stream-id rules are connection errors" $?

    # A GOAWAY must name the highest stream we might have acted on (RFC 9113 6.8).
    # Every error GOAWAY said 0 — "nothing was processed" — so a client would
    # retry everything in flight, including a proxied POST already executed.
    timeout 60 python3 test/tls/h2_goaway_last_stream.py $CA ${P61443} >/dev/null 2>&1
    check "http2 GOAWAY names the last processed stream" $?

    # Inline error bodies are flow-controlled too (RFC 9113 6.9.1). They were
    # written straight at the out cursor and charged against nothing, so a peer
    # advertising a zero window was sent one anyway, and the server's idea of the
    # connection window drifted above the peer's by every error body it had sent.
    timeout 120 python3 test/tls/h2_error_flow_control.py $CA ${P61443} >/dev/null 2>&1
    check "http2 error bodies respect the flow-control window" $?

    # Request-field rules the shared HPACK/QPACK decoder enforces: :scheme must
    # be present, :path must not be empty, connection-specific fields are
    # malformed (TE only for "trailers"), a space may not sit in a field name and
    # a value may not begin or end with whitespace (RFC 9113 8.2-8.3).
    timeout 60 python3 test/tls/h2_field_rules.py $CA ${P61443} >/dev/null 2>&1
    check "http2 request field rules" $?

    # A trailer section is allowed (RFC 9113 8.1) and used to draw a GOAWAY: its
    # stream id is one already seen, which the strictly-increasing test called
    # broken numbering, taking every concurrent stream down with it. The last
    # case checks the subtle half — the trailer's fields are decoded even though
    # unused, or HPACK's connection-wide table falls out of step.
    timeout 60 python3 test/tls/h2_trailers.py $CA ${P61443} >/dev/null 2>&1
    check "http2 trailer sections do not kill the connection" $?

    # Every TLS connection must end with close_notify (RFC 8446 6.1) or the peer
    # cannot tell a finished response from a cut one. The alert may only be
    # written where no other send is outstanding, so the cases after a large
    # response and after h2 traffic are the ones that matter.
    timeout 90 python3 test/tls/close_notify.py $CA ${P61443} >/dev/null 2>&1
    check "tls connections end with close_notify" $?


    # HPACK is stateful, so a block we REJECT must still be walked to its end:
    # the inserts after the offending field reach the peer's dynamic table
    # whether we like the request or not. Stopping early left our table behind
    # the peer's, and a later request referencing a dynamic index then decoded
    # against the wrong entry — the probe sees a 'range' header from the
    # rejected request applied to a later one, turning its 200 into a 206.
    timeout 30 python3 test/tls/hpack_sync.py $CA ${P61443} >/dev/null 2>&1
    check "http2 HPACK table stays in sync across a rejected block" $?

    # ...and across the arena's wrap. The arena was a bump allocator that
    # reclaimed only when the table emptied, so an entry landing at the end was
    # silently not stored while the peer DID store it — leaving our table an
    # entry behind and every later dynamic index resolving to the wrong header.
    timeout 240 python3 test/tls/hpack_arena.py $CA ${P61443} >/dev/null 2>&1
    check "http2 HPACK entries survive the arena wrapping" $?

    # We advertise HEADER_TABLE_SIZE 4096, so the table is load-bearing for real
    # traffic rather than dead state: this drives eviction from "drop one" to
    # "drop everything", the entry-slot ceiling, size updates down to 0 and back,
    # and reads back a marker by dynamic index after every phase.
    timeout 400 python3 test/tls/hpack_stress.py $CA ${P61443} >/dev/null 2>&1
    check "http2 HPACK dynamic table under sustained use" $?

    # Q130: h2/h3 read a SEPARATE mime table from h1's, so the types are
    # checked here too — a type added to one table only is the easy mistake.
    printf 'x' > $WWW/probe.wasm
    ct=$(timeout 10 curl -s -D - -o /dev/null --http2 --cacert $CA \
        --resolve localhost:${P61443}:127.0.0.1 https://localhost:${P61443}/probe.wasm \
        | grep -i '^content-type' | tr -d '\r')
    printf '%s' "$ct" | grep -qF "application/wasm"
    check "http2 mime table has the same types (.wasm)" $?

    # RFC 9110 15.5.6: a 405 must name what the resource does take. h1 always
    # sent Allow; h2 sent none, so a client could not tell what to retry with.
    al=$(timeout 10 curl -si --http2 --cacert $CA \
        --resolve localhost:${P61443}:127.0.0.1 -X PROPFIND \
        https://localhost:${P61443}/hello.txt | tr -d '\r')
    printf '%s' "$al" | grep -q "405" && printf '%s' "$al" | grep -qi "^allow: GET, HEAD"
    check "http2 405 carries Allow: GET, HEAD" $?
    # and nothing else claims to: a 200 and a 404 carry no allow
    for u in /hello.txt /nope.txt; do
        n=$(timeout 10 curl -si --http2 --cacert $CA \
            --resolve localhost:${P61443}:127.0.0.1 https://localhost:${P61443}$u \
            | tr -d '\r' | grep -ci "^allow:")
        [ "$n" -eq 0 ]
        check "http2 no Allow on a normal response ($u)" $?
    done
    rm -f $WWW/probe.wasm

    # Q120: h2 requests reach the access log — static and proxied alike, in
    # h1's exact format. Before this only h1 was logged, so most real browser
    # traffic was invisible.
    # checked separately: as one AND-ed grep a red run could not say which
    # half was missing, and the static and proxied lines are emitted by
    # different code (h2_serve's funnel vs h2p_finish_stream).
    grep -qE 'request localhost from [0-9.:]+ "GET /hello.txt HTTP/2" 200 ' "$LOG"
    check "http2 static request access-logged" $?
    grep -qE '"GET /api/simple HTTP/2" 200 ' "$LOG"
    check "http2 proxied request access-logged" $?

    # h2-14: a GOAWAY from the client announces it will open no NEW streams; the
    # ones already running still have to be finished (RFC 9113 6.8). Closing on
    # receipt threw away a response that was already in flight.
    timeout 30 python3 test/tls/h2_goaway_inflight.py $CA ${P61443} >/dev/null 2>&1
    check "http2 client GOAWAY still finishes the in-flight response" $?

    # h2-16 receive-window accounting: a request body costs the client both its
    # stream and its connection flow-control window, and neither refills on its
    # own. A body larger than the 65535-byte initial window therefore only
    # completes if we credit the bytes back as WINDOW_UPDATE on the stream AND on
    # stream 0 as they go upstream (h2p rq_credit). 300000 bytes needs the credit
    # to keep coming ~5 times over, so a client that stops after one window — or a
    # server that only credits the connection — hangs here rather than mismatching.
    # The h1 upload case above covers the same relay over HTTP/1.1, which has no
    # flow control, so this is the only place the h2 windows are exercised.
    python3 -c "
import random
random.seed(12)
open('$WWW/h2upload.bin','wb').write(bytes(random.getrandbits(8) for _ in range(300000)))"
    want=$(md5sum < $WWW/h2upload.bin | cut -d' ' -f1)
    curl -s --http2 --max-time 30 --cacert $CA --data-binary @$WWW/h2upload.bin \
        $U/api/echo > $RUNDIR/h2upload_echo.bin
    [ "$(md5sum < $RUNDIR/h2upload_echo.bin | cut -d' ' -f1)" = "$want" ]
    check "http2 carries a 300000-byte request body past the flow-control window" $?
    rm -f $RUNDIR/h2upload_echo.bin $WWW/h2upload.bin

    # ...and what that check structurally cannot see: how many ROUND TRIPS the
    # body costs. It passed, byte-exact, while the server advertised no
    # SETTINGS_INITIAL_WINDOW_SIZE and credited 16 KiB at a time — 16 KiB per
    # RTT, invisible on loopback and 546 KB/s from a laptop. The round-trip
    # count is a property of the flow-control policy alone, so it reads the
    # same here as it would over a real network.
    timeout 90 python3 test/tls/h2_upload_window.py $CA ${P61443} >/dev/null 2>&1
    check "http2 upload: window advertised, credit batched, round trips bounded" $?

    # Uploads one after another on ONE connection. The streaming buffer's
    # claim (conn.h2_upload) was released by the service pass but TESTED when
    # the next request head was parsed, so the second upload saw a claim whose
    # owner had finished, fell back to the bounded collect path, and was
    # refused 413 at LINNEA_H2P_BODY_MAX — 8 KiB — however large max_body was.
    # Dead alternation: 200 413 200 413. Every existing upload check used a
    # fresh connection, so none of them could see it.
    # Both the buffer and its claim are gone now (every body is captured), so
    # this guards the shape rather than the mechanism: several uploads down one
    # connection must all come back 200, whatever is carrying them.
    # The local_port comparison is load-bearing: if curl ever stopped reusing
    # the connection this would pass while testing nothing.
    python3 -c "open('$WWW/h2seq.bin','wb').write(b'S'*100000)"
    u3=$(curl -s --http2 --cacert $CA -H "Expect:" --max-time 30 \
            -X POST --data-binary @$WWW/h2seq.bin -w '%{http_code}:%{local_port} ' -o /dev/null $U/api/echo \
         --next -s --http2 --cacert $CA -H "Expect:" \
            -X POST --data-binary @$WWW/h2seq.bin -w '%{http_code}:%{local_port} ' -o /dev/null $U/api/echo \
         --next -s --http2 --cacert $CA -H "Expect:" \
            -X POST --data-binary @$WWW/h2seq.bin -w '%{http_code}:%{local_port}' -o /dev/null $U/api/echo)
    u3codes=$(echo "$u3" | tr ' ' '\n' | cut -d: -f1 | tr '\n' ' ')
    u3conns=$(echo "$u3" | tr ' ' '\n' | cut -d: -f2 | sort -u | grep -c .)
    [ "$u3codes" = "200 200 200 " ] && [ "$u3conns" -eq 1 ]
    check "http2: three uploads in a row on one connection all stream ($u3codes on $u3conns conn)" $?
    rm -f $WWW/h2seq.bin

    # Body-phase slowloris (Q119): head_timeout used to stop at the request
    # head, so a client trickling a proxied request body — or sitting silent
    # on an h2 upload, dodging the idle timeout — held its upstream slot
    # forever. The body clock (LINNEA_BODY_NS_PER_BYTE per received byte) cuts
    # a trickler about head_timeout after its last honest burst: h1 closes,
    # h2 fails the stream 408 and the connection and slot live on. A
    # full-speed upload must be untouched. Own server: head_timeout=3.
    start_server $CFG/tls-slowbody.json
    P61457=$SRV_PORT
    slowbody_pid=$SRV_PID
    sleep 0.3
    timeout 60 python3 test/tls/slow_body.py $CA ${P61457} >/dev/null 2>&1
    check "request-body slowloris cut on h1 and h2; honest uploads untouched" $?
    kill $slowbody_pid 2>/dev/null
    wait $slowbody_pid 2>/dev/null

    # --- HTTP/3 through an INDEPENDENT implementation -----------------------
    # Every other h3 check in this file drives aioquic. If linnea and aioquic
    # share a misreading of RFC 9114, that agreement looks exactly like
    # correctness and nothing here can tell. curl built against ngtcp2 +
    # nghttp3 shares no code with either, so where the two agree the reading is
    # very unlikely to be wrong.
    #
    # Optional, like the aioquic checks: skipped when the binary is absent, so
    # a clean checkout still passes. Build one with
    #   ./configure --with-ngtcp2 --with-nghttp3 --prefix=$HOME/curl-h3
    # and point LINNEA_CURL_H3 at it, or leave it at the default path.
    #
    # --http3-only, never --http3: the latter falls back to h2 when h3 fails,
    # which would let a broken h3 pass every check below.
    CURLH3=${LINNEA_CURL_H3:-$HOME/curl-h3/bin/curl}
    if [ -x "$CURLH3" ] && "$CURLH3" -V 2>/dev/null | grep -q HTTP3; then
        h3o="--http3-only -s --max-time 25 --cacert $CA"
        h3r="--resolve localhost:${P61443}:127.0.0.1"

        # big.txt, not hello.txt: 100000 bytes is many packets, so this covers
        # stream reassembly and flow control rather than one lucky datagram.
        "$CURLH3" $h3o $h3r -o $RUNDIR/h3big.out $U/big.txt
        curl -s --http2 --max-time 10 --cacert $CA -o $RUNDIR/h2big.out $U/big.txt
        [ -s $RUNDIR/h3big.out ] && cmp -s $RUNDIR/h3big.out $RUNDIR/h2big.out
        check "h3 (ngtcp2): a 100000-byte file is byte-identical to h2's copy" $?
        rm -f $RUNDIR/h3big.out $RUNDIR/h2big.out

        # h3 could not express a redirect at all until it could emit Location
        # (QPACK static index 12); before that a vhost with one was kept off h3
        # entirely, so this is also the check that the vhost HAS a listener.
        l3=$("$CURLH3" $h3o $h3r -o /dev/null -D - "$U/old/page?x=1" \
             | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
        l1=$(curl -s --http1.1 --max-time 10 --cacert $CA -o /dev/null -D - \
             "$U/old/page?x=1" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
        [ -n "$l3" ] && [ "$l3" = "$l1" ]
        check "h3 redirect: Location matches h1 exactly ($l3)" $?

        s3=$("$CURLH3" $h3o $h3r -o /dev/null -w '%{http_code}' "$U/old/page?x=1")
        [ "$s3" = "301" ]
        check "h3 redirect: 301 over QUIC ($s3)" $?

        # an upload over h3, which is the capture path rather than the FIFO
        python3 -c "
import random, sys
random.seed(23)
open(sys.argv[1],'wb').write(bytes(random.getrandbits(8) for _ in range(300000)))" "$WWW/h3up.bin"
        "$CURLH3" $h3o $h3r -o $RUNDIR/h3up.out -X POST \
            --data-binary @$WWW/h3up.bin $U/api/echo
        [ -s $RUNDIR/h3up.out ] &&
        [ "$(md5sum < $RUNDIR/h3up.out | cut -d' ' -f1)" = \
          "$(md5sum < $WWW/h3up.bin | cut -d' ' -f1)" ]
        check "h3 (ngtcp2): a 300000-byte upload round-trips byte-exact" $?
        rm -f $WWW/h3up.bin $RUNDIR/h3up.out

        m3=$("$CURLH3" $h3o $h3r -o /dev/null -w '%{http_code}' $U/nope.txt)
        [ "$m3" = "404" ]
        check "h3 (ngtcp2): a missing file is 404, not a hang ($m3)" $?
    else
        check "h3 via an independent client (skipped: no HTTP/3 curl — see the note above)" 0
    fi

    kill $tls_server_pid $tls_backend_pid 2>/dev/null
    wait $tls_server_pid 2>/dev/null
    wait $tls_backend_pid 2>/dev/null
    rm -f "$LOG" $WWW/big.txt

    # --- SNI: two TLS vhosts share 127.0.0.1:61444, each with its own cert
    start_server $CFG/tls-sni.json
    sni_server_pid=$SRV_PID
    sleep 0.3
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -servername sni.test 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=sni.test"
    check "sni selects the named vhost cert" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -servername localhost 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "sni selects the owner cert by name" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -noservername 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "no sni falls back to the listener owner" $?
    subj=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} \
        -servername unknown.test 2>/dev/null | openssl x509 -noout -subject)
    echo "$subj" | grep -q "CN=localhost"
    check "unknown sni falls back to the listener owner" $?
    # the SAME must hold over HTTP/3: the QUIC listener on this port registers both
    # vhosts, and the ClientHello SNI selects the certificate (before this, h3 always
    # served the first vhost's cert, so a second name got the wrong one).
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        python3 test/quic/h3_sni_cert_test.py ${P61444} sni.test sni.test >/dev/null 2>&1
        check "h3 sni selects the named vhost cert" $?
        python3 test/quic/h3_sni_cert_test.py ${P61444} localhost localhost >/dev/null 2>&1
        check "h3 sni selects the owner cert by name" $?
    fi
    # every h3 vhost advertises Alt-Svc, not only the socket owner, so each origin
    # tells its own clients they can switch to h3 (a non-owner vhost is checked).
    curl -s -D - -o /dev/null --http2 --cacert test/tls/sni.crt \
        --resolve sni.test:${P61444}:127.0.0.1 https://sni.test:${P61444}/page.html \
        | grep -qi 'alt-svc: h3='
    check "h3 alt-svc advertised by a non-owner vhost" $?
    # h2 is on by default (tls-sni.json sets no "http2" key): a static vhost
    # negotiates h2.
    echo | timeout 5 openssl s_client -connect 127.0.0.1:${P61444} -CAfile test/tls/sni.crt \
        -servername sni.test -tls1_3 -alpn h2,http/1.1 2>/dev/null \
        | grep -q "ALPN protocol: h2"
    check "alpn: h2 on by default (static vhost)" $?
    # a full request via the SNI vhost: curl verifies against the sni.test
    # cert AND the Host routing must land on the sni.test docroot (which
    # holds page.html; the listener owner does not). h2 is on by default now,
    # so this also exercises SNI vhost routing over HTTP/2.
    resp=$(curl -s --max-time 5 --cacert test/tls/sni.crt \
        --resolve sni.test:${P61444}:127.0.0.1 https://sni.test:${P61444}/page.html)
    check_http "sni end to end (cert + vhost routing)" "subdirectory page" "$resp"

    # Q126: h2 answers only for names the certificate it presented covers —
    # the rule h3 got in Q124. A cross-certificate request gets 421, a name
    # we do not host is served by the connection's own vhost, and two vhosts
    # sharing ONE certificate still coalesce onto a single connection. The
    # worker-PID check is not ceremony: the first version of this crashed the
    # worker (the 421 path skipped the vhost the response builder reads), and
    # a crash looks exactly like a closed connection from the client side.
    start_server $CFG/tls-coalesce.json
    coal_h2_pid=$SRV_PID
    sleep 0.4
    md_before=$(workers_of $sni_server_pid)
    timeout 60 python3 test/tls/h2_misdirected.py $CA ${P61444} ${P61459} >/dev/null 2>&1
    md_rc=$?
    md_after=$(workers_of $sni_server_pid)
    [ "$md_rc" -eq 0 ] && [ -n "$md_before" ] && [ "$md_before" = "$md_after" ]
    check "http2 misdirected request: 421 across certs, coalescing kept" $?
    kill $coal_h2_pid 2>/dev/null
    wait $coal_h2_pid 2>/dev/null

    # Q124: h3 honours :authority instead of serving whatever the TLS SNI
    # chose, and answers a name this connection's certificate does not cover
    # with 421 rather than the other vhost's page.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        timeout 90 python3 test/quic/h3_authority_test.py ${P61444} >/dev/null 2>&1
        check "h3 authority selects the vhost; cross-cert gets 421" $?
    else
        check "h3 authority test (skipped: deps unavailable)" 0
    fi

    # ...and the other side of that strictness: two vhosts sharing ONE
    # certificate are both names the connection can speak for, so a single
    # h3 connection serves both (what a browser coalesces). Own server: the
    # two vhosts differ from the SNI pair in using the same cert.
    if python3 -c 'import aioquic, pylsqpack' 2>/dev/null; then
        start_server $CFG/tls-coalesce.json
        coal_pid=$SRV_PID
        sleep 0.4
        timeout 60 python3 test/quic/h3_coalesce_test.py ${P61459} >/dev/null 2>&1
        check "h3 coalescing: one cert, two vhosts, one connection" $?
        kill $coal_pid 2>/dev/null
        wait $coal_pid 2>/dev/null
    else
        check "h3 coalescing test (skipped: deps unavailable)" 0
    fi
    kill $sni_server_pid 2>/dev/null
    wait $sni_server_pid 2>/dev/null
    rm -f "$LOG"
fi

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

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
