#!/usr/bin/env bash
# Run one or more shard directories -- or single shard files -- under
# test/shards/. Each directory holds *.sh fragments that assume common.sh is
# already sourced; they run in sorted (numeric-prefix) order. Coverage for a
# DIRECTORY is simply "every file in it runs": no region gating, nothing to
# silently skip, so no reference set and no union check are needed to know that
# run was complete.
#
# Naming a FILE deliberately breaks that property, which is why it announces
# itself. This tree has been bitten twice by a partial result reading like a
# complete one -- a skip counted as a pass, and a guard that had stopped
# guarding -- so a file run prints PARTIAL rather than the ordinary summary.
#
#   run.sh                     the whole suite, serially: base quic h1 tls
#   run.sh quic                just one shard (this is how run_shards runs a job)
#   run.sh base tls            several, in the given order
#   run.sh tls/20-e2e.sh tls/30-h3-proxy.sh    FILES, for iterating on a change
#
# Files share shell state, so naming one is not always enough. tls/20-e2e.sh
# starts the proxy backend and sets $U, and 30-h3-proxy, 40-http2 and
# 50-e2e-teardown all read them -- name 30-h3-proxy alone and every proxy check
# in it answers 502 and it dies on `U: unbound variable`. Prefixing 20-e2e.sh
# costs 12s and fixes both. Measured: tls is 486s, 20-e2e + 30-h3-proxy is 121s
# for the 98 checks that cover the h3 proxy path.
#   LINNEA_SUITE=full run.sh   include the slow checks
#
# A single file is for the edit-test loop, never for a verdict. The tls shard is
# 486s and two of its eight files are 66% of that (70-backend-tls-client 209s,
# 30-h3-proxy 111s), so re-running all of it to exercise one changed path costs
# minutes per iteration. A file run says PARTIAL in its summary for the reason
# below.
#
# Its exit status is 0 iff every check passed.
here=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)
# common.sh cd's to the repo root and does all one-time setup, the stray-server
# guards, and the helper definitions -- once, in this shell.
source "$here/lib/common.sh"

targets=("$@")
[ "${#targets[@]}" -eq 0 ] && targets=(base quic h1 tls)

partial=0                     # set when a single file was named, never cleared
for t in "${targets[@]}"; do
    if [ -d "$here/$t" ]; then
        ran=0
        for f in "$here/$t"/[0-9]*.sh; do
            [ -e "$f" ] || continue
            ran=1
            source "$f"
        done
        if [ "$ran" -eq 0 ]; then
            echo "FATAL: shard directory test/shards/$t has no NN-*.sh files" >&2
            exit 1
        fi
    elif [ -f "$here/$t" ]; then
        partial=1
        source "$here/$t"
    else
        echo "FATAL: no such shard directory or file: test/shards/$t" >&2
        exit 1
    fi
done

echo
if [ "$partial" -eq 1 ]; then
    # Loud, and before the count: the number is the first thing read, and on its
    # own "63 passed, 0 failed" from one file is indistinguishable from a shard.
    echo "*** PARTIAL RUN: named files only, NOT a shard. ***"
    echo "*** Run the whole shard before believing anything about coverage. ***"
fi
if [ "$SUITE" = full ]; then
    echo "$pass passed, $fail failed (full run)"
else
    # Said plainly and every time: "670 passed, 0 failed" reads exactly like a
    # complete run unless the line itself says otherwise.
    echo "$pass passed, $fail failed, $skipped SKIPPED (fast run)"
    echo "This is NOT a full run. Before deploying: LINNEA_SUITE=full ./test/run_tests.sh ${*:-}"
fi
[ "$fail" -eq 0 ]
