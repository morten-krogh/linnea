#!/usr/bin/env bash
# Run one or more shard directories under test/shards/. Each directory holds
# *.sh fragments that assume common.sh is already sourced; they run in sorted
# (numeric-prefix) order. Coverage is simply "every file in every named
# directory runs" -- there is no region gating and nothing to silently skip, so
# no reference set and no union check are needed to know a run was complete.
#
#   run.sh                     the whole suite, serially: base quic h1 tls
#   run.sh quic                just one shard (this is how run_shards runs a job)
#   run.sh base tls            several, in the given order
#   LINNEA_SUITE=full run.sh   include the slow checks
#
# Its exit status is 0 iff every check passed.
here=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)
# common.sh cd's to the repo root and does all one-time setup, the stray-server
# guards, and the helper definitions -- once, in this shell.
source "$here/lib/common.sh"

dirs=("$@")
[ "${#dirs[@]}" -eq 0 ] && dirs=(base quic h1 tls)

for d in "${dirs[@]}"; do
    if [ ! -d "$here/$d" ]; then
        echo "FATAL: no such shard directory: test/shards/$d" >&2
        exit 1
    fi
    ran=0
    for f in "$here/$d"/[0-9]*.sh; do
        [ -e "$f" ] || continue
        ran=1
        source "$f"
    done
    if [ "$ran" -eq 0 ]; then
        echo "FATAL: shard directory test/shards/$d has no NN-*.sh files" >&2
        exit 1
    fi
done

echo
if [ "$SUITE" = full ]; then
    echo "$pass passed, $fail failed (full run)"
else
    # Said plainly and every time: "670 passed, 0 failed" reads exactly like a
    # complete run unless the line itself says otherwise.
    echo "$pass passed, $fail failed, $skipped SKIPPED (fast run)"
    echo "This is NOT a full run. Before deploying: LINNEA_SUITE=full ./test/run_tests.sh ${*:-}"
fi
[ "$fail" -eq 0 ]
