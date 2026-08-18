#!/usr/bin/env bash
# Run the shard directories concurrently, each in its own process with its own
# port base (1000 apart), and merge the results.
#
# There is nothing to verify at the end. run.sh runs every NN-*.sh file in every
# directory it is handed, so a shard cannot silently skip a check the way the
# old region-gating could -- which is the whole reason the tests moved into
# per-shard directories and the union check went away with the reference file it
# needed. A check now runs in exactly one job, so the printed total is the real
# count, not an inflated one.
#
# usage: run_shards.sh                 (fast)
#        LINNEA_SUITE=full run_shards.sh
set -u
cd "$(dirname "$0")/../.."             # repo root (this file is test/shards/)

SUITE=${LINNEA_SUITE:-fast}
case "$SUITE" in fast|full) ;; *) echo "FATAL: LINNEA_SUITE must be fast|full" >&2; exit 1;; esac
BASE=${LINNEA_TEST_PORT_BASE:-61000}
OUT=${LINNEA_SHARD_OUT:-test/shards/out}
mkdir -p "$OUT"
rm -f "$OUT"/job-*.out

# The jobs, one per concurrent process. `base` (config parsing, the crypto
# vectors, the EMFILE backoff) is folded into the quic job: it is a few seconds
# and quic is the lightest region, so the three jobs stay balanced the way the
# old three shards were. Splitting further is pointless until one region is
# broken up -- a job can be no faster than its slowest region.
jobs=("base quic" "h1" "tls")

# Build the unit-test binaries ONCE, before any job. The suite builds them
# itself, which is right for one run and a race for three: they share a source
# tree, so three concurrent makes relink the same file while another job is
# executing it. That failed the crypto selftest in two jobs of three with a
# segfault on a binary that passes standing alone.
echo "pre-building the unit-test binaries..."
make -s bin/linnea-selftest bin/linnea-quictest bin/linnea-rtxtest \
        bin/linnea-nettest bin/linnea-strtest bin/linnea-qpacktest \
        bin/linnea-h3test bin/linnea-h3resp bin/linnea-ws-fast \
        bin/linnea-quichs tlstest \
        >/dev/null 2>&1

echo "running ${#jobs[@]} jobs of the $SUITE suite, port bases $BASE..$((BASE + (${#jobs[@]} - 1) * 1000))"
start=$(date +%s)
pids=""
i=0
for job in "${jobs[@]}"; do
    LINNEA_TEST_PORT_BASE=$((BASE + i * 1000)) \
    LINNEA_SUITE="$SUITE" \
        ./test/shards/run.sh $job > "$OUT/job-$i.out" 2>&1 &
    pids="$pids $!"
    i=$((i + 1))
done

rc=0
for p in $pids; do wait "$p" || rc=1; done
elapsed=$(( $(date +%s) - start ))

echo
pass=0
fail=0
i=0
for job in "${jobs[@]}"; do
    p=$(grep -c '^PASS' "$OUT/job-$i.out")
    f=$(grep -c '^FAIL' "$OUT/job-$i.out")
    pass=$((pass + p))
    fail=$((fail + f))
    printf 'job %d (%-9s): %4d passed, %d failed\n' "$i" "$job" "$p" "$f"
    grep '^FAIL' "$OUT/job-$i.out" | sed 's/^/    /'
    i=$((i + 1))
done
echo
echo "$pass passed, $fail failed across ${#jobs[@]} jobs in ${elapsed}s ($SUITE suite)"
[ "$fail" -eq 0 ] && [ "$rc" -eq 0 ]
