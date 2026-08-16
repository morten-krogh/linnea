#!/usr/bin/env bash
# Run the suite as N concurrent shards and merge the results.
#
# Each shard is an ordinary run of run_tests.sh with LINNEA_SHARD=i/N and its
# own port base, so they share no port, no RUNDIR and no fixture -- the same
# isolation two full runs have had since 455efb8. Ports are 1000 apart because
# every port the suite binds is base+0..base+999.
#
# A shard cannot be faster than the largest REGION it holds: measured at 160 s
# (quic/h3), 319 s (h1/proxy/ws/upload) and 371 s (tls/h2) of a full serial
# run's 858, so three is the useful maximum until one of those is broken up.
#
# WHAT MAKES THIS TRUSTWORTHY IS THE UNION CHECK AT THE END, not the shard
# arithmetic: the merged set of check names is compared against the names a
# serial run produces, and anything missing from every shard is reported as a
# failure of the sharding rather than of the code. A static reading of this
# script cannot establish that -- it has eleven embedded heredocs, and brace
# matching over them is how one attempt at exactly this analysis silently
# concluded the file was two blocks long.
#
# usage: run_shards.sh [N]            (default 3)
#        LINNEA_SUITE=full run_shards.sh
set -u
cd "$(dirname "$0")/.."

N=${1:-3}
BASE=${LINNEA_TEST_PORT_BASE:-61000}
SUITE=${LINNEA_SUITE:-fast}
OUT=${LINNEA_SHARD_OUT:-test/shard-out}
mkdir -p "$OUT"
rm -f "$OUT"/shard-*.out

if [ "$N" -gt 4 ]; then
    echo "FATAL: at most 4 shards -- base+${N}000 would pass 65000, and" >&2
    echo "       genports.py refuses a base that high." >&2
    exit 1
fi

echo "running $N shards of the $SUITE suite, port bases $BASE..$((BASE + (N-1)*1000))"
start=$(date +%s)
pids=""
for i in $(seq 0 $((N - 1))); do
    LINNEA_SHARD="$i/$N" \
    LINNEA_TEST_PORT_BASE=$((BASE + i * 1000)) \
    LINNEA_SUITE="$SUITE" \
        ./test/run_tests.sh > "$OUT/shard-$i.out" 2>&1 &
    pids="$pids $!"
done

rc=0
for p in $pids; do
    wait "$p" || rc=1
done
elapsed=$(( $(date +%s) - start ))

echo
pass=0; fail=0
for i in $(seq 0 $((N - 1))); do
    p=$(grep -c '^PASS' "$OUT/shard-$i.out")
    f=$(grep -c '^FAIL' "$OUT/shard-$i.out")
    pass=$((pass + p)); fail=$((fail + f))
    printf 'shard %d: %4d passed, %d failed\n' "$i" "$p" "$f"
    grep '^FAIL' "$OUT/shard-$i.out" | sed 's/^/    /'
done
echo
echo "$pass passed, $fail failed across $N shards in ${elapsed}s"
echo "(checks outside the three regions run in every shard, so passes are"
echo " counted more than once; the union check below is the real accounting.)"

# --- the union check ---------------------------------------------------------
# A serial run's names, against the union of the shards'. This is what catches a
# region gate that swallowed a block, which is the failure this design can have
# and the one that would otherwise look like a faster suite.
# One reference per mode: a fast run names its skipped checks with the reason
# attached, so a full run's names are not the same strings.
ref=$OUT/serial-$SUITE.names
if [ ! -s "$ref" ]; then
    echo
    echo "no reference names in $ref -- produce them once with:"
    echo "    LINNEA_SUITE=$SUITE ./test/run_tests.sh | grep -E '^(PASS|FAIL|SKIP)' \\"
    echo "        | sed 's/^[A-Z]*: //' | sort -u > $ref"
    exit "$rc"
fi
# Names are normalised before comparing: most carry an interpolated tail -- an
# elapsed time, a byte count, a kernel-chosen port, the run's own RUNDIR -- and
# comparing those raw reports every timing difference as a missing check, which
# buries the one line that matters.
norm() { sed 's/^[A-Z]*: //; s/([^()]*)//g; s/[0-9][0-9]*//g; s/  */ /g; s/ *$//'; }
grep -hE '^(PASS|FAIL|SKIP)' "$OUT"/shard-*.out | norm | sort -u > "$OUT/shards.names"
norm < "$ref" | sort -u > "$OUT/serial-$SUITE.norm"
ref=$OUT/serial-$SUITE.norm
missing=$(comm -23 "$ref" "$OUT/shards.names" | wc -l)
extra=$(comm -13 "$ref" "$OUT/shards.names" | wc -l)
echo
if [ "$missing" -eq 0 ] && [ "$extra" -eq 0 ]; then
    echo "union check: the shards ran exactly the checks a serial run does"
else
    echo "UNION CHECK FAILED: $missing check(s) ran in no shard, $extra unexpected"
    comm -23 "$ref" "$OUT/shards.names" | head -20 | sed 's/^/    missing: /'
    comm -13 "$ref" "$OUT/shards.names" | head -20 | sed 's/^/    extra:   /'
    rc=1
fi
exit "$rc"
