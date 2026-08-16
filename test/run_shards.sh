#!/usr/bin/env bash
# Run the test-suite directories concurrently, each in its own process with its
# own port base, and merge the results.
#
#   ./test/run_shards.sh                    (fast)
#   LINNEA_SUITE=full ./test/run_shards.sh  (everything)
#
# There is no union check any more: run.sh runs every file in every directory it
# is given, so a job cannot silently skip a check the way the old region-gating
# could. A check runs in exactly one job, so the printed total is the real count.
# The runner lives in test/shards/run_shards.sh.
exec "$(dirname "$0")/shards/run_shards.sh" "$@"
