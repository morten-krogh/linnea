#!/usr/bin/env bash
# The linnea test suite.
#
# The tests live in per-shard directories under test/shards/ -- each a directory
# of NN-*.sh fragments run in order against fixtures they start and stop
# themselves. This entry point runs them all in one process. Pass directory
# names to run only some:  ./test/run_tests.sh quic     (or  base h1  etc.)
# Run the directories CONCURRENTLY instead with  ./test/run_shards.sh.
#
#   LINNEA_SUITE=full ./test/run_tests.sh    also runs the ~two dozen slow checks
#
# Why it is shaped this way: the suite used to be one ~5300-line script, sharded
# by an `if region N % SHARDS` gate. That gate could silently drop a check from
# every shard (a helper defined in a skipped region, a mis-braced block), so a
# union check compared each run's check names against a gitignored reference to
# prove nothing went missing. With the tests in directories the gate is gone --
# coverage is just "every file in every directory runs" -- and so are the union
# check and its reference file. See test/shards/lib/common.sh for the shared
# setup and helpers, and test/shards/run.sh for the runner itself.
exec "$(dirname "$0")/shards/run.sh" "$@"
