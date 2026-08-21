#!/usr/bin/env bash
# The FAST test suite: every check except the couple dozen slow ones, run as
# concurrent jobs. Quick enough for iteration -- it does NOT gate a deploy.
#
#   ./test/run_fast_suite.sh          all directories, concurrently
#
# For the full, deploy-gating suite use ./test/run_full_suite.sh. To run one
# directory, or in a single process for easier debugging, use ./test/run_tests.sh.
exec "$(dirname "$0")/run_shards.sh" "$@"
