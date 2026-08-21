#!/usr/bin/env bash
# The FULL, deploy-gating test suite: every check INCLUDING the slow ones, run
# as concurrent jobs. This is what must pass before anything is deployed.
#
#   ./test/run_full_suite.sh          all directories + the slow checks
#
# For quick iteration use ./test/run_fast_suite.sh. To run one directory, or in
# a single process for easier debugging, use ./test/run_tests.sh.
export LINNEA_SUITE=full
exec "$(dirname "$0")/run_shards.sh" "$@"
