# Audit Report 94

Audited at `f76014b` (`linnea-api: accept a 107-byte socket path (audit-report-93)`), 2026-08-27.

This pass reviewed the report-93 boundary fix and its new end-to-end test, then
followed the TLS/keep-alive documentation through the runtime. The runtime
behavior is documented and intentional; one test-harness safety issue is
confirmed.

## Finding 1 — boundary test kills every `linnea-api` process by name

Severity: **High (P1 for a root/concurrent test run; the test can terminate an unrelated service)**  
Confidence: **High**  
Status: **Confirmed by source inspection; unfixed.**

The new pathname-boundary loop starts `./bin/linnea-api` under `timeout`, but
does not retain its PID. After each case it executes `pkill -x linnea-api`
([test/shards/h1/30-proxying.sh:448](/home/linnea/linnea/test/shards/h1/30-proxying.sh:448) through [test/shards/h1/30-proxying.sh:458](/home/linnea/linnea/test/shards/h1/30-proxying.sh:458)). `pkill -x` matches the executable name globally, not the process started by
this test.

### Impact

Running the suite as root, or on a host where the installed `linnea-api`
service runs under the same account, can stop the real backend and create a
production outage. A concurrent test invocation can also kill another run's
backend, making failures nondeterministic and undermining the suite's stated
sharded/concurrent execution model. The command is especially risky because
the test is otherwise careful to keep per-run socket and port state isolated.

### Reproduction

Start any unrelated process whose executable name is `linnea-api`, then run the
h1 shard. When the first 107/108-byte case completes, `pkill -x linnea-api`
sends it the default termination signal as well as terminating the test's
listener. No PID, process-group, socket path, or run-directory check narrows
the target.

### Recommended fix

Capture the PID returned when launching each boundary listener and terminate
only that process (and wait for it), or run the command in a private process
group and signal that group. Keep the existing per-case timeout, but never use
name-wide `pkill` in a test that can run beside installed services or another
suite instance. Add a regression guard that launches a sentinel process with
the same executable name and verifies it survives the boundary checks.

No production source was changed in this audit. Only this report was added.

---

## Resolution (2026-08-27)

**Finding 1: CONFIRMED and FIXED.** The blast radius was established with
`pgrep -x` rather than by firing the command — `pgrep` matches exactly the set
`pkill` would signal:

    $ pgrep -x -a linnea-api
    3352903 /usr/local/bin/linnea-api 7700 /var/lib/linnea-api
    3353254 /usr/local/bin/linnea-api unix:/run/linnea-api-2/api.sock ...

**Both production backends.** They survive only because they run as
`linnea-svc` while the suite runs as `linnea`, so the kernel refuses the
signal. That is an accident of user separation, not a safeguard. It was the
only `pkill`/`killall` in the entire test tree.

Each listener is now signalled by its own captured PID. The report's sentinel
recommendation is implemented: a process with the same executable name is
started before the loop and required to survive it. Control, with the old
name-wide cleanup restricted by `--uid` so production could not be touched:

    sentinel started: alive=yes
    after name-wide pkill: alive=NO -- the sentinel was killed

so the new check genuinely fails on the old code. Fast suite **1179/0**.

### One addition to the reproduction

The report suggests starting an unrelated `linnea-api` and running the h1
shard. On this host the likelier victim is a **concurrent suite run**:
`h1/40-ws-term.sh` starts its own `./bin/linnea-api`, so two runs at different
port bases would have one kill the other's backend. That needs no root and no
installed service, and it sits inside the suite's own documented concurrency
model — which makes it the more probable failure, not the more exotic one.

### The uncomfortable part

There is a standing note in this project about `pkill -f` matching more than
intended, written after it cost real time. I wrote a name-wide `pkill` into a
committed test anyway, one commit after being handed an off-by-one in the same
file. Knowing a trap is recorded is not the same as checking against it.
