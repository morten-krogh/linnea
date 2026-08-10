# Stopping, reloading and restarting linnea

The two ways of ending a worker mean opposite things, and linnea answers them
differently on purpose.

| Signal | Sent by | What a worker does |
|---|---|---|
| **SIGTERM** | `systemctl stop`, `systemctl restart`, and the kernel when the master dies (`PR_SET_PDEATHSIG`) | **Exits immediately**, dropping everything open — keep-alives, WebSocket tunnels, uploads and downloads in progress. |
| **SIGQUIT** | the master alone, retiring the previous generation during a reload | **Drains**: stops accepting, finishes what is already open, exits when the last connection closes or when `drain_timeout` expires, whichever comes first. |
| **SIGHUP** | a log rotation | Reopens the log file. Nothing else — it is *not* a configuration reload. |
| **SIGUSR2** | `systemctl reload` | The master re-execs in place, then SIGQUITs the old generation. |

---

## Why a stop is immediate

Nothing open outlives a stop however politely it is treated, so finishing
first buys nothing — and waiting was expensive. A browser almost always holds
an idle keep-alive, and a WebSocket tunnel is **never** idle: every frame
pushes its activity timestamp forward, so no timeout ever reaps it and it ends
only when a peer closes it, which a stop does not.

Draining on SIGTERM therefore meant a stop ran until systemd gave up and sent
SIGKILL. Measured, from the signal to the last worker gone:

| Open at the time | Draining | Immediate |
|---|---|---|
| nothing | 0.00 s | 0.00 s |
| an idle keep-alive | 0.00 s | 0.00 s |
| a quiet WebSocket | the idle timeout — 60 s on the live config | 0.00 s |
| a busy WebSocket | never; SIGKILL at `TimeoutStopSec` | 0.00 s |
| a 6 MiB download | until it finished | 0.00 s |

Clients reconnect to the server that comes back, which is what a restart is.
`TimeoutStopSec=10` remains in the unit as a backstop for a worker too wedged
to answer a signal; in normal operation it is never reached.

## Why a reload drains

A reload is the opposite case. The master re-execs, spawns a new generation on
the same listeners, and only then retires the old one — so everything arriving
already goes to the new workers, and the last requests in flight are all the
old ones have left to do. Finishing them is the entire point: it is what makes
the upgrade lossless.

But a tunnel never finishes, so the drain is bounded by **`drain_timeout`**
(seconds, 1–3600, default 30 — see [config.md](config.md)). Without that bound
a single open tab kept an old worker alive for as long as the tab lived, and
every reload left another one behind.

`0` is deliberately not accepted: an unbounded drain is the leak the deadline
exists to prevent.

---

## Applying a change

```
linnea --test --config /etc/linnea/linnea.json   # exits 0, or says why not
sudo systemctl reload linnea                     # or: kill -USR2 $MAINPID
```

`kill -USR2` needs no root when the unit runs as the `linnea` user, and is
exactly what the unit's `ExecReload` does. The master runs the new binary in
`--test` mode before committing, and **refuses the reload if the configuration
is bad, leaving the old generation serving** — so a typo cannot take the site
down. It picks up a new binary at the same time, since it re-execs; there is
no configuration-only reload.

The main PID does not change across a reload. `systemctl status` will keep
reporting the original "active since", and briefly show more tasks than usual
while the old generation drains. If the PID *has* changed and "active since"
has reset, what happened was a restart, not an upgrade — see below.

### When a reload cannot be hot

The upgrade hands the listening sockets to the new binary, which matches them
against the servers in the configuration. That only works while the set of
servers is unchanged. **Add or remove a server and the re-exec'd binary
refuses the handover and exits:**

```
linnea: hot upgrade needs an unchanged listener set; use restart
```

The old image is already gone by then — the check happens after the re-exec,
which is the point of no return — so there is nothing left to keep serving.
`Restart=on-failure` in the unit brings the server back within a second, but
as a **restart**: every connection is dropped, the main PID changes, and the
log shows a fresh `listening on …` rather than `adopted listener …`. The
refusal itself goes to stderr, so it lands in the journal and **not** in the
access log, which makes this look unexplained if you only read the log.

So: **use `systemctl restart` when adding or removing a server**, and reload
for everything else — values inside an existing server, locations, globals,
and a new binary.

Telling the two apart afterwards, in the log:

| A hot upgrade | A refused one |
|---|---|
| `adopted listener 0.0.0.0:443 (…)` | `listening on 0.0.0.0:443 (…)` |
| `binary upgrade complete: new workers up, draining old` | *(absent)* |
| old workers log `worker draining` / `worker drained` | they log `worker stopping: connections dropped` — the master died and PDEATHSIG reached them |

## What the log tells you

| Line | Meaning |
|---|---|
| `worker stopping: connections dropped` | a stop — SIGTERM |
| `worker draining: accepts closed, finishing open connections` | a reload's old generation beginning to drain |
| `worker drained` | it finished everything it held, and exited |
| `worker drain deadline reached, dropping what is left` | `drain_timeout` expired first |

The last one is worth noticing. It is normal when a WebSocket is connected —
that drain could never have ended on its own — but if it appears with no
long-lived connections around, something is not completing that should.

---

## Notes for maintainers

**Only the master's `kill_old_workers` sends SIGQUIT.** The master installs no
SIGQUIT handler, so `kill -QUIT $MAINPID` merely kills the master, and its
workers then receive SIGTERM from `PR_SET_PDEATHSIG` — an immediate stop, not
a drain. To exercise a drain you must signal the *workers*.

**Then stop the master, or it will respawn them.** `.supervise` respawns any
worker that dies more than a second after it was spawned.

**A worker already draining ignores the next stop signal** — `drain_flag` is
checked first in `.on_stop_signal`. That is what makes the sequence above
safe: SIGQUIT the workers, then SIGTERM the master, and the PDEATHSIG SIGTERM
that follows does not cancel the drain in progress. `drain_workers` in
`test/run_tests.sh`, and the copy in each of the four Python drain drivers,
does exactly this.

**A `drain_timeout` change takes two reloads to take visible effect.** A
worker reads the configuration at startup, so the first reload only loads the
new value into the generation it starts; the second is when that generation
retires under it. The generation being retired on the first reload still uses
the value it started with. The same is true of any setting read at startup.

**Measuring the deadline needs something that cannot finish.** Hold a busy
WebSocket open and the deadline is what ends the drain, so the number you
measure is the one under test. Without it the drain completes early — 3
seconds, against a 10-second deadline, on a worker that happened to hold
nothing — and tells you nothing.

**HTTP/3 drains on its own path**, `goaway_all` and `drain_sweep` off the QUIC
timer tick rather than the connection pool, so a change to one is not a change
to both.

The behaviour is covered by two checks in the suite: *a stop is immediate
whatever is open*, which holds a quiet tunnel, a busy tunnel and a streaming
response across a SIGTERM, and *a reload retires an old worker a tunnel pins*,
whose fixture sets `drain_timeout: 3` so it also proves the configured value
reaches the timer.
