# Unix-socket backends — implementation plan

Roadmap: a new item under *Backend / upstream side*. Let a `proxy` location
name a **Unix domain socket** instead of an `IPv4:port`, so linnea reaches a
local backend over the filesystem rather than the loopback TCP stack.

**Scope is the connect side only.** Listening on a Unix socket is deliberately
not planned — see [Why not the listen side](#why-not-the-listen-side).

## What it buys

The concrete case is this deployment: `linnea-api` on 7700 and 7702,
`linnea-ws` on 7701, all on loopback. Moving them to sockets gives

- **Access control by filesystem permission.** Today anything running on the
  box can reach 7700. A socket at `/run/linnea/api.sock` owned `linnea-svc:linnea`
  mode `0660` cannot be dialled by another uid. This is the real reason to do it.
- **No port bookkeeping.** No ephemeral-range collisions, no `LINNEA_TEST_PORT_BASE`
  arithmetic for backends, no second port (7702) needed purely to have a distinct
  name for a failover instance.
- **A shorter path.** No TCP handshake, no loopback checksum/ack machinery. On
  loopback the throughput win is modest and should not be the justification —
  claim it only if measured.

What it does **not** buy: nothing about remote backends, nothing about
performance under real network latency. This is a locality and access-control
feature.

## The hard constraint: no `proxy_tls`, therefore no `proxy_h2`

Backend TLS is implemented as **kTLS on the backend socket** (route (a)):
`linnea_uring.asm:2453` and `linnea_http2.asm:3879` call `linnea_ktls_enable`
on the upstream fd, which sets `TCP_ULP` to `"tls"`. That option does not exist
for `AF_UNIX`. Measured, with a TCP control:

    AF_INET (TCP)    TCP_ULP=tls -> ENOTCONN   (supported; wants a connected socket)
    AF_UNIX          TCP_ULP=tls -> ENOTSUP    (the ULP does not exist here)

The control is what makes this conclusive: TCP fails only because the probe
socket was unconnected, which is precisely the state linnea is *not* in when it
does the handoff. `AF_UNIX` fails on the family.

So a Unix backend is **HTTP/1.1 cleartext only**. `proxy_h2` requires
`proxy_tls`, so it is out too. **Reject both combinations at config time** with
a message that says why — a key silently ignored is a config that lies about
what the server will do, which is already this parser's stated rule.

This is the honest cost of the feature and the thing to weigh before starting:
the roadmap is heading toward h2 backends, and a Unix backend cannot follow it
without a userspace-TLS backend path (a much larger job, and one that would give
up the reason kTLS was chosen). TLS to a socket on the same machine buys little
— the filesystem permission *is* the boundary — but "unix implies h1" is a real
limitation, not a footnote.

## Config surface

    { "prefix": "/api", "proxy": "unix:/run/linnea/api.sock" }

    { "prefix": "/api", "proxy": ["unix:/run/linnea/api.sock",
                                  "unix:/run/linnea/api2.sock"] }

One key, one prefix. `unix:` is unambiguous — an `IPv4:port` can never begin
with it — so no new key and no change to the array form. Mixing families in one
location is **allowed** and needs no special code: family is per backend index,
and failover already steps by index.

Validation, all syntactic (`--test` never dials a backend, and must not start
doing so — the backend legitimately starts after linnea):

| Rule | Reason |
|---|---|
| path must start with `/` | a relative path resolves against the worker's CWD |
| 1..107 bytes | `sun_path` is 108 including its NUL |
| no `@` prefix (abstract namespace) | rejected in v1: no filesystem permissions, which is the whole point |
| `proxy_tls` / `proxy_h2` not set on this location | measured impossible (above) |

Deliberately **not** checked at `--test`: that the socket exists, or is a
socket, or is connectable. Same rule as a TCP port. This is a doc claim and
`doc_claims_test.py` must assert it.

## Storage: the one structural change

`linnea_config_location.proxy_addr` is `resb 16 * LINNEA_MAX_BACKENDS` — 16
bytes, exactly a `sockaddr_in`. A `sockaddr_un` is 110 (2 family + 108 path).

    proxy_addr now : 128 B/location  (16 x 8)
    proxy_addr new : 896 B/location  (112 x 8, 112 for 8-byte alignment)
    plus proxy_addrlen: resq LINNEA_MAX_BACKENDS   +64 B/location
    plus proxy_str 512 -> 1024 B/location           (MAX_PROXY_STR 63 -> 127)
    whole config   : +168 KB of .bss (8 locations x 16 servers, one instance)

`.bss` only — no file-size change. 168 KB against a config that is already a
static allocation is not a cost worth designing around; take the simple union
rather than a side table.

Two sites assume the 16-byte stride and both must become `imul ..., 112`:

- `linnea_config_parse.asm:1444` — `shl r14, 4`
- `linnea_upstream.asm:135` — `shl rax, 4`

**Store the addrlen at parse time** (`.proxy_addrlen`) rather than deriving it
at connect: `2 + strlen(path) + 1` for a pathname socket, `LINNEA_SOCKADDR_IN_SIZE`
for AF_INET. A `strlen` on the connect path is both wasted work and a place to
get the abstract-socket rule wrong later.

`LINNEA_MAX_PROXY_STR` must rise **63 -> 127** so the dump/log string can hold
`unix:` plus a full path (5 + 107 = 112). That doubles `.proxy_str` to 1024
B/location, included above.

> **Pre-existing doc defect found while checking this:** `docs/config.md:233`
> says a proxy string is "≤ 255 each"; the parser enforces 63
> (`linnea_config_parse.asm:1379`), and a 100-char value is rejected with
> *"proxy address too long"*. `doc_claims_test.py` does not assert that row's
> limit. Fix the doc (and add the assertion) as part of this work, since the
> limit changes anyway.

## Code changes, site by site

**Collapse the socket call before teaching it a new family.** There are seven
`socket()` sites, all the same three instructions, each hardcoding `AF_INET`:

    linnea_http.asm:3224   linnea_h3_proxy.asm:540   linnea_uring.asm:4159, 4207
    linnea_http2.asm:3409, 3449, 3491

Patching seven copies is how the sixth gets missed — the shape report 54 already
punished once ("the two sites" were three). Add

    linnea_upstream_socket(rdi = location, rsi = backend) -> rax = fd, or -errno

and let the seven call it. Whoever owns the syscall owns the reason.

**Two connect sites**, both `IORING_OP_CONNECT`, both already fetching the
address through `linnea_upstream_addr`:

    linnea_uring.asm:4243  (h1/h3 leg)      linnea_uring.asm:4509  (h2 leg)

Each sets `SQE_OFF` to the literal `LINNEA_SOCKADDR_IN_SIZE`. Both become the
stored per-backend addrlen, via a new `linnea_upstream_addrlen(location, backend)`.
`linnea_upstream_addr` keeps its contract unchanged — a pointer into the parsed
config that outlives the SQE.

**Needs no change**, confirmed by reading:

- The upstream pool. Parked connections are keyed by *(location, backend index)*,
  not by address (`linnea_upstream.asm:40`), so keep-alive, `_park`, `_take`,
  `_reap_one` are family-blind already.
- Round-robin, passive health, `bk_dead_at` / `bk_fails` — all index-keyed.
- The proxy request path, response parsing, capture-to-`O_TMPFILE`, timeouts.

## Error reporting — the part most likely to be got wrong

Today a failed connect logs `upstream <ip:port> connect failed`
(`linnea_upstream.asm:77`) and **names no errno**. For TCP that is tolerable
because `ECONNREFUSED` dominates. For a Unix socket the errno *is* the
diagnosis, and the three cases send an operator to three different places:

| errno | meaning | what the operator must do |
|---|---|---|
| `ENOENT` | no socket file at that path | start the backend, or fix the path |
| `ECONNREFUSED` | file exists, nobody listening | the backend died and left its socket behind |
| `EACCES` | file exists, wrong uid/mode | fix ownership — *the backend is fine* |

Collapsing these into "connect failed" is the exact defect class this codebase
keeps finding ([[error-cause-collapse]]): one reason reached from several causes
with the cause thrown away. **Carry the errno into the log line** as part of
this work, for TCP as well — it is a strict improvement there too, and
`EACCES` is a *new and likely-common* first-run failure that "connect failed"
actively misdirects.

## Test plan

Every check below needs a **pre-fix control**: it must fail on today's binary.
For most rows that is automatic (the config is rejected outright), which is the
weak kind of control — so the rows that matter are the ones that would pass on
a broken build.

**Config parsing** (`--test`, no server): accepted forms; each rejection rule
with its own message; the array form; a mixed unix+TCP array; `proxy_tls` +
`unix:` rejected; `proxy_h2` + `unix:` rejected; a 107-byte path accepted and a
108-byte one rejected — *the boundary, from both sides*, since a single value
at the limit tests one comparison and not the accumulator.

**End to end**: `test/proxy_backend.py` gains a Unix-socket mode
(`socket.AF_UNIX`, `bind(path)`, `unlink` first). Then GET, POST with a body
past the capture threshold, a chunked response, and a 502 — over h1, h2 **and**
h3 clients, because all three legs reach the same two connect sites but through
different arming paths.

**Failover**: two unix backends, kill one, assert the request is served by the
other and that the health lines appear. Then one unix + one TCP in the same
location, to prove per-index family really is per-index.

**The errno rows** — the ones with real value, because they pass wrongly on a
naive implementation: point at a nonexistent path (`ENOENT`), a path owned by
another uid mode `0600` (`EACCES`), and a socket file whose listener has exited
(`ECONNREFUSED`). Assert the **distinct** message each time. Asserting only
"502" here would pass on a build that collapses all three.

**`genports.py` must rewrite the socket path.** This is the trap: the generator
redirects everything a server writes into the run's own directory precisely so
two concurrent suites do not fight, and a hardcoded `/run/...` or repo-relative
socket path would have two runs binding **the same socket** — a failure that
appears only under `run_shards.sh`'s three concurrent jobs, i.e. not when you
test your new fixture alone. The header of that file says as much about
`error_log`; a `unix:` proxy value is the same class of key.

## Traps

- **Path length is 108 including the NUL, not 108 usable.** Off by one here is
  a silent truncation that connects to the wrong socket.
- **A run directory deep in `/tmp/claude-.../run` can exceed 107 bytes on its
  own.** The suite's socket paths need to be short by construction, or the tests
  fail for a reason that has nothing to do with the feature.
- **`unlink` before `bind` belongs to the backend, never to linnea.** linnea
  only ever connects. Nothing in this feature may remove a socket file.
- **`SOCK_STREAM` only.** No `SOCK_SEQPACKET`, no datagram.
- **`proxy_str` is what the log and config dump print.** Growing the stride
  without growing every consumer of it prints a truncated path, which in a
  diagnostic about the wrong path is worse than useless.

## Why not the listen side

For completeness, since it is the obvious next question. TCP listeners bind
`SO_REUSEPORT` **once per worker** (`linnea_network.asm:83`, `:455`) so the
kernel spreads accepts. `AF_UNIX` has no `SO_REUSEPORT`, so a Unix listener
would need a bound-once-inherited-by-fork model — a second worker model beside
the one in use. On top of that: the hot upgrade adopts listener fds by number
across `execve`, so a cold start needs `unlink`-before-`bind` while an upgrade
must *not* unlink, or it deletes the socket the previous generation is still
serving; h3 cannot ride it at all (UDP, GRO/GSO, BPF CID steering); h2 is
offered only via ALPN on TLS listeners, so it would be h1-only; and
`max_per_ip`, `rate_limit` and the access log all key on a client IP, which a
Unix peer does not have — every connection would collapse to one key, silently
disabling two access controls.

Not worth it for this deployment. Revisit only if linnea is ever put behind
another proxy.

## Staging

1. Struct + `LINNEA_MAX_PROXY_STR`, the two stride sites, `.proxy_addrlen`.
   Behaviour-neutral: full suite must be green with no test changes.
2. `linnea_upstream_socket` consolidating the seven socket sites, still
   `AF_INET` only. Also behaviour-neutral, also green with no test changes.
   **These two land and prove themselves before anything parses `unix:`.**
3. Errno in the connect-failure log (TCP first, where it is testable today).
4. Parser: `unix:` + every rejection rule + docs + `doc_claims_test.py`.
5. `linnea_upstream_addrlen` into the two connect sites; the fixture, the
   `genports.py` rewrite, and the end-to-end rows.
