# Linnea server audit report 2

Date: 2026-08-17  
Audit baseline: commit `64a4380` (`config: accept a specific IPv6 host literal, and a v6only listener option`)  
Scope: `src/server`, `src/lib`, `include`, configuration handling, listener setup, HTTP/1, HTTP/2, HTTP/3, TLS, QUIC, and the available test suite.

## Executive summary

This was a read-only follow-up audit. The thirty-four findings in
[`audit-report.md`](/home/linnea/linnea/audit-report.md) were reviewed against the
current tree and remain recorded there as fixed. I found two new, reproducible
issues:

1. **High: listener identity is based on raw host text rather than the effective
   socket address and options.** Equivalent wildcard spellings such as `::` and
   `0.0.0.0` can create separate `SO_REUSEPORT` listeners, causing the same
   hostname to reach different vhost tables and roots. The listener's effective
   `v6only` setting can also silently come from whichever textual entry is
   encountered first.
2. **Medium: authority parsing splits at the first colon and does not validate
   the port grammar.** Malformed authorities such as `three.test:garbage` are
   accepted, while bracketed IPv6 authorities are truncated before vhost
   selection. The same logic is present in HTTP/1, HTTP/2, and HTTP/3 paths.

No source code, tests, or the existing audit report were changed. Only this
report is added by this audit. An unrelated pre-existing modification to
`config/linnea-tls.json` was preserved.

## Finding 1 — listener sharing does not canonicalize the effective endpoint

Severity: **High (P1, configuration-dependent cross-vhost routing/content exposure)**  
Confidence: **High**  
Status: **FIXED** (commit `262ce73`'s follow-up; see Resolution)

### Evidence

The listener-sharing scan compares the configured numeric port and the raw host
string:

- [`src/server/linnea_network.asm:120`](/home/linnea/linnea/src/server/linnea_network.asm:120)
  through line 138 compare `port` and `linnea_string_equal(host)` before
  reusing the earlier file descriptor.
- [`src/server/linnea_config.asm:388`](/home/linnea/linnea/src/server/linnea_config.asm:388)
  through line 425 use the same raw host/port identity for duplicate and TLS
  consistency checks.
- [`src/server/linnea_network.asm:894`](/home/linnea/linnea/src/server/linnea_network.asm:894)
  through line 947 map both `"0.0.0.0"` and `"::"` to an unspecified IPv6
  address. Equivalent textual IPv6 literals likewise resolve to the same
  sockaddr even when their source strings differ.
- [`src/server/linnea_network.asm:539`](/home/linnea/linnea/src/server/linnea_network.asm:539)
  through line 548 apply `IPV6_V6ONLY` from the current server only when a
  listener is created. If raw host/port matching reuses a prior listener, a
  later vhost's conflicting `v6only` setting is ignored.

The configuration documentation explicitly describes `"::"` and
`"0.0.0.0"` as wildcard forms and documents the `v6only` option:
[`docs/config.md:153`](/home/linnea/linnea/docs/config.md:153)
through line 163.

### Reproduction

A temporary configuration used two vhosts on port `61555`, one bound to
`host: "::"` and the other to `host: "0.0.0.0"`, with the same hostname
selection setup but different document roots. Forty requests for the second
hostname produced:

```text
15 responses from the second vhost root
25 responses from the default root
```

The results vary with the kernel's reuse-port flow selection: the two textual
forms produced two effective listeners instead of one shared listener, so a
request can be dispatched to the wrong vhost table. This is not a race in the
test; the same connection consistently follows its selected listener.

The same identity defect also affects port `0`: aliases that should share one
endpoint can bind independently and receive different kernel-chosen ports.
Entries using the same raw host and port but conflicting `v6only` values instead
share silently and inherit the first listener's socket option.

### Impact

Under a documented wildcard configuration, requests can intermittently receive
the wrong vhost's files, default routing, TLS owner, or policy. In a multi-tenant
configuration this can expose content across vhosts. Port-file and duplicate/TLS
consistency behavior also disagrees with the effective sockets actually created.

### Recommendation

Parse and canonicalize the sockaddr once during configuration, then use that
canonical endpoint—not the source host string—for listener sharing, duplicate
checks, port-`0` resolution, and TCP/QUIC setup. Include the effective address
family and `v6only` mode in the listener identity, or reject conflicting
`v6only` values for one effective endpoint. Add regression cases covering:

- `::` versus `0.0.0.0` on the documented dual-stack wildcard;
- equivalent IPv6 spellings;
- port `0` aliases and their port files; and
- conflicting `v6only` values on one effective endpoint.

### Resolution — FIXED (2026-08-18)

Listener identity is now the **canonical socket endpoint**, computed by
`linnea_network_fill_sockaddr6`, not the host text. One comparator,
[`linnea_network_endpoint_cmp`](/home/linnea/linnea/src/server/linnea_network.asm)`(serverA, serverB)`,
decides whether two servers share an effective listener: it compares the
28-byte `sockaddr_in6` (address **and** port together) and the `v6only` option,
returning share / different / v6only-conflict. Both listener-sharing sites call
it — `linnea_network_listen_all`'s `.scan_prior` (fd sharing and
`listener_owner`) and `linnea_config_validate`'s duplicate/TLS scan — so they
can no longer disagree about which servers share a socket.

Consequences:

- `"::"` and `"0.0.0.0"` (both `in6addr_any`), and equivalent IPv6 spellings,
  resolve to **one** `SO_REUSEPORT` listener with one vhost table instead of
  several that split a hostname between them. This also removes the redundant
  wildcard QUIC socket noted in the multi-address update above: the QUIC
  socket loop keys on the now-canonical `listener_owner`.
- Two servers on one canonical `address`/`port` with disagreeing `v6only` are
  rejected at validation — *"servers on one address and port must agree on
  v6only"* — so the option can no longer be silently taken from the first
  textual entry.
- Port-`0` aliases share one endpoint and therefore one kernel-chosen port.
- The recommendation's "include the effective address family" is satisfied
  implicitly: every listener is `AF_INET6`, and `v6only` (which decides
  dual-stack vs IPv6-only) is part of the identity.

**Verification** (A/B against a pre-fix binary, `.text` differs):

- `"::"`/alpha.test and `"0.0.0.0"`/beta.test, disjoint roots, one port: the
  pre-fix binary bound **two** listeners and split 40 `beta.test` requests
  across the two roots (17 correct, 23 to the wrong default); the fixed binary
  binds **one** and serves all 40 from beta's own root. Regression test
  [`test/shards/h1/23-wildcard-alias.sh`](/home/linnea/linnea/test/shards/h1/23-wildcard-alias.sh)
  with `test/configs/wildcard-alias.json`.
- The same hostname on `"::"` and `"0.0.0.0"` is now a duplicate-hostname
  error, and the `v6only` conflict is rejected — both asserted in the base
  shard (`test/configs/wildcard-dup-hostname.json`, `bad-v6only-conflict.json`).

**Scope note.** The canonical identity governs cold start and steady state. On
the single hot upgrade *from* a pre-fix binary, an already-aliased config would
leave the retiring generation's now-redundant second listener fd inherited but
unused until that process exits; steady state (both generations canonical) is
clean, and no non-aliased config — the production config included, whose three
servers are three distinct endpoints — is affected.

## Finding 2 — authority parsing accepts malformed ports and mishandles IPv6

Severity: **Medium (P2 protocol correctness and request-routing ambiguity)**  
Confidence: **High**  
Status: **FIXED** (see Resolution)

### Evidence

Each protocol's vhost selector scans for the first colon and treats everything
before it as the hostname:

- HTTP/1: [`src/server/linnea_http.asm:1684`](/home/linnea/linnea/src/server/linnea_http.asm:1684)
  through line 1723;
- HTTP/2: [`src/server/linnea_http2.asm:5312`](/home/linnea/linnea/src/server/linnea_http2.asm:5312)
  through line 5367; and
- HTTP/3: [`src/server/linnea_quic_server.asm:665`](/home/linnea/linnea/src/server/linnea_quic_server.asm:665)
  through line 705.

HTTP/1 Host validation only rejects spaces, controls, and DEL at
[`src/server/linnea_http.asm:1483`](/home/linnea/linnea/src/server/linnea_http.asm:1483)
through line 1496. The shared HTTP/2/HTTP/3 field validation at
[`src/server/linnea_hpack.asm:1405`](/home/linnea/linnea/src/server/linnea_hpack.asm:1405)
through line 1457 similarly checks for emptiness and control bytes but does not
validate authority syntax or numeric ports.

### Reproduction

Against the existing two-vhost listen fixture:

- `Host: three.test:garbage` returned `200 OK` from the `three.test` subdirectory
  root.
- `Host: three.test:80:bad` also returned `200 OK` from that root.
- `Host: [::1]:61080` was truncated to `[` for vhost lookup and fell back to the
  default root instead of matching a bracketed IPv6 authority.

The behavior is shared by the HTTP/1, HTTP/2, and HTTP/3 selector structures,
although the direct reproduction above used raw HTTP/1 requests.

### Impact

Invalid authorities are accepted and can be interpreted differently by Linnea,
proxies, caches, or upstream components that enforce the authority grammar.
That creates request-routing ambiguity and can invalidate host-based policy.
Bracketed IPv6 authorities, which are the required unambiguous form for an IPv6
literal with a port, cannot be selected correctly by the current vhost parser.

### Recommendation

Implement one shared authority parser for all three protocols. For a bracketed
literal, find the closing `]`, compare the complete bracketed host as intended,
and accept only an absent port or a colon followed solely by decimal digits. For
an unbracketed authority, allow at most the host syntax supported by the
configuration and validate any single port delimiter the same way. Reject empty,
non-numeric, or extra port components before vhost selection. Add cross-protocol
tests for valid bracketed IPv6 authorities, malformed ports, extra colons, and
case-insensitive DNS host matching.

### Resolution — FIXED (2026-08-18)

There is now one authority parser,
[`linnea_http_authority_host`](/home/linnea/linnea/src/server/linnea_http.asm)`(ptr, len)`,
shared by all three protocols. It parses the RFC 3986 request-target grammar --
`reg-name-or-IPv4 [ ":" port ]` or `"[" IPv6 "]" [ ":" port ]` -- and returns
the host slice (offset past any `[`, length short of `]` or `:port`), or -1 when
the authority is malformed: a port that is not one to five decimal digits, an
extra port component, an unterminated or empty bracket, or junk after the
literal. It is called in five places:

- **validation** -- the HTTP/1.1 `Host` check
  ([`linnea_http.asm`](/home/linnea/linnea/src/server/linnea_http.asm)) and the
  shared HTTP/2/HTTP/3 `linnea_hpack_req_check`
  ([`linnea_hpack.asm`](/home/linnea/linnea/src/server/linnea_hpack.asm)) --
  where a -1 is the existing reject path: **400** on h1, a refused stream on
  h2/h3. `three.test:garbage` and `three.test:80:bad` are no longer 200.
- **vhost selection** -- the three selectors (`linnea_http.asm`,
  `h2_select_vhost`, `authority_vhost`) now match on the parser's bracket-aware
  slice, so `[::1]:443` matches on `::1`, not on the `"["` a first-colon split
  produced.

The host *character* policy is unchanged (printable, no space, no DEL; high
bytes still tolerated) -- only the STRUCTURE is now enforced. A consequence is
that a bare unbracketed IPv6 in an authority (`Host: ::1`) is now correctly
malformed; a client that means the literal must bracket it, which every client
that emits one already does.

**Verification** -- A/B against a pre-fix binary (`.text` differs), one probe
per protocol:

- **HTTP/1.1**: `beta.test:garbage`, `beta.test:80:bad` and `[::1` returned
  **200** pre-fix and **400** after; a valid `beta.test:8080` and a bracketed
  `[::1]:443` still route.
  [`test/shards/h1/24-authority.sh`](/home/linnea/linnea/test/shards/h1/24-authority.sh)
  + `test/configs/authority-vhosts.json`.
- **HTTP/2**: the pre-fix binary served `:authority: localhost:garbage`; the
  fix refuses its stream.
  [`test/tls/h2_authority_grammar.py`](/home/linnea/linnea/test/tls/h2_authority_grammar.py).
- **HTTP/3**: the pre-fix binary served `:authority: sni.test:garbage`; the fix
  refuses it, and a well-formed `[::1]:port` is served locally rather than
  mangled. Malformed cases added to
  [`test/quic/h3_authority_test.py`](/home/linnea/linnea/test/quic/h3_authority_test.py).

## Verification

### Build and focused audit checks

- `make -j2`: completed successfully (`Nothing to be done for all`).
- IPv6 parser self-tests: passed.
- Listener-alias reproduction: confirmed the mixed-root responses described in
  Finding 1.
- Authority reproduction: confirmed malformed ports are accepted and bracketed
  IPv6 is mis-selected as described in Finding 2.

### Test suite

The independent fast suites completed with no failures:

| Suite | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| base | 53 | 0 | 0 |
| h1 | 370 | 0 | 7 |
| quic | 96 | 0 | 12 |
| tls | 188 | 0 | 7 |

The requested full run was allowed to completion and ended with:

```text
695 passed, 38 failed (full run)
```

The first full-run failures were the slow HTTP/1 proxy-timeout checks. Later
upload, websocket, and termination checks reported connection refusals after
that fixture failed; one separate HTTP/3 `DATA_BLOCKED` check could not inject
its test frame. The fast suites, including the normal h1 proxy and IPv6
coverage, remained green. These full-run failures are recorded as a verification
caveat and should be investigated independently; they were not used to claim
either new audit finding without a direct reproduction.

## Audit conclusion

Two new issues were found and reproduced against the current server. **Both are
now FIXED** — Finding 1 (canonical listener identity) and Finding 2
(grammar-aware authority parsing), each with its own Resolution and
cross-protocol A/B verification. The original audit itself made no code changes;
the fixes were applied afterward.

## Update — 2026-08-18: multi-address HTTP/3 (commit `262ce73`, deployed)

After this audit, a separate but adjacent listener defect was fixed and
deployed. It is recorded here because it lives in the same listener-setup area
as Finding 1. It does **not** close Finding 1 or Finding 2 — both remain
**OPEN**.

### What it fixes

HTTP/3 setup created exactly one QUIC UDP socket — for the *first* eligible TLS
server on the port — and stopped. A second server with a **different specific
host** on the same port received no HTTP/3 at all (the "mapped-v4 h3" gap: e.g.
a specific IPv6 literal beside a wildcard, or two specific hosts). The loss was
silent: that host's TCP listener still answered HTTP/1 and HTTP/2, so a browser
simply never upgraded. A dual-stack `"::"`/`"0.0.0.0"` primary masked it (it
already accepts both families); two separate specific hosts expose it.

### The change

In [`src/server/linnea_uring.asm`](/home/linnea/linnea/src/server/linnea_uring.asm)
(`.quic_scan`) and
[`src/server/linnea_quic_server.asm`](/home/linnea/linnea/src/server/linnea_quic_server.asm):
after the primary, a QUIC socket is bound for every host that owns a listener
among the TLS servers on the h3 port, into `quic_fds[]` (capped at
`LINNEA_QUIC_MAX_LISTENERS = 4`, over which the excess hosts serve TCP only and
the worker logs it). The receive buffers (`qrecv_msg/iov/cmsg/peer`, the GRO
batch, the overflow counter) become per-socket arrays; `arm_qrecv` takes a
socket index carried in the completion's `user_data`, so each socket re-arms
independently. Each connection records the socket its first datagram arrived on
(`conn.udp_fd`), and the timer-driven retransmission, drain, goaway and close
sweeps reply on that socket per connection rather than a single global fd. The
single-listener path (nfd = 1) is behaviourally the one it replaced.

### Relationship to Finding 1

The new loop selects which hosts get a socket using the same **raw-host-string
`listener_owner` identity that Finding 1 flags**
([`src/server/linnea_network.asm:137`](/home/linnea/linnea/src/server/linnea_network.asm:137)
through line 153), not a canonical sockaddr. So this fix does not resolve
Finding 1, and it inherits the alias defect on the QUIC side: two equivalent
wildcard spellings (`"::"` and `"0.0.0.0"`) on one port are now treated as two
distinct listener owners and bind two redundant wildcard QUIC sockets in one
`SO_REUSEPORT` group (before this change the single-socket path bound only one).
This is redundant rather than incorrect — each connection is pinned to its
arrival socket via `conn.udp_fd` — but it is another symptom of the
un-canonicalized listener identity, and the canonicalization recommended for
Finding 1 would also dedup it. Finding 2 (authority parsing) is unrelated.

### Verification

A/B against a pre-fix binary (`.text` differs): with two specific hosts
(`127.0.0.1` first, `::1` second) on one port, the pre-fix binary binds only
`::ffff:127.0.0.1` and the `::1` handshake never completes; the fix binds both
and serves both. New regression test
[`test/quic/h3_multiaddr_test.py`](/home/linnea/linnea/test/quic/h3_multiaddr_test.py)
(with `test/configs/tls-h3-multi.json`), wired into the quic shard. Full suite
734/0; quic shard 109/0. On prod (`linnea.amberbio.com`), `ss -uln` now shows a
dedicated `[2a04:3541:8000:1000:80a9:4aff:fe36:78dd]:443` UDP socket beside the
`*:443` wildcard, and HTTP/3 GETs over both the IPv6 literal and IPv4 return
`200`.
