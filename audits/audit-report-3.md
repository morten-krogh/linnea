# Linnea server audit report 3

Date: 2026-08-18  
Audit baseline: commit `8e15eb6` (`audit-report-2: mark Finding 2 FIXED (grammar-aware authority parsing)`)  
Scope: `src/server`, `src/lib`, `include`, configuration handling, listener setup, HTTP/1, HTTP/2, HTTP/3, TLS, QUIC, proxying, lifecycle/resource paths, and the available test suite.

## Executive summary

This was a read-only follow-up audit. The two findings in
[`audit-report-2.md`](/home/linnea/linnea/audit-report-2.md) were rechecked, and
the full regression suite passes. I found two new, reproducible issues:

1. **Medium: asynchronous HTTP/3 proxy completions use the global primary UDP
   socket.** A request received through a secondary address can lose its first
   response because the completion path emits through the primary socket; a
   later retransmission may recover it through the connection's correct socket.
2. **Medium: authority validation is still only structural.** The new shared
   parser fixes delimiter handling, but accepts arbitrary bracket contents and
   out-of-range numeric ports. Invalid authorities are therefore accepted and
   can be interpreted differently by Linnea and other HTTP components.

No source code, tests, configuration, or earlier audit report was changed by
this audit. Only this report is added.

## Finding 1 — secondary-address HTTP/3 proxy completions use the primary fd

Severity: **Medium (P2, availability and latency for multi-address H3 proxy traffic)**  
Confidence: **High**  
Status: **FIXED** (see Resolution)

### Evidence

The multi-address listener setup stores every QUIC socket in `quic_fds`, while
`quic_fd` remains the primary socket:

- [`src/server/linnea_uring.asm:547`](/home/linnea/linnea/src/server/linnea_uring.asm:547)
  through line 598 creates and records one socket per distinct eligible host.
- The receive path passes the actual socket index to the datagram handler at
  [`src/server/linnea_uring.asm:825`](/home/linnea/linnea/src/server/linnea_uring.asm:825)
  through line 832.
- A newly allocated connection records that socket in
  [`src/server/linnea_quic_server.asm:954`](/home/linnea/linnea/src/server/linnea_quic_server.asm:954)
  through line 959. Timer-driven retransmissions use that per-connection value
  at [`src/server/linnea_quic_server.asm:8147`](/home/linnea/linnea/src/server/linnea_quic_server.asm:8147)
  through line 8153.

The asynchronous upstream completion path does not preserve that identity:

- H3 proxy failure completion passes `[quic_fd]` at
  [`src/server/linnea_uring.asm:2120`](/home/linnea/linnea/src/server/linnea_uring.asm:2120)
  through line 2124.
- H3 proxy success completion passes `[quic_fd]` at
  [`src/server/linnea_uring.asm:2332`](/home/linnea/linnea/src/server/linnea_uring.asm:2332)
  through line 2336.
- Both callees treat the supplied argument as the UDP fd: see
  [`src/server/linnea_h3_proxy.asm:934`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:934)
  through line 948 and
  [`src/server/linnea_h3_proxy.asm:1081`](/home/linnea/linnea/src/server/linnea_h3_proxy.asm:1081)
  through line 1091. The QUIC delivery routine then stores that argument as
  the socket used by `emit_1rtt` at
  [`src/server/linnea_quic_server.asm:8012`](/home/linnea/linnea/src/server/linnea_quic_server.asm:8012)
  through line 8039.

### Reproduction

A temporary TLS configuration bound the primary H3 listener to `::1` and a
secondary H3 listener to `127.0.0.1`. An HTTP/3 request sent through the IPv4
secondary address was proxied to a local backend. Tracing the server's UDP
sends showed the completion path first attempting to send on the primary fd:

```text
sendto(8, ..., {AF_INET6, peer ::ffff:127.0.0.1}, ...) = -1 ENETUNREACH
```

The secondary fd then sent successfully after QUIC loss recovery retried the
response:

```text
sendto(9, ..., {AF_INET6, peer ::ffff:127.0.0.1}, ...) = success
```

The wrong-fd failure is deterministic for this address arrangement. The later
success depends on retransmission and therefore adds latency; if the retry
budget is exhausted, the proxied response can time out.

### Impact

HTTP/3 proxy requests received on a secondary address do not reliably receive
their first response transmission. This affects configurations with distinct
TLS listener hosts sharing one H3 port, including the multi-address listener
feature. The issue is not present in the single-socket case and does not affect
ordinary direct H3 responses whose connection state already supplies the
correct fd.

### Recommendation

Pass the connection's `linnea_quic_conn.udp_fd` to every asynchronous H3 proxy
delivery and failure path, or retain the fd in the H3 leg until completion.
Add a regression test that sends a proxied H3 request through a secondary
address and verifies that the first response is emitted on that address,
without an attempted send through the primary socket.

### Resolution — FIXED (2026-08-18)

Every proxied HTTP/3 response is emitted through one chokepoint,
[`linnea_quic_h3_deliver`](/home/linnea/linnea/src/server/linnea_quic_server.asm),
which the success and failure completion paths both call. It already resolves
the target connection (by the parked owner index, with a generation check); it
now takes the send socket from **that connection's `udp_fd`** rather than the
`quic_fd` argument the async completion handed it. The two `uring` call sites
still pass a value, now vestigial and annotated as such. A connection is bound
to its socket at allocation, so this is the same source of truth the
timer-driven retransmission, drain and close sweeps already used.

**Verification** -- A/B against a pre-fix binary (`.text` differs) under
`strace`, primary `::1` + secondary `127.0.0.1`, one h3 port, `/api` proxied,
an h3 request through the IPv4 secondary:

```text
pre-fix:  sendto(8, ..., ::ffff:127.0.0.1) = -1 ENETUNREACH   (the primary ::1 socket)
          sendto(9, ..., ::ffff:127.0.0.1) = 125              (recovered by retransmission)
fixed:    sendto(9, ...) only -- zero ENETUNREACH, first send on the right socket
```

Regression: a strace-gated block in
[`test/shards/tls/30-h3-proxy.sh`](/home/linnea/linnea/test/shards/tls/30-h3-proxy.sh)
(with `test/configs/h3proxy-multi.json`) requires the proxied request to
succeed AND the strace to carry zero cross-socket `ENETUNREACH`.

## Finding 2 — authority parsing does not validate IP-literal or port semantics

Severity: **Medium (P2, protocol correctness and request-routing ambiguity)**  
Confidence: **High**  
Status: **FIXED** (see Resolution)

### Evidence

The shared parser is a meaningful improvement over the previous first-colon
split, but its validation stops at printable-byte and delimiter checks:

- The unbracketed form accepts every printable byte except `[` and `]`; the
  scan at [`src/server/linnea_http.asm:3198`](/home/linnea/linnea/src/server/linnea_http.asm:3198)
  through line 3214 does not enforce the permitted `reg-name` character set.
  Consequently characters such as `/`, `?`, and `#` can be accepted in an
  authority value.
- The bracketed form only checks that the contents are non-empty, printable,
  and free of nested brackets at
  [`src/server/linnea_http.asm:3234`](/home/linnea/linnea/src/server/linnea_http.asm:3234)
  through line 3253. It never validates that the contents are an IPv6 address
  or a permitted IPvFuture literal. The existing
  [`linnea_network_parse_ipv6`](/home/linnea/linnea/src/server/linnea_network.asm:1061)
  routine could provide the IPv6 semantic check.
- The port helper at
  [`src/server/linnea_http.asm:3274`](/home/linnea/linnea/src/server/linnea_http.asm:3274)
  through line 3293 checks only for one to five decimal digits. It does not
  convert or range-check the value, so `65536` and `99999` are accepted as
  ports. Values with six or more digits are rejected solely by the length cap;
  this is not a numeric port-range check.

The parser is shared by HTTP/1, HTTP/2, and HTTP/3 validation and selection:

- HTTP/1 calls it at
  [`src/server/linnea_http.asm:1488`](/home/linnea/linnea/src/server/linnea_http.asm:1488)
  through line 1496 and selects the vhost using the returned slice at line
  1695 and following.
- HTTP/2 and HTTP/3 use the same validation call from
  [`src/server/linnea_hpack.asm:1445`](/home/linnea/linnea/src/server/linnea_hpack.asm:1445)
  through line 1455 and the same host slice during selection.

### Reproduction

With a temporary vhost named `deadbeef`, raw HTTP/1 requests returned the
following statuses:

```text
Host: [deadbeef]          -> 200
Host: deadbeef:65536      -> 200
Host: deadbeef:99999      -> 200
Host: deadbeef:123456     -> 400
Host: deadbeef/foo        -> 200
```

`[deadbeef]` is not an IPv6 or IPvFuture literal, yet the parser accepts it and
returns the bytes inside the brackets (`deadbeef`) as the host slice. The
out-of-range numeric ports are stripped and the request is accepted as if the
authority were valid. The slash example demonstrates that the unbracketed
character filter is broader than authority syntax. The same parser is used by
all three HTTP protocol paths, so the semantic gap is shared even though this
reproduction used HTTP/1.

### Impact

Malformed authorities can be accepted by Linnea while being rejected or parsed
differently by a reverse proxy, cache, client, or upstream service. A malformed
authority that is reduced to a configured host can still participate in vhost
selection, while an invalid port is ignored for routing. This creates protocol
and policy ambiguity, especially in deployments relying on host-specific roots,
TLS policy, access control, or an upstream proxy's authority validation.

### Recommendation

Keep the shared parser, but add semantic validation to it:

- validate bracket contents as IPv6address or the supported IPvFuture grammar;
- reject authority characters outside the supported `reg-name` grammar; and
- convert the port digits and reject values outside the supported port range
  (normally `0` through `65535`), while documenting the chosen policy.

Add HTTP/1, HTTP/2, and HTTP/3 regression cases for invalid bracket literals,
out-of-range ports, forbidden authority characters, and valid IPv6 literals
with and without ports.

### Resolution — FIXED (2026-08-18)

`linnea_http_authority_host` now validates the authority *semantically*, not
just structurally:

- **port range** -- the digits are accumulated and the value must be
  `0..65535`; `65536` and `99999` are rejected, not silently stripped.
- **reg-name** -- the unbracketed host is checked byte by byte against an RFC
  3986 reg-name allowlist (unreserved + sub-delims) via a bitmap; `/`, `?`,
  `#`, `@`, control and non-ASCII bytes no longer pass. **Policy**:
  pct-encoding is *not* supported (a bare `%` is rejected) -- no HTTP client
  sends a percent-encoded Host, and half-implementing `%XX` would be worse than
  refusing it; IPvFuture is likewise unsupported.
- **IP-literal** -- a bracketed authority's contents are copied NUL-terminated
  and run through the config's inet_pton-style
  [`linnea_network_parse_ipv6`](/home/linnea/linnea/src/server/linnea_network.asm);
  `[deadbeef]` and `[gggg::1]` are rejected, while `[::1]`, `[::1]:443` and the
  v4-mapped `[::ffff:1.2.3.4]` are accepted. The grammar and this policy are
  documented in the function's header comment.

The parser is shared, so HTTP/1, HTTP/2 and HTTP/3 all gain the checks at once.

**Verification** -- A/B against the structural-only parser (`8e15eb6`): it
served `beta.test:65536`, `beta.test:99999`, `beta.test/foo`, `beta.test?x`,
`[alpha.test]`, `[deadbeef]` and `[gggg::1]` all **200**; the semantic parser
returns **400** for each while valid names, ports and IPv6 literals (with and
without a port, v4-mapped included) still route. Cross-protocol regressions were
added to
[`test/shards/h1/24-authority.sh`](/home/linnea/linnea/test/shards/h1/24-authority.sh),
[`test/tls/h2_authority_grammar.py`](/home/linnea/linnea/test/tls/h2_authority_grammar.py),
and [`test/quic/h3_authority_test.py`](/home/linnea/linnea/test/quic/h3_authority_test.py).

## Reviewed behavior with no additional finding

- The two audit-report-2 fixes were exercised by the updated wildcard-alias,
  authority-grammar, and multi-address H3 tests, and by the complete suite.
- Port-`0` behavior was checked separately and matches the current documented
  policy: two servers that both specify `0` receive two different kernel-chosen
  ports; sharing a listener requires an explicitly shared real port. See
  [`docs/config.md:118`](/home/linnea/linnea/docs/config.md:118) through line
  125. This is intentional behavior, not a finding.
- The secondary H3 listener's lack of BPF CID steering is documented as a
  non-migrating-client design constraint at
  [`src/server/linnea_uring.asm:616`](/home/linnea/linnea/src/server/linnea_uring.asm:616)
  through line 623. It remains a coverage/design consideration, but was not
  counted as a separate defect in this report.

## Verification

The audit did not modify source code. The available build and tests completed
successfully:

```text
make -j2
Nothing to be done for 'all'.

LINNEA_SUITE=fast ./test/run_tests.sh
721 passed, 0 failed, 26 SKIPPED (fast run)

LINNEA_SUITE=full ./test/run_tests.sh
747 passed, 0 failed (full run)
```

The working tree was clean before this report was created; the only intended
new file is `audit-report-3.md`.

## Conclusion

Both findings are now **FIXED**: the secondary-address H3 proxy fd selection
sources the socket from the connection, and authority validation is now
semantic (port range, reg-name, IPv6 literal) across all three protocols. Each
was A/B-verified against a pre-fix binary and carries a regression test; the
complete suite remains green. The audit is complete.
