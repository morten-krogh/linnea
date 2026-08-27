# Audit Report 93

Audited at `9aef672` (`test: a proxy_h2 location with two backends; and a correction`), 2026-08-27.

This pass followed report 92's Unix-backend validation changes through the
listener helper and the proxy's three client-protocol paths. I found one
independently reproducible boundary defect; no second finding survived review.

## Finding 1 — demo Unix listener rejects the documented maximum pathname

Severity: **Low (P3, a valid deployment/backend fixture cannot start)**  
Confidence: **High**  
Status: **Confirmed by source trace; unfixed.**

The Unix pathname limit is documented as 107 bytes, with the 108-byte
`sun_path` array including its terminating NUL ([docs/config.md:233](/home/linnea/linnea/docs/config.md:233)). The listener's copy loop checks
`ecx >= LINNEA_SUN_PATH_MAX` before loading the byte at that index
([test/api/linnea_api.asm:1664](/home/linnea/linnea/test/api/linnea_api.asm:1664)).
`LINNEA_SUN_PATH_MAX` is 107, so a pathname whose 107 characters occupy
indices 0..106 reaches `ecx == 107`; the loop takes `.fail` without reading
the valid NUL at index 107. In practice the helper accepts at most 106
pathname bytes, while the proxy parser and the documented contract accept
107.

### Reproduction

Build `bin/linnea-api`, then invoke it with `unix:/` followed by 106 `a`
characters (a 107-byte pathname). The process reports `linnea-api: cannot
bind` before attempting the valid 110-byte `sockaddr_un` address. A shorter
pathname starts normally. The same 107-byte pathname is accepted by the main
configuration parser, creating an inconsistent boundary between the shipped
demo backend and the proxy that is supposed to connect to it.

### Impact

An operator or integration test using the maximum legal socket path cannot
start `linnea-api`; the resulting proxy failure looks like an unavailable
backend. The defect is limited to the demonstration backend binary, not the
main proxy's `sockaddr_un` construction, so severity is low.

### Recommended fix

Allow the loop to inspect index 107 so it can copy the terminating NUL, and
reject only a non-NUL byte beyond the 107-character limit. Add a listener-side
boundary test for 107-byte acceptance and 108-byte rejection, matching the
existing parser tests.

No production proxy source was changed in this audit. Only this report was
added.

---

## Resolution (2026-08-27)

**Finding 1: CONFIRMED and FIXED.** Reproduced before reading the trace, on the
real binary:

    path 105 bytes -> STARTED
    path 106 bytes -> STARTED
    path 107 bytes -> linnea-api: cannot bind
    path 108 bytes -> linnea-api: cannot bind

The report's source trace is exactly right. `.u_copy` bounded itself before
LOADING the byte at index 107, so it rejected the terminating NUL rather than a
108th character. `linnea-api` accepted 106 while linnea's parser accepts 107:
one documented limit, two implementations, one off by one.

Fixed by moving the test onto the CHARACTER rather than the index — a NUL is
stored at any index up to and including 107; a non-NUL at 107 is the 108th byte
and is what cannot fit. After:

    path 106 bytes -> STARTED
    path 107 bytes -> STARTED
    path 108 bytes -> linnea-api: cannot bind

And the whole contract at the maximum: the real `linnea-api` on a 107-byte path,
proxied through linnea, `{"value":660}`, zero connect failures.

Two boundary rows added to `h1/30-proxying.sh`, asserting 107 starts and 108
does not, against the real binary. Full suite **1205/0**.

### Why report 92 — my own audit, one commit earlier — missed this

Report 92 claims it checked "the 107-byte path boundary at RUNTIME". It did,
but against `test/proxy_backend.py`, the **Python fixture**, whose `bind()` has
no such bug. The real backend shares the same documented contract and was never
tested at the boundary. **Testing a boundary against one of two implementations
proves it for one of two implementations** — and the fixture is the one that
cannot have the bug, because it does not do the copy by hand. When a limit is
implemented twice, both ends need the same two-sided test.

### One correction to the report's framing

It scopes the impact to "the demonstration backend binary, not the main proxy".
`linnea-api` is a production service here — it serves `/api` on this host, and
since 2026-08-27 one of its two instances listens on a Unix socket. Severity is
still low (prod's path is 30 bytes and 107-byte paths are rare), but the defect
was not confined to a demo.
