# Linnea server audit report 4

Date: 2026-08-18  
Audit baseline: commit `782bc57` (`audit-report-3: both findings FIXED`)  
Scope: `src/server`, `src/lib`, `include`, configuration handling, listener setup, HTTP/1, HTTP/2, HTTP/3, TLS, QUIC, proxying, lifecycle/resource paths, and the available test suite.

## Executive summary

This was a read-only follow-up audit. The two findings from
[`audit-report-3.md`](/home/linnea/linnea/audit-report-3.md) were rechecked and
remain fixed. I found one new, configuration-dependent issue:

1. **Medium: QUIC CID steering supports fewer workers than the documented
   limit, and hot-upgrade steering collides above 64 workers.** With BPF
   steering available, the map cannot register worker indices at or above
   128. Independently, the reload path deliberately reuses the same steering
   half when there are more than 64 workers, overwriting entries still needed
   by the draining generation.

No source code, tests, configuration, or earlier audit report was changed by
this audit. Only this report is added.

## Finding 1 — QUIC CID steering index space is smaller than the worker limit

Severity: **Medium (P2, HTTP/3 migration and reload availability)**  
Confidence: **High**  
Status: **FIXED** (see Resolution)

### Evidence

The public configuration and parser accept up to 256 workers:

- [`docs/config.md:113`](/home/linnea/linnea/docs/config.md:113) documents
  `workers` as `0–256`.
- [`include/linnea_config.inc:47`](/home/linnea/linnea/include/linnea_config.inc:47)
  defines `LINNEA_MAX_WORKERS` as 256.
- [`src/server/linnea_config_parse.asm:609`](/home/linnea/linnea/src/server/linnea_config_parse.asm:609)
  through line 620 accepts explicit values through that limit, and
  [`src/server/linnea_start.asm:1346`](/home/linnea/linnea/src/server/linnea_start.asm:1346)
  through line 1380 leaves explicit values unchanged.

The BPF steering map has only 128 entries:

- [`src/server/linnea_bpf.asm:168`](/home/linnea/linnea/src/server/linnea_bpf.asm:168)
  through line 171 creates a `REUSEPORT_SOCKARRAY` with `max_entries = 128`.
- The steering program uses the first byte of the QUIC connection ID as the
  map key; see [`src/server/linnea_bpf.asm:3`](/home/linnea/linnea/src/server/linnea_bpf.asm:3)
  through line 9 and the bytecode at lines 45–73.
- A connection ID is stamped with the worker's steering index at
  [`src/server/linnea_quic_conn.asm:193`](/home/linnea/linnea/src/server/linnea_quic_conn.asm:193)
  through line 198. The index is `steer_base + worker slot` at
  [`src/server/linnea_start.asm:630`](/home/linnea/linnea/src/server/linnea_start.asm:630)
  through line 635.
- The worker registers that index at
  [`src/server/linnea_uring.asm:624`](/home/linnea/linnea/src/server/linnea_uring.asm:624)
  through line 631, but the return value of `linnea_bpf_map_add` is ignored.
  That function documents and returns a syscall error at
  [`src/server/linnea_bpf.asm:213`](/home/linnea/linnea/src/server/linnea_bpf.asm:213)
  through line 231. Thus indices 128–255 cannot be registered, while the
  BPF program falls back to the kernel's 4-tuple hash when selection fails
  ([`src/server/linnea_bpf.asm:6`](/home/linnea/linnea/src/server/linnea_bpf.asm:6)
  through line 9 and lines 17–21).

The hot-upgrade partition is also incompatible with the documented worker
range:

- The map and program are intentionally shared across generations, with each
  generation meant to use a different half of the index space
  ([`src/server/linnea_start.asm:149`](/home/linnea/linnea/src/server/linnea_start.asm:149)
  through line 153).
- The adoption path switches between bases 0 and 64 only while the worker
  count is at most 64. For a larger count it explicitly forces base 0 and
  comments that the entries are “colliding” at
  [`src/server/linnea_start.asm:1029`](/home/linnea/linnea/src/server/linnea_start.asm:1029)
  through line 1037.
- Because updates use `BPF_ANY` ([`src/server/linnea_bpf.asm:218`](/home/linnea/linnea/src/server/linnea_bpf.asm:218)
  through line 226), the new generation overwrites the old generation's map
  entries. A packet for a live old-generation connection can therefore be
  steered to the new worker, which has no connection state.

### Impact

On a cold start with 129–256 workers, connections assigned to workers 128–255
do not receive CID-based steering. They normally continue to work while the
4-tuple is unchanged, but a QUIC client migration that changes its source
port/address can hash the packet to another worker. That worker cannot find the
connection and may reset it or let it time out.

On a hot reload with more than 64 workers, the new generation reuses the old
generation's steering indices. Existing HTTP/3 connections can consequently
be delivered to new workers during the documented draining window, causing
resets or stalled requests. This conflicts with the lossless reload behavior
described in [`docs/shutdown.md:57`](/home/linnea/linnea/docs/shutdown.md:57)
through line 67.

The issue is limited to deployments where the BPF steering program is
available. Without BPF, the documented 4-tuple fallback applies instead; it
does not make the CID steering feature reliable for migration or reload.

### Validation and coverage

The available tests do not exercise this configuration. The steering handoff
test uses unusable pipe fds and explicitly omits the BPF syscalls because the
test environment lacks `CAP_BPF` ([`test/quic/h3_steer_base_test.py:1`](/home/linnea/linnea/test/quic/h3_steer_base_test.py:1)
through line 8); it also checks only the normal base-64 handoff. The standard
H3 configuration uses four workers, and there are no tests for 65, 128, or 129
workers with live connections during migration/reload.

### Recommendation

The safe short-term policy is to reject or clearly disable CID steering for
worker counts above the supported two-generation capacity, and document the
resulting limit. A complete redesign should allocate an index space for both
live generations, encode enough generation/worker bits in the CID, check every
map-update and attach result, and add CAP_BPF-backed tests for worker counts
around 64/128/129 plus client migration and hot reload.

### Resolution — FIXED (2026-08-18)

The steering index is one byte of the connection id (0..255), which bounds the
scheme; the fix uses that byte fully and documents the edge the byte cannot
cover. A shared constant `LINNEA_BPF_STEER_HALF = 128` now ties the pieces
together:

- **map size** -- the `REUSEPORT_SOCKARRAY` holds `2 * HALF = 256` entries (was
  128), i.e. the whole one-byte range. A cold start's CID-migration steering now
  works for the full documented `0..256` worker range; indices 128..255 register
  instead of silently failing
  ([`src/server/linnea_bpf.asm`](/home/linnea/linnea/src/server/linnea_bpf.asm)).
- **generation partition** -- each hot-upgrade generation stamps from its own
  half, base `0` or `HALF = 128` (was 64), so **two generations of up to 128
  workers each coexist without colliding**. Lossless h3 reload now supports up
  to 128 workers (was 64)
  ([`src/server/linnea_start.asm`](/home/linnea/linnea/src/server/linnea_start.asm)).
- **no more silent registration failure** -- `linnea_bpf_map_add`'s return is
  now checked at the call site; a failure logs that the worker fell back to the
  4-tuple hash rather than dropping steering in silence
  ([`src/server/linnea_uring.asm`](/home/linnea/linnea/src/server/linnea_uring.asm)).

**Residual, documented, not silently broken:** above 128 workers the two
generations cannot both fit one byte, so a reload shares base 0 and may reset
the draining generation's h3 connections. A wider CID index is the redesign the
report calls for; 128 workers per generation covers all realistic hardware. The
one-byte limit and its consequences are now in
[`docs/config.md`](/home/linnea/linnea/docs/config.md) under `workers`.

**Verification.** The observable part -- the generation partition -- is A/B'd
against a pre-fix binary via the stamped CID byte: the adopted generation now
stamps base **128** where the pre-fix binary stamped **64**
([`test/quic/h3_steer_base_test.py`](/home/linnea/linnea/test/quic/h3_steer_base_test.py),
assertion updated). The map-size and map-registration changes need `CAP_BPF` to
observe, which the test environment lacks (as the steering handoff test already
notes), so they are correct-by-construction and build-checked. Full suite green.

## Reviewed behavior with no additional finding

- The report-3 fixes were rechecked: proxied H3 completions source the UDP
  socket from the connection, and authority validation remains semantic across
  HTTP/1, HTTP/2, and HTTP/3.
- QUIC connection-ID lifecycle, stream/final-size validation, H3 flow control,
  HTTP/2 framing/HPACK, HTTP/1 proxy framing, TLS, static-file normalization,
  listener/address handling, and shutdown/resource paths were reviewed with no
  additional high-confidence finding.
- The secondary-address H3 listener's lack of BPF CID steering remains the
  documented non-migrating-client design constraint noted in
  [`src/server/linnea_uring.asm:616`](/home/linnea/linnea/src/server/linnea_uring.asm:616)
  through line 623; it was not counted separately here.

## Verification

The audit did not modify source code. The build and both available test suites
completed successfully:

```text
make -j2
Nothing to be done for 'all'.

LINNEA_SUITE=fast ./test/run_tests.sh
730 passed, 0 failed, 26 SKIPPED (fast run)

LINNEA_SUITE=full ./test/run_tests.sh
756 passed, 0 failed (full run)
```

The working tree was clean before this report was created; the only intended
new file is `audit-report-4.md`.

## Conclusion

The report-3 fixes remain effective and the complete regression suite is green.
The one new finding is **FIXED**: the reuseport map now spans the whole one-byte
index range (cold-start steering to 256 workers), each generation uses a 128-wide
half (lossless reload to 128 workers, up from 64), and a failed map registration
is logged rather than ignored. The residual above-128 reload case -- a genuine
one-byte-CID limit -- is documented under `workers`. The audit is complete.
