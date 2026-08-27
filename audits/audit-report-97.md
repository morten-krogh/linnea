# Audit Report 97

Audited at `cbec7d5` (`crypto: check every getrandom result, and fail closed (audit-report-96)`), 2026-08-27.

Report 96's fix introduced a shared exact-length entropy helper and corrected
the security-critical server call sites it identified. A tree-wide follow-up
shows that the claimed “every result” sweep is incomplete. Two distinct
remaining classes are batched here:

1. **Medium: the TLS and QUIC ticket-key setup loops spin forever on a
   persistent entropy error.**
2. **Medium: the shipped `linnea-probe` still ignores entropy results for TLS
   and QUIC key material.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — ticket-key initialization busy-loops on `getrandom` errors

Severity: **Medium (P2 availability; startup or hot replacement can hang indefinitely at 100% CPU)**  
Confidence: **High**  
Status: **Confirmed by source trace; unfixed.**

Both pre-fork session-ticket setup functions call `getrandom(2)` directly and
branch back to the syscall whenever the result is not exactly 16 bytes:

- [src/server/linnea_tls.asm:124](/home/linnea/linnea/src/server/linnea_tls.asm:124)
- [src/lib/linnea_quic_crypto.asm:591](/home/linnea/linnea/src/lib/linnea_quic_crypto.asm:591)

That handles a transient short return only by retrying the full buffer, but it
also retries every negative errno immediately and forever. A persistent denial
such as a sandbox policy, unsupported syscall, or repeated fault therefore
turns initialization into a tight CPU loop with no diagnostic and no return to
the caller.

These functions run in the master before workers fork
([src/server/linnea_ktls.asm:107](/home/linnea/linnea/src/server/linnea_ktls.asm:107)). On initial startup no worker becomes available; during a hot replacement the
new generation never reaches readiness. This differs from the new stateless
reset and Retry secret paths, which return failure and make startup terminate
with an explicit entropy error.

### Reproduction

Deny `getrandom` for the process (for example with a test interposer or a
seccomp fixture) and start a TLS-enabled configuration. The master remains in
`.again` in `linnea_tls_ticket_setup`; it neither exits nor logs an error. If
the first setup is allowed and the second is denied, the identical behavior
occurs in `linnea_quic_ticket_setup`.

### Recommended fix

Use `linnea_random_bytes` for both 16-byte keys. Return `-1` on failure and
propagate it through `linnea_ktls_setup` to the existing named startup-error
path. Retry partial positive reads inside the helper, but do not retry a
persistent error in a tight loop. Add fault-injection coverage for failure in
each of the two setup calls and assert prompt, diagnosed termination.

## Finding 2 — `linnea-probe` still fails open on cryptographic entropy reads

Severity: **Medium (P2 cryptographic correctness in a separately shipped binary)**  
Confidence: **High**  
Status: **Confirmed by source trace; unfixed.**

`bin/linnea-probe` is shipped as a standalone HTTP/1, HTTP/2, and HTTP/3
compliance prober. Its TLS-over-TCP handshake generates an X25519 private key,
ClientHello random, and session ID with three unchecked syscalls, then clamps
and uses the private-key buffer and sends the ClientHello regardless of the
results ([src/probe/linnea_probe.asm:2684](/home/linnea/linnea/src/probe/linnea_probe.asm:2684)).

The QUIC/H3 connection setup repeats the same unchecked key, random, and
session-ID reads and adds unchecked destination/source connection-ID reads
([src/probe/linnea_probe.asm:6112](/home/linnea/linnea/src/probe/linnea_probe.asm:6112)). A second H3 probe path contains the same five-call sequence
([src/probe/linnea_probe.asm:8893](/home/linnea/linnea/src/probe/linnea_probe.asm:8893)). These buffers are global and reused across the probe battery, so failure does not
merely yield zeroes on first use: later probes can repeat the preceding
handshake's ephemeral private key and identifiers.

The probe already links `src/lib/linnea_random.o`, because the server-side TLS
client now depends on it. There is therefore no binary/linkage obstacle to
using the exact-length helper here.

### Impact

On entropy failure the prober continues with stale or zero-filled key material
instead of reporting that the probe could not be performed. This breaks the
per-handshake X25519 freshness invariant and can make repeated QUIC identifiers
linkable or colliding. It can also produce misleading compliance results: a
failure attributed to the target may actually be a malformed or repeated
client handshake generated locally.

The endpoint being probed cannot normally force the local entropy syscall to
fail, so this is not rated as a remotely exploitable compromise. It is still a
cryptographic fail-open in a binary the project documents and distributes in
its own right.

### Recommended fix

Replace every probe-side cryptographic/identifier read with
`linnea_random_bytes`, abort the current probe or connection on `-1`, and emit a
diagnostic that distinguishes local entropy failure from target noncompliance.
Centralize the repeated TLS/QUIC initialization sequence so the three copies
cannot drift. Use fault injection to verify that no ClientHello or QUIC Initial
is transmitted after any failed fill.

---

## Resolution (2026-08-27)

**Both findings CONFIRMED and FIXED.** Fast suite **1166/0**. Both are genuine
misses in report 96's sweep, and each failed for its own reason.

### F1 — I checked for the PRESENCE of a check, not its correctness

Report 96's sweep script asked "is there a `cmp rax` within three lines of the
syscall?" and marked both of these **CHECKED**. They do compare:
`cmp rax, 16 / jne .again` — and then retry every negative errno forever, at
100% CPU, in the master before any worker forks, with no diagnostic. A grep for
whether a check exists says nothing about what its branch does.

Both now use `linnea_random_bytes` and return `0`/`-1`, propagated through
`linnea_ktls_setup` to a named startup error.

**A trap on the way:** both functions ended in a TAIL CALL to
`linnea_aesgcm_init`. `jmp` leaves the callee seeing the entry alignment;
`call` does not, and AES-GCM reads `movdqa` from the stack — the exact
8-misalignment this tree has already debugged as a NULL SIGSEGV. Both fixes
carry an explicit `sub rsp, 8` and say why.

### F2 — my grep excluded the directory

Report 96's sweep ran over `src/lib/*.asm src/server/*.asm`. `src/probe/` was
never looked at. The report finds 13 reads across three paths; there are
**19**, including a fourth copy of the sequence at `quic_fresh_ids` (6507) —
which is itself already a named helper that the other three duplicate — and the
DNS query-id read at 2399.

All 19 now go through `probe_rand`, which stops with a diagnostic naming local
entropy failure. That policy is deliberate for this binary: a compliance prober
that continues on stale key material reports **the wrong thing**, a local
failure dressed as target noncompliance, which is worse than not reporting.

Verified against the live site after the rewrite: h1 19 probes, h2 9 probes,
h3 29 probes, **0 deviations** — which exercises every rewritten read (x25519
keys, ClientHello randoms, session ids, QUIC connection ids).

### One process note

A scripted replacement of the first F1 site matched an unrelated function's
`ret` and spliced the failure path into the transcript-hash routine. It was
reverted with `git checkout` to the committed state and redone by hand rather
than patched over. Mechanical edits to assembly need the anchor verified after
the fact, not just the assembler's approval — it assembled fine.

### What the report did not say, and should be recorded

`quic_fresh_ids` exists precisely to be the one place that mints a fresh QUIC
identity, and three other sites open-code the same five reads instead of
calling it. The entropy checks are now uniform, but the duplication remains:
the next change to that sequence has four places to reach. Not fixed here — it
is a refactor, not a defect, and it belongs in its own commit.
