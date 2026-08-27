# Audit Report 98

Audited at `18877fe` (`crypto: no entropy busy-loop, and check the probe's reads too (report 97)`), 2026-08-27.

Report 97's fixes correctly make ticket-key initialization return a diagnosed
startup failure and route all probe-side random fills through the shared
exact-length helper. Continuing the same tree-wide entropy audit found two
remaining fail-open packet-generation paths in the QUIC server. They are
batched here because they have the same root cause but different wire effects:

1. **Low: Retry packets are sent with a stale or partially refreshed source
   connection ID after `getrandom` fails.**
2. **Low: stateless resets are sent with a stale or zero predictable prefix
   after `getrandom` fails or returns short.**

Neither finding exposes the separately generated Retry-token or
stateless-reset secret: those pre-fork keys now use `linnea_random_bytes`, and
startup fails if either cannot be seeded. The defects are instead in the
per-packet randomness layered around those keyed constructions. They cause
protocol noncompliance, linkability, and misleading output under a local
entropy failure, not token forgery.

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — Retry ignores failure while minting its source connection ID

Severity: **Low (P3 protocol correctness and identifier freshness)**

Confidence: **High**

Status: **Confirmed by source trace; unfixed.**

`send_retry` constructs an eight-byte server source connection ID from two
routing bytes and a six-byte random tail. It calls `getrandom_bytes` for that
tail, but does not test the return value before binding the ID into the Retry
token, authenticating the Retry packet, and sending it
([src/server/linnea_quic_server.asm:7115](/home/linnea/linnea/src/server/linnea_quic_server.asm:7115), [src/server/linnea_quic_server.asm:7124](/home/linnea/linnea/src/server/linnea_quic_server.asm:7124), [src/server/linnea_quic_server.asm:7189](/home/linnea/linnea/src/server/linnea_quic_server.asm:7189)).

The helper itself loops over positive short returns, but on zero or a negative
errno it returns that raw value immediately
([src/server/linnea_quic_server.asm:7205](/home/linnea/linnea/src/server/linnea_quic_server.asm:7205)). Therefore:

- failure before any byte is written leaves the six-byte tail at its previous
  value in the worker-global `retry_buf`, or zero on first use;
- a positive short return followed by failure combines a fresh prefix with the
  remainder from the previous contents; and
- in both cases the caller emits the packet as though a fresh ID had been
  generated.

The buffer is static `.bss`, shared by every Retry built by that worker
([src/server/linnea_quic_server.asm:519](/home/linnea/linnea/src/server/linnea_quic_server.asm:519)). The path is reached when the unvalidated-connection pool is at its
limit and a tokenless Initial arrives
([src/server/linnea_quic_server.asm:920](/home/linnea/linnea/src/server/linnea_quic_server.asm:920)). Thus persistent entropy denial makes one worker repeatedly issue the same
`worker || 0xff || stale-tail` ID to unrelated clients.

RFC 9000 allows a server to choose its Retry source connection ID, but requires
that it differ from the Destination Connection ID in the triggering Initial,
and requires the client to use the chosen ID in subsequent packets
([RFC 9000 §17.2.5.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5.1)). Reusing a predictable value makes an otherwise negligible accidental equality
repeatable, and a peer that already observed the stale value can deliberately
select it as a future original destination ID. More generally, repeated IDs
make Retry traffic from the same worker linkable and contradict the function's
explicit promise to offer “a fresh id of ours.”

### Impact boundaries

The Retry token is still AEAD-protected by a checked pre-fork secret and is
bound to the peer address, the original destination ID, and this server ID.
The Retry integrity tag also covers the packet. Predicting or repeating the
source ID therefore does not let a remote peer forge a Retry token or bypass
address validation. A normal remote peer also cannot ordinarily make the
server's local `getrandom(2)` fail. Those constraints keep the severity Low.

The concrete failure is that a server already experiencing entropy loss sends
a valid-looking response with an identifier it did not freshly generate. A
strict client can discard the response if its source ID equals the original
destination ID; other clients proceed using an unnecessarily correlated ID.

### Reproduction

Run a worker with a fault-injection shim that permits startup entropy reads but
returns an error for the six-byte fill in `send_retry`. Fill the unvalidated
connection allowance, then send two otherwise valid 1200-byte tokenless
Initial datagrams that route to the same worker. Capture the Retry packets.
Their two routing bytes and six-byte tails repeat; on a worker's first Retry the
tail is zero-filled. A shim that returns three bytes and then fails produces a
three-byte fresh prefix followed by three stale bytes, and the packet is still
sent.

### Recommended fix

Delete the private `getrandom_bytes` helper and call the already linked
`linnea_random_bytes` exact-length helper. Test its `0`/`-1` result before
building the token. If entropy is unavailable, unwind `send_retry` without
calling `sendto`; dropping the Initial is preferable to inventing freshness,
and QUIC clients already retransmit unanswered Initials. Add a fault-injection
test for failure before the first byte and after a partial fill, asserting that
no Retry datagram is emitted.

## Finding 2 — stateless reset sends predictable bytes after an unchecked fill

Severity: **Low (P3 privacy and QUIC wire-format indistinguishability)**

Confidence: **High**

Status: **Confirmed by source trace; unfixed.**

`send_stateless_reset` chooses a response length, asks `getrandom(2)` to fill
the entire packet, and immediately consumes `srst_buf` without checking whether
the syscall returned the requested length
([src/server/linnea_quic_server.asm:6532](/home/linnea/linnea/src/server/linnea_quic_server.asm:6532), [src/server/linnea_quic_server.asm:6540](/home/linnea/linnea/src/server/linnea_quic_server.asm:6540)). It forces the first byte into short-header form, overwrites the trailing 16
bytes with the keyed reset token, and sends the result unconditionally
([src/server/linnea_quic_server.asm:6546](/home/linnea/linnea/src/server/linnea_quic_server.asm:6546), [src/server/linnea_quic_server.asm:6550](/home/linnea/linnea/src/server/linnea_quic_server.asm:6550)).

On a first-use failure, the `.bss` buffer contributes a prefix of `0x40`
followed by zero bytes. On later failures it repeats bytes from the preceding
reset. A short read likewise leaves the unfilled suffix stale. Since the
response ranges from 21 to 64 bytes and the last 16 bytes are replaced by the
token, even the minimum response has five prefix bytes whose unpredictability
depends on this unchecked call.

That conflicts directly with the purpose of the Stateless Reset format. RFC
9000 defines at least 38 unpredictable bits before the token and says the
remaining first-byte bits and following bytes should be indistinguishable from
random so that a reset resembles an ordinary protected short-header packet
([RFC 9000 §10.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3)). A fixed zero pattern makes the reset recognizable to an observer and creates a
stable implementation fingerprint precisely when the random source is failing.

The path is remotely reachable for a sufficiently long short-header packet
whose apparent eight-byte destination ID carries the current worker index but
does not match live state
([src/server/linnea_quic_server.asm:1027](/home/linnea/linnea/src/server/linnea_quic_server.asm:1027)). A remote sender cannot normally induce the entropy failure, but once the host is
in that state it can elicit and recognize the malformed resets.

### Impact boundaries

The final reset token is still derived from the unknown connection ID with a
secret whose initialization is checked. The unchecked packet fill therefore
does not make reset tokens guessable and does not let an observer terminate a
connection. The length logic also remains one byte shorter than the trigger,
so this finding does not reintroduce amplification or reset loops. Its impact
is loss of the protocol's intended indistinguishability and privacy, rather
than loss of token authentication.

### Reproduction

Permit the pre-fork stateless-reset secret initialization, then make the
worker's next `getrandom` return an error. Send a 22-byte short-header-shaped
datagram with the worker's index in the first destination-ID byte and an
unknown ID. The returned 21-byte datagram begins with `40 00 00 00 00` before
its 16-byte token. Repeating with longer triggers exposes a longer all-zero or
stale prefix. A short-return injector demonstrates the mixed fresh/stale form.

### Recommended fix

Use `linnea_random_bytes` for the exact response length and return without
sending if it reports failure. Filling only the bytes before the token would
avoid generating 16 bytes that are immediately overwritten, but whichever
length is requested must be checked exactly. Add first-use, reused-buffer, and
partial-return fault cases; each should assert that no datagram is sent after
an incomplete fill.

## Audit coverage note

This pass reclassified every remaining direct `getrandom` in production and
test assembly after report 97. The handshake key/random helpers fail closed;
initial and replacement connection-ID allocation checks exact lengths; ticket
nonces use `linnea_random_bytes`; the small `ticket_age_add` reads are
deliberately non-key padding reached only after successful ticket-nonce fills;
and the API fixture checks its eight-byte result. The two packet paths above
are the remaining sites that both ignore an incomplete result and transmit the
affected bytes.

---

## Resolution (2026-08-27)

**Both findings CONFIRMED and FIXED.** Fast suite **1166/0**.

Both now send NOTHING on entropy failure rather than a valid-looking packet
built from stale bytes. `send_retry` unwinds without `sendto` (QUIC clients
retransmit unanswered Initials); `send_stateless_reset` returns without
sending. The private `getrandom_bytes` helper is deleted — a second entropy
path with its own rationale is how the two drift apart.

### Why report 96 missed these: the exclusion was the bug, again

Report 96's sweep was `grep ... src/lib/*.asm src/server/*.asm | grep -v
quic_server`. I filtered the file OUT after seeing its good `.getrandom32`
helper and assuming the file was handled. That is the second time an exclusion
in my own sweep hid the defect — report 97's F2 was `src/probe/` sitting
outside the glob. **Both times, the code I chose not to look at was the code
with the defect.**

My scanner also under-reported: its 3-line window marked site 6670 UNCHECKED
when the check sits four lines down past two pops, correctly falling back with
"leave the slot as it was".

### F1 was a documented decision, not an oversight

`getrandom_bytes` carried: *"a failing getrandom is fatal for secrecy, but the
caller's ids are still unguessable enough."* Someone weighed this. The report's
secrecy argument does not actually defeat that reasoning — the Retry token is
AEAD-sealed under a now-checked key and bound to the address and original DCID,
so SCID secrecy is not what protects it. What defeats it is RFC 9000 17.2.5.1:
the Retry SCID must DIFFER from the Initial's DCID, and a stale tail makes that
collision selectable by any peer that has seen the value.

### TWO MISTAKES OF MINE, both worth recording

**1. I claimed `send_retry` had no coverage. It has had coverage all along.**
`test/quic/h3_retry_test.py` drives exactly this path; its check is labelled
"forged-Initial flood does not lock out real clients". My coverage search
grepped check LABELS for "retry" and that label has no such word. Third
instance in this run of my search method being the flaw.

**2. I then OVERWROTE that file** with `cat >`, destroying it, and the two
suite failures that followed were mine — the flood check was running my script
with `300` as its cafile. This is the mistake already recorded from report 77
("noticed only because git said modified not untracked"), and I did not check
`git status` before writing. Restored with `git checkout`.

What survived is the genuinely additive part, folded into that existing file:
it proved a Retry HAPPENED but asserted nothing about what was IN it. It now
also requires the Retry source id's random tail to be non-zero and distinct
across four Retries — the property an unchecked `getrandom` destroyed:

    ok (served through a 300-Initial flood; retries seen: 1;
        4 distinct Retry source ids)

One test for Retry rather than two competing for the same unvalidated-slot
pool, which is what made them collide.

### Severity

Unchanged from the report: Low. As established in report 96, `getrandom` at
these sizes does not fail on a running Linux and neither unit sets a
`SystemCallFilter`. This is conformance hardening against a future sandbox
change, not a live risk.
