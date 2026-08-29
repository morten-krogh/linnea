# Audit Report 135

Audited commit `e4ee846` (`audit 134: no issues found`), 2026-08-29.

This pass examined QUIC connection lifecycle and handshake demultiplexing,
HTTP/2 request-stream lifecycle and flow-control accounting, backend TLS-client
record/handshake parsing, and io_uring submission/completion progress. The
HTTP/2, backend-TLS, and io_uring areas came back clean. It found one QUIC
lifecycle defect: a packet routed by the original destination connection ID
during a fragmented Initial handshake does not refresh the connection idle
timer. No source, test, or configuration file was changed in this audit; only
this report was added.

## Finding 1 — Original-DCID handshake traffic does not refresh the QUIC idle timer

**Severity:** Medium  
**Confidence:** High  
**Status:** Open

[`linnea_quic_conn_lookup`](../src/server/linnea_quic_conn.asm#L56) stamps
`.last_active` after finding a connection by one of Linnea's issued CIDs.
[`linnea_quic_conn_lookup_odcid`](../src/server/linnea_quic_conn.asm#L111),
which is specifically used to route later Initial packets before the client has
learned Linnea's CID, returns its matching slot without that stamp. The receive
path calls the latter at
[`linnea_quic_server.asm`](../src/server/linnea_quic_server.asm#L859) and no
later receive-path write updates `.last_active`.

QUIC permits a ClientHello to span Initial packets. A client whose fragmented
or retransmitted Initials continue arriving through the original-DCID path can
therefore have its live handshake reclaimed after the short handshake idle
window. The next fragment is treated as a new connection rather than completing
the existing cryptographic stream.

### Reproduction

From the repository root, assemble this temporary harness. It allocates one
QUIC slot, gives it an original CID, looks that CID up (the same path as a
second Initial), then sweeps at four seconds. The supplied PTO stub only keeps
the harness self-contained; the connection is in the three-second handshake
idle state.

```sh
d=$(mktemp -d /tmp/linnea-audit-135-XXXXXX)
trap 'rm -rf "$d"' EXIT
cat >"$d/odcid_idle.asm" <<'ASM'
default rel
%include "linnea_syscall.inc"
%include "linnea_quic.inc"
%include "linnea_quic_conn.inc"
global _start, linnea_quic_pto_ms, linnea_memory_map
extern linnea_quic_conn_alloc, linnea_quic_conn_lookup_odcid
extern linnea_quic_conn_sweep

section .rodata
peer:  db 2,0,0,0,127,0,0,1
       times 20 db 0
odcid: db 1,2,3,4
bad:   db "reclaimed after ODCID packet",10
bad_len equ $-bad
good:  db "survived",10
good_len equ $-good

section .text
linnea_quic_pto_ms: mov eax, 10
                    ret
linnea_memory_map:  xor eax, eax
                    ret
_start:
    lea rdi, [peer]
    mov esi, 28
    call linnea_quic_conn_alloc
    mov rbx, rax
    mov qword [rbx + linnea_quic_conn.odcid_len], 4
    mov eax, [odcid]
    mov [rbx + linnea_quic_conn.odcid], eax
    mov qword [rbx + linnea_quic_conn.last_active], 0
    lea rdi, [odcid]
    mov esi, 4
    call linnea_quic_conn_lookup_odcid
    test rax, rax
    jz .fail
    mov edi, 4
    mov esi, LINNEA_QUIC_IDLE_SECS
    call linnea_quic_conn_sweep
    test rax, rax
    jz .good
    lea rsi, [bad]
    mov edx, bad_len
    jmp .print
.good:
    lea rsi, [good]
    mov edx, good_len
.print:
    mov edi, 1
    mov eax, LINNEA_SYS_WRITE
    syscall
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall
ASM
nasm -f elf64 -I include/ -o "$d/odcid_idle.o" "$d/odcid_idle.asm"
ld -o "$d/odcid_idle" "$d/odcid_idle.o" src/server/linnea_quic_conn.o
"$d/odcid_idle"
```

Observed output:

```
reclaimed after ODCID packet
```

The lookup succeeded, but the sweep still freed the slot. If the lookup had
credited that received packet, its timestamp would be ahead of the harness's
synthetic four-second sweep time and it would survive.

### Impact

A sufficiently slow, lossy, or deliberately fragmented QUIC Initial handshake
can fail despite the client continuing to send valid packets. This is most
visible with large ClientHellos, which the server explicitly supports by
reassembling CRYPTO frames across Initial packets. It also makes the handshake
slot accounting disagree with actual peer activity, needlessly abandoning live
state under load.

### Recommended fix

Refresh `.last_active` in `linnea_quic_conn_lookup_odcid`, matching the normal
CID lookup, or stamp every successfully demultiplexed packet in one common
receive-path location. Add a paired pool test: an ODCID lookup immediately
before a handshake idle sweep must preserve its slot, while an otherwise
identical untouched slot must be reclaimed.

## Resolution (fix pass)

**Finding 1: FIXED** — reproduced verbatim, then fixed and A/B'd.

The report's harness was assembled and run exactly as written, against
`src/server/linnea_quic_conn.o` at `e4ee846`:

```
reclaimed after ODCID packet
```

The reading behind it holds. `.last_active` has exactly two writers in the whole
tree — `linnea_quic_conn.asm:94` (the `.match` arm of `linnea_quic_conn_lookup`)
and `:249` (the tail of `linnea_quic_conn_alloc`). `grep -rn last_active
--include=*.asm --include=*.inc` finds no third, so the receive path really does
have one demux that does not count as activity, and it is the handshake one: a
ClientHello too large for a single Initial, or an Initial that has to be
retransmitted, is addressed to the client's original DCID until it has processed
our ServerHello, so **every** packet of such a handshake routes through
`linnea_quic_conn_lookup_odcid` and none of them credited the slot. The slot
carries `LINNEA_QUIC_ST_NEW`, so `linnea_quic_conn_sweep` applies the
three-second `LINNEA_QUIC_HS_IDLE_SECS` window to it and reclaims it while its
peer is still sending.

The fix is the report's first suggestion: `.lo_hit` now calls `conn_now` and
stamps `.last_active` before returning the slot, which is the same credit
`.match` gives a lookup by an id we issued. The second suggestion — one common
stamp on the receive path — was not taken: the two lookups are the receive
path's only two demux entry points and both now stamp, so a third site would
only add a place for the two to disagree.

### Coverage, and the A/B

The paired test went into `test/quic/linnea_pooltest.asm`, which is where the
sweep is already exercised. Two slots are allocated, both left `ST_NEW`, both
back-dated to `last_active = 0`; a lookup by original DCID arrives for A and
nothing arrives for B; **one** sweep at `LINNEA_QUIC_HS_IDLE_SECS + 1` then has
to reclaim B and keep A. Five checks, and the pairing is the point: a lookup
that credits nothing fails "A survived", a lookup that credits everything fails
"exactly one reclaimed" and "B is gone", and the `EXPECT rax, rbx` on the lookup
itself fails if the fix broke routing. Measured:

```
pre-fix  (e4ee846 linnea_quic_conn.o)   quic-pool 17/20   rc=1   failing: 17, 18, 20
post-fix                                quic-pool 20/20   rc=0
```

Checks 17/18/20 are "exactly one slot reclaimed", "A still in use" and "one
connection active". Checks 16 (routing) and 19 (the control slot *was*
reclaimed) pass in **both** builds — they are the acceptance controls that stop
the fix being scored by a test a blanket implementation could satisfy.

One trap found while writing it, worth recording: allocation sweeps before it
scans, so back-dating A and *then* allocating B has B's own sweep reclaim A and
hand back the same slot. Both slots are now taken before either is aged.

### The pool selftest had not existed for 54 commits

Building the test surfaced something the report did not look for. `make
pooltest` at `e4ee846` does not link:

```
ld: src/server/linnea_quic_conn.o: undefined reference to `linnea_quic_pto_ms'
```

`9cf8c94` (2026-08-27) moved the RFC 9000 10.1 three-PTO idle floor into
`linnea_quic_conn_sweep`, which made the pool depend on `src/lib/linnea_quic.o`
— the transport module `POOLTEST_OBJS` deliberately omits. `bin/linnea-pooltest`
has therefore not been produced since, and `test/shards/base/20-crypto.sh`
reported that as

```
PASS: quic pool selftest (skipped: binary unavailable)
```

confirmed in the pre-change baseline log. A vacuous pass, for 54 commits, over
precisely the file this finding is in. Three changes, all needed for the new
test to be coverage at all rather than nice-to-haves:

- a `linnea_quic_pto_ms` stub in `linnea_pooltest.asm` (10ms, so the three-PTO
  floor rounds to one second and never decides a check in that file), restoring
  the link;
- `bin/linnea-pooltest` and `bin/linnea-ringtest` added to the `run_shards.sh`
  pre-build list, which had never named them;
- the two "binary unavailable" arms in `20-crypto.sh` changed from `check ... 0`
  to `skip`, so a missing binary lands in the shard's SKIPPED count instead of
  its pass count.

Note that the fifteen pre-existing pool checks had also not run since `9cf8c94`.
They all pass.

### Acceptance controls

Run **before** any edit, `./test/shards/run.sh base` → `66 passed, 0 failed, 0
SKIPPED`, with the two vacuous skips above visible in it.

Run **after**, `./test/shards/run.sh base quic` → **164 passed, 0 failed, 13
SKIPPED**, rc=0. `base` is unchanged at 66 and `quic` contributes 98; the
thirteen SKIPPED are the fast-run time-gated h3 checks, not the pool. The checks
that bear directly on this change are all green:

- `quic pool selftest (quic-pool 20/20)` — no longer skipped;
- `h3 (io_uring): out-of-order multi-frame ClientHello reassembled` — the
  original-DCID demux still routes;
- `h3 (io_uring): forged-Initial flood does not lock out real clients` — the
  control for the one cost of this fix. Crediting the ODCID lookup means an
  attacker replaying a sniffed original DCID can hold a handshake slot past the
  three seconds it used to be capped at. That is already true of the issued-CID
  lookup, which has always stamped unconditionally, and pool admission is gated
  separately by `linnea_quic_conn_unvalidated`; the flood check confirms the
  behaviour did not change. Accepted deliberately — a live handshake being
  reclaimed under its own retransmissions is the worse failure.

`test/configs/doc_claims_test.py` → 191 claims, "all claims hold".

No oracle comparison and no `test/tls/prod_cert_check.sh`: this change is
entirely in QUIC connection-pool bookkeeping and touches no certificate, PEM or
DER code. `git diff --stat` is `linnea_quic_conn.asm`, `linnea_pooltest.asm`,
`20-crypto.sh`, `run_shards.sh`.

### What was not run

**The full suite was not run.** What ran was `./test/shards/run.sh base`
(baseline) and `./test/shards/run.sh base quic` (after), plus the standalone
`bin/linnea-pooltest` A/B and `doc_claims_test.py`. The `h1` and `tls` shards
were not run — nothing in this diff is reachable from either — and
`LINNEA_SUITE=full` was not run, so `h3 (io_uring): multi-packet ClientHello
reassembled` (18s, fast-run skip), the end-to-end check closest to this path,
remains unexercised here and should be watched in the pre-deploy full run.
