# Audit Report 96

Audited at `6307d08` (`tls: omit server_name when there is no SNI; validate proxy_sni (report 95)`), 2026-08-27.

This pass verified the report-95 ClientHello and SNI fixes, then widened through
TLS-client initialization and the new hostname validator. Two distinct findings
are batched here:

1. **High: backend TLS continues after unchecked entropy failures, potentially
   reusing an ephemeral private key and ClientHello randomness.**
2. **Low: the SNI validator enforces label limits but not the DNS total-name
   limit.**

No production source, configuration, or test files were changed in this audit.
Only this report was added.

## Finding 1 — backend TLS ignores all three `getrandom` results

Severity: **High (P1 cryptographic fail-open; an entropy failure can reuse key material)**  
Confidence: **High**  
Status: **Confirmed by source trace; unfixed.**

`linnea_tls_client_start` makes three 32-byte `getrandom(2)` calls: one for the
X25519 private key, one for the ClientHello random, and one for the legacy
session ID. None checks the syscall return value before using the destination
buffer and building the ClientHello
([src/server/linnea_tls_client.asm:919](/home/linnea/linnea/src/server/linnea_tls_client.asm:919)). Linux reports the number of bytes copied, and can return an error or fewer
bytes when interrupted; callers must inspect that result
([getrandom(2)](https://man7.org/linux/man-pages/man2/getrandom.2.html#RETURN_VALUE)).

The consequence is worse than merely sending zeros. Backend-TLS arenas are
indexed by reusable connection slots, and the pool states that
`linnea_tls_client_start` reinitializes an existing arena
([src/server/linnea_tls_client_pool.asm:32](/home/linnea/linnea/src/server/linnea_tls_client_pool.asm:32)). If an entropy read fails on a later use, its destination retains the previous
handshake's bytes. The private-key buffer is clamped and used to derive a new
public key without knowing whether any byte was refreshed; the ClientHello is
then sent unconditionally because `linnea_tls_client_start` has no failure
result and both callers immediately advance to the handshake state.

The QUIC handshake already applies the correct invariant: its 32-byte helper
retries partial reads and aborts on error because serving with a non-random
ephemeral key is worse than refusing the handshake
([src/server/linnea_quic_server.asm:6129](/home/linnea/linnea/src/server/linnea_quic_server.asm:6129)). Backend TLS does not.

### Impact

If `getrandom` is interrupted before pool initialization, denied by a sandbox,
or otherwise fails, a first-use arena starts from zero-filled mapped memory; a
reused arena can repeat its previous X25519 private key, ClientHello random, and
session ID. Reusing an ephemeral private key breaks the intended
per-connection forward-secrecy boundary. Partial success would mix fresh and
stale bytes. In all cases the server fails open into a cryptographic handshake
instead of returning an upstream error.

### Recommended fix

Use a shared exact-length entropy helper that loops until all 32 bytes are
filled and fails closed on zero/error, as the QUIC path does. Change
`linnea_tls_client_start` to return success/failure and make both the ordinary
and h2p callers abandon the backend leg before sending anything on failure.
Cover first-use and reused-arena failures with an injectable entropy stub;
assert that no ClientHello is emitted.

## Finding 2 — `proxy_sni` accepts DNS names beyond the total length limit

Severity: **Low (P3, an invalid hostname passes `--test` and reaches the wire)**  
Confidence: **High**  
Status: **Confirmed by source trace; unfixed.**

RFC 1035 limits each DNS label to 63 octets and the complete DNS name — label
bytes plus their length bytes and the terminating root label — to 255 octets
([RFC 1035 §2.3.4](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4)). For the textual, no-trailing-dot form required by SNI, that permits at most 253
characters.

The new validator correctly enforces 63 bytes per label, but its only total
bound remains `LINNEA_MAX_SNI = 255`
([src/server/linnea_config_parse.asm:1322](/home/linnea/linnea/src/server/linnea_config_parse.asm:1322), [include/linnea_config.inc:23](/home/linnea/linnea/include/linnea_config.inc:23)). Consequently a value made from four 63-character alphabetic labels separated
by three dots is 255 characters, passes every current check, and is copied into
SNI even though its DNS form would require 257 octets (252 label characters,
four label-length octets, and the root terminator).

### Impact

The configuration now promises DNS-hostname validation, but still accepts a
boundary value no DNS resolver can represent as a valid full name. A backend
may reject or ignore it at request time instead of the proxy rejecting it at
startup. This is an availability and diagnostic defect, not an authentication
bypass because SPKI pinning remains mandatory.

### Recommended fix

Set the textual `proxy_sni` maximum to 253 bytes, or track the encoded DNS
length while walking labels and require `label_bytes + label_count + 1 <= 255`.
Add both sides of the total boundary: a valid 253-character name whose labels
fit, and a 254-character name that must be rejected, in addition to the
existing 63/64-byte label tests.

---

## Resolution (2026-08-27)

**Both findings CONFIRMED and FIXED.** Fast suite **1166/0**.

### F1 is a CLASS, not three sites

The report cites the three reads in `linnea_tls_client_start`. The tree has
**13 `getrandom` sites, 8 of them unchecked**, and the five it did not name are
not benign:

| site | fills | a stale value means |
|---|---|---|
| `linnea_tls.asm:1463` | 12-byte AEAD nonce, session ticket | nonce reuse under one AES-GCM key |
| `quic_crypto.asm:618` | 12-byte AEAD nonce, QUIC ticket | the same |
| `quic_crypto.asm:204` | stateless-reset key, pre-fork | forgeable reset tokens, process lifetime |
| `quic_crypto.asm:946` | Retry token key, pre-fork | forgeable Retry tokens |
| `linnea_tls.asm:1486` | `ticket_age_add` | nothing — padding |

Fixing 3 of 8 instances of one class is the mistake this tree has recorded
before ("the two sites" were three), so all of them are fixed through one
helper, `linnea_random_bytes`, which loops on a short read and reports failure
**without deciding what failure means**.

That separation paid for itself immediately: the first attempt had the lib call
`linnea_error_exit` and broke `bin/linnea-probe`, which links the lib but not
the server's error module. Policy now lives with each caller:

- per-request backend handshake -> abandon the leg, 502, nothing sent
- pre-fork key -> refuse to start
- AEAD nonce -> issue no ticket (costs a resumption; a reused nonce costs the key)

`ticket_age_add` stays unchecked ON PURPOSE and now says so: it is
anti-correlation padding, and it is unreachable on failure anyway because the
nonce read earlier in the same function returns first.

Stack arithmetic on the two new failure paths was verified by hand rather than
trusted to the assembler: `build_nst`'s mirrors the real epilogue (`add rsp,
128` plus five pops, `rbx` confirmed as `hs`), and the seal's sits before its
`sub rsp, 16`, so only the three pushes are live.

### F2

Fixed at 253. The arithmetic checks out: a textual no-trailing-dot name encodes
as a length byte per label plus its bytes plus a root byte, i.e. `len + 2`, so
RFC 1035's 255 octets puts the textual maximum at 253. The report's exact case
— four 63-byte labels and three dots, 255 characters, 257 encoded — is now
rejected, with both sides asserted in `doc_claims_test.py`.

### On severity

F1 is a genuine fail-open and worth every line of this. It is also, on a
running Linux, close to unreachable: `getrandom(2)` for 32 bytes with no flags
blocks only until the pool is initialised at boot and does not fail afterwards,
and neither unit sets a `SystemCallFilter` that could deny it. The value here
is that the tree now fails closed the way its own QUIC path already did, so a
future sandbox change cannot turn entropy loss into silent key reuse.
