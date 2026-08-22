# ECDSA P-256 verify — implementation plan

The pivotal new primitive for backend TLS (see
[`backend-tls-h2.md`](backend-tls-h2.md)). Tier 0 pins the backend's P-256
certificate; pinning is meaningless unless we verify the handshake's
**CertificateVerify** signature (the cert is public — only the signature proves
the peer holds the private key). That check is an ECDSA P-256 verify, which does
not exist today: `src/lib/linnea_p256_ecdsa.asm` only **signs**. Build and fuzz
this in isolation *before* any TLS wiring.

## The one simplification that makes this easier than signing

**Verify operates only on public data** — public key, signature, message hash.
There are **no secrets**, so unlike the signer (which guards the secret nonce),
verify needs **no constant-time discipline**: it may branch freely on validation
failures and take data-dependent paths. The only obligations are *correctness*
and *never crashing / misbehaving on malformed input*. (The existing `point_mul`
happens to be constant-time; that's fine, just not required here.)

## The toolbox (what already exists — and the traps)

All System V AMD64; the field/scalar/point routines preserve callee-saved regs
and may alias in/out. **Three representation facts drive the whole plan:**

1. **Field elements (mod p) and scalars (mod n) are 32 bytes, 4 little-endian
   limbs, in *Montgomery form*.** The byte boundary (`frombytes`/`tobytes`) is
   **big-endian (SEC1)**; Montgomery form never escapes the modules.
2. **Points are homogeneous *projective* `(X:Y:Z)`, NOT Jacobian.** 96 bytes
   (`.x=0 .y=32 .z=64`), each coord a Montgomery fe. **Infinity is `Z=0`. Affine
   `x = X/Z`** (single inverse — do *not* use the Jacobian `X/Z²`).
3. **`point_mul` takes its scalar `k` as PLAIN big-endian bytes, not Montgomery.**
   So any scalar computed in Montgomery-n form must be pushed through
   `scalar_tobytes` before it feeds `point_mul`. This is the easiest place to get
   it wrong.

Reusable routines (file:line in `src/lib/`):

- **Field mod p** (`linnea_p256_fe.asm`): `fe_mul`:69, `fe_sq`:74, `fe_add`:79,
  `fe_sub`:84, `fe_inv`:89 (Fermat, `inv(0)=0`), `fe_frombytes`:95 (BE→Mont,
  silently reduces mod p), `fe_tobytes`:101, `fe_1`:106, `fe_0`:112, `fe_copy`,
  `fe_cmov`. Prime `p` at global `linnea_p256_ctx_p` (`fe.asm:49`). **No
  `fe_is_zero`** — add one (trivial) or compare via `fe_tobytes`.
- **Scalar mod n** (`linnea_p256_scalar.asm`): `scalar_mul`:75, `scalar_sub`:85,
  `scalar_inv`:91 (Fermat, `inv(0)=0`), `scalar_frombytes`:101 (BE→Mont-n,
  reduces mod n — this is `bits2int`-then-mod-n, correct for both the hash and
  r), `scalar_tobytes`:107, `scalar_is_zero`:126 (works in Montgomery form),
  `scalar_is_valid`:147 (**reads raw BE, no reduce, returns 1 iff ∈ [1, n-1]** —
  exactly the range test). Order `n` at global `linnea_p256_ctx_n`
  (`scalar.asm:56`). **No scalar equality** — build `r == x` from `scalar_sub` +
  `scalar_is_zero`.
- **Points** (`linnea_p256_point.asm`): `point_add`:89 (Renes–Costello–Batina
  **complete** — correct for doubling, infinity, `P+(−P)`, no edge cases, may
  alias), `point_mul`:184 (`rdi=r, rsi=k(plain BE), rdx=base`; variable base),
  `point_identity`:165. **Generator G** at global `linnea_p256_g` (`point.asm:31`,
  projective, Z=1). There is no fixed-base fast path — `u1·G` and `u2·Q` both go
  through `point_mul`.
- **Projective→affine x** (recipe the signer uses, `ecdsa.asm:223`): `fe_inv(zi,
  R.z)` → `fe_mul(x, R.x, zi)` → `fe_tobytes(xb, x)` → `scalar_frombytes(v, xb)`
  (reduces mod n).

## The algorithm (exact primitive calls)

Inputs to the core routine: message hash `e` (32 B), signature `r`,`s` (32 B BE
each, already DER-decoded), public key `Q` as SEC1 affine `X‖Y` (64 B). Returns
1 = valid, 0 = invalid.

1. **Range-check the signature.** `scalar_is_valid(r)` **and** `scalar_is_valid(s)`
   must both be 1. Rejects `r=0`, `s=0`, `r≥n`, `s≥n`. (Cheap; do first.)
2. **Validate the public key `Q`** — see *New work* §1; SECURITY-CRITICAL.
   Canonical (`X<p`, `Y<p`), not infinity, and **on the curve**
   (`y² ≡ x³ − 3x + b mod p`). Only after this, build the projective point:
   `fe_frombytes(Q.x, X)`, `fe_frombytes(Q.y, Y)`, `fe_1(Q.z)`.
3. **`w = s⁻¹ mod n`.** `scalar_frombytes(s_m, s)`; `scalar_inv(w, s_m)`.
4. **`u1 = e·w`, `u2 = r·w` (mod n).** `scalar_frombytes(e_m, e)`;
   `scalar_frombytes(r_m, r)`; `scalar_mul(u1, e_m, w)`; `scalar_mul(u2, r_m, w)`.
5. **To plain bytes for the ladder** (the trap): `scalar_tobytes(u1b, u1)`;
   `scalar_tobytes(u2b, u2)`.
6. **`R = u1·G + u2·Q`.** `point_mul(T1, u1b, linnea_p256_g)`;
   `point_mul(T2, u2b, Q)`; `point_add(R, T1, T2)`.
7. **Reject if `R` is infinity:** `R.z == 0` (fe zero check).
8. **Reduce `R.x` to affine mod n:** the recipe above → `v` (Montgomery-n).
9. **Accept iff `v == r_m`:** `scalar_sub(d, v, r_m)`; return `scalar_is_zero(d)`.

## New work (small, but two pieces are the whole point)

1. **Public-key / on-curve validation — the largest and most important piece.**
   Absent today. Without it, an attacker supplying an **off-curve `Q`** breaks the
   group assumptions the complete addition formulas rely on (the classic
   invalid-curve attack) — the routine would return a confident wrong answer, not
   crash. Steps:
   - **Canonicality:** `X < p` and `Y < p` on the *raw* bytes (`fe_frombytes`
     silently reduces, so this is a separate check — add an `fe_is_valid`
     mirroring `scalar_is_valid`, or compare bytes to `linnea_p256_ctx_p.m`).
   - **Not infinity:** reject `X==0 && Y==0` (also caught by on-curve, but explicit
     is cheap).
   - **On the curve:** compute `lhs = y²` (`fe_sq`), `rhs = x³ − 3x + b`
     (`fe_sq`,`fe_mul` for `x³`; `x+x+x` or a `·3` for `3x`; `fe_sub`; `fe_add`
     `b`); accept iff `lhs == rhs`. **`b` is not exposed** (only file-local
     `p256_b3`), so add `b` as 32 plain BE bytes in rodata and `fe_frombytes` it
     to Montgomery once. Needs the fe zero/equality helper from §below.
   For the *pinned* Tier-0 path `Q` is fixed and trusted, so invalid-curve isn't
   reachable in production — but the primitive is general (Tier 2, tests, fuzzing
   all feed arbitrary `Q`), so on-curve validation is **mandatory in the routine**.
2. **Strict DER signature parser** (`SEQUENCE { INTEGER r, INTEGER s }`). The
   signer only *emits* DER (`ecdsa.asm:93`); no parser exists. Keep it a separate
   helper so the core verify takes raw `r,s` and is independently testable. It
   must be **strict** (lax/BER decoding is a known signature-malleability /
   bypass source — Wycheproof is full of these): require `0x30` + short-form
   length (valid P-256 sigs never need long form — reject it), two `0x02`
   INTEGERs, **minimal encoding** (reject non-minimal leading `0x00`, reject
   negative/high-bit), strip one legal leading `0x00`, left-pad to 32 B, reject
   `>33` B, and reject **trailing bytes** after the SEQUENCE.
3. **Small glue absent today:** an `fe_is_zero` (or `fe`-equality via `tobytes`),
   scalar equality via `scalar_sub`+`is_zero`, projective-point construction from
   `X‖Y`, and the `u1·G + u2·Q` combination (composed, no new math).
4. **The entry points:** `linnea_p256_ecdsa_verify(hash, r, s, pubkey_xy) →
   rax∈{0,1}` (core), and a thin `..._verify_der(hash, der, der_len, pubkey_xy)`
   wrapper. The TLS caller computes the CertificateVerify digest (the
   `0x20×64 || context || 0x00 || transcript-hash` construction) and passes the
   32-byte hash — that framing is the handshake's job, not this primitive's.

## Security-critical checklist

- **On-curve validation of `Q` (invalid-curve attack).** The single most
  important check. Test it fires: an off-curve `Q` **must** be rejected — a green
  suite that never feeds an off-curve point cannot tell a present check from a
  missing one (cf. the all-zero X25519 omission in [[crypto-review]]).
- **Strict DER** — no BER, no non-minimal integers, no trailing garbage.
- **Range `r,s ∈ [1,n-1]`** before use; **reject `R = ∞`** before comparing.
- No secret data ⇒ constant-time not required, but **robustness is**: malformed
  DER, wrong lengths, `X`/`Y ≥ p`, truncated inputs must return 0, never fault.

## File layout & build

- Add `linnea_p256_ecdsa_verify` (+ DER wrapper) to the existing
  `src/lib/linnea_p256_ecdsa.asm`; add `fe_is_valid`/`fe_is_zero` to
  `linnea_p256_fe.asm` and the `b` constant near it. **No new object or Makefile
  change** — the p256 objects already link into the server, the probe, and the
  selftest binary. Keep the build **warning-free** (the tripwire).

## Test plan

The existing model is a stdin selftest binary + Python differential drivers under
`test/crypto/` (`bin/linnea-selftest`, `diff_p256*.py`, references in
`gen_vectors.py`). Extend it:

1. **Selftest mode.** Add `p256-ecdsa-verify-stdin` to
   `test/crypto/linnea_selftest.asm` (dispatch near `:227`): read
   `hash(32) ‖ Qx(32) ‖ Qy(32) ‖ r(32) ‖ s(32)`, output 1 byte accept/reject.
   Add a second **DER** mode feeding raw DER so the parser is tested apart from
   the math.
2. **Python reference.** Add `p256_ecdsa_verify` to `gen_vectors.py` — it already
   has `P256_P`:401, `P256_N`:430, `GX/GY`:514, `p256_padd`:521, `p256_mul`:571,
   `p256_affine`:581, and mod-p/mod-n inverses; verify is a few lines on top.
3. **Round-trip** (`diff_p256_ecdsa.py`): sign with the existing linnea signer →
   verify with linnea ⇒ **accept**; flip one bit of hash / `r` / `s` ⇒ **reject**.
4. **OpenSSL interop:** sign with OpenSSL (random nonce, so it exercises sigs the
   deterministic signer never produces) → verify with linnea ⇒ accept; and the
   existing OpenSSL-verify of linnea's signatures stays.
5. **Known-answer suites — the real confidence:**
   - **NIST CAVP FIPS 186-4** ECDSA P-256/SHA-256 *verify* vectors (`SigVer.rsp`:
     `Msg/Qx/Qy/R/S/Result`) — includes deliberate bad-`R`, bad-`S`, altered-hash,
     bad-`Q` cases; assert accept/reject matches `Result`.
   - **Wycheproof** `ecdsa_secp256r1_sha256_test.json` — the gold standard for
     edge cases (BER encodings, `r`/`s` range, `s=0`, non-minimal INTEGERs,
     point-not-on-curve, modified lengths). Assert each `result` matches.
6. **Explicit negatives** (own vectors): `r=0`, `s=0`, `r=n`, `s=n`, `r=n−1`,
   **off-curve `Q`**, `Q=∞`, non-canonical `X`/`Y ≥ p`, DER with trailing byte /
   long-form length / non-minimal leading zero / truncated.
7. **Fuzzing:** fuzz the DER parser and the whole entry with mutated bytes; assert
   no fault and (control) that a known-good vector still accepts. **Prove the
   fuzzer reaches the verify** and that the off-curve case actually reaches the
   on-curve check — per [[verifying-changes]], a watch that never fired is not
   evidence of quiet.

## Sequencing / definition of done

1. `fe_is_valid`/`fe_is_zero` + `b` constant + on-curve validator, unit-tested
   against the reference (feed on- and off-curve points).
2. Core `linnea_p256_ecdsa_verify` composing the primitives; round-trip + CAVP
   green.
3. Strict DER wrapper; Wycheproof green.
4. Fuzzing with a proven-reaching harness; warning-free build; full suite green.

Done = CAVP + Wycheproof + round-trip + OpenSSL-interop all pass, the off-curve
and malformed-DER negatives are demonstrated to reject, and the fuzzer is shown
to reach both the parser and the on-curve check. Only then wire it into the TLS
client handshake (next design step).
