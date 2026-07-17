; linnea_p256_scalar.asm — arithmetic modulo the P-256 group order n.
;
; n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
;
; The second of P-256's two moduli: ECDSA's signature equation
; s = k^-1 * (e + r*d) mod n lives here, while point coordinates live in
; linnea_p256_fe.asm mod p. Both are linnea_p256_mont.asm's core bound to a
; modulus; this file is n's context plus names that spare call sites the
; context argument.
;
; Unlike p, n has no structural shortcut: its n0' is a real constant, so each
; reduction round pays an imul to find the multiplier. That is the whole
; difference between the two bindings.
;
; Scalars are secret (the private key, the nonce), so everything here is the
; core's constant-time arithmetic. The one exception is is_valid below, which
; inspects a candidate nonce's range -- see its comment.
;
; ABI: System V, inherited from the core. Callee-saved registers preserved,
; output may alias any input.

default rel

%include "linnea_p256_mont.inc"

global linnea_p256_scalar_frombytes
global linnea_p256_scalar_tobytes
global linnea_p256_scalar_mul
global linnea_p256_scalar_add
global linnea_p256_scalar_sub
global linnea_p256_scalar_inv
global linnea_p256_scalar_copy
global linnea_p256_scalar_cmov
global linnea_p256_scalar_1
global linnea_p256_scalar_0
global linnea_p256_scalar_is_zero
global linnea_p256_scalar_is_valid
global linnea_p256_ctx_n

extern linnea_p256_mont_mul
extern linnea_p256_mont_add
extern linnea_p256_mont_sub
extern linnea_p256_mont_inv
extern linnea_p256_mont_frombytes
extern linnea_p256_mont_tobytes
extern linnea_p256_mont_copy
extern linnea_p256_mont_cmov
extern linnea_p256_mont_1
extern linnea_p256_mont_0

section .rodata

; The modulus context; the field order must match linnea_p256_mont_ctx.
; Constants derived from the Python model, not typed from a reference.
align 8
linnea_p256_ctx_n:
    ; .m = n, the group order
    dq 0xf3b9cac2fc632551, 0xbce6faada7179e84
    dq 0xffffffffffffffff, 0xffffffff00000000
    ; .n0 = -n^-1 mod 2^64. No shortcut here, unlike p's 1.
    dq 0xccd1c8aaee00bc4f
    ; .r1 = 2^256 mod n
    dq 0x0c46353d039cdaaf, 0x4319055258e8617b
    dq 0x0000000000000000, 0x00000000ffffffff
    ; .r2 = (2^256)^2 mod n
    dq 0x83244c95be79eea2, 0x4699799c49bd6fa6
    dq 0x2845b2392b6bec59, 0x66e12d94f3d95620
    ; .exp = n-2, the Fermat exponent
    dq 0xf3b9cac2fc63254f, 0xbce6faada7179e84
    dq 0xffffffffffffffff, 0xffffffff00000000

section .text

; linnea_p256_scalar_mul(rdi=out, rsi=a, rdx=b) — out = a * b * R^-1 mod n
linnea_p256_scalar_mul:
    lea rcx, [linnea_p256_ctx_n]
    jmp linnea_p256_mont_mul

; linnea_p256_scalar_add(rdi=out, rsi=a, rdx=b) — out = a + b mod n
linnea_p256_scalar_add:
    lea rcx, [linnea_p256_ctx_n]
    jmp linnea_p256_mont_add

; linnea_p256_scalar_sub(rdi=out, rsi=a, rdx=b) — out = a - b mod n
linnea_p256_scalar_sub:
    lea rcx, [linnea_p256_ctx_n]
    jmp linnea_p256_mont_sub

; linnea_p256_scalar_inv(rdi=out, rsi=a) — out = a^-1 mod n (inv(0) = 0).
;   This is the k^-1 of the signature equation.
linnea_p256_scalar_inv:
    lea rdx, [linnea_p256_ctx_n]
    jmp linnea_p256_mont_inv

; linnea_p256_scalar_frombytes(rdi=out, rsi=in) — 32 big-endian bytes into
;   Montgomery form, REDUCING mod n. That reduction is exactly RFC 6979's
;   bits2int-then-mod-n for the P-256/SHA-256 pairing, where qlen == hlen*8
;   and no truncation is needed; it is also how a point's x-coordinate
;   becomes the signature's r. Callers that must instead REJECT an
;   out-of-range value (a 6979 nonce candidate) want is_valid first.
linnea_p256_scalar_frombytes:
    lea rdx, [linnea_p256_ctx_n]
    jmp linnea_p256_mont_frombytes

; linnea_p256_scalar_tobytes(rdi=out, rsi=a) — out of Montgomery form to 32
;   canonical big-endian bytes
linnea_p256_scalar_tobytes:
    lea rdx, [linnea_p256_ctx_n]
    jmp linnea_p256_mont_tobytes

; linnea_p256_scalar_1(rdi=out) — out = 1, in Montgomery form
linnea_p256_scalar_1:
    lea rsi, [linnea_p256_ctx_n]
    jmp linnea_p256_mont_1

linnea_p256_scalar_0:
    jmp linnea_p256_mont_0
linnea_p256_scalar_copy:
    jmp linnea_p256_mont_copy
linnea_p256_scalar_cmov:
    jmp linnea_p256_mont_cmov

; linnea_p256_scalar_is_zero(rdi=a) — rax = 1 if a is zero, else 0.
;   Montgomery form maps zero to zero, so this needs no conversion. ECDSA
;   must reject r == 0 and s == 0.
linnea_p256_scalar_is_zero:
    mov rax, [rdi]
    or rax, [rdi + 8]
    or rax, [rdi + 16]
    or rax, [rdi + 24]
    neg rax                     ; CF = (a != 0)
    sbb rax, rax                ; -1 if non-zero, 0 if zero
    inc rax                     ; 1 if zero, 0 if non-zero
    ret

; linnea_p256_scalar_is_valid(rdi=in) — rax = 1 iff the 32 big-endian bytes
;   at rdi encode a scalar in [1, n-1], else 0. Reads the raw encoding, NOT
;   Montgomery form, and does not reduce: this is the range test RFC 6979
;   applies to each nonce candidate, where a value outside the range must be
;   rejected and redrawn rather than folded into range.
;
;   Branch-free, though it need not be: 6979 rejects a candidate with
;   probability about 2^-32 for this curve, so a leak of "how many candidates
;   were drawn" is both astronomically unlikely to be observed and, being a
;   function of the DRBG output rather than of the key, not obviously useful.
;   Constant time is nearly free here, so it is not worth the argument.
linnea_p256_scalar_is_valid:
    mov r8, [rdi + 24]
    bswap r8                    ; limb 0 (least significant)
    mov r9, [rdi + 16]
    bswap r9
    mov r10, [rdi + 8]
    bswap r10
    mov r11, [rdi]
    bswap r11                   ; limb 3 (most significant)

    mov rax, r8
    or rax, r9
    or rax, r10
    or rax, r11
    neg rax
    sbb rax, rax                ; rax = -1 iff the value is non-zero

    ; v < n ? Borrow out of v - n says yes. `mov` does not touch the flags,
    ; so the chain survives reloading the minuend each step.
    lea rcx, [linnea_p256_ctx_n]
    mov rsi, r8
    sub rsi, [rcx]
    mov rsi, r9
    sbb rsi, [rcx + 8]
    mov rsi, r10
    sbb rsi, [rcx + 16]
    mov rsi, r11
    sbb rsi, [rcx + 24]
    sbb rdx, rdx                ; rdx = -1 iff v < n

    and rax, rdx
    and rax, 1
    ret
