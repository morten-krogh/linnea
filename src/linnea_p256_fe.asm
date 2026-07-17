; linnea_p256_fe.asm — arithmetic in GF(p), p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
;
; The P-256 coordinate field: linnea_p256_mont.asm's core bound to p. The
; arithmetic, the representation and the carry subtleties all live there;
; this file is the modulus and a set of names that spare every call site the
; context argument.
;
; See include/linnea_p256_fe.inc for the representation and how its
; conventions differ from fe25519's.
;
; ABI: System V, inherited from the core. Callee-saved registers preserved,
; output may alias any input.

default rel

%include "linnea_p256_fe.inc"
%include "linnea_p256_mont.inc"

global linnea_p256_fe_frombytes
global linnea_p256_fe_tobytes
global linnea_p256_fe_mul
global linnea_p256_fe_sq
global linnea_p256_fe_add
global linnea_p256_fe_sub
global linnea_p256_fe_inv
global linnea_p256_fe_copy
global linnea_p256_fe_cmov
global linnea_p256_fe_1
global linnea_p256_fe_0
global linnea_p256_ctx_p

extern linnea_p256_mont_mul
extern linnea_p256_mont_sq
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
linnea_p256_ctx_p:
    ; .m = p. p0 = 2^64-1 = -1 mod 2^64, which is what makes .n0 below 1.
    dq 0xffffffffffffffff, 0x00000000ffffffff
    dq 0x0000000000000000, 0xffffffff00000001
    ; .n0 = -p^-1 mod 2^64. The one structural gift P-256 gives: the
    ; reduction's multiplier is the low limb itself.
    dq 1
    ; .r1 = 2^256 mod p
    dq 0x0000000000000001, 0xffffffff00000000
    dq 0xffffffffffffffff, 0x00000000fffffffe
    ; .r2 = (2^256)^2 mod p
    dq 0x0000000000000003, 0xfffffffbffffffff
    dq 0xfffffffffffffffe, 0x00000004fffffffd
    ; .exp = p-2, the Fermat exponent
    dq 0xfffffffffffffffd, 0x00000000ffffffff
    dq 0x0000000000000000, 0xffffffff00000001

section .text

; linnea_p256_fe_mul(rdi=out, rsi=a, rdx=b) — out = a * b * R^-1 mod p
linnea_p256_fe_mul:
    lea rcx, [linnea_p256_ctx_p]
    jmp linnea_p256_mont_mul

; linnea_p256_fe_sq(rdi=out, rsi=a) — out = a^2 * R^-1 mod p
linnea_p256_fe_sq:
    lea rdx, [linnea_p256_ctx_p]
    jmp linnea_p256_mont_sq

; linnea_p256_fe_add(rdi=out, rsi=a, rdx=b) — out = a + b mod p
linnea_p256_fe_add:
    lea rcx, [linnea_p256_ctx_p]
    jmp linnea_p256_mont_add

; linnea_p256_fe_sub(rdi=out, rsi=a, rdx=b) — out = a - b mod p
linnea_p256_fe_sub:
    lea rcx, [linnea_p256_ctx_p]
    jmp linnea_p256_mont_sub

; linnea_p256_fe_inv(rdi=out, rsi=a) — out = a^-1 mod p (inv(0) = 0)
linnea_p256_fe_inv:
    lea rdx, [linnea_p256_ctx_p]
    jmp linnea_p256_mont_inv

; linnea_p256_fe_frombytes(rdi=out, rsi=in) — 32 big-endian bytes into
;   Montgomery form, reducing mod p
linnea_p256_fe_frombytes:
    lea rdx, [linnea_p256_ctx_p]
    jmp linnea_p256_mont_frombytes

; linnea_p256_fe_tobytes(rdi=out, rsi=a) — out of Montgomery form to 32
;   canonical big-endian bytes
linnea_p256_fe_tobytes:
    lea rdx, [linnea_p256_ctx_p]
    jmp linnea_p256_mont_tobytes

; linnea_p256_fe_1(rdi=out) — out = 1, in Montgomery form
linnea_p256_fe_1:
    lea rsi, [linnea_p256_ctx_p]
    jmp linnea_p256_mont_1

; The remaining three do not depend on the modulus; the names exist so call
; sites read consistently with the rest of the field API.
linnea_p256_fe_0:
    jmp linnea_p256_mont_0
linnea_p256_fe_copy:
    jmp linnea_p256_mont_copy
linnea_p256_fe_cmov:
    jmp linnea_p256_mont_cmov
