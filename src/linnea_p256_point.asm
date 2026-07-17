; linnea_p256_point.asm — the P-256 group: complete addition and k*G.
;
; The addition is EFD's add-2015-rcb (Renes-Costello-Batina 2015) for a = -3,
; transcribed line for line from the formula listing and validated in a Python
; model against an independent affine implementation before any of this was
; written. It is COMPLETE on a prime-order curve: correct for P == Q, for the
; identity, and for P == -Q, with no exceptional case.
;
; That completeness is a security property here, not a convenience. The
; textbook Jacobian formulas fail when the accumulator equals the addend or is
; the identity, and the usual dodges -- start the ladder at the scalar's
; highest set bit, or branch on "is this infinity" -- leak the bit length of a
; secret nonce. A complete formula has nothing to branch on, so the ladder
; below runs the same 256 iterations with the same operations for every k.
; The same reasoning (and the same shape: one unified formula, doubling by
; calling add with p == q) is already in linnea_ed25519.asm.
;
; Cost: doubling through the general formula is ~12 field multiplies where a
; dedicated dbl-2015-rcb would be ~8. On a path that runs once per handshake
; that buys nothing worth the second formula's surface area.
;
; ABI: System V. Callee-saved rbx, rbp, r12-r15 preserved.

default rel

%include "linnea_p256_point.inc"

global linnea_p256_point_add
global linnea_p256_point_mul
global linnea_p256_point_identity
global linnea_p256_g

extern linnea_p256_fe_mul
extern linnea_p256_fe_add
extern linnea_p256_fe_sub
extern linnea_p256_fe_copy
extern linnea_p256_fe_cmov
extern linnea_p256_fe_1
extern linnea_p256_fe_0

section .rodata

; Curve constants in Montgomery form, derived by the Python model rather than
; typed from a reference. The model asserts G is on the curve and that
; n*G is the identity, so a wrong digit here cannot survive the tests.
align 8
p256_a:                                 ; a = -3
    dq 0xfffffffffffffffc, 0x00000003ffffffff
    dq 0x0000000000000000, 0xfffffffc00000004
p256_b3:                                ; b3 = 3*b, as add-2015-rcb wants it
    dq 0x89d69e267d4e399f, 0x06d01166698c91b2
    dq 0xb0e66203e5638c84, 0x949012590d95d89c

; The base point, projective with Z = 1.
align 8
linnea_p256_g:
    dq 0x79e730d418a9143c, 0x75ba95fc5fedb601   ; X
    dq 0x79fb732b77622510, 0x18905f76a53755c6
    dq 0xddf25357ce95560a, 0x8b4ab8e4ba19e45c   ; Y
    dq 0xd2e88688dd21f325, 0x8571ff1825885d85
    dq 0x0000000000000001, 0xffffffff00000000   ; Z = 1
    dq 0xffffffffffffffff, 0x00000000fffffffe

section .text

; Stack layout for linnea_p256_point_add. Nine field temporaries plus the
; caller's output pointer, which has to be parked somewhere the fe calls
; cannot reach.
%define T0    0
%define T1   32
%define T2   64
%define T3   96
%define T4  128
%define T5  160
%define OX  192
%define OY  224
%define OZ  256
%define RPTR 288
%define ADD_FRAME 296       ; two pushes + this leaves rsp 16-aligned

; A step of the formula: dst = src1 <op> src2, with p in rbx and q in rbp.
%macro FEOP 4               ; %1 = op, %2 = dst, %3 = src1, %4 = src2
    lea rdi, %2
    lea rsi, %3
    lea rdx, %4
    call %1
%endmacro

; linnea_p256_point_add(rdi=r, rsi=p, rdx=q) — r = p + q.
;   Complete: no input is special. r may alias p and/or q; the result is
;   assembled in stack temporaries and only copied out at the end.
linnea_p256_point_add:
    push rbx
    push rbp
    sub rsp, ADD_FRAME

    mov [rsp + RPTR], rdi
    mov rbx, rsi                ; p
    mov rbp, rdx                ; q

    ; The EFD add-2015-rcb sequence, in order. Kept in the source order of
    ; the listing so it can be diffed against it; the comments are the
    ; listing's own left-hand sides.
    FEOP linnea_p256_fe_mul, [rsp+T0], [rbx+linnea_p256_point.x], [rbp+linnea_p256_point.x]   ; t0 = X1*X2
    FEOP linnea_p256_fe_mul, [rsp+T1], [rbx+linnea_p256_point.y], [rbp+linnea_p256_point.y]   ; t1 = Y1*Y2
    FEOP linnea_p256_fe_mul, [rsp+T2], [rbx+linnea_p256_point.z], [rbp+linnea_p256_point.z]   ; t2 = Z1*Z2
    FEOP linnea_p256_fe_add, [rsp+T3], [rbx+linnea_p256_point.x], [rbx+linnea_p256_point.y]   ; t3 = X1+Y1
    FEOP linnea_p256_fe_add, [rsp+T4], [rbp+linnea_p256_point.x], [rbp+linnea_p256_point.y]   ; t4 = X2+Y2
    FEOP linnea_p256_fe_mul, [rsp+T3], [rsp+T3], [rsp+T4]                                     ; t3 = t3*t4
    FEOP linnea_p256_fe_add, [rsp+T4], [rsp+T0], [rsp+T1]                                     ; t4 = t0+t1
    FEOP linnea_p256_fe_sub, [rsp+T3], [rsp+T3], [rsp+T4]                                     ; t3 = t3-t4
    FEOP linnea_p256_fe_add, [rsp+T4], [rbx+linnea_p256_point.x], [rbx+linnea_p256_point.z]   ; t4 = X1+Z1
    FEOP linnea_p256_fe_add, [rsp+T5], [rbp+linnea_p256_point.x], [rbp+linnea_p256_point.z]   ; t5 = X2+Z2
    FEOP linnea_p256_fe_mul, [rsp+T4], [rsp+T4], [rsp+T5]                                     ; t4 = t4*t5
    FEOP linnea_p256_fe_add, [rsp+T5], [rsp+T0], [rsp+T2]                                     ; t5 = t0+t2
    FEOP linnea_p256_fe_sub, [rsp+T4], [rsp+T4], [rsp+T5]                                     ; t4 = t4-t5
    FEOP linnea_p256_fe_add, [rsp+T5], [rbx+linnea_p256_point.y], [rbx+linnea_p256_point.z]   ; t5 = Y1+Z1
    FEOP linnea_p256_fe_add, [rsp+OX], [rbp+linnea_p256_point.y], [rbp+linnea_p256_point.z]   ; X3 = Y2+Z2
    FEOP linnea_p256_fe_mul, [rsp+T5], [rsp+T5], [rsp+OX]                                     ; t5 = t5*X3
    FEOP linnea_p256_fe_add, [rsp+OX], [rsp+T1], [rsp+T2]                                     ; X3 = t1+t2
    FEOP linnea_p256_fe_sub, [rsp+T5], [rsp+T5], [rsp+OX]                                     ; t5 = t5-X3
    FEOP linnea_p256_fe_mul, [rsp+OZ], [rsp+T4], [p256_a]                                     ; Z3 = a*t4
    FEOP linnea_p256_fe_mul, [rsp+OX], [rsp+T2], [p256_b3]                                    ; X3 = b3*t2
    FEOP linnea_p256_fe_add, [rsp+OZ], [rsp+OX], [rsp+OZ]                                     ; Z3 = X3+Z3
    FEOP linnea_p256_fe_sub, [rsp+OX], [rsp+T1], [rsp+OZ]                                     ; X3 = t1-Z3
    FEOP linnea_p256_fe_add, [rsp+OZ], [rsp+T1], [rsp+OZ]                                     ; Z3 = t1+Z3
    FEOP linnea_p256_fe_mul, [rsp+OY], [rsp+OX], [rsp+OZ]                                     ; Y3 = X3*Z3
    FEOP linnea_p256_fe_add, [rsp+T1], [rsp+T0], [rsp+T0]                                     ; t1 = t0+t0
    FEOP linnea_p256_fe_add, [rsp+T1], [rsp+T1], [rsp+T0]                                     ; t1 = t1+t0
    FEOP linnea_p256_fe_mul, [rsp+T2], [rsp+T2], [p256_a]                                     ; t2 = a*t2
    FEOP linnea_p256_fe_mul, [rsp+T4], [rsp+T4], [p256_b3]                                    ; t4 = b3*t4
    FEOP linnea_p256_fe_add, [rsp+T1], [rsp+T1], [rsp+T2]                                     ; t1 = t1+t2
    FEOP linnea_p256_fe_sub, [rsp+T2], [rsp+T0], [rsp+T2]                                     ; t2 = t0-t2
    FEOP linnea_p256_fe_mul, [rsp+T2], [rsp+T2], [p256_a]                                     ; t2 = a*t2
    FEOP linnea_p256_fe_add, [rsp+T4], [rsp+T4], [rsp+T2]                                     ; t4 = t4+t2
    FEOP linnea_p256_fe_mul, [rsp+T0], [rsp+T1], [rsp+T4]                                     ; t0 = t1*t4
    FEOP linnea_p256_fe_add, [rsp+OY], [rsp+OY], [rsp+T0]                                     ; Y3 = Y3+t0
    FEOP linnea_p256_fe_mul, [rsp+T0], [rsp+T5], [rsp+T4]                                     ; t0 = t5*t4
    FEOP linnea_p256_fe_mul, [rsp+OX], [rsp+T3], [rsp+OX]                                     ; X3 = t3*X3
    FEOP linnea_p256_fe_sub, [rsp+OX], [rsp+OX], [rsp+T0]                                     ; X3 = X3-t0
    FEOP linnea_p256_fe_mul, [rsp+T0], [rsp+T3], [rsp+T1]                                     ; t0 = t3*t1
    FEOP linnea_p256_fe_mul, [rsp+OZ], [rsp+T5], [rsp+OZ]                                     ; Z3 = t5*Z3
    FEOP linnea_p256_fe_add, [rsp+OZ], [rsp+OZ], [rsp+T0]                                     ; Z3 = Z3+t0

    ; only now is it safe to touch r, which may be p or q
    mov rbx, [rsp + RPTR]
    lea rdi, [rbx + linnea_p256_point.x]
    lea rsi, [rsp + OX]
    call linnea_p256_fe_copy
    mov rbx, [rsp + RPTR]
    lea rdi, [rbx + linnea_p256_point.y]
    lea rsi, [rsp + OY]
    call linnea_p256_fe_copy
    mov rbx, [rsp + RPTR]
    lea rdi, [rbx + linnea_p256_point.z]
    lea rsi, [rsp + OZ]
    call linnea_p256_fe_copy

    add rsp, ADD_FRAME
    pop rbp
    pop rbx
    ret

; linnea_p256_point_identity(rdi=r) — r = the identity, (0 : 1 : 0).
linnea_p256_point_identity:
    push rbx
    mov rbx, rdi
    call linnea_p256_fe_0                       ; X = 0
    lea rdi, [rbx + linnea_p256_point.y]
    call linnea_p256_fe_1                       ; Y = 1
    lea rdi, [rbx + linnea_p256_point.z]
    call linnea_p256_fe_0                       ; Z = 0
    mov rdi, rbx
    pop rbx
    ret

%define ACC   0
%define CAND 96
%define KLIM 192
%define BPTR 224
%define OPTR 232
%define MUL_FRAME 248       ; four pushes + this leaves rsp 16-aligned

; linnea_p256_point_mul(rdi=r, rsi=k, rdx=base) — r = k * base, where k is 32
;   big-endian bytes (SEC1 order, like everything else in this module family).
;
;   Double-and-always-add over all 256 bits, selecting with fe_cmov: the same
;   work happens for every scalar, and neither a branch nor a memory index
;   depends on k. k is secret -- it is the ECDSA nonce, from which the private
;   key follows immediately if it leaks.
;
;   k is used as a plain integer here, NOT in Montgomery form: the ladder
;   reads its bits.
linnea_p256_point_mul:
    push rbx
    push rbp
    push r12
    push r13
    sub rsp, MUL_FRAME

    mov [rsp + OPTR], rdi
    mov [rsp + BPTR], rdx

    ; k, big-endian bytes -> little-endian limbs, so bit i is limb i>>6
    mov rax, [rsi + 24]
    bswap rax
    mov [rsp + KLIM], rax
    mov rax, [rsi + 16]
    bswap rax
    mov [rsp + KLIM + 8], rax
    mov rax, [rsi + 8]
    bswap rax
    mov [rsp + KLIM + 16], rax
    mov rax, [rsi]
    bswap rax
    mov [rsp + KLIM + 24], rax

    lea rdi, [rsp + ACC]
    call linnea_p256_point_identity

    mov r12, 255
.bit:
    lea rdi, [rsp + ACC]                ; acc = 2*acc, via the complete add
    lea rsi, [rsp + ACC]
    lea rdx, [rsp + ACC]
    call linnea_p256_point_add

    lea rdi, [rsp + CAND]               ; cand = acc + base
    lea rsi, [rsp + ACC]
    mov rdx, [rsp + BPTR]
    call linnea_p256_point_add

    ; r13 = bit r12 of k, then select cand into acc if it is set
    mov rax, r12
    shr rax, 6
    mov rcx, r12
    and rcx, 63
    lea rbx, [rsp + KLIM]
    mov rax, [rbx + rax*8]
    shr rax, cl
    and rax, 1
    mov r13, rax

    lea rdi, [rsp + ACC + linnea_p256_point.x]
    lea rsi, [rsp + CAND + linnea_p256_point.x]
    mov rdx, r13
    call linnea_p256_fe_cmov
    lea rdi, [rsp + ACC + linnea_p256_point.y]
    lea rsi, [rsp + CAND + linnea_p256_point.y]
    mov rdx, r13
    call linnea_p256_fe_cmov
    lea rdi, [rsp + ACC + linnea_p256_point.z]
    lea rsi, [rsp + CAND + linnea_p256_point.z]
    mov rdx, r13
    call linnea_p256_fe_cmov

    dec r12
    jns .bit

    mov rbx, [rsp + OPTR]
    lea rdi, [rbx + linnea_p256_point.x]
    lea rsi, [rsp + ACC + linnea_p256_point.x]
    call linnea_p256_fe_copy
    mov rbx, [rsp + OPTR]
    lea rdi, [rbx + linnea_p256_point.y]
    lea rsi, [rsp + ACC + linnea_p256_point.y]
    call linnea_p256_fe_copy
    mov rbx, [rsp + OPTR]
    lea rdi, [rbx + linnea_p256_point.z]
    lea rsi, [rsp + ACC + linnea_p256_point.z]
    call linnea_p256_fe_copy

    add rsp, MUL_FRAME
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
