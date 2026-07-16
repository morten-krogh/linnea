; linnea_fe25519.asm — arithmetic in GF(2^255-19), radix 2^51 (donna64).
;
; The representation and the multiply/carry structure follow Adam Langley's
; public-domain curve25519-donna (64-bit). Everything runs only during the
; TLS handshake (X25519 key agreement, Ed25519 signing), never on bulk
; data, so this is written for correctness, not for the last cycle. No
; secret-dependent branches or memory indices: the ladder that calls this
; is constant-time, and cswap below is branch-free.
;
; ABI: System V. Callee-saved rbx, rbp, r12-r15 preserved. A field element
; is passed by pointer to five little-endian 64-bit limbs.

default rel

%include "linnea_fe25519.inc"

global linnea_fe25519_frombytes
global linnea_fe25519_tobytes
global linnea_fe25519_mul
global linnea_fe25519_sq
global linnea_fe25519_add
global linnea_fe25519_sub
global linnea_fe25519_mul121665
global linnea_fe25519_copy
global linnea_fe25519_cswap
global linnea_fe25519_cmov
global linnea_fe25519_invert
global linnea_fe25519_1
global linnea_fe25519_0

section .text

; fe_carry(rdi=fe) — reduce all limbs below ~2^52 in place. File-local.
; Two fold passes leave limbs < 2^51 except limb1, which may be 2^51+1.
fe_carry:
    push rbx
    mov r8,  [rdi]
    mov r9,  [rdi + 8]
    mov r10, [rdi + 16]
    mov r11, [rdi + 24]
    mov rbx, [rdi + 32]
    mov rcx, LINNEA_FE25519_MASK51
    mov rax, r8
    shr rax, 51
    and r8, rcx
    add r9, rax
    mov rax, r9
    shr rax, 51
    and r9, rcx
    add r10, rax
    mov rax, r10
    shr rax, 51
    and r10, rcx
    add r11, rax
    mov rax, r11
    shr rax, 51
    and r11, rcx
    add rbx, rax
    mov rax, rbx
    shr rax, 51
    and rbx, rcx
    imul rax, rax, 19
    add r8, rax
    mov rax, r8                 ; second, small fold of the *19 carry
    shr rax, 51
    and r8, rcx
    add r9, rax
    mov [rdi], r8
    mov [rdi + 8], r9
    mov [rdi + 16], r10
    mov [rdi + 24], r11
    mov [rdi + 32], rbx
    pop rbx
    ret

; linnea_fe25519_add(rdi=h, rsi=f, rdx=g) — h = f + g, then carry.
linnea_fe25519_add:
    mov rax, [rsi]
    add rax, [rdx]
    mov [rdi], rax
    mov rax, [rsi + 8]
    add rax, [rdx + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    add rax, [rdx + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    add rax, [rdx + 24]
    mov [rdi + 24], rax
    mov rax, [rsi + 32]
    add rax, [rdx + 32]
    mov [rdi + 32], rax
    jmp fe_carry               ; tail call: reduce and return

; linnea_fe25519_sub(rdi=h, rsi=f, rdx=g) — h = f - g, then carry.
; Adds 8p (limb constants 2^54-152, 2^54-8) so every limb stays positive.
linnea_fe25519_sub:
    mov r8, (1 << 54) - 8
    mov rax, [rsi]
    mov r9, (1 << 54) - 152
    add rax, r9
    sub rax, [rdx]
    mov [rdi], rax
    mov rax, [rsi + 8]
    add rax, r8
    sub rax, [rdx + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    add rax, r8
    sub rax, [rdx + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    add rax, r8
    sub rax, [rdx + 24]
    mov [rdi + 24], rax
    mov rax, [rsi + 32]
    add rax, r8
    sub rax, [rdx + 32]
    mov [rdi + 32], rax
    jmp fe_carry

; linnea_fe25519_mul(rdi=h, rsi=f, rdx=g) — h = f * g mod p.
; f and g are copied in first, so h may alias either.
%macro MAC0 2
    mov rax, %1
    mul qword %2
    mov r13, rax
    mov r14, rdx
%endmacro
%macro MAC 2
    mov rax, %1
    mul qword %2
    add r13, rax
    adc r14, rdx
%endmacro

; stack scratch offsets
%define MF 0        ; f0..f4
%define MG 40       ; g0..g4
%define MM 80       ; 19*f1 .. 19*f4
%define MT 112      ; t0lo,t0hi .. t4lo,t4hi (80 bytes)

linnea_fe25519_mul:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 192
    mov r12, rdi               ; output
    ; copy f and g into the scratch
    mov rax, [rsi]
    mov [rsp + MF], rax
    mov rax, [rsi + 8]
    mov [rsp + MF + 8], rax
    mov rax, [rsi + 16]
    mov [rsp + MF + 16], rax
    mov rax, [rsi + 24]
    mov [rsp + MF + 24], rax
    mov rax, [rsi + 32]
    mov [rsp + MF + 32], rax
    mov rax, [rdx]
    mov [rsp + MG], rax
    mov rax, [rdx + 8]
    mov [rsp + MG + 8], rax
    mov rax, [rdx + 16]
    mov [rsp + MG + 16], rax
    mov rax, [rdx + 24]
    mov [rsp + MG + 24], rax
    mov rax, [rdx + 32]
    mov [rsp + MG + 32], rax
    ; 19*f1 .. 19*f4
    mov rax, [rsp + MF + 8]
    imul rax, rax, 19
    mov [rsp + MM], rax
    mov rax, [rsp + MF + 16]
    imul rax, rax, 19
    mov [rsp + MM + 8], rax
    mov rax, [rsp + MF + 24]
    imul rax, rax, 19
    mov [rsp + MM + 16], rax
    mov rax, [rsp + MF + 32]
    imul rax, rax, 19
    mov [rsp + MM + 24], rax
    ; t0 = f0*g0 + 19f4*g1 + 19f1*g4 + 19f2*g3 + 19f3*g2
    MAC0 [rsp+MF], [rsp+MG]
    MAC  [rsp+MM+24], [rsp+MG+8]
    MAC  [rsp+MM], [rsp+MG+32]
    MAC  [rsp+MM+8], [rsp+MG+24]
    MAC  [rsp+MM+16], [rsp+MG+16]
    mov [rsp + MT], r13
    mov [rsp + MT + 8], r14
    ; t1 = f0*g1 + f1*g0 + 19f4*g2 + 19f2*g4 + 19f3*g3
    MAC0 [rsp+MF], [rsp+MG+8]
    MAC  [rsp+MF+8], [rsp+MG]
    MAC  [rsp+MM+24], [rsp+MG+16]
    MAC  [rsp+MM+8], [rsp+MG+32]
    MAC  [rsp+MM+16], [rsp+MG+24]
    mov [rsp + MT + 16], r13
    mov [rsp + MT + 24], r14
    ; t2 = f0*g2 + f1*g1 + f2*g0 + 19f4*g3 + 19f3*g4
    MAC0 [rsp+MF], [rsp+MG+16]
    MAC  [rsp+MF+8], [rsp+MG+8]
    MAC  [rsp+MF+16], [rsp+MG]
    MAC  [rsp+MM+24], [rsp+MG+24]
    MAC  [rsp+MM+16], [rsp+MG+32]
    mov [rsp + MT + 32], r13
    mov [rsp + MT + 40], r14
    ; t3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + 19f4*g4
    MAC0 [rsp+MF], [rsp+MG+24]
    MAC  [rsp+MF+8], [rsp+MG+16]
    MAC  [rsp+MF+16], [rsp+MG+8]
    MAC  [rsp+MF+24], [rsp+MG]
    MAC  [rsp+MM+24], [rsp+MG+32]
    mov [rsp + MT + 48], r13
    mov [rsp + MT + 56], r14
    ; t4 = f0*g4 + f1*g3 + f2*g2 + f3*g1 + f4*g0
    MAC0 [rsp+MF], [rsp+MG+32]
    MAC  [rsp+MF+8], [rsp+MG+24]
    MAC  [rsp+MF+16], [rsp+MG+16]
    MAC  [rsp+MF+24], [rsp+MG+8]
    MAC  [rsp+MF+32], [rsp+MG]
    mov [rsp + MT + 64], r13
    mov [rsp + MT + 72], r14
    ; carry chain -> r0..r4 in r8,r9,r10,r11,r15
    mov rcx, LINNEA_FE25519_MASK51
    mov r13, [rsp + MT]
    mov r14, [rsp + MT + 8]
    mov r8, r13
    and r8, rcx                ; r0
    mov rax, r13
    shrd rax, r14, 51          ; carry = t0 >> 51
    mov r13, [rsp + MT + 16]
    mov r14, [rsp + MT + 24]
    add r13, rax
    adc r14, 0
    mov r9, r13
    and r9, rcx                ; r1
    mov rax, r13
    shrd rax, r14, 51
    mov r13, [rsp + MT + 32]
    mov r14, [rsp + MT + 40]
    add r13, rax
    adc r14, 0
    mov r10, r13
    and r10, rcx               ; r2
    mov rax, r13
    shrd rax, r14, 51
    mov r13, [rsp + MT + 48]
    mov r14, [rsp + MT + 56]
    add r13, rax
    adc r14, 0
    mov r11, r13
    and r11, rcx               ; r3
    mov rax, r13
    shrd rax, r14, 51
    mov r13, [rsp + MT + 64]
    mov r14, [rsp + MT + 72]
    add r13, rax
    adc r14, 0
    mov r15, r13
    and r15, rcx               ; r4
    mov rax, r13
    shrd rax, r14, 51          ; final carry
    imul rax, rax, 19
    add r8, rax
    mov rax, r8
    shr rax, 51
    and r8, rcx
    add r9, rax
    mov rax, r9
    shr rax, 51
    and r9, rcx
    add r10, rax
    mov [r12], r8
    mov [r12 + 8], r9
    mov [r12 + 16], r10
    mov [r12 + 24], r11
    mov [r12 + 32], r15
    add rsp, 192
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_fe25519_sq(rdi=h, rsi=f) — h = f^2 mod p.
linnea_fe25519_sq:
    mov rdx, rsi
    jmp linnea_fe25519_mul

; linnea_fe25519_mul121665(rdi=h, rsi=f) — h = 121665 * f mod p.
linnea_fe25519_mul121665:
    mov r8, 121665
    mov r11, LINNEA_FE25519_MASK51
    mov rax, [rsi]
    mul r8
    mov r9, rax
    and r9, r11                ; out0 (held back for the final fold)
    shrd rax, rdx, 51
    mov rcx, rax               ; carry
    mov rax, [rsi + 8]
    mul r8
    add rax, rcx
    adc rdx, 0
    mov r10, rax
    and r10, r11
    mov [rdi + 8], r10
    shrd rax, rdx, 51
    mov rcx, rax
    mov rax, [rsi + 16]
    mul r8
    add rax, rcx
    adc rdx, 0
    mov r10, rax
    and r10, r11
    mov [rdi + 16], r10
    shrd rax, rdx, 51
    mov rcx, rax
    mov rax, [rsi + 24]
    mul r8
    add rax, rcx
    adc rdx, 0
    mov r10, rax
    and r10, r11
    mov [rdi + 24], r10
    shrd rax, rdx, 51
    mov rcx, rax
    mov rax, [rsi + 32]
    mul r8
    add rax, rcx
    adc rdx, 0
    mov r10, rax
    and r10, r11
    mov [rdi + 32], r10
    shrd rax, rdx, 51
    imul rax, rax, 19          ; fold the top carry into out0
    add r9, rax
    mov rax, r9
    shr rax, 51
    and r9, r11
    add [rdi + 8], rax
    mov [rdi], r9
    ret

; linnea_fe25519_frombytes(rdi=fe, rsi=bytes32) — decode, dropping bit 255.
linnea_fe25519_frombytes:
    mov rcx, LINNEA_FE25519_MASK51
    mov rax, [rsi]
    and rax, rcx
    mov [rdi], rax
    mov rax, [rsi + 6]
    shr rax, 3
    and rax, rcx
    mov [rdi + 8], rax
    mov rax, [rsi + 12]
    shr rax, 6
    and rax, rcx
    mov [rdi + 16], rax
    mov rax, [rsi + 19]
    shr rax, 1
    and rax, rcx
    mov [rdi + 24], rax
    mov rax, [rsi + 24]
    shr rax, 12
    and rax, rcx
    mov [rdi + 32], rax
    ret

; linnea_fe25519_tobytes(rdi=bytes32, rsi=fe) — fully reduce and serialize.
linnea_fe25519_tobytes:
    push rbx
    push r12
    mov r8, [rsi]
    mov r9, [rsi + 8]
    mov r10, [rsi + 16]
    mov r11, [rsi + 24]
    mov rbx, [rsi + 32]
    mov rcx, LINNEA_FE25519_MASK51
    ; two full fold passes: value < 2^255-1, properly carried
%rep 2
    mov rax, r8
    shr rax, 51
    and r8, rcx
    add r9, rax
    mov rax, r9
    shr rax, 51
    and r9, rcx
    add r10, rax
    mov rax, r10
    shr rax, 51
    and r10, rcx
    add r11, rax
    mov rax, r11
    shr rax, 51
    and r11, rcx
    add rbx, rax
    mov rax, rbx
    shr rax, 51
    and rbx, rcx
    imul rax, rax, 19
    add r8, rax
%endrep
    ; add 19, fold: shifts a value in [2^255-19, 2^255-1] to carry out
    add r8, 19
    mov rax, r8
    shr rax, 51
    and r8, rcx
    add r9, rax
    mov rax, r9
    shr rax, 51
    and r9, rcx
    add r10, rax
    mov rax, r10
    shr rax, 51
    and r10, rcx
    add r11, rax
    mov rax, r11
    shr rax, 51
    and r11, rcx
    add rbx, rax
    mov rax, rbx
    shr rax, 51
    and rbx, rcx
    imul rax, rax, 19
    add r8, rax
    ; add 2^51 - {19,1,1,1,1}; the final carry chain subtracts p if needed
    mov r12, (1 << 51) - 19
    add r8, r12
    mov r12, (1 << 51) - 1
    add r9, r12
    add r10, r12
    add r11, r12
    add rbx, r12
    mov rax, r8
    shr rax, 51
    and r8, rcx
    add r9, rax
    mov rax, r9
    shr rax, 51
    and r9, rcx
    add r10, rax
    mov rax, r10
    shr rax, 51
    and r10, rcx
    add r11, rax
    mov rax, r11
    shr rax, 51
    and r11, rcx
    add rbx, rax
    and rbx, rcx               ; discard the 2^255 offset bit
    ; pack five 51-bit limbs into 32 little-endian bytes
    mov rax, r9
    shl rax, 51
    or rax, r8
    mov [rdi], rax
    mov rax, r9
    shr rax, 13
    mov rdx, r10
    shl rdx, 38
    or rax, rdx
    mov [rdi + 8], rax
    mov rax, r10
    shr rax, 26
    mov rdx, r11
    shl rdx, 25
    or rax, rdx
    mov [rdi + 16], rax
    mov rax, r11
    shr rax, 39
    mov rdx, rbx
    shl rdx, 12
    or rax, rdx
    mov [rdi + 24], rax
    pop r12
    pop rbx
    ret

; linnea_fe25519_copy(rdi=h, rsi=f)
linnea_fe25519_copy:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    mov [rdi + 24], rax
    mov rax, [rsi + 32]
    mov [rdi + 32], rax
    ret

; linnea_fe25519_1(rdi=fe) — set to 1.
linnea_fe25519_1:
    mov qword [rdi], 1
    xor eax, eax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    mov [rdi + 32], rax
    ret

; linnea_fe25519_0(rdi=fe) — set to 0.
linnea_fe25519_0:
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    mov [rdi + 32], rax
    ret

; linnea_fe25519_cswap(rdi=a, rsi=b, rdx=swap) — swap a and b iff swap==1.
; Branch-free: mask = 0 - swap, then XOR the masked difference into both.
linnea_fe25519_cswap:
    mov r8, rdx
    neg r8                     ; 0 or 0xFFFF...FFFF
%assign i 0
%rep 5
    mov rax, [rdi + i]
    mov rcx, [rsi + i]
    mov rdx, rax
    xor rdx, rcx
    and rdx, r8
    xor rax, rdx
    xor rcx, rdx
    mov [rdi + i], rax
    mov [rsi + i], rcx
%assign i i + 8
%endrep
    ret

; linnea_fe25519_cmov(rdi=r, rsi=a, rdx=move) — r = a iff move==1, in
; constant time (mask = 0 - move, XOR the masked difference into r).
linnea_fe25519_cmov:
    mov r8, rdx
    neg r8                     ; 0 or 0xFFFF...FFFF
%assign i 0
%rep 5
    mov rax, [rdi + i]
    mov rcx, [rsi + i]
    xor rcx, rax
    and rcx, r8
    xor rax, rcx
    mov [rdi + i], rax
%assign i i + 8
%endrep
    ret

; linnea_fe25519_invert(rdi=out, rsi=in) — out = in^(p-2) mod p.
; The tweetnacl chain: 254 squarings, multiplying by `in` at every step
; except squarings 2 and 4 (counting the exponent bit position down).
linnea_fe25519_invert:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 56                ; c (40 bytes) + alignment
    mov rbx, rdi               ; out
    mov r12, rsi               ; in
    mov rdi, rsp
    mov rsi, r12
    call linnea_fe25519_copy   ; c = in
    mov r13, 253
.loop:
    mov rdi, rsp
    mov rsi, rsp
    call linnea_fe25519_sq     ; c = c^2
    cmp r13, 2
    je .skip
    cmp r13, 4
    je .skip
    mov rdi, rsp
    mov rsi, rsp
    mov rdx, r12
    call linnea_fe25519_mul    ; c = c * in
.skip:
    dec r13
    jns .loop
    mov rdi, rbx
    mov rsi, rsp
    call linnea_fe25519_copy   ; out = c
    add rsp, 56
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
