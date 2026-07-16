; linnea_ed25519.asm — Ed25519 signing (RFC 8032), on the fe25519 field.
;
; Points use extended twisted-Edwards coordinates (X:Y:Z:T), T = XY/Z, on
; -x^2 + y^2 = 1 + d x^2 y^2. A single complete/unified addition formula
; (Hisil-Wong-Carter-Dawson 2008, "add-2008-hwcd-3") serves both add and
; double, so there are no special cases and no data-dependent branches.
; Scalar multiplication is constant-time double-and-add: every bit doubles
; and adds, and a masked cmov keeps the sum only when the bit is set.
;
; Scalar reduction mod L and the r + k*a combination reuse tweetnacl's
; compact modL. The group order L = 2^252 + 27742317777372353535851937790883648493.
;
; Signing only — the server never verifies signatures (no client auth).
; Runs on the handshake path; correctness over speed. ABI: System V.

default rel

%include "linnea_ed25519.inc"

global linnea_ed25519_sign

extern linnea_sha512
extern linnea_sha512_init
extern linnea_sha512_update
extern linnea_sha512_final
extern linnea_fe25519_frombytes
extern linnea_fe25519_tobytes
extern linnea_fe25519_mul
extern linnea_fe25519_add
extern linnea_fe25519_sub
extern linnea_fe25519_copy
extern linnea_fe25519_cmov
extern linnea_fe25519_1
extern linnea_fe25519_0
extern linnea_fe25519_invert

section .rodata

align 8
; base point affine coordinates, little-endian; Z=1, T=Bx*By built at run time
ed_bx: db 0x1a,0xd5,0x25,0x8f,0x60,0x2d,0x56,0xc9,0xb2,0xa7,0x25,0x95,0x60,0xc7,0x2c,0x69
       db 0x5c,0xdc,0xd6,0xfd,0x31,0xe2,0xa4,0xc0,0xfe,0x53,0x6e,0xcd,0xd3,0x36,0x69,0x21
ed_by: db 0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
       db 0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
; 2*d mod p, little-endian
ed_d2: db 0x59,0xf1,0xb2,0x26,0x94,0x9b,0xd6,0xeb,0x56,0xb1,0x83,0x82,0x9a,0x14,0xe0,0x00
       db 0x30,0xd1,0xf3,0xee,0xf2,0x80,0x8e,0x19,0xe7,0xfc,0xdf,0x56,0xdc,0xd9,0x06,0x24
; L = group order, as 32 little-endian bytes (used by modL as L[j] values)
ed_L:  db 0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14
       db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10

section .bss

ed_d2_fe: resb 40              ; 2d as a field element (built per sign call)

section .text

; point layout: X at +0, Y at +40, Z at +80, T at +120 (four fe = 160 bytes)
%define PX 0
%define PY 40
%define PZ 80
%define PT 120
%define POINT_SIZE 160

; ge_add(rdi=r, rsi=p, rdx=q) — r = p + q (unified; r may alias p or q).
; Results build in stack locals, so aliasing is safe.
%define GA_A  0
%define GA_B  40
%define GA_C  80
%define GA_D  120
%define GA_E  160
%define GA_F  200
%define GA_G  240
%define GA_H  280
%define GA_T1 320
%define GA_T2 360
%define GA_LX 400
%define GA_LY 440
%define GA_LZ 480
%define GA_LT 520
ge_add:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 560
    mov r13, rdi               ; r
    mov rbx, rsi               ; p
    mov r12, rdx               ; q
    ; A = (pY-pX)*(qY-qX)
    lea rdi, [rsp + GA_T1]
    lea rsi, [rbx + PY]
    lea rdx, [rbx + PX]
    call linnea_fe25519_sub
    lea rdi, [rsp + GA_T2]
    lea rsi, [r12 + PY]
    lea rdx, [r12 + PX]
    call linnea_fe25519_sub
    lea rdi, [rsp + GA_A]
    lea rsi, [rsp + GA_T1]
    lea rdx, [rsp + GA_T2]
    call linnea_fe25519_mul
    ; B = (pY+pX)*(qY+qX)
    lea rdi, [rsp + GA_T1]
    lea rsi, [rbx + PY]
    lea rdx, [rbx + PX]
    call linnea_fe25519_add
    lea rdi, [rsp + GA_T2]
    lea rsi, [r12 + PY]
    lea rdx, [r12 + PX]
    call linnea_fe25519_add
    lea rdi, [rsp + GA_B]
    lea rsi, [rsp + GA_T1]
    lea rdx, [rsp + GA_T2]
    call linnea_fe25519_mul
    ; C = pT * 2d * qT
    lea rdi, [rsp + GA_T1]
    lea rsi, [rbx + PT]
    lea rdx, [ed_d2_fe]
    call linnea_fe25519_mul
    lea rdi, [rsp + GA_C]
    lea rsi, [rsp + GA_T1]
    lea rdx, [r12 + PT]
    call linnea_fe25519_mul
    ; D = 2 * pZ * qZ
    lea rdi, [rsp + GA_T1]
    lea rsi, [rbx + PZ]
    lea rdx, [r12 + PZ]
    call linnea_fe25519_mul
    lea rdi, [rsp + GA_D]
    lea rsi, [rsp + GA_T1]
    lea rdx, [rsp + GA_T1]
    call linnea_fe25519_add
    ; E=B-A  F=D-C  G=D+C  H=B+A
    lea rdi, [rsp + GA_E]
    lea rsi, [rsp + GA_B]
    lea rdx, [rsp + GA_A]
    call linnea_fe25519_sub
    lea rdi, [rsp + GA_F]
    lea rsi, [rsp + GA_D]
    lea rdx, [rsp + GA_C]
    call linnea_fe25519_sub
    lea rdi, [rsp + GA_G]
    lea rsi, [rsp + GA_D]
    lea rdx, [rsp + GA_C]
    call linnea_fe25519_add
    lea rdi, [rsp + GA_H]
    lea rsi, [rsp + GA_B]
    lea rdx, [rsp + GA_A]
    call linnea_fe25519_add
    ; X=E*F  Y=G*H  T=E*H  Z=F*G
    lea rdi, [rsp + GA_LX]
    lea rsi, [rsp + GA_E]
    lea rdx, [rsp + GA_F]
    call linnea_fe25519_mul
    lea rdi, [rsp + GA_LY]
    lea rsi, [rsp + GA_G]
    lea rdx, [rsp + GA_H]
    call linnea_fe25519_mul
    lea rdi, [rsp + GA_LT]
    lea rsi, [rsp + GA_E]
    lea rdx, [rsp + GA_H]
    call linnea_fe25519_mul
    lea rdi, [rsp + GA_LZ]
    lea rsi, [rsp + GA_F]
    lea rdx, [rsp + GA_G]
    call linnea_fe25519_mul
    ; store into r
    lea rdi, [r13 + PX]
    lea rsi, [rsp + GA_LX]
    call linnea_fe25519_copy
    lea rdi, [r13 + PY]
    lea rsi, [rsp + GA_LY]
    call linnea_fe25519_copy
    lea rdi, [r13 + PZ]
    lea rsi, [rsp + GA_LZ]
    call linnea_fe25519_copy
    lea rdi, [r13 + PT]
    lea rsi, [rsp + GA_LT]
    call linnea_fe25519_copy
    add rsp, 560
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ge_cmov(rdi=r, rsi=a, rdx=move) — r = a iff move==1, coordinate-wise.
ge_cmov:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    call linnea_fe25519_cmov
    lea rdi, [rbx + PY]
    lea rsi, [r12 + PY]
    mov rdx, r13
    call linnea_fe25519_cmov
    lea rdi, [rbx + PZ]
    lea rsi, [r12 + PZ]
    mov rdx, r13
    call linnea_fe25519_cmov
    lea rdi, [rbx + PT]
    lea rsi, [r12 + PT]
    mov rdx, r13
    call linnea_fe25519_cmov
    pop r13
    pop r12
    pop rbx
    ret

; ge_scalarmult_base(rdi=out_point, rsi=scalar32) — out = scalar * B.
; Constant-time double-and-add over 256 bits.
%define SM_B   0                ; the base point B
%define SM_TMP 160              ; the trial sum acc+B
ge_scalarmult_base:
    push rbx
    push r12
    push r13
    sub rsp, 320
    mov rbx, rdi               ; out (the accumulator)
    mov r12, rsi               ; scalar
    ; B = (Bx, By, 1, Bx*By)
    lea rdi, [rsp + SM_B + PX]
    lea rsi, [ed_bx]
    call linnea_fe25519_frombytes
    lea rdi, [rsp + SM_B + PY]
    lea rsi, [ed_by]
    call linnea_fe25519_frombytes
    lea rdi, [rsp + SM_B + PZ]
    call linnea_fe25519_1
    lea rdi, [rsp + SM_B + PT]
    lea rsi, [rsp + SM_B + PX]
    lea rdx, [rsp + SM_B + PY]
    call linnea_fe25519_mul
    ; acc = identity (0, 1, 1, 0)
    lea rdi, [rbx + PX]
    call linnea_fe25519_0
    lea rdi, [rbx + PY]
    call linnea_fe25519_1
    lea rdi, [rbx + PZ]
    call linnea_fe25519_1
    lea rdi, [rbx + PT]
    call linnea_fe25519_0
    mov r13, 255
.loop:
    ; acc = 2*acc
    mov rdi, rbx
    mov rsi, rbx
    mov rdx, rbx
    call ge_add
    ; tmp = acc + B
    lea rdi, [rsp + SM_TMP]
    mov rsi, rbx
    lea rdx, [rsp + SM_B]
    call ge_add
    ; select tmp into acc when scalar bit r13 is set
    mov rax, r13
    shr rax, 3
    movzx edx, byte [r12 + rax]
    mov rcx, r13
    and rcx, 7
    shr edx, cl
    and edx, 1
    mov rdi, rbx
    lea rsi, [rsp + SM_TMP]
    call ge_cmov
    dec r13
    jns .loop
    add rsp, 320
    pop r13
    pop r12
    pop rbx
    ret

; ge_encode(rdi=out32, rsi=point) — compress to 32 bytes: y with x's low
; bit in the top bit.
%define EN_ZI 0
%define EN_X  40
%define EN_Y  80
%define EN_XB 120              ; x serialized, to read its parity
ge_encode:
    push rbx
    push r12
    sub rsp, 160
    mov rbx, rdi               ; out
    mov r12, rsi               ; point
    lea rdi, [rsp + EN_ZI]
    lea rsi, [r12 + PZ]
    call linnea_fe25519_invert
    lea rdi, [rsp + EN_X]
    lea rsi, [r12 + PX]
    lea rdx, [rsp + EN_ZI]
    call linnea_fe25519_mul
    lea rdi, [rsp + EN_Y]
    lea rsi, [r12 + PY]
    lea rdx, [rsp + EN_ZI]
    call linnea_fe25519_mul
    mov rdi, rbx
    lea rsi, [rsp + EN_Y]
    call linnea_fe25519_tobytes
    lea rdi, [rsp + EN_XB]
    lea rsi, [rsp + EN_X]
    call linnea_fe25519_tobytes
    mov al, [rsp + EN_XB]
    and al, 1
    shl al, 7
    or [rbx + 31], al
    add rsp, 160
    pop r12
    pop rbx
    ret

; modL(rdi=out32, rsi=x) — reduce the signed i64[64] at x modulo L, writing
; 32 little-endian bytes to out. tweetnacl's reduction; x is clobbered.
modL:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    ; for i = 63 downto 32
    mov r12, 63
.outer:
    cmp r12, 32
    jl .second
    xor r13, r13               ; carry
    mov r14, r12
    sub r14, 32                ; j = i - 32
.inner:
    mov rax, r12
    sub rax, 12
    cmp r14, rax
    jge .inner_done            ; stop when j >= i-12
    mov rax, [rsi + r12*8]     ; x[i]
    mov rbx, r14
    sub rbx, r12
    add rbx, 32                ; L index = j - (i-32)
    movzx ecx, byte [ed_L + rbx]
    imul rax, rcx
    imul rax, rax, 16          ; 16 * x[i] * L[idx]
    mov rdx, [rsi + r14*8]
    add rdx, r13
    sub rdx, rax               ; x[j] += carry - 16*x[i]*L
    mov [rsi + r14*8], rdx
    add rdx, 128
    sar rdx, 8
    mov r13, rdx               ; carry = (x[j]+128) >> 8
    mov rdx, [rsi + r14*8]
    mov rax, r13
    shl rax, 8
    sub rdx, rax               ; x[j] -= carry << 8
    mov [rsi + r14*8], rdx
    inc r14
    jmp .inner
.inner_done:
    mov rdx, [rsi + r14*8]
    add rdx, r13
    mov [rsi + r14*8], rdx     ; x[i-12] += carry
    mov qword [rsi + r12*8], 0 ; x[i] = 0
    dec r12
    jmp .outer
.second:
    xor r13, r13               ; carry
    mov rax, [rsi + 31*8]
    sar rax, 4
    mov r15, rax               ; q = x[31] >> 4
    xor r14, r14
.s2:
    cmp r14, 32
    jge .s3
    movzx ecx, byte [ed_L + r14]
    mov rax, r15
    imul rax, rcx
    mov rdx, [rsi + r14*8]
    add rdx, r13
    sub rdx, rax               ; x[j] += carry - q*L[j]
    mov rax, rdx
    sar rax, 8
    mov r13, rax               ; carry = x[j] >> 8
    and rdx, 255
    mov [rsi + r14*8], rdx
    inc r14
    jmp .s2
.s3:
    xor r14, r14
.s3l:
    cmp r14, 32
    jge .s4
    movzx ecx, byte [ed_L + r14]
    mov rax, r13
    imul rax, rcx
    mov rdx, [rsi + r14*8]
    sub rdx, rax               ; x[j] -= carry * L[j]
    mov [rsi + r14*8], rdx
    inc r14
    jmp .s3l
.s4:
    xor r14, r14
.s4l:
    cmp r14, 32
    jge .done
    mov rax, [rsi + r14*8]
    sar rax, 8
    mov rdx, [rsi + r14*8 + 8]
    add rdx, rax
    mov [rsi + r14*8 + 8], rdx ; x[i+1] += x[i] >> 8
    mov rax, [rsi + r14*8]
    and rax, 255
    mov [rdi + r14], al
    inc r14
    jmp .s4l
.done:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; sc_reduce(rdi=out32, rsi=in64) — out = in mod L (in is 64 bytes LE).
sc_reduce:
    push rbx
    push r12
    push r13
    sub rsp, 520               ; x[64] as i64 (+8 pad for alignment)
    mov rbx, rdi
    mov r12, rsi
    xor r13, r13
.load:
    cmp r13, 64
    jge .reduce
    movzx eax, byte [r12 + r13]
    mov [rsp + r13*8], rax
    inc r13
    jmp .load
.reduce:
    mov rdi, rbx
    mov rsi, rsp
    call modL
    add rsp, 520
    pop r13
    pop r12
    pop rbx
    ret

; sc_muladd(rdi=out32, rsi=a32, rdx=b32, rcx=c32) — out = (a*b + c) mod L.
sc_muladd:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 520               ; x[64] i64 (+pad)
    mov rbx, rdi               ; out
    mov r12, rsi               ; a
    mov r13, rdx               ; b
    mov r14, rcx               ; c
    ; x[i] = c[i] for i < 32, else 0
    xor r15, r15
.zc:
    cmp r15, 64
    jge .mul
    xor rax, rax
    cmp r15, 32
    jge .zc_store
    movzx eax, byte [r14 + r15]
.zc_store:
    mov [rsp + r15*8], rax
    inc r15
    jmp .zc
.mul:
    ; x[i+j] += a[i] * b[j]
    xor r15, r15               ; i
.mi:
    cmp r15, 32
    jge .reduce
    movzx r8d, byte [r12 + r15]
    xor rbp, rbp               ; j
.mj:
    cmp rbp, 32
    jge .minext
    movzx eax, byte [r13 + rbp]
    imul rax, r8
    lea rcx, [r15 + rbp]
    add [rsp + rcx*8], rax
    inc rbp
    jmp .mj
.minext:
    inc r15
    jmp .mi
.reduce:
    mov rdi, rbx
    mov rsi, rsp
    call modL
    add rsp, 520
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_ed25519_sign(rdi=sig64, rsi=msg, rdx=msglen, rcx=seed32)
%define SG_D    0              ; SHA512(seed): a (clamped, 0..31) || prefix (32..63)
%define SG_A    64             ; public key A (encoded), 32
%define SG_H    96             ; a SHA-512 output, 64
%define SG_RS   160            ; r reduced mod L, 32
%define SG_KS   192            ; k reduced mod L, 32
%define SG_PA   224            ; point scratch A
%define SG_PR   384            ; point scratch R
%define SG_CTX  544            ; sha512 ctx (200)
linnea_ed25519_sign:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 752
    mov rbx, rdi               ; sig
    mov r12, rsi               ; msg
    mov r13, rdx               ; msglen
    mov r14, rcx               ; seed
    ; 2d as a field element, for ge_add
    lea rdi, [ed_d2_fe]
    lea rsi, [ed_d2]
    call linnea_fe25519_frombytes
    ; d = SHA512(seed); clamp d[0:32] into the scalar a
    mov rdi, r14
    mov esi, 32
    lea rdx, [rsp + SG_D]
    call linnea_sha512
    and byte [rsp + SG_D], 248
    and byte [rsp + SG_D + 31], 127
    or byte [rsp + SG_D + 31], 64
    ; A = encode(a * B)
    lea rdi, [rsp + SG_PA]
    lea rsi, [rsp + SG_D]
    call ge_scalarmult_base
    lea rdi, [rsp + SG_A]
    lea rsi, [rsp + SG_PA]
    call ge_encode
    ; r = SHA512(prefix || M) mod L
    lea rdi, [rsp + SG_CTX]
    call linnea_sha512_init
    lea rdi, [rsp + SG_CTX]
    lea rsi, [rsp + SG_D + 32]
    mov edx, 32
    call linnea_sha512_update
    lea rdi, [rsp + SG_CTX]
    mov rsi, r12
    mov rdx, r13
    call linnea_sha512_update
    lea rdi, [rsp + SG_CTX]
    lea rsi, [rsp + SG_H]
    call linnea_sha512_final
    lea rdi, [rsp + SG_RS]
    lea rsi, [rsp + SG_H]
    call sc_reduce
    ; R = encode(r * B) -> sig[0:32]
    lea rdi, [rsp + SG_PR]
    lea rsi, [rsp + SG_RS]
    call ge_scalarmult_base
    mov rdi, rbx
    lea rsi, [rsp + SG_PR]
    call ge_encode
    ; k = SHA512(R || A || M) mod L
    lea rdi, [rsp + SG_CTX]
    call linnea_sha512_init
    lea rdi, [rsp + SG_CTX]
    mov rsi, rbx               ; R = sig[0:32]
    mov edx, 32
    call linnea_sha512_update
    lea rdi, [rsp + SG_CTX]
    lea rsi, [rsp + SG_A]
    mov edx, 32
    call linnea_sha512_update
    lea rdi, [rsp + SG_CTX]
    mov rsi, r12
    mov rdx, r13
    call linnea_sha512_update
    lea rdi, [rsp + SG_CTX]
    lea rsi, [rsp + SG_H]
    call linnea_sha512_final
    lea rdi, [rsp + SG_KS]
    lea rsi, [rsp + SG_H]
    call sc_reduce
    ; S = (k * a + r) mod L -> sig[32:64]
    lea rdi, [rbx + 32]
    lea rsi, [rsp + SG_KS]     ; k
    lea rdx, [rsp + SG_D]      ; a (clamped scalar)
    lea rcx, [rsp + SG_RS]     ; r
    call sc_muladd
    add rsp, 752
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
