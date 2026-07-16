; linnea_x25519.asm — X25519 (RFC 7748) on the fe25519 field.
;
; The Montgomery ladder: for each scalar bit from 254 down to 0, a
; constant-time conditional swap followed by one differential
; add-and-double. The bit drives only cswap's mask, never a branch, so
; the whole routine is constant-time. Field limbs are kept reduced (add
; and sub carry their outputs), so every multiply input stays small.
;
; ABI: System V; callee-saved preserved.

default rel

%include "linnea_fe25519.inc"

global linnea_x25519

extern linnea_fe25519_frombytes
extern linnea_fe25519_tobytes
extern linnea_fe25519_mul
extern linnea_fe25519_sq
extern linnea_fe25519_add
extern linnea_fe25519_sub
extern linnea_fe25519_mul121665
extern linnea_fe25519_copy
extern linnea_fe25519_cswap
extern linnea_fe25519_invert
extern linnea_fe25519_1
extern linnea_fe25519_0

section .text

; stack frame: the working field elements, the clamped scalar, and swap
%define X1   0
%define X2   40
%define Z2   80
%define X3   120
%define Z3   160
%define A_   200
%define AA   240
%define B_   280
%define BB   320
%define E_   360
%define C_   400
%define D_   440
%define DA   480
%define CB   520
%define T0   560
%define T1   600
%define T2   640
%define T3   680
%define T4   720
%define ZINV 760
%define SCALAR 800     ; 32 bytes: the clamped scalar
%define SWAP 832       ; running cswap condition
%define FRAME 864

; linnea_x25519(rdi=out32, rsi=scalar32, rdx=point32)
linnea_x25519:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, FRAME
    mov rbx, rdi               ; out
    mov r14, rdx               ; point
    ; copy and clamp the scalar
    mov rax, [rsi]
    mov [rsp + SCALAR], rax
    mov rax, [rsi + 8]
    mov [rsp + SCALAR + 8], rax
    mov rax, [rsi + 16]
    mov [rsp + SCALAR + 16], rax
    mov rax, [rsi + 24]
    mov [rsp + SCALAR + 24], rax
    and byte [rsp + SCALAR], 248
    and byte [rsp + SCALAR + 31], 127
    or byte [rsp + SCALAR + 31], 64
    ; x1 = decode(point); x2 = 1; z2 = 0; x3 = x1; z3 = 1
    lea rdi, [rsp + X1]
    mov rsi, r14
    call linnea_fe25519_frombytes
    lea rdi, [rsp + X2]
    call linnea_fe25519_1
    lea rdi, [rsp + Z2]
    call linnea_fe25519_0
    lea rdi, [rsp + X3]
    lea rsi, [rsp + X1]
    call linnea_fe25519_copy
    lea rdi, [rsp + Z3]
    call linnea_fe25519_1
    mov qword [rsp + SWAP], 0
    mov r12, 254               ; ladder bit position
.ladder:
    ; b = bit r12 of the scalar
    mov rax, r12
    shr rax, 3
    movzx edx, byte [rsp + SCALAR + rax]
    mov rcx, r12
    and rcx, 7
    shr edx, cl
    and edx, 1
    mov r13, rdx               ; b
    mov rax, [rsp + SWAP]
    xor rax, r13               ; cswap condition = swap ^ b
    mov r15, rax
    lea rdi, [rsp + X2]
    lea rsi, [rsp + X3]
    mov rdx, r15
    call linnea_fe25519_cswap
    lea rdi, [rsp + Z2]
    lea rsi, [rsp + Z3]
    mov rdx, r15
    call linnea_fe25519_cswap
    mov [rsp + SWAP], r13       ; swap = b
    ; A = x2+z2 ; AA = A^2
    lea rdi, [rsp + A_]
    lea rsi, [rsp + X2]
    lea rdx, [rsp + Z2]
    call linnea_fe25519_add
    lea rdi, [rsp + AA]
    lea rsi, [rsp + A_]
    call linnea_fe25519_sq
    ; B = x2-z2 ; BB = B^2
    lea rdi, [rsp + B_]
    lea rsi, [rsp + X2]
    lea rdx, [rsp + Z2]
    call linnea_fe25519_sub
    lea rdi, [rsp + BB]
    lea rsi, [rsp + B_]
    call linnea_fe25519_sq
    ; E = AA-BB
    lea rdi, [rsp + E_]
    lea rsi, [rsp + AA]
    lea rdx, [rsp + BB]
    call linnea_fe25519_sub
    ; C = x3+z3 ; D = x3-z3
    lea rdi, [rsp + C_]
    lea rsi, [rsp + X3]
    lea rdx, [rsp + Z3]
    call linnea_fe25519_add
    lea rdi, [rsp + D_]
    lea rsi, [rsp + X3]
    lea rdx, [rsp + Z3]
    call linnea_fe25519_sub
    ; DA = D*A ; CB = C*B
    lea rdi, [rsp + DA]
    lea rsi, [rsp + D_]
    lea rdx, [rsp + A_]
    call linnea_fe25519_mul
    lea rdi, [rsp + CB]
    lea rsi, [rsp + C_]
    lea rdx, [rsp + B_]
    call linnea_fe25519_mul
    ; x3 = (DA+CB)^2
    lea rdi, [rsp + T0]
    lea rsi, [rsp + DA]
    lea rdx, [rsp + CB]
    call linnea_fe25519_add
    lea rdi, [rsp + X3]
    lea rsi, [rsp + T0]
    call linnea_fe25519_sq
    ; z3 = x1 * (DA-CB)^2
    lea rdi, [rsp + T1]
    lea rsi, [rsp + DA]
    lea rdx, [rsp + CB]
    call linnea_fe25519_sub
    lea rdi, [rsp + T2]
    lea rsi, [rsp + T1]
    call linnea_fe25519_sq
    lea rdi, [rsp + Z3]
    lea rsi, [rsp + X1]
    lea rdx, [rsp + T2]
    call linnea_fe25519_mul
    ; x2 = AA*BB
    lea rdi, [rsp + X2]
    lea rsi, [rsp + AA]
    lea rdx, [rsp + BB]
    call linnea_fe25519_mul
    ; z2 = E * (AA + 121665*E)
    lea rdi, [rsp + T3]
    lea rsi, [rsp + E_]
    call linnea_fe25519_mul121665
    lea rdi, [rsp + T4]
    lea rsi, [rsp + AA]
    lea rdx, [rsp + T3]
    call linnea_fe25519_add
    lea rdi, [rsp + Z2]
    lea rsi, [rsp + E_]
    lea rdx, [rsp + T4]
    call linnea_fe25519_mul
    dec r12
    jns .ladder
    ; a final conditional swap settles x2/z2
    mov r15, [rsp + SWAP]
    lea rdi, [rsp + X2]
    lea rsi, [rsp + X3]
    mov rdx, r15
    call linnea_fe25519_cswap
    lea rdi, [rsp + Z2]
    lea rsi, [rsp + Z3]
    mov rdx, r15
    call linnea_fe25519_cswap
    ; out = x2 / z2 = x2 * z2^(p-2)
    lea rdi, [rsp + ZINV]
    lea rsi, [rsp + Z2]
    call linnea_fe25519_invert
    lea rdi, [rsp + X2]
    lea rsi, [rsp + X2]
    lea rdx, [rsp + ZINV]
    call linnea_fe25519_mul
    mov rdi, rbx
    lea rsi, [rsp + X2]
    call linnea_fe25519_tobytes
    add rsp, FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
