; linnea_sha512.asm — SHA-512 (FIPS 180-4). Same structure as SHA-256 with
; 64-bit words, 128-byte blocks and 80 rounds. Used only by Ed25519 on the
; handshake path, so scalar and clarity-first. No secret-dependent control
; flow. ABI: System V, callee-saved preserved.

default rel

%include "linnea_sha512.inc"

global linnea_sha512_init
global linnea_sha512_update
global linnea_sha512_final
global linnea_sha512

section .rodata

align 8
sha512_h0:
    dq 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b
    dq 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f
    dq 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

align 8
sha512_k:
    dq 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f
    dq 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019
    dq 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242
    dq 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
    dq 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235
    dq 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3
    dq 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275
    dq 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
    dq 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f
    dq 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725
    dq 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc
    dq 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
    dq 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6
    dq 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001
    dq 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218
    dq 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8
    dq 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99
    dq 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
    dq 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc
    dq 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec
    dq 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915
    dq 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207
    dq 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba
    dq 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b
    dq 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc
    dq 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
    dq 0x5fcb6fab3ad6faec, 0x6c44198c4a475817

section .text

; sha512_compress(rdi=ctx, rsi=block) — one 128-byte block. File-local.
; a..h live in r8..r15, the 80-word schedule W on the stack.
sha512_compress:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 648
    mov [rsp + 640], rdi
    ; W[0..15] big-endian
    xor ecx, ecx
.load:
    mov rax, [rsi + rcx*8]
    bswap rax
    mov [rsp + rcx*8], rax
    inc ecx
    cmp ecx, 16
    jb .load
    ; W[16..79] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]
.extend:
    mov rax, [rsp + rcx*8 - 16]     ; W[t-2]
    mov rdx, rax
    ror rdx, 19
    mov rbx, rax
    ror rbx, 61
    xor rdx, rbx
    mov rbx, rax
    shr rbx, 6
    xor rdx, rbx                    ; s1
    add rdx, [rsp + rcx*8 - 56]     ; + W[t-7]
    mov rax, [rsp + rcx*8 - 120]    ; W[t-15]
    mov rbx, rax
    ror rbx, 1
    mov rdi, rax
    ror rdi, 8
    xor rbx, rdi
    mov rdi, rax
    shr rdi, 7
    xor rbx, rdi                    ; s0
    add rdx, rbx
    add rdx, [rsp + rcx*8 - 128]    ; + W[t-16]
    mov [rsp + rcx*8], rdx
    inc ecx
    cmp ecx, 80
    jb .extend
    ; working variables
    mov rcx, [rsp + 640]
    mov r8,  [rcx + 0]
    mov r9,  [rcx + 8]
    mov r10, [rcx + 16]
    mov r11, [rcx + 24]
    mov r12, [rcx + 32]
    mov r13, [rcx + 40]
    mov r14, [rcx + 48]
    mov r15, [rcx + 56]
    lea rdi, [sha512_k]
    mov rsi, rsp
    xor ebp, ebp
.round:
    ; T1 = h + S1(e) + Ch(e,f,g) + K[t] + W[t]
    mov rax, r12
    ror rax, 14
    mov rbx, r12
    ror rbx, 18
    xor rax, rbx
    mov rbx, r12
    ror rbx, 41
    xor rax, rbx                    ; S1(e)
    mov rbx, r12
    and rbx, r13
    mov rdx, r12
    not rdx
    and rdx, r14
    xor rbx, rdx                    ; Ch(e,f,g)
    add rax, rbx
    add rax, r15
    add rax, [rdi + rbp*8]
    add rax, [rsi + rbp*8]          ; T1
    ; T2 = S0(a) + Maj(a,b,c)
    mov rbx, r8
    ror rbx, 28
    mov rdx, r8
    ror rdx, 34
    xor rbx, rdx
    mov rdx, r8
    ror rdx, 39
    xor rbx, rdx                    ; S0(a)
    mov rdx, r8
    and rdx, r9
    mov rcx, r8
    and rcx, r10
    xor rdx, rcx
    mov rcx, r9
    and rcx, r10
    xor rdx, rcx                    ; Maj(a,b,c)
    add rbx, rdx                    ; T2
    mov r15, r14
    mov r14, r13
    mov r13, r12
    lea r12, [r11 + rax]            ; e = d + T1
    mov r11, r10
    mov r10, r9
    mov r9, r8
    lea r8, [rax + rbx]            ; a = T1 + T2
    inc rbp
    cmp rbp, 80
    jb .round
    mov rcx, [rsp + 640]
    add [rcx + 0],  r8
    add [rcx + 8],  r9
    add [rcx + 16], r10
    add [rcx + 24], r11
    add [rcx + 32], r12
    add [rcx + 40], r13
    add [rcx + 48], r14
    add [rcx + 56], r15
    add rsp, 648
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; linnea_sha512_init(rdi=ctx)
linnea_sha512_init:
    lea rsi, [sha512_h0]
    mov rcx, 8
.copy:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec rcx
    jnz .copy
    mov qword [rdi], 0             ; rdi now points at ctx.len (past the 8 words)
    ret

; linnea_sha512_update(rdi=ctx, rsi=data, rdx=len)
linnea_sha512_update:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov rax, [rbx + linnea_sha512_ctx.len]
    and rax, 127
    add [rbx + linnea_sha512_ctx.len], r13
    test r13, r13
    jz .ret
    test rax, rax
    jz .blocks
    mov r14, 128
    sub r14, rax                   ; free space in the partial block
    cmp r13, r14
    jae .fill
    lea rdi, [rbx + linnea_sha512_ctx.buf]
    add rdi, rax
    mov rsi, r12
    mov rcx, r13
    rep movsb
    jmp .ret
.fill:
    lea rdi, [rbx + linnea_sha512_ctx.buf]
    add rdi, rax
    mov rsi, r12
    mov rcx, r14
    rep movsb
    add r12, r14
    sub r13, r14
    mov rdi, rbx
    lea rsi, [rbx + linnea_sha512_ctx.buf]
    call sha512_compress
.blocks:
    cmp r13, 128
    jb .tail
    mov rdi, rbx
    mov rsi, r12
    call sha512_compress
    add r12, 128
    sub r13, 128
    jmp .blocks
.tail:
    test r13, r13
    jz .ret
    lea rdi, [rbx + linnea_sha512_ctx.buf]
    mov rsi, r12
    mov rcx, r13
    rep movsb
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_sha512_final(rdi=ctx, rsi=out) — 64-byte digest.
linnea_sha512_final:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, [rbx + linnea_sha512_ctx.len]
    mov rax, r13
    and rax, 127
    lea rcx, [rbx + linnea_sha512_ctx.buf]
    mov byte [rcx + rax], 0x80
    inc rax
    cmp rax, 112
    jbe .pad
.z1:
    cmp rax, 128
    jae .c1
    mov byte [rcx + rax], 0
    inc rax
    jmp .z1
.c1:
    mov rdi, rbx
    lea rsi, [rbx + linnea_sha512_ctx.buf]
    call sha512_compress
    lea rcx, [rbx + linnea_sha512_ctx.buf]
    xor eax, eax
.pad:
    cmp rax, 112
    jae .len
    mov byte [rcx + rax], 0
    inc rax
    jmp .pad
.len:
    ; 128-bit big-endian bit length: high qword then low qword
    mov rax, r13
    shr rax, 61                    ; bits 64..127 of len*8
    bswap rax
    mov [rcx + 112], rax
    mov rax, r13
    shl rax, 3                     ; low 64 bits of len*8
    bswap rax
    mov [rcx + 120], rax
    mov rdi, rbx
    lea rsi, [rbx + linnea_sha512_ctx.buf]
    call sha512_compress
    xor ecx, ecx
.out:
    mov rax, [rbx + rcx*8]
    bswap rax
    mov [r12 + rcx*8], rax
    inc ecx
    cmp ecx, 8
    jb .out
    pop r13
    pop r12
    pop rbx
    ret

; linnea_sha512(rdi=data, rsi=len, rdx=out) — one-shot 64-byte digest.
linnea_sha512:
    push rbx
    push r12
    push r13
    sub rsp, 208                   ; a ctx on the stack
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov rdi, rsp
    call linnea_sha512_init
    mov rdi, rsp
    mov rsi, rbx
    mov rdx, r12
    call linnea_sha512_update
    mov rdi, rsp
    mov rsi, r13
    call linnea_sha512_final
    add rsp, 208
    pop r13
    pop r12
    pop rbx
    ret
