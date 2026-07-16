; linnea_sha256.asm — SHA-256, HMAC-SHA256, HKDF-SHA256.
;
; A straightforward scalar implementation (no SHA-NI): this runs only
; during the TLS handshake for the transcript hash and key schedule, not
; on the bulk data path (that is kTLS/AES-NI once the keys are installed),
; so clarity is worth more here than the last cycle. No secret-dependent
; branches or memory indices anyway — the round function is fixed.
;
; ABI: System V. Callee-saved rbx, rbp, r12-r15 are preserved.

default rel

%include "linnea_sha256.inc"

global linnea_sha256_init
global linnea_sha256_update
global linnea_sha256_final
global linnea_sha256
global linnea_hmac_sha256
global linnea_hkdf_extract
global linnea_hkdf_expand

section .rodata

align 4
sha256_h0:
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

align 4
sha256_k:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

section .text

; sha256_compress(rdi=ctx, rsi=block) — fold one 64-byte block into ctx.h.
; File-local. a..h live in r8d..r15d, the message schedule W on the stack.
sha256_compress:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 264
    mov [rsp + 256], rdi           ; save ctx across the round loop
    ; W[0..15] = the block words, big-endian
    xor ecx, ecx
.load:
    mov eax, [rsi + rcx*4]
    bswap eax
    mov [rsp + rcx*4], eax
    inc ecx
    cmp ecx, 16
    jb .load
    ; W[16..63] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]
.extend:
    mov eax, [rsp + rcx*4 - 8]     ; W[t-2]
    mov edx, eax
    ror eax, 17
    mov ebx, edx
    ror ebx, 19
    xor eax, ebx
    shr edx, 10
    xor eax, edx                   ; s1
    add eax, [rsp + rcx*4 - 28]    ; + W[t-7]
    mov edx, [rsp + rcx*4 - 60]    ; W[t-15]
    mov ebx, edx
    ror ebx, 7
    mov edi, edx
    ror edi, 18
    xor ebx, edi
    shr edx, 3
    xor ebx, edx                   ; s0
    add eax, ebx
    add eax, [rsp + rcx*4 - 64]    ; + W[t-16]
    mov [rsp + rcx*4], eax
    inc ecx
    cmp ecx, 64
    jb .extend
    ; working variables from the saved state
    mov rcx, [rsp + 256]
    mov r8d,  [rcx + 0]            ; a
    mov r9d,  [rcx + 4]            ; b
    mov r10d, [rcx + 8]            ; c
    mov r11d, [rcx + 12]           ; d
    mov r12d, [rcx + 16]           ; e
    mov r13d, [rcx + 20]           ; f
    mov r14d, [rcx + 24]           ; g
    mov r15d, [rcx + 28]           ; h
    lea rdi, [sha256_k]            ; K base
    mov rsi, rsp                   ; W base
    xor ebp, ebp                   ; round t
.round:
    ; T1 = h + S1(e) + Ch(e,f,g) + K[t] + W[t]
    mov eax, r12d
    ror eax, 6
    mov ebx, r12d
    ror ebx, 11
    xor eax, ebx
    mov ebx, r12d
    ror ebx, 25
    xor eax, ebx                   ; S1(e)
    mov ebx, r12d
    and ebx, r13d
    mov edx, r12d
    not edx
    and edx, r14d
    xor ebx, edx                   ; Ch(e,f,g)
    add eax, ebx
    add eax, r15d                  ; + h
    add eax, [rdi + rbp*4]         ; + K[t]
    add eax, [rsi + rbp*4]         ; + W[t]  -> T1 in eax
    ; T2 = S0(a) + Maj(a,b,c)
    mov ebx, r8d
    ror ebx, 2
    mov edx, r8d
    ror edx, 13
    xor ebx, edx
    mov edx, r8d
    ror edx, 22
    xor ebx, edx                   ; S0(a)
    mov edx, r8d
    and edx, r9d
    mov ecx, r8d
    and ecx, r10d
    xor edx, ecx
    mov ecx, r9d
    and ecx, r10d
    xor edx, ecx                   ; Maj(a,b,c)
    add ebx, edx                   ; T2 in ebx
    ; shift the working variables down
    mov r15d, r14d                 ; h = g
    mov r14d, r13d                 ; g = f
    mov r13d, r12d                 ; f = e
    lea r12d, [r11 + rax]          ; e = d + T1
    mov r11d, r10d                 ; d = c
    mov r10d, r9d                  ; c = b
    mov r9d, r8d                   ; b = a
    lea r8d, [rax + rbx]           ; a = T1 + T2
    inc rbp
    cmp rbp, 64
    jb .round
    ; fold back into the state
    mov rcx, [rsp + 256]
    add [rcx + 0],  r8d
    add [rcx + 4],  r9d
    add [rcx + 8],  r10d
    add [rcx + 12], r11d
    add [rcx + 16], r12d
    add [rcx + 20], r13d
    add [rcx + 24], r14d
    add [rcx + 28], r15d
    add rsp, 264
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; linnea_sha256_init(rdi=ctx)
linnea_sha256_init:
    lea rsi, [sha256_h0]
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    mov [rdi + 24], rax
    mov qword [rdi + linnea_sha256_ctx.len], 0
    ret

; linnea_sha256_update(rdi=ctx, rsi=data, rdx=len)
linnea_sha256_update:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi                   ; ctx
    mov r12, rsi                   ; data
    mov r13, rdx                   ; len
    mov rax, [rbx + linnea_sha256_ctx.len]
    and rax, 63                    ; bytes already in the partial block
    add [rbx + linnea_sha256_ctx.len], r13
    test r13, r13
    jz .ret
    test rax, rax
    jz .blocks
    ; top up the partial block first
    mov r14, 64
    sub r14, rax                   ; free space
    cmp r13, r14
    jae .fill
    ; not enough to complete a block: stash and return
    lea rdi, [rbx + linnea_sha256_ctx.buf]
    add rdi, rax
    mov rsi, r12
    mov rcx, r13
    rep movsb
    jmp .ret
.fill:
    lea rdi, [rbx + linnea_sha256_ctx.buf]
    add rdi, rax
    mov rsi, r12
    mov rcx, r14
    rep movsb
    add r12, r14
    sub r13, r14
    mov rdi, rbx
    lea rsi, [rbx + linnea_sha256_ctx.buf]
    call sha256_compress
.blocks:
    cmp r13, 64
    jb .tail
    mov rdi, rbx
    mov rsi, r12
    call sha256_compress
    add r12, 64
    sub r13, 64
    jmp .blocks
.tail:
    test r13, r13
    jz .ret
    lea rdi, [rbx + linnea_sha256_ctx.buf]
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

; linnea_sha256_final(rdi=ctx, rsi=out) — 32-byte digest to out.
linnea_sha256_final:
    push rbx
    push r12
    push r13
    mov rbx, rdi                   ; ctx
    mov r12, rsi                   ; out
    mov r13, [rbx + linnea_sha256_ctx.len]   ; total bytes, for the length field
    mov rax, r13
    and rax, 63                    ; current fill
    lea rcx, [rbx + linnea_sha256_ctx.buf]
    mov byte [rcx + rax], 0x80     ; the mandatory 1 bit
    inc rax
    cmp rax, 56
    jbe .pad
    ; not enough room for the length: zero-fill, compress, start a fresh block
.z1:
    cmp rax, 64
    jae .c1
    mov byte [rcx + rax], 0
    inc rax
    jmp .z1
.c1:
    mov rdi, rbx
    lea rsi, [rbx + linnea_sha256_ctx.buf]
    call sha256_compress
    lea rcx, [rbx + linnea_sha256_ctx.buf]
    xor eax, eax
.pad:
    ; zero the gap up to the length field
    cmp rax, 56
    jae .len
    mov byte [rcx + rax], 0
    inc rax
    jmp .pad
.len:
    mov rax, r13
    shl rax, 3                     ; message length in bits (< 2^61 bytes)
    bswap rax
    mov [rcx + 56], rax
    mov rdi, rbx
    lea rsi, [rbx + linnea_sha256_ctx.buf]
    call sha256_compress
    ; state out, big-endian
    xor ecx, ecx
.out:
    mov eax, [rbx + rcx*4]
    bswap eax
    mov [r12 + rcx*4], eax
    inc ecx
    cmp ecx, 8
    jb .out
    pop r13
    pop r12
    pop rbx
    ret

; linnea_sha256(rdi=data, rsi=len, rdx=out) — one-shot digest.
linnea_sha256:
    push rbx
    push r12
    push r13
    sub rsp, 112                   ; a ctx on the stack
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov rdi, rsp
    call linnea_sha256_init
    mov rdi, rsp
    mov rsi, rbx
    mov rdx, r12
    call linnea_sha256_update
    mov rdi, rsp
    mov rsi, r13
    call linnea_sha256_final
    add rsp, 112
    pop r13
    pop r12
    pop rbx
    ret

; linnea_hmac_sha256(rdi=key, rsi=keylen, rdx=msg, rcx=msglen, r8=out)
; out is 32 bytes. Keys longer than the block are hashed down first.
linnea_hmac_sha256:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 240
    ; frame: [0]=ctx(112) [112]=pad(64) [176]=inner(32) [208]=keyhash(32)
    mov rbx, rdi                   ; key
    mov r12, rsi                   ; keylen
    mov r13, rdx                   ; msg
    mov r14, rcx                   ; msglen
    mov r15, r8                    ; out
    cmp r12, 64
    jbe .key_ok
    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rsp + 208]
    call linnea_sha256
    lea rbx, [rsp + 208]
    mov r12, 32
.key_ok:
    ; ipad = (key padded to 64) XOR 0x36
    lea rdi, [rsp + 112]
    xor ecx, ecx
.ipad:
    xor eax, eax
    cmp rcx, r12
    jae .ipad_x
    movzx eax, byte [rbx + rcx]
.ipad_x:
    xor al, 0x36
    mov [rdi + rcx], al
    inc rcx
    cmp rcx, 64
    jb .ipad
    ; inner = H(ipad || msg)
    lea rdi, [rsp]
    call linnea_sha256_init
    lea rdi, [rsp]
    lea rsi, [rsp + 112]
    mov rdx, 64
    call linnea_sha256_update
    lea rdi, [rsp]
    mov rsi, r13
    mov rdx, r14
    call linnea_sha256_update
    lea rdi, [rsp]
    lea rsi, [rsp + 176]
    call linnea_sha256_final
    ; opad = (key padded to 64) XOR 0x5c
    lea rdi, [rsp + 112]
    xor ecx, ecx
.opad:
    xor eax, eax
    cmp rcx, r12
    jae .opad_x
    movzx eax, byte [rbx + rcx]
.opad_x:
    xor al, 0x5c
    mov [rdi + rcx], al
    inc rcx
    cmp rcx, 64
    jb .opad
    ; out = H(opad || inner)
    lea rdi, [rsp]
    call linnea_sha256_init
    lea rdi, [rsp]
    lea rsi, [rsp + 112]
    mov rdx, 64
    call linnea_sha256_update
    lea rdi, [rsp]
    lea rsi, [rsp + 176]
    mov rdx, 32
    call linnea_sha256_update
    lea rdi, [rsp]
    mov rsi, r15
    call linnea_sha256_final
    add rsp, 240
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_hkdf_extract(rdi=salt, rsi=saltlen, rdx=ikm, rcx=ikmlen, r8=out)
; HKDF-Extract(salt, IKM) = HMAC(salt, IKM). out is 32 bytes.
linnea_hkdf_extract:
    jmp linnea_hmac_sha256

; linnea_hkdf_expand(rdi=prk, rsi=prklen, rdx=info, rcx=infolen,
;                    r8=out, r9=outlen)
; HKDF-Expand. The per-round message T(i-1)||info||i is built in a stack
; buffer; info is TLS-sized (HkdfLabel, well under 1 KiB).
linnea_hkdf_expand:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 1096
    ; frame: [0]=msg(1024) [1024]=Ti(32) [1056]=produced [1064]=i [1072]=Tlen
    mov rbx, rdi                   ; prk
    mov r12, rsi                   ; prklen
    mov r13, rdx                   ; info
    mov r14, rcx                   ; infolen
    mov r15, r8                    ; out
    mov rbp, r9                    ; outlen
    mov qword [rsp + 1056], 0      ; produced
    mov qword [rsp + 1064], 1      ; block counter i
    mov qword [rsp + 1072], 0      ; length of T(i-1), 0 on the first round
.loop:
    mov rax, [rsp + 1056]
    cmp rax, rbp
    jae .done
    ; msg = T(i-1) || info || i
    lea rdi, [rsp]
    mov rcx, [rsp + 1072]
    lea rsi, [rsp + 1024]          ; previous Ti
    rep movsb
    mov rcx, r14
    mov rsi, r13                   ; info
    rep movsb
    mov rax, [rsp + 1064]
    mov [rdi], al                  ; the counter byte
    lea rcx, [rdi + 1]
    sub rcx, rsp                   ; msg length
    ; Ti = HMAC(prk, msg)
    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rsp]
    lea r8, [rsp + 1024]
    call linnea_hmac_sha256
    ; copy min(32, outlen - produced) into out
    mov rax, [rsp + 1056]
    mov rdx, rbp
    sub rdx, rax                   ; remaining
    mov rcx, 32
    cmp rdx, rcx
    jae .cp
    mov rcx, rdx
.cp:
    lea rdi, [r15 + rax]
    lea rsi, [rsp + 1024]
    mov r9, rcx                    ; rep movsb consumes rcx
    rep movsb
    add [rsp + 1056], r9
    mov qword [rsp + 1072], 32
    inc qword [rsp + 1064]
    jmp .loop
.done:
    add rsp, 1096
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
