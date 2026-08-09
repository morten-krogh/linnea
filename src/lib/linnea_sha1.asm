; linnea_sha1.asm — SHA-1.
;
; Here for one reason: the WebSocket opening handshake. RFC 6455 4.2.2 fixes
; Sec-WebSocket-Accept as base64(sha1(key ++ GUID)), and no other choice of
; hash is available — it is not a security property (the value is public and
; the input is the client's own nonce), it is a fixed handshake token that
; proves the peer understood the protocol rather than being an HTTP server
; that echoed something. So SHA-1's weaknesses are not in play, and nothing
; else in this server uses it.
;
; A straightforward scalar implementation, in the same shape as
; linnea_sha256.asm: this runs once per WebSocket connection, on 60 bytes.
;
; ABI: System V. Callee-saved rbx, rbp, r12-r15 are preserved.

default rel

global linnea_sha1

section .text

; sha1_block(rdi = state, five dwords; rsi = one 64-byte block)
; The compression function. The message schedule is expanded onto the stack.
sha1_block:
    push rbx
    push rbp
    push r12
    sub rsp, 328                     ; w[80] dwords, plus 8. NOT a 16-alignment
                                     ; claim: this frame preserves whatever
                                     ; parity the caller had rather than fixing
                                     ; it, which is only safe because nothing
                                     ; below here touches SSE. Anything added
                                     ; that does must align rsp itself.
    mov rbp, rsp
    ; w[0..15]: the block's dwords, big-endian as SHA-1 reads them
    xor ecx, ecx
.load:
    mov eax, [rsi + rcx * 4]
    bswap eax
    mov [rbp + rcx * 4], eax
    inc ecx
    cmp ecx, 16
    jb .load
    ; w[i] = rol1(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16])
.extend:
    mov eax, [rbp + rcx * 4 - 3 * 4]
    xor eax, [rbp + rcx * 4 - 8 * 4]
    xor eax, [rbp + rcx * 4 - 14 * 4]
    xor eax, [rbp + rcx * 4 - 16 * 4]
    rol eax, 1
    mov [rbp + rcx * 4], eax
    inc ecx
    cmp ecx, 80
    jb .extend

    mov r8d,  [rdi]                  ; a
    mov r9d,  [rdi + 4]              ; b
    mov r10d, [rdi + 8]              ; c
    mov r11d, [rdi + 12]             ; d
    mov ebx,  [rdi + 16]             ; e
    xor ecx, ecx                     ; round
.round:
    ; the round's f and k, which change every twenty rounds
    cmp ecx, 20
    jae .q2
    mov edx, r9d                     ; f = (b & c) | (~b & d)
    and edx, r10d
    mov eax, r9d
    not eax
    and eax, r11d
    or edx, eax
    mov eax, 0x5A827999
    jmp .mix
.q2:
    cmp ecx, 40
    jae .q3
    mov edx, r9d                     ; f = b ^ c ^ d
    xor edx, r10d
    xor edx, r11d
    mov eax, 0x6ED9EBA1
    jmp .mix
.q3:
    cmp ecx, 60
    jae .q4
    mov edx, r9d                     ; f = (b & c) | (b & d) | (c & d)
    and edx, r10d
    mov eax, r9d
    and eax, r11d
    or edx, eax
    mov eax, r10d
    and eax, r11d
    or edx, eax
    mov eax, 0x8F1BBCDC
    jmp .mix
.q4:
    mov edx, r9d                     ; f = b ^ c ^ d again
    xor edx, r10d
    xor edx, r11d
    mov eax, 0xCA62C1D6
.mix:
    ; temp = rol5(a) + f + e + k + w[i], computed before anything shifts
    add edx, eax
    add edx, ebx
    add edx, [rbp + rcx * 4]
    mov eax, r8d
    rol eax, 5
    add edx, eax
    ; e = d, d = c, c = rol30(b), b = a, a = temp — each source read before
    ; the register holding it is overwritten
    mov ebx, r11d
    mov r11d, r10d
    mov r10d, r9d
    rol r10d, 30
    mov r9d, r8d
    mov r8d, edx
    inc ecx
    cmp ecx, 80
    jb .round

    add [rdi], r8d
    add [rdi + 4], r9d
    add [rdi + 8], r10d
    add [rdi + 12], r11d
    add [rdi + 16], ebx
    add rsp, 328
    pop r12
    pop rbp
    pop rbx
    ret

; linnea_sha1(rdi = data, rsi = length, rdx = out) — out is 20 bytes.
; One-shot, matching linnea_sha256's shape.
linnea_sha1:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 168                     ; state at [rsp], the padded tail at +32
    mov rbx, rdi                     ; data cursor
    mov r12, rsi                     ; the length, kept for the bit count
    mov r13, rdx                     ; out
    mov dword [rsp],      0x67452301
    mov dword [rsp + 4],  0xEFCDAB89
    mov dword [rsp + 8],  0x98BADCFE
    mov dword [rsp + 12], 0x10325476
    mov dword [rsp + 16], 0xC3D2E1F0
    mov r14, r12                     ; bytes still to consume
.blocks:
    cmp r14, 64
    jb .tail
    mov rdi, rsp
    mov rsi, rbx
    call sha1_block
    add rbx, 64
    sub r14, 64
    jmp .blocks
.tail:
    ; The last partial block, plus the 0x80 terminator and the 64-bit
    ; big-endian bit count. Both fit one block unless the remainder leaves no
    ; room for the count, which takes a second.
    lea rdi, [rsp + 32]
    xor eax, eax
    mov ecx, 16
    rep stosq                        ; 128 bytes of scratch, cleared
    lea rdi, [rsp + 32]
    mov rsi, rbx
    mov rcx, r14
    rep movsb                        ; rdi lands just past the copy
    mov byte [rdi], 0x80
    mov rax, r12
    shl rax, 3                       ; the length in bits
    bswap rax
    cmp r14, 56
    jae .two_blocks
    mov [rsp + 32 + 56], rax
    lea rsi, [rsp + 32]
    mov rdi, rsp
    call sha1_block
    jmp .emit
.two_blocks:
    mov [rsp + 32 + 120], rax
    lea rsi, [rsp + 32]
    mov rdi, rsp
    call sha1_block
    lea rsi, [rsp + 32 + 64]
    mov rdi, rsp
    call sha1_block
.emit:
    xor ecx, ecx
.store:
    mov eax, [rsp + rcx * 4]
    bswap eax
    mov [r13 + rcx * 4], eax
    inc ecx
    cmp ecx, 5
    jb .store
    add rsp, 168
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
