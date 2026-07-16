; linnea_aesgcm.asm — AES-128-GCM (NIST SP 800-38D) via AES-NI + PCLMULQDQ.
;
; Only what TLS 1.3 needs: 96-bit nonces, 128-bit tags, seal and open.
; The counter starts at 2 (block 1 is the tag mask E_K(nonce||1)) and the
; 32-bit inc32 never wraps at TLS record sizes. GHASH works on
; byte-swapped blocks with H pre-shifted left by one bit at init
; (conditionally xoring the reflected polynomial 0xc2...01), which lines
; the carry-less product up so no per-block bit shift is needed. The
; two-phase shift reduction in ghash_mul was verified bit-for-bit
; against the textbook GF(2^128) multiply before this file was written.
;
; Constant-time by hardware: AES-NI and PCLMULQDQ are data-independent,
; branches and rep-string lengths depend only on public message lengths,
; and the tag check is a full 16-byte compare via pcmpeqb/pmovmskb.
; Open writes plaintext to out before the tag is verified and zeroes it
; on failure — callers must not touch out unless open returned 0.
;
; ABI: System V; callee-saved preserved.

default rel

%include "linnea_aesgcm.inc"

global linnea_aesgcm_init
global linnea_aesgcm_seal
global linnea_aesgcm_open

section .rodata

align 16
bswap_mask:  db 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
ghash_poly:  dq 1, 0xc200000000000000    ; reflected x^128+x^7+x^2+x+1

section .bss

alignb 16
ghash_pad:   resb 16       ; zero-padding buffer for partial GHASH blocks

section .text

; ---- linnea_aesgcm_init(rdi=ctx, rsi=key16) --------------------------
; Expand the AES-128 key schedule, then derive the GHASH key
; H = E_K(0^128), byte-swap it and pre-shift for the clmul multiply.

%macro AES_ROUND_KEY 2      ; %1 = rcon, %2 = round-key offset in ctx
    aeskeygenassist xmm2, xmm1, %1
    call key_fold
    movdqu [rbp + linnea_aesgcm_ctx.rk + %2], xmm1
%endmacro

linnea_aesgcm_init:
    push rbp
    mov rbp, rdi
    movdqu xmm1, [rsi]
    movdqu [rbp + linnea_aesgcm_ctx.rk], xmm1
    AES_ROUND_KEY 0x01, 16
    AES_ROUND_KEY 0x02, 32
    AES_ROUND_KEY 0x04, 48
    AES_ROUND_KEY 0x08, 64
    AES_ROUND_KEY 0x10, 80
    AES_ROUND_KEY 0x20, 96
    AES_ROUND_KEY 0x40, 112
    AES_ROUND_KEY 0x80, 128
    AES_ROUND_KEY 0x1b, 144
    AES_ROUND_KEY 0x36, 160

    ; H = E_K(0), byte-swapped
    pxor xmm0, xmm0
    call aes_enc_block
    pshufb xmm0, [bswap_mask]

    ; H <<= 1 (128-bit), xor the poly constant if bit 127 was set
    pshufd xmm2, xmm0, 0xff
    movdqa xmm1, xmm0
    psllq xmm0, 1
    psrlq xmm1, 63
    pslldq xmm1, 8
    por xmm0, xmm1
    psrad xmm2, 31             ; replicate the old top bit into a mask
    pand xmm2, [ghash_poly]
    pxor xmm0, xmm2
    movdqu [rbp + linnea_aesgcm_ctx.h], xmm0
    pop rbp
    ret

; key_fold — one AES-128 key-schedule step. xmm1 = previous round key,
; xmm2 = aeskeygenassist(xmm1, rcon); leaves the next round key in xmm1.
key_fold:
    pshufd xmm2, xmm2, 0xff
    movdqa xmm3, xmm1
    pslldq xmm3, 4
    pxor xmm1, xmm3
    pslldq xmm3, 4
    pxor xmm1, xmm3
    pslldq xmm3, 4
    pxor xmm1, xmm3
    pxor xmm1, xmm2
    ret

; aes_enc_block — encrypt xmm0 in place with the schedule at rbp.
; Round keys are loaded unaligned so the ctx needs no alignment (it will
; live inside the connection struct). Clobbers xmm1 only; no GPRs.
aes_enc_block:
    movdqu xmm1, [rbp + linnea_aesgcm_ctx.rk]
    pxor xmm0, xmm1
%assign rk_off 16
%rep 9
    movdqu xmm1, [rbp + linnea_aesgcm_ctx.rk + rk_off]
    aesenc xmm0, xmm1
%assign rk_off rk_off + 16
%endrep
    movdqu xmm1, [rbp + linnea_aesgcm_ctx.rk + 160]
    aesenclast xmm0, xmm1
    ret

; ghash_mul — one GF(2^128) multiply: xmm0 = acc (byte-swapped domain),
; xmm1 = pre-shifted H; result in xmm0. Karatsuba carry-less multiply
; into a 256-bit product, then the two-phase shift reduction.
; Clobbers xmm2-xmm5; no GPRs.
ghash_mul:
    movdqa xmm2, xmm0
    movdqa xmm3, xmm0
    movdqa xmm4, xmm0
    movdqa xmm5, xmm0
    pclmulqdq xmm2, xmm1, 0x00   ; lo = x.lo * h.lo
    pclmulqdq xmm3, xmm1, 0x11   ; hi = x.hi * h.hi
    pclmulqdq xmm4, xmm1, 0x10   ; x.lo * h.hi
    pclmulqdq xmm5, xmm1, 0x01   ; x.hi * h.lo
    pxor xmm4, xmm5              ; mid
    movdqa xmm5, xmm4
    pslldq xmm4, 8
    psrldq xmm5, 8
    pxor xmm2, xmm4              ; lo ^= mid << 64
    pxor xmm3, xmm5              ; hi ^= mid >> 64

    ; reduction, first phase: fold lo's contribution left
    movdqa xmm4, xmm2            ; original lo
    movdqa xmm5, xmm2
    psllq xmm2, 5
    pxor xmm5, xmm2
    psllq xmm2, 1
    pxor xmm2, xmm5              ; lo ^ lo<<5 ^ lo<<6
    psllq xmm2, 57
    movdqa xmm5, xmm2
    pslldq xmm2, 8
    psrldq xmm5, 8
    pxor xmm2, xmm4
    pxor xmm3, xmm5

    ; second phase: fold right and combine with hi
    movdqa xmm4, xmm2
    psrlq xmm2, 1
    pxor xmm3, xmm4
    pxor xmm4, xmm2
    psrlq xmm2, 5
    pxor xmm2, xmm4
    psrlq xmm2, 1
    pxor xmm2, xmm3
    movdqa xmm0, xmm2
    ret

; ghash_absorb — fold one raw 16-byte block (xmm0) into the accumulator.
; Register contract shared by seal/open: xmm8 = pre-shifted H,
; xmm9 = byte-swap mask, xmm10 = accumulator. Clobbers xmm0-xmm5.
ghash_absorb:
    pshufb xmm0, xmm9
    pxor xmm0, xmm10
    movdqa xmm1, xmm8
    call ghash_mul
    movdqa xmm10, xmm0
    ret

; ghash_absorb_bytes — absorb rsi/rcx bytes, zero-padding the final
; partial block (how GCM hashes AAD and ciphertext).
; Clobbers rax, rcx, rsi, rdi, xmm0-xmm5.
ghash_absorb_bytes:
.full:
    cmp rcx, 16
    jb .partial
    movdqu xmm0, [rsi]
    call ghash_absorb
    add rsi, 16
    sub rcx, 16
    jmp .full
.partial:
    test rcx, rcx
    jz .done
    pxor xmm0, xmm0
    movdqa [ghash_pad], xmm0
    lea rdi, [ghash_pad]
    rep movsb
    movdqa xmm0, [ghash_pad]
    call ghash_absorb
.done:
    ret

; Shared frame for seal/open. After six pushes rsp is 8 mod 16, so the
; 56-byte frame realigns it and the three 16-byte locals can use movdqa.
%define CTR   0             ; counter block: nonce || be32 counter
%define TMASK 16            ; E_K(nonce || 1), xored into the final tag
%define PBUF  32            ; partial-block bounce buffer
%define FRAME 56
%define ARG7  FRAME + 48 + 8   ; frame + saved regs + return address

; prologue shared by seal and open: stash the args in callee-saved
; registers, build the counter block, compute the tag mask and load the
; GHASH register set (xmm8/xmm9/xmm10).
%macro AEAD_PROLOGUE 0
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, FRAME
    mov rbp, rdi               ; ctx
    mov rbx, rdx               ; aad
    mov r12, rcx               ; aadlen
    mov r13, r8                ; in
    mov r14, r9                ; inlen
    mov r15, [rsp + ARG7]      ; out
    mov rax, [rsi]             ; counter block = nonce || be32(1)
    mov [rsp + CTR], rax
    mov eax, [rsi + 8]
    mov [rsp + CTR + 8], eax
    mov dword [rsp + CTR + 12], 0x01000000
    movdqa xmm0, [rsp + CTR]
    call aes_enc_block
    movdqa [rsp + TMASK], xmm0
    movdqu xmm8, [rbp + linnea_aesgcm_ctx.h]
    movdqa xmm9, [bswap_mask]
    pxor xmm10, xmm10
%endmacro

%macro AEAD_EPILOGUE 0
    add rsp, FRAME
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
%endmacro

; next_keystream — encrypt the counter block for counter r10d into xmm0
; and step the counter. Clobbers xmm1 and rax.
next_keystream:
    mov eax, r10d
    bswap eax
    mov [rsp + CTR + 12 + 8], eax   ; +8: our caller's return address
    movdqa xmm0, [rsp + CTR + 8]    ; ditto
    call aes_enc_block
    inc r10d
    ret

; ---- linnea_aesgcm_seal(rdi=ctx, rsi=nonce12, rdx=aad, rcx=aadlen,
;                         r8=pt, r9=ptlen, [stack]=out) ----------------
; Writes ptlen ciphertext bytes followed by the 16-byte tag to out.
linnea_aesgcm_seal:
    AEAD_PROLOGUE

    mov rsi, rbx               ; absorb the AAD
    mov rcx, r12
    call ghash_absorb_bytes

    mov r10d, 2                ; counter (1 was the tag mask)
    mov rsi, r13               ; plaintext cursor
    mov rdi, r15               ; ciphertext cursor
    mov r11, r14               ; bytes remaining
.block:
    cmp r11, 16
    jb .partial
    call next_keystream
    movdqu xmm1, [rsi]
    pxor xmm0, xmm1
    movdqu [rdi], xmm0
    call ghash_absorb          ; absorbs the ciphertext block
    add rsi, 16
    add rdi, 16
    sub r11, 16
    jmp .block
.partial:
    test r11, r11
    jz .lens
    call next_keystream
    pxor xmm1, xmm1
    movdqa [rsp + PBUF], xmm1
    mov rdx, rdi               ; hold the out cursor across the copies
    lea rdi, [rsp + PBUF]
    mov rcx, r11
    rep movsb                  ; plaintext tail into the zeroed buffer
    movdqa xmm1, [rsp + PBUF]
    pxor xmm0, xmm1
    movdqa [rsp + PBUF], xmm0  ; tail bytes now hold raw keystream...
    lea rdi, [rsp + PBUF]
    add rdi, r11
    mov rcx, 16
    sub rcx, r11
    xor eax, eax
    rep stosb                  ; ...so re-zero them: GHASH needs ct || 0*
    mov rdi, rdx
    lea rsi, [rsp + PBUF]
    mov rcx, r11
    rep movsb                  ; ciphertext tail to out
    movdqa xmm0, [rsp + PBUF]
    call ghash_absorb
.lens:
    mov rax, r12               ; length block: be64(aad bits) || be64(ct bits)
    shl rax, 3
    bswap rax
    mov [rsp + PBUF], rax
    mov rax, r14
    shl rax, 3
    bswap rax
    mov [rsp + PBUF + 8], rax
    movdqa xmm0, [rsp + PBUF]
    call ghash_absorb

    movdqa xmm0, xmm10         ; tag = bswap(acc) ^ E_K(nonce || 1)
    pshufb xmm0, xmm9
    pxor xmm0, [rsp + TMASK]
    movdqu [r15 + r14], xmm0
    xor eax, eax
    AEAD_EPILOGUE

; ---- linnea_aesgcm_open(rdi=ctx, rsi=nonce12, rdx=aad, rcx=aadlen,
;                         r8=ct, r9=ctlen incl. tag, [stack]=out) ------
; Writes ctlen-16 plaintext bytes to out. Returns 0 and the plaintext on
; a valid tag; -1 with out zeroed otherwise (out is untouched when
; ctlen < 16).
linnea_aesgcm_open:
    cmp r9, LINNEA_AESGCM_TAG
    jb .too_short
    AEAD_PROLOGUE
    sub r14, LINNEA_AESGCM_TAG ; r14 = plaintext length

    mov rsi, rbx               ; absorb the AAD
    mov rcx, r12
    call ghash_absorb_bytes

    mov r10d, 2
    mov rsi, r13               ; ciphertext cursor
    mov rdi, r15               ; plaintext cursor
    mov r11, r14
.block:
    cmp r11, 16
    jb .partial
    call next_keystream
    movdqu xmm1, [rsi]         ; ciphertext block
    pxor xmm0, xmm1
    movdqu [rdi], xmm0
    movdqa xmm0, xmm1
    call ghash_absorb          ; absorbs the ciphertext block
    add rsi, 16
    add rdi, 16
    sub r11, 16
    jmp .block
.partial:
    test r11, r11
    jz .lens
    call next_keystream
    movdqa xmm6, xmm0          ; keystream survives the helpers below
    pxor xmm1, xmm1
    movdqa [rsp + PBUF], xmm1
    mov rdx, rdi
    lea rdi, [rsp + PBUF]
    mov rcx, r11
    rep movsb                  ; ciphertext tail, zero padded
    movdqa xmm0, [rsp + PBUF]
    call ghash_absorb
    movdqa xmm0, [rsp + PBUF]
    pxor xmm0, xmm6
    movdqa [rsp + PBUF], xmm0
    mov rdi, rdx
    lea rsi, [rsp + PBUF]
    mov rcx, r11
    rep movsb                  ; plaintext tail to out
.lens:
    mov rax, r12
    shl rax, 3
    bswap rax
    mov [rsp + PBUF], rax
    mov rax, r14
    shl rax, 3
    bswap rax
    mov [rsp + PBUF + 8], rax
    movdqa xmm0, [rsp + PBUF]
    call ghash_absorb

    movdqa xmm0, xmm10         ; expected tag
    pshufb xmm0, xmm9
    pxor xmm0, [rsp + TMASK]
    movdqu xmm1, [r13 + r14]   ; received tag
    pxor xmm0, xmm1            ; all-zero iff equal
    pxor xmm1, xmm1
    pcmpeqb xmm0, xmm1
    pmovmskb eax, xmm0
    cmp eax, 0xffff
    jne .bad_tag
    xor eax, eax
    AEAD_EPILOGUE
.bad_tag:
    mov rdi, r15               ; never hand back unauthenticated bytes
    mov rcx, r14
    xor eax, eax
    rep stosb
    mov rax, -1
    AEAD_EPILOGUE
.too_short:
    mov rax, -1
    ret
