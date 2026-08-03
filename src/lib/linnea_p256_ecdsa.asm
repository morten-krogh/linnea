; linnea_p256_ecdsa.asm — deterministic ECDSA signing on P-256 (RFC 6979).
;
; Everything above the arithmetic: the nonce DRBG, the signature equation, and
; the DER encoding. The moduli live in linnea_p256_fe.asm (p) and
; linnea_p256_scalar.asm (n); the group lives in linnea_p256_point.asm.
;
; The whole construction was modelled in Python first and pinned against RFC
; 6979 Appendix A.2.5, which publishes k, r and s for this exact curve and
; hash. Determinism is what makes that possible: OpenSSL signs with a random
; nonce and can only ever VERIFY our output, never match it byte for byte.
;
; ABI: System V. Callee-saved rbx, rbp, r12-r15 preserved.

default rel

%include "linnea_p256_ecdsa.inc"
%include "linnea_p256_point.inc"

global linnea_p256_ecdsa_sign

extern linnea_hmac_sha256
extern linnea_p256_scalar_frombytes
extern linnea_p256_scalar_tobytes
extern linnea_p256_scalar_mul
extern linnea_p256_scalar_add
extern linnea_p256_scalar_inv
extern linnea_p256_scalar_is_zero
extern linnea_p256_scalar_is_valid
extern linnea_p256_fe_mul
extern linnea_p256_fe_inv
extern linnea_p256_fe_tobytes
extern linnea_p256_point_mul
extern linnea_p256_g

section .text

; Stack layout for linnea_p256_ecdsa_sign.
%define K       0       ; RFC 6979 DRBG state
%define V      32
%define T      64       ; the nonce candidate, 32 big-endian bytes
%define Z      96       ; bits2octets(h1)
%define HOUT  128       ; HMAC output; never written over its own key
%define HBUF  160       ; V || sep || d || z -- 97 bytes, also the DER body
%define RPT   264       ; the point k*G
%define SCK   360       ; scalars, Montgomery form
%define SCR   392
%define SCS   424
%define SCE   456
%define SCD   488
%define SCT   520
%define RB    552       ; r, canonical big-endian bytes
%define SB    584       ; s
%define DPTR  616
%define HPTR  624
%define SIGPTR 632
%define SIGN_FRAME 648  ; six pushes + this leaves rsp 16-aligned

; copy32(rdi=dst, rsi=src) — file-local.
copy32:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    mov [rdi + 24], rax
    ret

; HMAC-SHA256 keyed by K over a message, into %1. Never lets the output
; alias the key: the result lands in HOUT and is copied, so `K = HMAC_K(...)`
; is expressible without depending on how linnea_hmac_sha256 orders its reads.
%macro HMAC_K_TO 3      ; %1 = dst, %2 = msg, %3 = msglen
    lea rdi, [rsp + K]
    mov rsi, 32
    lea rdx, %2
    mov rcx, %3
    lea r8, [rsp + HOUT]
    call linnea_hmac_sha256
    lea rdi, %1
    lea rsi, [rsp + HOUT]
    call copy32
%endmacro

; p256_der_int(rdi=dst, rsi=src) — encode the 32 big-endian bytes at src as a
;   DER INTEGER; returns the number of bytes written in rax.
;
;   DER wants the minimal form: strip leading zero bytes, but keep one 0x00 in
;   front when the top bit is set, or the value would read as negative. r and
;   s are public (they are the signature), so the data-dependent length and
;   loop here leak nothing.
;   File-local. Clobbers rax rcx rdx r8 r9 r10.
p256_der_int:
    xor rcx, rcx
.skip:
    cmp rcx, 31                 ; keep the last byte even if it is zero
    jae .emit
    cmp byte [rsi + rcx], 0
    jne .emit
    inc rcx
    jmp .skip
.emit:
    mov r8, 32
    sub r8, rcx                 ; content length, at least 1
    mov byte [rdi], 0x02
    mov al, [rsi + rcx]
    test al, 0x80
    jz .no_pad
    lea rax, [r8 + 1]
    mov [rdi + 1], al           ; length includes the pad byte
    mov byte [rdi + 2], 0
    lea r9, [rdi + 3]
    jmp .copy
.no_pad:
    mov [rdi + 1], r8b
    lea r9, [rdi + 2]
.copy:
    lea r10, [rsi + rcx]
    xor rdx, rdx
.cp:
    cmp rdx, r8
    jae .cp_done
    mov al, [r10 + rdx]
    mov [r9 + rdx], al
    inc rdx
    jmp .cp
.cp_done:
    mov rax, r9
    sub rax, rdi
    add rax, r8
    ret

; linnea_p256_ecdsa_sign(rdi=sig, rsi=hash, rdx=priv) — sign the 32-byte
;   SHA-256 digest at rsi under the private key at rdx (32 big-endian bytes,
;   assumed already in [1, n-1] -- the key loader validates that once at
;   startup, not once per signature). Writes DER to sig, at most
;   LINNEA_P256_ECDSA_MAX_SIG bytes, and returns its length in rax.
;
;   The caller supplies the digest, not the message: RFC 6979's h1 is H(m),
;   and TLS builds the CertificateVerify content and hashes it anyway.
linnea_p256_ecdsa_sign:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, SIGN_FRAME

    mov [rsp + SIGPTR], rdi
    mov [rsp + HPTR], rsi
    mov [rsp + DPTR], rdx

    ; z = bits2octets(h1): reduce the digest mod n and re-encode. scalar
    ; frombytes reduces mod n, which for P-256 with SHA-256 is exactly
    ; bits2int-then-mod-n -- qlen equals hlen*8, so 6979's truncation step is
    ; a no-op here.
    lea rdi, [rsp + SCT]
    mov rsi, [rsp + HPTR]
    call linnea_p256_scalar_frombytes
    lea rdi, [rsp + Z]
    lea rsi, [rsp + SCT]
    call linnea_p256_scalar_tobytes

    ; --- RFC 6979 section 3.2 steps b-d: V = 0x01..., K = 0x00... ---
    mov rax, 0x0101010101010101
    mov [rsp + V], rax
    mov [rsp + V + 8], rax
    mov [rsp + V + 16], rax
    mov [rsp + V + 24], rax
    xor eax, eax
    mov [rsp + K], rax
    mov [rsp + K + 8], rax
    mov [rsp + K + 16], rax
    mov [rsp + K + 24], rax

    ; HBUF = V || sep || int2octets(x) || bits2octets(h1); only the separator
    ; changes between the two seeding rounds, so d and z are placed once.
    lea rdi, [rsp + HBUF + 33]
    mov rsi, [rsp + DPTR]
    call copy32
    lea rdi, [rsp + HBUF + 65]
    lea rsi, [rsp + Z]
    call copy32

    ; step d: K = HMAC_K(V || 0x00 || x || z)
    lea rdi, [rsp + HBUF]
    lea rsi, [rsp + V]
    call copy32
    mov byte [rsp + HBUF + 32], 0x00
    HMAC_K_TO [rsp + K], [rsp + HBUF], 97
    ; step e: V = HMAC_K(V)
    HMAC_K_TO [rsp + V], [rsp + V], 32
    ; step f: K = HMAC_K(V || 0x01 || x || z)
    lea rdi, [rsp + HBUF]
    lea rsi, [rsp + V]
    call copy32
    mov byte [rsp + HBUF + 32], 0x01
    HMAC_K_TO [rsp + K], [rsp + HBUF], 97
    ; step g: V = HMAC_K(V)
    HMAC_K_TO [rsp + V], [rsp + V], 32

    ; --- step h: draw candidates until one yields a signature ---
.retry:
    ; T = V = HMAC_K(V). qlen is 256 and HMAC-SHA256 gives exactly 32 bytes,
    ; so 6979's "while tlen < qlen" loop runs exactly once here.
    HMAC_K_TO [rsp + V], [rsp + V], 32
    lea rdi, [rsp + T]
    lea rsi, [rsp + V]
    call copy32

    ; reject a candidate outside [1, n-1] -- redraw, never reduce
    lea rdi, [rsp + T]
    call linnea_p256_scalar_is_valid
    test eax, eax
    jz .reseed

    ; R = k*G, then r = x(R) mod n
    lea rdi, [rsp + RPT]
    lea rsi, [rsp + T]
    lea rdx, [linnea_p256_g]
    call linnea_p256_point_mul
    lea rdi, [rsp + SCT]                        ; 1/Z
    lea rsi, [rsp + RPT + linnea_p256_point.z]
    call linnea_p256_fe_inv
    lea rdi, [rsp + SCT]                        ; x = X/Z
    lea rsi, [rsp + RPT + linnea_p256_point.x]
    lea rdx, [rsp + SCT]
    call linnea_p256_fe_mul
    lea rdi, [rsp + RB]
    lea rsi, [rsp + SCT]
    call linnea_p256_fe_tobytes
    lea rdi, [rsp + SCR]                        ; r = x mod n
    lea rsi, [rsp + RB]
    call linnea_p256_scalar_frombytes

    lea rdi, [rsp + SCR]
    call linnea_p256_scalar_is_zero
    test eax, eax
    jnz .reseed                                 ; r == 0: redraw, per 6979

    ; s = k^-1 * (e + r*d) mod n
    lea rdi, [rsp + SCE]                        ; e = bits2int(h1) mod n
    mov rsi, [rsp + HPTR]
    call linnea_p256_scalar_frombytes
    lea rdi, [rsp + SCD]
    mov rsi, [rsp + DPTR]
    call linnea_p256_scalar_frombytes
    lea rdi, [rsp + SCK]
    lea rsi, [rsp + T]
    call linnea_p256_scalar_frombytes

    lea rdi, [rsp + SCT]                        ; r*d
    lea rsi, [rsp + SCR]
    lea rdx, [rsp + SCD]
    call linnea_p256_scalar_mul
    lea rdi, [rsp + SCT]                        ; e + r*d
    lea rsi, [rsp + SCE]
    lea rdx, [rsp + SCT]
    call linnea_p256_scalar_add
    lea rdi, [rsp + SCK]                        ; k^-1
    lea rsi, [rsp + SCK]
    call linnea_p256_scalar_inv
    lea rdi, [rsp + SCS]
    lea rsi, [rsp + SCK]
    lea rdx, [rsp + SCT]
    call linnea_p256_scalar_mul

    lea rdi, [rsp + SCS]
    call linnea_p256_scalar_is_zero
    test eax, eax
    jnz .reseed                                 ; s == 0: redraw, per 6979

    ; --- DER: SEQUENCE { INTEGER r, INTEGER s } ---
    lea rdi, [rsp + RB]
    lea rsi, [rsp + SCR]
    call linnea_p256_scalar_tobytes
    lea rdi, [rsp + SB]
    lea rsi, [rsp + SCS]
    call linnea_p256_scalar_tobytes

    ; HBUF is free again by now; build the body there
    lea rdi, [rsp + HBUF]
    lea rsi, [rsp + RB]
    call p256_der_int
    mov r12, rax
    lea rdi, [rsp + HBUF]
    add rdi, r12
    lea rsi, [rsp + SB]
    call p256_der_int
    add r12, rax                                ; body length, at most 70

    mov rbx, [rsp + SIGPTR]
    mov byte [rbx], 0x30
    mov [rbx + 1], r12b                         ; < 128, so one length byte
    xor rcx, rcx
    lea r8, [rsp + HBUF]
.copy_body:
    cmp rcx, r12
    jae .copy_done
    mov al, [r8 + rcx]
    mov [rbx + 2 + rcx], al
    inc rcx
    jmp .copy_body
.copy_done:
    lea rax, [r12 + 2]
    add rsp, SIGN_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

    ; RFC 6979 step h3: K = HMAC_K(V || 0x00), V = HMAC_K(V), then redraw.
    ; Reached when the candidate is out of range, or when r or s came out
    ; zero -- the last two have probability around 2^-256 and have never been
    ; observed, but they are one branch, so there is no reason to omit them.
.reseed:
    lea rdi, [rsp + HBUF]
    lea rsi, [rsp + V]
    call copy32
    mov byte [rsp + HBUF + 32], 0x00
    HMAC_K_TO [rsp + K], [rsp + HBUF], 33
    HMAC_K_TO [rsp + V], [rsp + V], 32
    jmp .retry
