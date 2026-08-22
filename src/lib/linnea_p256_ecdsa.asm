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
global linnea_p256_ecdsa_verify
global linnea_p256_ecdsa_verify_der

extern linnea_hmac_sha256
extern linnea_p256_scalar_frombytes
extern linnea_p256_scalar_tobytes
extern linnea_p256_scalar_mul
extern linnea_p256_scalar_add
extern linnea_p256_scalar_sub
extern linnea_p256_scalar_inv
extern linnea_p256_scalar_is_zero
extern linnea_p256_scalar_is_valid
extern linnea_p256_fe_mul
extern linnea_p256_fe_sq
extern linnea_p256_fe_add
extern linnea_p256_fe_sub
extern linnea_p256_fe_inv
extern linnea_p256_fe_frombytes
extern linnea_p256_fe_tobytes
extern linnea_p256_fe_1
extern linnea_p256_fe_is_zero
extern linnea_p256_fe_is_valid
extern linnea_p256_point_mul
extern linnea_p256_point_add
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

; ============================================================================
; ECDSA P-256 verify (added for backend TLS: verifying a server's
; CertificateVerify). See docs/design/ecdsa-verify-plan.md.
;
; Verify touches only PUBLIC data -- the public key, the signature, the message
; hash. There is no secret, so unlike the signer it needs no constant-time
; discipline: it branches freely on validation failures. Its only obligations
; are correctness and never faulting on malformed input.
; ============================================================================

section .rodata
align 8
; The curve coefficient b, 32 big-endian bytes (plain, not Montgomery). The
; point module keeps only 3b in Montgomery form and file-local, so the on-curve
; test carries its own b and converts it with fe_frombytes at run time.
p256_b_be:
    db 0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7
    db 0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc
    db 0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6
    db 0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b

section .text

; Stack layout for linnea_p256_ecdsa_verify. No callee-saved registers are used,
; so there are no pushes; the frame is 872 (== 8 mod 16), which with the return
; address leaves rsp 16-aligned at every call.
%define V_HASHP  0      ; saved argument pointers
%define V_RP     8
%define V_SP    16
%define V_QP    24
%define V_QPT   32      ; Q, projective point (96)
%define V_RPT  128      ; R = u1*G + u2*Q, projective point (96)
%define V_T2   224      ; u2*Q, projective point (96)
%define V_EM   320      ; e mod n, Montgomery
%define V_RM   352      ; r mod n, Montgomery
%define V_SM   384      ; s mod n, Montgomery
%define V_W    416      ; s^-1 mod n
%define V_U1   448      ; e*w mod n
%define V_U2   480      ; r*w mod n
%define V_U1B  512      ; u1, plain big-endian bytes (for the ladder)
%define V_U2B  544      ; u2, plain big-endian bytes
%define V_VV   576      ; x(R) mod n, Montgomery
%define V_BM   608      ; b, Montgomery
%define V_LHS  640      ; y^2
%define V_RHS  672      ; x^3 - 3x + b
%define V_TA   704      ; scratch fe
%define V_TB   736      ; scratch fe
%define V_ZI   768      ; 1/Z
%define V_XA   800      ; affine x, Montgomery
%define V_XB   832      ; affine x, bytes
%define VERIFY_FRAME 872

; linnea_p256_ecdsa_verify(rdi=hash, rsi=r, rdx=s, rcx=pubkey) -> rax in {0,1}.
;   hash: the 32-byte message digest. r, s: 32 big-endian bytes each (already
;   range-checked here). pubkey: 64 bytes, the uncompressed affine point X||Y
;   (SEC1 without the 0x04 prefix). Returns 1 iff the signature is valid.
linnea_p256_ecdsa_verify:
    sub rsp, VERIFY_FRAME
    mov [rsp + V_HASHP], rdi
    mov [rsp + V_RP], rsi
    mov [rsp + V_SP], rdx
    mov [rsp + V_QP], rcx

    ; 1. r and s must each be in [1, n-1].
    mov rdi, [rsp + V_RP]
    call linnea_p256_scalar_is_valid
    test eax, eax
    jz .bad
    mov rdi, [rsp + V_SP]
    call linnea_p256_scalar_is_valid
    test eax, eax
    jz .bad

    ; 2. The public-key coordinates must be canonical (each < p) BEFORE
    ;    frombytes silently reduces them.
    mov rdi, [rsp + V_QP]
    call linnea_p256_fe_is_valid
    test eax, eax
    jz .bad
    mov rdi, [rsp + V_QP]
    add rdi, 32
    call linnea_p256_fe_is_valid
    test eax, eax
    jz .bad

    ; 3. Build Q = (X : Y : 1) and check it is on the curve. An off-curve Q is
    ;    the invalid-curve attack; the complete addition formula would give a
    ;    confident wrong answer, so this rejection is security-critical.
    lea rdi, [rsp + V_QPT + linnea_p256_point.x]
    mov rsi, [rsp + V_QP]
    call linnea_p256_fe_frombytes
    lea rdi, [rsp + V_QPT + linnea_p256_point.y]
    mov rsi, [rsp + V_QP]
    add rsi, 32
    call linnea_p256_fe_frombytes
    lea rdi, [rsp + V_QPT + linnea_p256_point.z]
    call linnea_p256_fe_1

    lea rdi, [rsp + V_BM]                       ; b -> Montgomery
    lea rsi, [p256_b_be]
    call linnea_p256_fe_frombytes

    lea rdi, [rsp + V_LHS]                      ; lhs = Y^2
    lea rsi, [rsp + V_QPT + linnea_p256_point.y]
    call linnea_p256_fe_sq
    lea rdi, [rsp + V_TA]                       ; ta = X^2
    lea rsi, [rsp + V_QPT + linnea_p256_point.x]
    call linnea_p256_fe_sq
    lea rdi, [rsp + V_TA]                       ; ta = X^3
    lea rsi, [rsp + V_TA]
    lea rdx, [rsp + V_QPT + linnea_p256_point.x]
    call linnea_p256_fe_mul
    lea rdi, [rsp + V_TB]                       ; tb = 2X
    lea rsi, [rsp + V_QPT + linnea_p256_point.x]
    lea rdx, [rsp + V_QPT + linnea_p256_point.x]
    call linnea_p256_fe_add
    lea rdi, [rsp + V_TB]                       ; tb = 3X
    lea rsi, [rsp + V_TB]
    lea rdx, [rsp + V_QPT + linnea_p256_point.x]
    call linnea_p256_fe_add
    lea rdi, [rsp + V_RHS]                      ; rhs = X^3 - 3X
    lea rsi, [rsp + V_TA]
    lea rdx, [rsp + V_TB]
    call linnea_p256_fe_sub
    lea rdi, [rsp + V_RHS]                      ; rhs = X^3 - 3X + b
    lea rsi, [rsp + V_RHS]
    lea rdx, [rsp + V_BM]
    call linnea_p256_fe_add
    lea rdi, [rsp + V_TA]                       ; lhs - rhs
    lea rsi, [rsp + V_LHS]
    lea rdx, [rsp + V_RHS]
    call linnea_p256_fe_sub
    lea rdi, [rsp + V_TA]
    call linnea_p256_fe_is_zero
    test eax, eax
    jz .bad

    ; 4. w = s^-1 mod n; u1 = e*w; u2 = r*w (all mod n, Montgomery).
    lea rdi, [rsp + V_SM]
    mov rsi, [rsp + V_SP]
    call linnea_p256_scalar_frombytes
    lea rdi, [rsp + V_W]
    lea rsi, [rsp + V_SM]
    call linnea_p256_scalar_inv
    lea rdi, [rsp + V_EM]
    mov rsi, [rsp + V_HASHP]
    call linnea_p256_scalar_frombytes
    lea rdi, [rsp + V_RM]
    mov rsi, [rsp + V_RP]
    call linnea_p256_scalar_frombytes
    lea rdi, [rsp + V_U1]
    lea rsi, [rsp + V_EM]
    lea rdx, [rsp + V_W]
    call linnea_p256_scalar_mul
    lea rdi, [rsp + V_U2]
    lea rsi, [rsp + V_RM]
    lea rdx, [rsp + V_W]
    call linnea_p256_scalar_mul

    ; The ladder reads its scalar as PLAIN big-endian bytes, so convert u1, u2
    ; out of Montgomery form first -- the easy place to go wrong.
    lea rdi, [rsp + V_U1B]
    lea rsi, [rsp + V_U1]
    call linnea_p256_scalar_tobytes
    lea rdi, [rsp + V_U2B]
    lea rsi, [rsp + V_U2]
    call linnea_p256_scalar_tobytes

    ; 5. R = u1*G + u2*Q.
    lea rdi, [rsp + V_RPT]
    lea rsi, [rsp + V_U1B]
    lea rdx, [linnea_p256_g]
    call linnea_p256_point_mul
    lea rdi, [rsp + V_T2]
    lea rsi, [rsp + V_U2B]
    lea rdx, [rsp + V_QPT]
    call linnea_p256_point_mul
    lea rdi, [rsp + V_RPT]                      ; add allows r to alias p
    lea rsi, [rsp + V_RPT]
    lea rdx, [rsp + V_T2]
    call linnea_p256_point_add

    ; 6. Reject R == infinity (Z == 0).
    lea rdi, [rsp + V_RPT + linnea_p256_point.z]
    call linnea_p256_fe_is_zero
    test eax, eax
    jnz .bad

    ; 7. v = x(R) mod n = (X/Z) reduced mod n.
    lea rdi, [rsp + V_ZI]
    lea rsi, [rsp + V_RPT + linnea_p256_point.z]
    call linnea_p256_fe_inv
    lea rdi, [rsp + V_XA]
    lea rsi, [rsp + V_RPT + linnea_p256_point.x]
    lea rdx, [rsp + V_ZI]
    call linnea_p256_fe_mul
    lea rdi, [rsp + V_XB]
    lea rsi, [rsp + V_XA]
    call linnea_p256_fe_tobytes
    lea rdi, [rsp + V_VV]
    lea rsi, [rsp + V_XB]
    call linnea_p256_scalar_frombytes

    ; 8. Accept iff v == r (mod n): v - r == 0.
    lea rdi, [rsp + V_VV]
    lea rsi, [rsp + V_VV]
    lea rdx, [rsp + V_RM]
    call linnea_p256_scalar_sub
    lea rdi, [rsp + V_VV]
    call linnea_p256_scalar_is_zero             ; rax = accept/reject
    add rsp, VERIFY_FRAME
    ret

.bad:
    xor eax, eax
    add rsp, VERIFY_FRAME
    ret

; p256_der_parse_uint(rdi=in, rsi=inlen, rdx=out32) -> rax = bytes consumed
;   (tag+len+content) on success, 0 on any error. Strict DER for a non-negative
;   INTEGER: tag 0x02, short-form length, minimal encoding (no needless leading
;   0x00), non-negative (top content bit clear), magnitude <= 32 bytes.
;   Left-pads the magnitude big-endian into out32. File-local.
;
;   Strictness matters: lax/BER decoding is a classic signature-malleability and
;   bypass source (Wycheproof exercises it heavily).
p256_der_parse_uint:
    cmp rsi, 2                  ; need at least tag + length
    jb .err
    cmp byte [rdi], 0x02        ; INTEGER tag
    jne .err
    movzx rcx, byte [rdi + 1]   ; length
    test rcx, rcx
    jz .err                     ; empty INTEGER is invalid
    cmp rcx, 0x80
    jae .err                    ; long form / indefinite not allowed
    lea rax, [rcx + 2]          ; tag + len + content must fit in inlen
    cmp rax, rsi
    ja .err
    test byte [rdi + 2], 0x80   ; top bit set => negative => reject
    jnz .err
    cmp rcx, 1
    je .nozero
    cmp byte [rdi + 2], 0
    jne .nozero
    test byte [rdi + 3], 0x80   ; leading 0x00 legal only to clear a set top bit
    jz .err                     ; otherwise it is non-minimal
    lea r10, [rdi + 3]          ; strip the pad byte
    lea r11, [rcx - 1]
    jmp .havemag
.nozero:
    lea r10, [rdi + 2]
    mov r11, rcx
.havemag:
    cmp r11, 32                 ; magnitude wider than the field => reject
    ja .err
    xor eax, eax                ; zero the 32-byte output
    mov [rdx], rax
    mov [rdx + 8], rax
    mov [rdx + 16], rax
    mov [rdx + 24], rax
    mov r8, 32                  ; left-pad: dest = out + (32 - maglen)
    sub r8, r11
    lea r9, [rdx + r8]
    xor rax, rax
.cp:
    cmp rax, r11
    jae .cpdone
    mov r8b, [r10 + rax]
    mov [r9 + rax], r8b
    inc rax
    jmp .cp
.cpdone:
    lea rax, [rcx + 2]          ; consumed = tag + len + content
    ret
.err:
    xor eax, eax
    ret

; Stack layout for linnea_p256_ecdsa_verify_der.
%define D_HASH  0
%define D_DER   8
%define D_PUB  16
%define D_R    24
%define D_S    56
%define D_CR   88               ; bytes consumed by r
%define D_FRAME 104             ; no pushes; 104 == 8 mod 16

; linnea_p256_ecdsa_verify_der(rdi=hash, rsi=der, rdx=der_len, rcx=pubkey)
;   -> rax in {0,1}. Strictly decodes SEQUENCE { INTEGER r, INTEGER s } and
;   verifies. Any decode error returns 0 (no fallback, no partial accept).
linnea_p256_ecdsa_verify_der:
    sub rsp, D_FRAME
    mov [rsp + D_HASH], rdi
    mov [rsp + D_DER], rsi
    mov [rsp + D_PUB], rcx

    cmp rdx, 2                  ; SEQUENCE tag + length
    jb .derbad
    cmp byte [rsi], 0x30
    jne .derbad
    movzx rax, byte [rsi + 1]  ; L
    cmp rax, 0x80
    jae .derbad                ; long form not allowed
    lea r8, [rax + 2]          ; 2 + L must be exactly der_len (no trailing data)
    cmp r8, rdx
    jne .derbad

    lea rdi, [rsi + 2]         ; parse r from the SEQUENCE content
    mov rsi, rax               ; available = L
    lea rdx, [rsp + D_R]
    call p256_der_parse_uint
    test rax, rax
    jz .derbad
    mov [rsp + D_CR], rax

    mov rsi, [rsp + D_DER]     ; parse s, right after r
    movzx rcx, byte [rsi + 1]  ; L
    mov r10, [rsp + D_CR]
    lea rdi, [rsi + 2]
    add rdi, r10
    mov rsi, rcx
    sub rsi, r10               ; available = L - consumed(r)
    lea rdx, [rsp + D_S]
    call p256_der_parse_uint
    test rax, rax
    jz .derbad

    add rax, [rsp + D_CR]      ; r and s together must fill the SEQUENCE exactly
    mov rsi, [rsp + D_DER]
    movzx rcx, byte [rsi + 1]
    cmp rax, rcx
    jne .derbad

    mov rdi, [rsp + D_HASH]
    lea rsi, [rsp + D_R]
    lea rdx, [rsp + D_S]
    mov rcx, [rsp + D_PUB]
    call linnea_p256_ecdsa_verify
    add rsp, D_FRAME
    ret
.derbad:
    xor eax, eax
    add rsp, D_FRAME
    ret
