; linnea_tls_client.asm — the TLS 1.3 CLIENT handshake, for backend TLS.
;
; linnea is a TLS server everywhere else; this is the other direction: the
; reverse proxy connecting to an HTTPS backend. The protocol body mirrors
; linnea-probe's client handshake, but this one AUTHENTICATES the peer -- it
; pins the server's certificate and verifies its CertificateVerify -- and is
; shaped as a state machine (linnea_tls_client_input) so the same code serves a
; blocking test driver and the async io_uring proxy path.
;
; Authentication is by SPKI PIN, not a trust store: the operator runs the
; backend, so the trust decision is "this exact P-256 key" (see
; docs/design/tls-client-handshake-plan.md and backend-tls-h2.md).
;
; ABI: System V; callee-saved preserved.

default rel

global linnea_tls_client_verify_certverify

extern linnea_sha256
extern linnea_p256_ecdsa_verify_der

section .rodata

; RFC 8446 4.4.3: the CertificateVerify signature is over
;   64 * 0x20  ||  "TLS 1.3, server CertificateVerify"  ||  0x00  ||  Th
; where Th is the transcript hash through the Certificate message. The label
; here includes that trailing 0x00 separator.
cv_context:     db "TLS 1.3, server CertificateVerify", 0
cv_context_len  equ $ - cv_context               ; 34, including the 0x00

section .text

; Stack layout for linnea_tls_client_verify_certverify.
%define CV_SC     0      ; the signed content: 64 + 34 + 32 = 130 bytes
%define CV_DG   136      ; SHA-256 of the signed content
%define CV_HASH 168      ; saved transcript-hash pointer
%define CV_SIG  176      ; saved signature DER pointer
%define CV_SLEN 184      ; saved signature DER length
%define CV_PUB  192      ; saved public-key pointer
%define CV_FRAME 200     ; no pushes; 200 == 8 mod 16 -> rsp 16-aligned at calls

; linnea_tls_client_verify_certverify(rdi=transcript_hash(32), rsi=sig_der,
;   rdx=sig_len, rcx=pubkey(64)) -> rax in {0,1}. Rebuilds the RFC 8446 signed
;   content, hashes it, and verifies the DER ECDSA signature under the server's
;   P-256 public key (the one extracted from the pinned certificate). 1 = the
;   server holds the private key for that certificate; 0 = reject.
linnea_tls_client_verify_certverify:
    sub rsp, CV_FRAME
    mov [rsp + CV_HASH], rdi
    mov [rsp + CV_SIG], rsi
    mov [rsp + CV_SLEN], rdx
    mov [rsp + CV_PUB], rcx

    mov rax, 0x2020202020202020             ; 64 spaces
    mov [rsp + CV_SC + 0], rax
    mov [rsp + CV_SC + 8], rax
    mov [rsp + CV_SC + 16], rax
    mov [rsp + CV_SC + 24], rax
    mov [rsp + CV_SC + 32], rax
    mov [rsp + CV_SC + 40], rax
    mov [rsp + CV_SC + 48], rax
    mov [rsp + CV_SC + 56], rax

    lea rsi, [cv_context]                    ; context string + 0x00
    lea rdi, [rsp + CV_SC + 64]
    mov ecx, cv_context_len
    rep movsb

    mov rsi, [rsp + CV_HASH]                 ; transcript hash
    lea rdi, [rsp + CV_SC + 64 + cv_context_len]
    mov ecx, 32
    rep movsb

    lea rdi, [rsp + CV_SC]                   ; digest = SHA-256(signed content)
    mov esi, 64 + cv_context_len + 32
    lea rdx, [rsp + CV_DG]
    call linnea_sha256

    lea rdi, [rsp + CV_DG]                   ; verify the signature
    mov rsi, [rsp + CV_SIG]
    mov rdx, [rsp + CV_SLEN]
    mov rcx, [rsp + CV_PUB]
    call linnea_p256_ecdsa_verify_der        ; rax = accept/reject
    add rsp, CV_FRAME
    ret
