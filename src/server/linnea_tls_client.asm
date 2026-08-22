; linnea_tls_client.asm — the TLS 1.3 CLIENT handshake, for backend TLS.
;
; linnea is a TLS server everywhere else; this is the other direction: the
; reverse proxy connecting to an HTTPS backend. The protocol body mirrors
; linnea-probe's client handshake, but this one AUTHENTICATES the peer -- it
; PINS the server's certificate (SHA-256 of the SubjectPublicKeyInfo) and
; verifies its CertificateVerify and Finished. Authentication is by pin, not a
; trust store: the operator runs the backend, so the trust decision is "this
; exact P-256 key" (see docs/design/tls-client-handshake-plan.md).
;
; This is the blocking form, used by the linnea-tlsclient test harness to prove
; the protocol + authentication end to end. The async io_uring proxy path (which
; will drive the same crypto over a per-connection state arena) is a later brick;
; the .bss state here means one handshake at a time, which the harness satisfies.
;
; ABI: System V; callee-saved preserved. Profile: TLS 1.3, x25519,
; TLS_AES_128_GCM_SHA256, ecdsa_secp256r1_sha256 -- the same fixed profile
; linnea serves.

default rel

%include "linnea_syscall.inc"
%include "linnea_tls.inc"

global linnea_tls_client_verify_certverify
global linnea_tls_client_handshake
global linnea_tls_client_app_send
global linnea_tls_client_app_recv

extern linnea_x25519
extern linnea_sha256
extern linnea_hmac_sha256
extern linnea_hkdf_extract
extern linnea_tls_derive_secret
extern linnea_tls_hkdf_expand_label
extern linnea_tls_keys_init
extern linnea_tls_seal
extern linnea_tls_open
extern linnea_p256_ecdsa_verify_der
extern linnea_x509_find_spki
extern linnea_x509_spki_point

%define TR_BUF_CAP 16384
%define REC_CAP    20480

section .rodata

; TLS 1.3 key-schedule labels (RFC 8446 7.1) and constants.
empty_hash:  db 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8
             db 0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c
             db 0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55           ; SHA-256("")
zeros32:     times 32 db 0
x25519_base: db 9
             times 31 db 0
lbl_derived:  db "derived"
lbl_c_hs:     db "c hs traffic"
lbl_s_hs:     db "s hs traffic"
lbl_c_ap:     db "c ap traffic"
lbl_s_ap:     db "s ap traffic"
lbl_finished: db "finished"

; ClientHello static bytes. cipher_suites = TLS_AES_128_GCM_SHA256, one
; compression method (null). signature_algorithms = ecdsa_secp256r1_sha256 only:
; we pin an ECDSA backend and can only verify P-256, so we advertise nothing we
; cannot check.
ch_suites:   db 0x00, 0x02, 0x13, 0x01, 0x01, 0x00
ch_suites_len equ $ - ch_suites
ch_sigalgs:  db 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03
ch_sigalgs_len equ $ - ch_sigalgs

; The HelloRetryRequest sentinel ServerHello.random (RFC 8446 4.1.3). We offer
; only x25519, so an HRR means the server wants a group we do not have: fail.
hrr_random:  db 0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02
             db 0x1E,0x65,0xB8,0x91,0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E
             db 0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C

; RFC 8446 4.4.3 CertificateVerify context label (includes the 0x00 separator).
cv_context:  db "TLS 1.3, server CertificateVerify", 0
cv_context_len equ $ - cv_context

section .bss

alignb 8
cli_fd:       resq 1
cli_pin:      resq 1          ; -> 32-byte pinned SHA-256(SPKI)
cli_out:      resq 1          ; -> 64-byte out: c_ap || s_ap
cli_sni_ptr:  resq 1
cli_sni_len:  resq 1
cli_alpn_ptr: resq 1
cli_alpn_len: resq 1

tls_priv:     resb 32
tls_pub:      resb 32
tls_random:   resb 32
tls_sessid:   resb 32
tls_shared:   resb 32
tls_srvpub:   resb 32
sec_early:    resb 32
sec_derived:  resb 32
sec_hs:       resb 32
sec_chs:      resb 32
sec_shs:      resb 32
sec_master:   resb 32
sec_cap:      resb 32
sec_sap:      resb 32
th_buf:       resb 32
fin_key:      resb 32
srv_fin_key:  resb 32
srv_fin_calc: resb 32
spki_hash:    resb 32
cv_sc:        resb 160         ; CertificateVerify signed-content scratch
cli_pubkey:   resb 64          ; extracted server public key X||Y

tr_len:       resq 1
hs_plain_len: resq 1
parse_off:    resq 1
rec_total:    resq 1
sv_bodylen:   resq 1          ; current handshake message body length
sv_spki:      resq 1          ; leaf SPKI span (ptr, len) across the pin hash
sv_spkilen:   resq 1

alignb 16
tls_wkeys:    resb linnea_tls_keys_size
tls_rkeys:    resb linnea_tls_keys_size
hs_buf:       resb 4096
tr_buf:       resb TR_BUF_CAP
tls_rec:      resb REC_CAP
hs_plain:     resb REC_CAP

section .text

; ============================================================================
; CertificateVerify signature check (also used standalone by the selftest).
; ============================================================================

%define CV_SCF    0
%define CV_DG   160
%define CV_HASH 192
%define CV_SIG  200
%define CV_SLEN 208
%define CV_PUB  216
%define CV_FRAME 232

; linnea_tls_client_verify_certverify(rdi=transcript_hash(32), rsi=sig_der,
;   rdx=sig_len, rcx=pubkey(64)) -> rax in {0,1}. Rebuilds the RFC 8446 signed
;   content, hashes it, and ECDSA-verifies the DER signature under the server's
;   P-256 key. Uses a local frame so it is reentrant / callable in isolation.
linnea_tls_client_verify_certverify:
    sub rsp, CV_FRAME
    mov [rsp + CV_HASH], rdi
    mov [rsp + CV_SIG], rsi
    mov [rsp + CV_SLEN], rdx
    mov [rsp + CV_PUB], rcx
    mov rax, 0x2020202020202020
    mov [rsp + CV_SCF + 0], rax
    mov [rsp + CV_SCF + 8], rax
    mov [rsp + CV_SCF + 16], rax
    mov [rsp + CV_SCF + 24], rax
    mov [rsp + CV_SCF + 32], rax
    mov [rsp + CV_SCF + 40], rax
    mov [rsp + CV_SCF + 48], rax
    mov [rsp + CV_SCF + 56], rax
    lea rsi, [cv_context]
    lea rdi, [rsp + CV_SCF + 64]
    mov ecx, cv_context_len
    rep movsb
    mov rsi, [rsp + CV_HASH]
    lea rdi, [rsp + CV_SCF + 64 + cv_context_len]
    mov ecx, 32
    rep movsb
    lea rdi, [rsp + CV_SCF]
    mov esi, 64 + cv_context_len + 32
    lea rdx, [rsp + CV_DG]
    call linnea_sha256
    lea rdi, [rsp + CV_DG]
    mov rsi, [rsp + CV_SIG]
    mov rdx, [rsp + CV_SLEN]
    mov rcx, [rsp + CV_PUB]
    call linnea_p256_ecdsa_verify_der
    add rsp, CV_FRAME
    ret

; ============================================================================
; Small blocking helpers.
; ============================================================================

; read_all(rdi=fd, rsi=buf, rdx=n) -> rax = 0 ok / -1 on EOF/error.
read_all:
    push rbx
    push r12
    push r13
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
.loop:
    test r13, r13
    jz .ok
    mov eax, LINNEA_SYS_READ
    mov edi, ebx
    mov rsi, r12
    mov rdx, r13
    syscall
    test rax, rax
    jle .fail
    add r12, rax
    sub r13, rax
    jmp .loop
.ok:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret

; send_all(rdi=fd, rsi=buf, rdx=n) -> rax = 0 ok / -1.
send_all:
    push rbx
    push r12
    push r13
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
.loop:
    test r13, r13
    jz .ok
    mov eax, LINNEA_SYS_WRITE
    mov edi, ebx
    mov rsi, r12
    mov rdx, r13
    syscall
    test rax, rax
    jle .fail
    add r12, rax
    sub r13, rax
    jmp .loop
.ok:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret

; recv_record(rdi=fd) -> rax = outer content type (-1 on error). The record
; lands at tls_rec; rec_total = 5 + payload length.
recv_record:
    push rbx
    mov ebx, edi
    mov edi, ebx
    lea rsi, [tls_rec]
    mov edx, 5
    call read_all
    test rax, rax
    js .fail
    movzx eax, byte [tls_rec + 3]
    shl eax, 8
    movzx ecx, byte [tls_rec + 4]
    or eax, ecx
    cmp eax, REC_CAP - 5
    ja .fail
    mov [rec_total], rax
    test eax, eax
    jz .empty
    mov edi, ebx
    lea rsi, [tls_rec + 5]
    mov edx, [rec_total]
    call read_all
    test rax, rax
    js .fail
.empty:
    mov rax, [rec_total]
    add rax, 5
    mov [rec_total], rax
    movzx eax, byte [tls_rec]
    pop rbx
    ret
.fail:
    mov rax, -1
    pop rbx
    ret

; tr_add(rsi=buf, rdx=len) — append to the transcript, bounded.
tr_add:
    mov rcx, TR_BUF_CAP
    sub rcx, [tr_len]
    cmp rdx, rcx
    ja .overflow
    push rdi
    mov rdi, [tr_len]
    lea rdi, [tr_buf + rdi]
    mov rcx, rdx
    rep movsb
    add [tr_len], rdx
    pop rdi
    ret
.overflow:
    ret                          ; leaves tr_len unchanged; a later hash mismatch
                                 ; turns a too-large transcript into a clean fail

; eq32(rdi, rsi) -> rax = 1 if the 32 bytes are equal, else 0 (constant time).
eq32:
    xor eax, eax
    mov ecx, 4
.l:
    mov rdx, [rdi]
    xor rdx, [rsi]
    or rax, rdx
    add rdi, 8
    add rsi, 8
    dec ecx
    jnz .l
    neg rax
    sbb rax, rax
    inc rax
    ret

; ============================================================================
; ServerHello parse and ClientHello build (ported from linnea-probe).
; ============================================================================

; parse_serverhello(rsi=HS ptr, rdx=HS len) -> rax = 0 ok / -1. Extracts the
; server x25519 key_share into tls_srvpub.
parse_serverhello:
    push rbx
    push r12
    mov rbx, rsi
    lea r12, [rsi + rdx]
    add rbx, 4 + 2 + 32
    cmp rbx, r12
    jae .fail
    movzx eax, byte [rbx]
    inc rbx
    add rbx, rax
    add rbx, 2 + 1
    cmp rbx, r12
    jae .fail
    add rbx, 2
.ext:
    lea rax, [rbx + 4]
    cmp rax, r12
    ja .fail
    movzx eax, byte [rbx]
    shl eax, 8
    movzx ecx, byte [rbx + 1]
    or eax, ecx
    movzx edx, byte [rbx + 2]
    shl edx, 8
    movzx ecx, byte [rbx + 3]
    or edx, ecx
    add rbx, 4
    cmp eax, 0x0033
    je .keyshare
    add rbx, rdx
    jmp .ext
.keyshare:
    lea rax, [rbx + 4 + 32]
    cmp rax, r12
    ja .fail
    lea rdi, [tls_srvpub]
    lea rsi, [rbx + 4]
    mov ecx, 32
    rep movsb
    xor eax, eax
    pop r12
    pop rbx
    ret
.fail:
    mov rax, -1
    pop r12
    pop rbx
    ret

; build_clienthello() -> rax = total record length (record at hs_buf); appends
; the ClientHello to the transcript. Uses cli_sni_* and cli_alpn_* globals.
build_clienthello:
    push rbx
    push r12
    push r13
    mov r12, [cli_sni_len]
    lea rdi, [hs_buf + 5]
    mov byte [rdi], 0x01
    lea r13, [rdi + 1]
    add rdi, 4
    mov byte [rdi], 0x03
    mov byte [rdi + 1], 0x03
    add rdi, 2
    lea rsi, [tls_random]
    mov ecx, 32
    rep movsb
    mov byte [rdi], 32
    inc rdi
    lea rsi, [tls_sessid]
    mov ecx, 32
    rep movsb
    lea rsi, [ch_suites]
    mov ecx, ch_suites_len
    rep movsb
    mov rbx, rdi
    add rdi, 2
    ; SNI
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x00
    lea rax, [r12 + 5]
    mov [rdi + 2], ah
    mov [rdi + 3], al
    lea rax, [r12 + 3]
    mov [rdi + 4], ah
    mov [rdi + 5], al
    mov byte [rdi + 6], 0x00
    mov rax, r12
    mov [rdi + 7], ah
    mov [rdi + 8], al
    add rdi, 9
    mov rsi, [cli_sni_ptr]
    mov rcx, r12
    rep movsb
    ; supported_versions (TLS 1.3)
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x2b
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x03
    mov byte [rdi + 4], 0x02
    mov byte [rdi + 5], 0x03
    mov byte [rdi + 6], 0x04
    add rdi, 7
    ; supported_groups (x25519)
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x0a
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x04
    mov byte [rdi + 4], 0x00
    mov byte [rdi + 5], 0x02
    mov byte [rdi + 6], 0x00
    mov byte [rdi + 7], 0x1d
    add rdi, 8
    ; signature_algorithms (ecdsa_secp256r1_sha256)
    lea rsi, [ch_sigalgs]
    mov ecx, ch_sigalgs_len
    rep movsb
    ; key_share (x25519)
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x33
    mov byte [rdi + 2], 0x00
    mov byte [rdi + 3], 0x26
    mov byte [rdi + 4], 0x00
    mov byte [rdi + 5], 0x24
    mov byte [rdi + 6], 0x00
    mov byte [rdi + 7], 0x1d
    mov byte [rdi + 8], 0x00
    mov byte [rdi + 9], 0x20
    add rdi, 10
    lea rsi, [tls_pub]
    mov ecx, 32
    rep movsb
    ; ALPN
    mov r8, [cli_alpn_len]
    mov byte [rdi], 0x00
    mov byte [rdi + 1], 0x10
    lea rax, [r8 + 3]
    mov [rdi + 2], ah
    mov [rdi + 3], al
    lea rax, [r8 + 1]
    mov [rdi + 4], ah
    mov [rdi + 5], al
    mov [rdi + 6], r8b
    add rdi, 7
    mov rsi, [cli_alpn_ptr]
    mov rcx, r8
    rep movsb
    ; backpatch extensions length
    mov rax, rdi
    sub rax, rbx
    sub rax, 2
    mov [rbx], ah
    mov [rbx + 1], al
    ; backpatch handshake body length (24-bit)
    mov rax, rdi
    sub rax, r13
    sub rax, 3
    mov byte [r13], 0
    mov ecx, eax
    shr ecx, 8
    mov [r13 + 1], cl
    mov [r13 + 2], al
    ; record header
    mov byte [hs_buf], 0x16
    mov byte [hs_buf + 1], 0x03
    mov byte [hs_buf + 2], 0x01
    mov rax, rdi
    lea rcx, [hs_buf + 5]
    sub rax, rcx
    mov [hs_buf + 3], ah
    mov [hs_buf + 4], al
    ; transcript += ClientHello
    lea rsi, [hs_buf + 5]
    mov rdx, rax
    push rax
    call tr_add
    pop rax
    add rax, 5
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; The handshake.
; ============================================================================

%define ALPN_H1 alpn_h1
section .rodata
alpn_h1: db "http/1.1"
alpn_h1_len equ $ - alpn_h1
section .text

; linnea_tls_client_handshake(rdi=fd, rsi=pin32, rdx=sni_ptr, rcx=sni_len,
;   r8=out_secrets) -> rax = 0 on success (out_secrets = c_ap(32) || s_ap(32),
;   and tls_wkeys/tls_rkeys are set to the application keys for app_send/recv),
;   negative on any failure. Authenticates the server by the SPKI pin, its
;   CertificateVerify, and its Finished.
linnea_tls_client_handshake:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and rsp, -16
    mov [cli_fd], rdi
    mov [cli_pin], rsi
    mov [cli_out], r8
    mov [cli_sni_ptr], rdx
    mov [cli_sni_len], rcx
    lea rax, [alpn_h1]
    mov [cli_alpn_ptr], rax
    mov qword [cli_alpn_len], alpn_h1_len
    mov r15, rdi                          ; fd (kept in a reg too)

    ; x25519 keypair
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [tls_priv]
    mov esi, 32
    xor edx, edx
    syscall
    and byte [tls_priv], 248
    and byte [tls_priv + 31], 127
    or byte [tls_priv + 31], 64
    lea rdi, [tls_pub]
    lea rsi, [tls_priv]
    lea rdx, [x25519_base]
    call linnea_x25519
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [tls_random]
    mov esi, 32
    xor edx, edx
    syscall
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [tls_sessid]
    mov esi, 32
    xor edx, edx
    syscall
    mov qword [tr_len], 0

    ; ClientHello
    call build_clienthello
    mov edi, r15d
    lea rsi, [hs_buf]
    mov rdx, rax
    call send_all
    test rax, rax
    js .fail

    ; ServerHello
    mov edi, r15d
    call recv_record
    cmp rax, 22
    jne .fail
    ; reject a HelloRetryRequest (its ServerHello.random is the fixed sentinel)
    lea rdi, [tls_rec + 5 + 6]            ; type(1)+len(3)+version(2) -> random
    lea rsi, [hrr_random]
    call eq32
    test eax, eax
    jnz .fail
    lea rsi, [tls_rec + 5]
    mov rdx, [rec_total]
    sub rdx, 5
    push rsi
    push rdx
    call tr_add
    pop rdx
    pop rsi
    call parse_serverhello
    test rax, rax
    js .fail

    ; shared = x25519(priv, srvpub)
    lea rdi, [tls_shared]
    lea rsi, [tls_priv]
    lea rdx, [tls_srvpub]
    call linnea_x25519
    ; early = HKDF-Extract(0, 0)
    lea rdi, [zeros32]
    xor esi, esi
    lea rdx, [zeros32]
    mov ecx, 32
    lea r8, [sec_early]
    call linnea_hkdf_extract
    ; derived = Derive-Secret(early, "derived", H(""))
    lea rdi, [sec_early]
    lea rsi, [lbl_derived]
    mov edx, 7
    lea rcx, [empty_hash]
    lea r8, [sec_derived]
    call linnea_tls_derive_secret
    ; hs = HKDF-Extract(derived, shared)
    lea rdi, [sec_derived]
    mov esi, 32
    lea rdx, [tls_shared]
    mov ecx, 32
    lea r8, [sec_hs]
    call linnea_hkdf_extract
    ; th = H(CH || SH)
    lea rdi, [tr_buf]
    mov rsi, [tr_len]
    lea rdx, [th_buf]
    call linnea_sha256
    ; c_hs, s_hs
    lea rdi, [sec_hs]
    lea rsi, [lbl_c_hs]
    mov edx, 12
    lea rcx, [th_buf]
    lea r8, [sec_chs]
    call linnea_tls_derive_secret
    lea rdi, [sec_hs]
    lea rsi, [lbl_s_hs]
    mov edx, 12
    lea rcx, [th_buf]
    lea r8, [sec_shs]
    call linnea_tls_derive_secret
    ; derived2, master
    lea rdi, [sec_hs]
    lea rsi, [lbl_derived]
    mov edx, 7
    lea rcx, [empty_hash]
    lea r8, [sec_derived]
    call linnea_tls_derive_secret
    lea rdi, [sec_derived]
    mov esi, 32
    lea rdx, [zeros32]
    mov ecx, 32
    lea r8, [sec_master]
    call linnea_hkdf_extract
    ; handshake traffic keys: write=c_hs, read=s_hs
    lea rdi, [tls_wkeys]
    lea rsi, [sec_chs]
    call linnea_tls_keys_init
    lea rdi, [tls_rkeys]
    lea rsi, [sec_shs]
    call linnea_tls_keys_init

    ; server flight, decrypted into hs_plain
    mov qword [hs_plain_len], 0
    mov qword [parse_off], 0
.flight_read:
    mov edi, r15d
    call recv_record
    test rax, rax
    js .fail
    cmp rax, 20
    je .flight_read                       ; ChangeCipherSpec: ignore
    cmp rax, 23
    jne .fail
    lea rdi, [tls_rkeys]
    lea rsi, [tls_rec]
    mov rdx, [rec_total]
    mov rcx, [hs_plain_len]
    lea rcx, [hs_plain + rcx]
    call linnea_tls_open
    test rax, rax
    js .fail
    cmp rdx, 22
    jne .fail
    add [hs_plain_len], rax
.walk:
    mov r12, [parse_off]
    mov r13, [hs_plain_len]
    lea rax, [r12 + 4]
    cmp rax, r13
    ja .flight_read
    movzx ecx, byte [hs_plain + r12 + 1]
    shl ecx, 8
    movzx eax, byte [hs_plain + r12 + 2]
    or ecx, eax
    shl ecx, 8
    movzx eax, byte [hs_plain + r12 + 3]
    or ecx, eax                           ; ecx = body length (rcx: high bits 0)
    mov [sv_bodylen], rcx
    lea rax, [r12 + 4]
    add rax, rcx
    cmp rax, r13
    ja .flight_read                       ; message not fully arrived
    movzx r14d, byte [hs_plain + r12]     ; message type
    ; CertificateVerify and Finished need the transcript hash BEFORE this
    ; message is absorbed, so authenticate first, then absorb. Loop-locals live
    ; in .bss (not the stack) so the SSE crypto below stays 16-aligned.
    cmp r14d, 0x0f
    je .do_certverify
    cmp r14d, 0x14
    je .do_finished
    jmp .absorb
.do_certverify:
    lea rdi, [tr_buf]                      ; th_cv = H(CH..Certificate)
    mov rsi, [tr_len]
    lea rdx, [th_buf]
    call linnea_sha256
    movzx eax, byte [hs_plain + r12 + 4]  ; sig_alg
    shl eax, 8
    movzx edx, byte [hs_plain + r12 + 5]
    or eax, edx
    cmp eax, 0x0403                       ; ecdsa_secp256r1_sha256 only
    jne .fail
    movzx edx, byte [hs_plain + r12 + 6]  ; sig_len
    shl edx, 8
    movzx eax, byte [hs_plain + r12 + 7]
    or edx, eax
    lea rsi, [hs_plain + r12 + 8]         ; sig DER
    lea rdi, [th_buf]
    lea rcx, [cli_pubkey]
    call linnea_tls_client_verify_certverify
    test eax, eax
    jz .fail
    jmp .absorb
.do_finished:
    lea rdi, [tr_buf]                      ; th_fin = H(CH..CertificateVerify)
    mov rsi, [tr_len]
    lea rdx, [th_buf]
    call linnea_sha256
    ; srv_fin_key = HKDF-Expand-Label(s_hs, "finished", "", 32)
    lea rdi, [sec_shs]
    lea rsi, [lbl_finished]
    mov edx, 8
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [srv_fin_key]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    lea rdi, [srv_fin_key]                 ; expected = HMAC(srv_fin_key, th_fin)
    mov esi, 32
    lea rdx, [th_buf]
    mov ecx, 32
    lea r8, [srv_fin_calc]
    call linnea_hmac_sha256
    lea rdi, [srv_fin_calc]                ; compare to the message's verify_data
    lea rsi, [hs_plain + r12 + 4]
    call eq32
    test eax, eax
    jz .fail
    mov rcx, [sv_bodylen]                  ; absorb the server Finished, then done
    lea rsi, [hs_plain + r12]
    lea rdx, [rcx + 4]
    call tr_add
    jmp .flight_done
.absorb:
    mov rcx, [sv_bodylen]
    lea rsi, [hs_plain + r12]
    lea rdx, [rcx + 4]
    call tr_add
    cmp r14d, 0x0b                        ; Certificate: pin + extract pubkey
    je .do_cert
    mov rcx, [sv_bodylen]
    lea r12, [r12 + rcx + 4]
    mov [parse_off], r12
    jmp .walk
.do_cert:
    ; body: ctx_len(1) [ctx] list_len(3) entry{ der_len(3) der ext(2) } ...
    lea rbx, [hs_plain + r12 + 4]         ; body
    movzx eax, byte [rbx]                 ; certificate_request_context length
    lea rbx, [rbx + rax + 1]              ; skip ctx
    add rbx, 3                            ; skip certificate_list length (u24)
    movzx eax, byte [rbx]                 ; leaf der_len (u24)
    shl eax, 8
    movzx edx, byte [rbx + 1]
    or eax, edx
    shl eax, 8
    movzx edx, byte [rbx + 2]
    or eax, edx
    lea rdi, [rbx + 3]                    ; leaf DER
    mov rsi, rax                          ; leaf DER length
    call linnea_x509_find_spki           ; rax = SPKI ptr (0 fail), rdx = len
    test rax, rax
    jz .fail
    mov [sv_spki], rax
    mov [sv_spkilen], rdx
    mov rdi, rax                          ; pin: sha256(SPKI) == cli_pin
    mov rsi, rdx
    lea rdx, [spki_hash]
    call linnea_sha256
    lea rdi, [spki_hash]
    mov rsi, [cli_pin]
    call eq32
    test eax, eax
    jz .fail
    mov rdi, [sv_spki]                    ; extract the point
    mov rsi, [sv_spkilen]
    lea rdx, [cli_pubkey]
    call linnea_x509_spki_point
    test eax, eax
    jz .fail
    mov rcx, [sv_bodylen]
    lea r12, [r12 + rcx + 4]
    mov [parse_off], r12
    jmp .walk
.flight_done:
    ; app secrets: th2 = H(CH..server Finished)
    lea rdi, [tr_buf]
    mov rsi, [tr_len]
    lea rdx, [th_buf]
    call linnea_sha256
    lea rdi, [sec_master]
    lea rsi, [lbl_c_ap]
    mov edx, 12
    lea rcx, [th_buf]
    lea r8, [sec_cap]
    call linnea_tls_derive_secret
    lea rdi, [sec_master]
    lea rsi, [lbl_s_ap]
    mov edx, 12
    lea rcx, [th_buf]
    lea r8, [sec_sap]
    call linnea_tls_derive_secret

    ; client Finished (under the handshake write keys)
    lea rdi, [sec_chs]
    lea rsi, [lbl_finished]
    mov edx, 8
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [fin_key]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    lea rdi, [fin_key]                     ; verify_data = HMAC(fin_key, th2)
    mov esi, 32
    lea rdx, [th_buf]
    mov ecx, 32
    lea r8, [hs_buf + 4]
    call linnea_hmac_sha256
    mov byte [hs_buf], 0x14
    mov byte [hs_buf + 1], 0
    mov byte [hs_buf + 2], 0
    mov byte [hs_buf + 3], 32
    lea rdi, [tls_wkeys]
    mov esi, 22
    lea rdx, [hs_buf]
    mov ecx, 36
    lea r8, [tls_rec]
    call linnea_tls_seal
    mov edi, r15d
    lea rsi, [tls_rec]
    mov rdx, rax
    call send_all
    test rax, rax
    js .fail

    ; switch to application traffic keys
    lea rdi, [tls_wkeys]
    lea rsi, [sec_cap]
    call linnea_tls_keys_init
    lea rdi, [tls_rkeys]
    lea rsi, [sec_sap]
    call linnea_tls_keys_init

    ; hand the app secrets back to the caller (for the kTLS handoff, later)
    mov rdi, [cli_out]
    lea rsi, [sec_cap]
    mov ecx, 32
    rep movsb
    lea rsi, [sec_sap]
    mov ecx, 32
    rep movsb

    xor eax, eax
    jmp .ret
.fail:
    mov rax, -1
.ret:
    lea rsp, [rbp - 40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ============================================================================
; Application data over the negotiated keys (for the blocking test harness; the
; proxy uses kTLS instead). Uses tls_wkeys/tls_rkeys as set by the handshake.
; ============================================================================

; linnea_tls_client_app_send(rdi=fd, rsi=buf, rdx=len) -> rax = 0 / -1.
linnea_tls_client_app_send:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    and rsp, -16
    mov ebx, edi                           ; fd
    mov r12, rsi                           ; buf
    mov r13, rdx                           ; len
    lea rdi, [tls_wkeys]
    mov esi, 23                            ; inner type application_data
    mov rdx, r12
    mov rcx, r13
    lea r8, [tls_rec]
    call linnea_tls_seal                   ; rax = record length
    mov edi, ebx
    lea rsi, [tls_rec]
    mov rdx, rax
    call send_all
    lea rsp, [rbp - 24]
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; linnea_tls_client_app_recv(rdi=fd, rsi=out, rdx=outcap) -> rax = plaintext
;   length (>=0), or -1. Reads one app-data record and decrypts it. Skips a
;   post-handshake handshake record (e.g. NewSessionTicket) by returning 0.
linnea_tls_client_app_recv:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    and rsp, -16
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
    mov edi, ebx
    call recv_record
    cmp rax, 23
    jne .other
    lea rdi, [tls_rkeys]
    lea rsi, [tls_rec]
    mov rdx, [rec_total]
    lea rcx, [hs_plain]
    call linnea_tls_open                   ; rax = len, rdx = inner type
    test rax, rax
    js .fail
    cmp rdx, 23                            ; application_data
    jne .zero                              ; post-handshake msg / alert: 0
    mov rcx, rax
    cmp rcx, r13
    ja .fail
    mov rdi, r12
    lea rsi, [hs_plain]
    rep movsb
    mov rax, rcx
    jmp .ret
.other:
    cmp rax, 20                            ; CCS: ignore, report 0
    je .zero
    jmp .fail
.zero:
    xor eax, eax
    jmp .ret
.fail:
    mov rax, -1
.ret:
    lea rsp, [rbp - 24]
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
