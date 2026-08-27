; linnea_tls_client.asm — the TLS 1.3 CLIENT handshake, for backend TLS.
;
; linnea is a TLS server everywhere else; this is the other direction: the
; reverse proxy connecting to an HTTPS backend. It AUTHENTICATES the peer -- it
; PINS the server's certificate (SHA-256 of the SubjectPublicKeyInfo) and
; verifies its CertificateVerify and Finished. Authentication is by pin, not a
; trust store: the operator runs the backend (docs/design/tls-client-handshake-plan.md).
;
; One crypto core, two drivers. All state lives in a linnea_tls_client_hs
; (include/linnea_tls_client.inc), addressed through rbx:
;   linnea_tls_client_start(hs, pin, sni, snilen) -- builds the ClientHello.
;   linnea_tls_client_input(hs, in, inlen) -> MORE/DONE/FAIL -- feed received
;     bytes; on DONE, hs.out holds the client Finished to send and hs.c_ap/s_ap
;     are ready for the (kTLS) handoff.
; input() is idempotent per call: it re-processes the whole accumulated inbound
; buffer from the start each time (resetting the re-derivable state), so partial
; records need no fine-grained resume state -- the buffer only grows. The proxy
; will drive start/input from io_uring completions; the blocking
; linnea_tls_client_handshake below drives them in a recv loop for the harness.
;
; Profile: TLS 1.3, x25519, TLS_AES_128_GCM_SHA256, ecdsa_secp256r1_sha256.
; ABI: System V; callee-saved preserved.

default rel

%include "linnea_syscall.inc"
%include "linnea_tls.inc"
%include "linnea_tls_client.inc"

global linnea_tls_client_verify_certverify
global linnea_tls_client_start
global linnea_tls_client_input
global linnea_tls_client_handshake
global linnea_tls_client_app_send
global linnea_tls_client_app_recv
global cli_chunk_cap                   ; test knob: cap the blocking recv chunk
; The per-leg handshake arena pool (linnea_tls_client_pool_init / _hs_for) lives
; in linnea_tls_client_pool.asm so this object stays free of linnea_memory_map,
; which the standalone harness cannot link.
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

%define HS_TMP_CAP 8192

section .rodata

empty_hash:  db 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8
             db 0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c
             db 0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
zeros32:     times 32 db 0
x25519_base: db 9
             times 31 db 0
lbl_derived:  db "derived"
lbl_c_hs:     db "c hs traffic"
lbl_s_hs:     db "s hs traffic"
lbl_c_ap:     db "c ap traffic"
lbl_s_ap:     db "s ap traffic"
lbl_finished: db "finished"

ch_suites:   db 0x00, 0x02, 0x13, 0x01, 0x01, 0x00
ch_suites_len equ $ - ch_suites
ch_sigalgs:  db 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03
ch_sigalgs_len equ $ - ch_sigalgs
alpn_h1:     db "http/1.1"
alpn_h1_len  equ $ - alpn_h1
alpn_h2:     db "h2"
alpn_h2_len  equ $ - alpn_h2

hrr_random:  db 0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02
             db 0x1E,0x65,0xB8,0x91,0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E
             db 0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C

cv_context:  db "TLS 1.3, server CertificateVerify", 0
cv_context_len equ $ - cv_context

section .bss

alignb 16
cli_hs:        resb linnea_tls_client_hs_size    ; the blocking harness's one leg
cli_chunk_cap: resq 1                            ; 0 = read HS_TMP_CAP at a time
hs_tmp:        resb HS_TMP_CAP
app_out:       resb 20480
app_rec:       resb 20480
app_plain:     resb 20480

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
;   rdx=sig_len, rcx=pubkey(64)) -> rax in {0,1}.
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
; Small helpers (no SSE; alignment-agnostic).
; ============================================================================

; eq32(rdi, rsi) -> rax = 1 iff equal, else 0 (constant time).
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

; hs_tr_add(rbx=hs, rsi=buf, rdx=len) — append to the transcript, bounded.
hs_tr_add:
    mov rcx, LINNEA_CLIENT_TR_CAP
    sub rcx, [rbx + linnea_tls_client_hs.tr_len]
    cmp rdx, rcx
    ja .ov
    mov rdi, [rbx + linnea_tls_client_hs.tr_len]
    lea rdi, [rbx + linnea_tls_client_hs.tr_buf + rdi]
    mov rcx, rdx
    rep movsb
    add [rbx + linnea_tls_client_hs.tr_len], rdx
.ov:
    ret

; read_all(rdi=fd, rsi=buf, rdx=n) -> rax = 0 / -1.
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

; send_all(rdi=fd, rsi=buf, rdx=n) -> rax = 0 / -1.
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

; recv_record(rdi=fd, rsi=dst) -> rax = 5 + payload length, or -1. Reads one
; whole TLS record into dst (>= 20480 bytes). Used by the app-recv helper.
recv_record:
    push rbx
    push r12
    mov ebx, edi
    mov r12, rsi
    mov edi, ebx
    mov rsi, r12
    mov edx, 5
    call read_all
    test rax, rax
    js .fail
    movzx eax, byte [r12 + 3]
    shl eax, 8
    movzx ecx, byte [r12 + 4]
    or eax, ecx
    cmp eax, 20480 - 5
    ja .fail
    test eax, eax
    jz .empty
    mov edi, ebx
    lea rsi, [r12 + 5]
    mov edx, eax
    push rax
    call read_all
    pop rcx
    test rax, rax
    js .fail
    lea rax, [rcx + 5]
    pop r12
    pop rbx
    ret
.empty:
    mov eax, 5
    pop r12
    pop rbx
    ret
.fail:
    mov rax, -1
    pop r12
    pop rbx
    ret

; ============================================================================
; Handshake pieces — all take rbx = hs.
; ============================================================================

; parse_serverhello(rbx=hs, rsi=SH ptr, rdx=SH len) -> rax = 0 / -1. Extracts
; the server x25519 key_share into hs.srvpub. No crypto calls.
parse_serverhello:
    mov r8, rsi
    lea r9, [rsi + rdx]
    add r8, 4 + 2 + 32
    cmp r8, r9
    jae .fail
    movzx eax, byte [r8]
    inc r8
    add r8, rax
    add r8, 2 + 1
    cmp r8, r9
    jae .fail
    add r8, 2
.ext:
    lea rax, [r8 + 4]
    cmp rax, r9
    ja .fail
    movzx eax, byte [r8]
    shl eax, 8
    movzx ecx, byte [r8 + 1]
    or eax, ecx
    movzx edx, byte [r8 + 2]
    shl edx, 8
    movzx ecx, byte [r8 + 3]
    or edx, ecx
    add r8, 4
    cmp eax, 0x0033
    je .ks
    add r8, rdx
    jmp .ext
.ks:
    lea rax, [r8 + 4 + 32]
    cmp rax, r9
    ja .fail
    lea rdi, [rbx + linnea_tls_client_hs.srvpub]
    lea rsi, [r8 + 4]
    mov ecx, 32
    rep movsb
    xor eax, eax
    ret
.fail:
    mov rax, -1
    ret

; build_clienthello(rbx=hs) — build the ClientHello record into hs.out, set
; hs.out_len, and absorb the handshake message into the transcript.
build_clienthello:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    and rsp, -16
    mov r12, [rbx + linnea_tls_client_hs.sni_len]
    lea rdi, [rbx + linnea_tls_client_hs.out + 5]
    mov byte [rdi], 0x01
    lea r13, [rdi + 1]
    add rdi, 4
    mov byte [rdi], 0x03
    mov byte [rdi + 1], 0x03
    add rdi, 2
    lea rsi, [rbx + linnea_tls_client_hs.random]
    mov ecx, 32
    rep movsb
    mov byte [rdi], 32
    inc rdi
    lea rsi, [rbx + linnea_tls_client_hs.sessid]
    mov ecx, 32
    rep movsb
    lea rsi, [ch_suites]
    mov ecx, ch_suites_len
    rep movsb
    mov r14, rdi
    add rdi, 2
    ; SNI -- OMITTED ENTIRELY when there is none. RFC 6066 3 defines HostName as
    ; opaque HostName<1..2^16-1>, so a zero-length name is not a legal encoding;
    ; this emitted one whenever sni_len was 0, which is the DEFAULT for a
    ; proxy_tls location with no proxy_sni, not some exotic setting
    ; (audit-report-95). The extensions length below is backpatched from the
    ; cursor, so leaving the block out needs nothing else.
    test r12, r12
    jz .no_sni
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
    mov rsi, [rbx + linnea_tls_client_hs.sni_ptr]
    mov rcx, r12
    rep movsb
.no_sni:
    ; supported_versions
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
    lea rsi, [rbx + linnea_tls_client_hs.pub]
    mov ecx, 32
    rep movsb
    ; ALPN
    mov r8, [rbx + linnea_tls_client_hs.alpn_len]
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
    mov rsi, [rbx + linnea_tls_client_hs.alpn_ptr]
    mov rcx, r8
    rep movsb
    ; backpatch extensions length (r14 is an extended reg -> REX, so no AH)
    mov rax, rdi
    sub rax, r14
    sub rax, 2
    mov ecx, eax
    shr ecx, 8
    mov [r14], cl
    mov [r14 + 1], al
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
    mov byte [rbx + linnea_tls_client_hs.out], 0x16
    mov byte [rbx + linnea_tls_client_hs.out + 1], 0x03
    mov byte [rbx + linnea_tls_client_hs.out + 2], 0x01
    mov rax, rdi
    lea rcx, [rbx + linnea_tls_client_hs.out + 5]
    sub rax, rcx                       ; payload length
    mov [rbx + linnea_tls_client_hs.out + 3], ah
    mov [rbx + linnea_tls_client_hs.out + 4], al
    mov r15, rax                       ; payload length
    lea rax, [rax + 5]
    mov [rbx + linnea_tls_client_hs.out_len], rax
    ; transcript += ClientHello handshake message
    lea rsi, [rbx + linnea_tls_client_hs.out + 5]
    mov rdx, r15
    call hs_tr_add
    lea rsp, [rbp - 24]
    pop r14
    pop r13
    pop r12
    pop rbp
    ret

; derive_hs_keys(rbx=hs) — the TLS 1.3 key schedule up to the handshake traffic
; keys, from hs.srvpub. Sets wkeys=c_hs, rkeys=s_hs (seq 0).
derive_hs_keys:
    push rbp
    mov rbp, rsp
    and rsp, -16
    lea rdi, [rbx + linnea_tls_client_hs.shared]
    lea rsi, [rbx + linnea_tls_client_hs.priv]
    lea rdx, [rbx + linnea_tls_client_hs.srvpub]
    call linnea_x25519
    lea rdi, [zeros32]
    xor esi, esi
    lea rdx, [zeros32]
    mov ecx, 32
    lea r8, [rbx + linnea_tls_client_hs.master]   ; early secret (scratch in master)
    call linnea_hkdf_extract
    lea rdi, [rbx + linnea_tls_client_hs.master]
    lea rsi, [lbl_derived]
    mov edx, 7
    lea rcx, [empty_hash]
    lea r8, [rbx + linnea_tls_client_hs.c_hs]      ; derived (scratch in c_hs)
    call linnea_tls_derive_secret
    lea rdi, [rbx + linnea_tls_client_hs.c_hs]
    mov esi, 32
    lea rdx, [rbx + linnea_tls_client_hs.shared]
    mov ecx, 32
    lea r8, [rbx + linnea_tls_client_hs.master]    ; handshake secret (in master)
    call linnea_hkdf_extract
    ; th = H(CH || SH)
    lea rdi, [rbx + linnea_tls_client_hs.tr_buf]
    mov rsi, [rbx + linnea_tls_client_hs.tr_len]
    lea rdx, [rbx + linnea_tls_client_hs.th_buf]
    call linnea_sha256
    lea rdi, [rbx + linnea_tls_client_hs.master]
    lea rsi, [lbl_c_hs]
    mov edx, 12
    lea rcx, [rbx + linnea_tls_client_hs.th_buf]
    lea r8, [rbx + linnea_tls_client_hs.c_hs]
    call linnea_tls_derive_secret
    lea rdi, [rbx + linnea_tls_client_hs.master]
    lea rsi, [lbl_s_hs]
    mov edx, 12
    lea rcx, [rbx + linnea_tls_client_hs.th_buf]
    lea r8, [rbx + linnea_tls_client_hs.s_hs]
    call linnea_tls_derive_secret
    ; derived2, master (final master secret)
    lea rdi, [rbx + linnea_tls_client_hs.master]
    lea rsi, [lbl_derived]
    mov edx, 7
    lea rcx, [empty_hash]
    lea r8, [rbx + linnea_tls_client_hs.srv_fin_key]   ; derived2 (scratch)
    call linnea_tls_derive_secret
    lea rdi, [rbx + linnea_tls_client_hs.srv_fin_key]
    mov esi, 32
    lea rdx, [zeros32]
    mov ecx, 32
    lea r8, [rbx + linnea_tls_client_hs.master]
    call linnea_hkdf_extract
    ; traffic keys: write=c_hs, read=s_hs
    lea rdi, [rbx + linnea_tls_client_hs.wkeys]
    lea rsi, [rbx + linnea_tls_client_hs.c_hs]
    call linnea_tls_keys_init
    lea rdi, [rbx + linnea_tls_client_hs.rkeys]
    lea rsi, [rbx + linnea_tls_client_hs.s_hs]
    call linnea_tls_keys_init
    mov rsp, rbp
    pop rbp
    ret

; client_finish(rbx=hs) — flight is complete and authenticated: derive the
; application secrets, seal the client Finished into hs.out (under the handshake
; write keys), and set state DONE. Does NOT switch to app keys (the caller's
; handoff does).
client_finish:
    push rbp
    mov rbp, rsp
    and rsp, -16
    ; th2 = H(transcript through the server Finished)
    lea rdi, [rbx + linnea_tls_client_hs.tr_buf]
    mov rsi, [rbx + linnea_tls_client_hs.tr_len]
    lea rdx, [rbx + linnea_tls_client_hs.th_buf]
    call linnea_sha256
    lea rdi, [rbx + linnea_tls_client_hs.master]
    lea rsi, [lbl_c_ap]
    mov edx, 12
    lea rcx, [rbx + linnea_tls_client_hs.th_buf]
    lea r8, [rbx + linnea_tls_client_hs.c_ap]
    call linnea_tls_derive_secret
    lea rdi, [rbx + linnea_tls_client_hs.master]
    lea rsi, [lbl_s_ap]
    mov edx, 12
    lea rcx, [rbx + linnea_tls_client_hs.th_buf]
    lea r8, [rbx + linnea_tls_client_hs.s_ap]
    call linnea_tls_derive_secret
    ; fin_key = HKDF-Expand-Label(c_hs, "finished", "", 32)   (scratch: srv_fin_key)
    lea rdi, [rbx + linnea_tls_client_hs.c_hs]
    lea rsi, [lbl_finished]
    mov edx, 8
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rbx + linnea_tls_client_hs.srv_fin_key]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    ; verify_data = HMAC(fin_key, th2)   (scratch: srv_fin_calc)
    lea rdi, [rbx + linnea_tls_client_hs.srv_fin_key]
    mov esi, 32
    lea rdx, [rbx + linnea_tls_client_hs.th_buf]
    mov ecx, 32
    lea r8, [rbx + linnea_tls_client_hs.srv_fin_calc]
    call linnea_hmac_sha256
    ; assemble the Finished handshake message (0x14 00 00 20 || verify_data)
    sub rsp, 48
    mov byte [rsp], 0x14
    mov byte [rsp + 1], 0
    mov byte [rsp + 2], 0
    mov byte [rsp + 3], 32
    lea rdi, [rsp + 4]
    lea rsi, [rbx + linnea_tls_client_hs.srv_fin_calc]
    mov ecx, 32
    rep movsb
    ; seal (inner type 22) under the handshake write keys, into hs.out
    lea rdi, [rbx + linnea_tls_client_hs.wkeys]
    mov esi, 22
    mov rdx, rsp
    mov ecx, 36
    lea r8, [rbx + linnea_tls_client_hs.out]
    call linnea_tls_seal
    mov [rbx + linnea_tls_client_hs.out_len], rax
    add rsp, 48
    mov qword [rbx + linnea_tls_client_hs.state], LINNEA_CLIENT_HS_DONE
    mov rsp, rbp
    pop rbp
    ret

; walk_flight(rbx=hs) — process every complete handshake message now in
; hs.hs_plain (from hs.parse_off), authenticating as it goes. On the server
; Finished it derives app secrets + client Finished and sets state DONE; on a
; bad message it sets state FAILED. Returns when a message is incomplete.
walk_flight:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    and rsp, -16
.loop:
    mov r12, [rbx + linnea_tls_client_hs.parse_off]
    mov r13, [rbx + linnea_tls_client_hs.hs_plain_len]
    lea rax, [r12 + 4]
    cmp rax, r13
    ja .ret                          ; need a 4-byte header
    movzx ecx, byte [rbx + linnea_tls_client_hs.hs_plain + r12 + 1]
    shl ecx, 8
    movzx eax, byte [rbx + linnea_tls_client_hs.hs_plain + r12 + 2]
    or ecx, eax
    shl ecx, 8
    movzx eax, byte [rbx + linnea_tls_client_hs.hs_plain + r12 + 3]
    or ecx, eax
    mov [rbx + linnea_tls_client_hs.bodylen], rcx
    lea rax, [r12 + 4]
    add rax, rcx
    cmp rax, r13
    ja .ret                          ; message not fully present
    movzx r14d, byte [rbx + linnea_tls_client_hs.hs_plain + r12]
    cmp r14d, 0x0f
    je .cv
    cmp r14d, 0x14
    je .fin
    jmp .absorb
.cv:
    lea rdi, [rbx + linnea_tls_client_hs.tr_buf]
    mov rsi, [rbx + linnea_tls_client_hs.tr_len]
    lea rdx, [rbx + linnea_tls_client_hs.th_buf]
    call linnea_sha256
    movzx eax, byte [rbx + linnea_tls_client_hs.hs_plain + r12 + 4]
    shl eax, 8
    movzx edx, byte [rbx + linnea_tls_client_hs.hs_plain + r12 + 5]
    or eax, edx
    cmp eax, 0x0403
    jne .fail
    movzx edx, byte [rbx + linnea_tls_client_hs.hs_plain + r12 + 6]
    shl edx, 8
    movzx eax, byte [rbx + linnea_tls_client_hs.hs_plain + r12 + 7]
    or edx, eax
    lea rsi, [rbx + linnea_tls_client_hs.hs_plain + r12 + 8]
    lea rdi, [rbx + linnea_tls_client_hs.th_buf]
    lea rcx, [rbx + linnea_tls_client_hs.srv_pubkey]
    call linnea_tls_client_verify_certverify
    test eax, eax
    jz .fail
    jmp .absorb
.fin:
    lea rdi, [rbx + linnea_tls_client_hs.tr_buf]
    mov rsi, [rbx + linnea_tls_client_hs.tr_len]
    lea rdx, [rbx + linnea_tls_client_hs.th_buf]
    call linnea_sha256
    lea rdi, [rbx + linnea_tls_client_hs.s_hs]
    lea rsi, [lbl_finished]
    mov edx, 8
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rbx + linnea_tls_client_hs.srv_fin_key]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    lea rdi, [rbx + linnea_tls_client_hs.srv_fin_key]
    mov esi, 32
    lea rdx, [rbx + linnea_tls_client_hs.th_buf]
    mov ecx, 32
    lea r8, [rbx + linnea_tls_client_hs.srv_fin_calc]
    call linnea_hmac_sha256
    lea rdi, [rbx + linnea_tls_client_hs.srv_fin_calc]
    lea rsi, [rbx + linnea_tls_client_hs.hs_plain + r12 + 4]
    call eq32
    test eax, eax
    jz .fail
    mov rcx, [rbx + linnea_tls_client_hs.bodylen]   ; absorb the server Finished
    lea rsi, [rbx + linnea_tls_client_hs.hs_plain + r12]
    lea rdx, [rcx + 4]
    call hs_tr_add
    call client_finish
    jmp .ret
.absorb:
    mov rcx, [rbx + linnea_tls_client_hs.bodylen]
    lea rsi, [rbx + linnea_tls_client_hs.hs_plain + r12]
    lea rdx, [rcx + 4]
    call hs_tr_add
    cmp r14d, 0x0b
    je .cert
    mov rcx, [rbx + linnea_tls_client_hs.bodylen]
    lea r12, [r12 + rcx + 4]
    mov [rbx + linnea_tls_client_hs.parse_off], r12
    jmp .loop
.cert:
    ; body: ctx_len(1) [ctx] list_len(3) entry{ der_len(3) der ext(2) } ...
    lea rdx, [rbx + linnea_tls_client_hs.hs_plain + r12 + 4]
    movzx eax, byte [rdx]
    lea rdx, [rdx + rax + 1]
    add rdx, 3
    movzx eax, byte [rdx]
    shl eax, 8
    movzx ecx, byte [rdx + 1]
    or eax, ecx
    shl eax, 8
    movzx ecx, byte [rdx + 2]
    or eax, ecx
    lea rdi, [rdx + 3]                ; leaf DER
    mov esi, eax                      ; leaf DER length
    call linnea_x509_find_spki        ; rax = SPKI ptr (0 fail), rdx = len
    test rax, rax
    jz .fail
    mov r13, rax                      ; SPKI ptr  (r13/r14 reloaded at .loop)
    mov r14, rdx                      ; SPKI len
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [rbx + linnea_tls_client_hs.spki_hash]
    call linnea_sha256
    lea rdi, [rbx + linnea_tls_client_hs.spki_hash]
    lea rsi, [rbx + linnea_tls_client_hs.pin]
    call eq32
    test eax, eax
    jz .fail
    mov rdi, r13
    mov rsi, r14
    lea rdx, [rbx + linnea_tls_client_hs.srv_pubkey]
    call linnea_x509_spki_point
    test eax, eax
    jz .fail
    mov rcx, [rbx + linnea_tls_client_hs.bodylen]
    lea r12, [r12 + rcx + 4]
    mov [rbx + linnea_tls_client_hs.parse_off], r12
    jmp .loop
.fail:
    mov qword [rbx + linnea_tls_client_hs.state], LINNEA_CLIENT_HS_FAILED
.ret:
    lea rsp, [rbp - 24]
    pop r14
    pop r13
    pop r12
    pop rbp
    ret

; process_flight(rbx=hs) -> rax = MORE(0) / DONE(1) / FAIL(-1). Re-processes the
; whole accumulated inbound buffer from the start (idempotent): parse the
; ServerHello, derive keys, then decrypt + walk each flight record. Returns MORE
; when the buffered bytes do not yet contain a complete flight.
process_flight:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    and rsp, -16
    ; reset re-derivable state (keep the ClientHello in the transcript)
    mov rax, [rbx + linnea_tls_client_hs.tr_ch_len]
    mov [rbx + linnea_tls_client_hs.tr_len], rax
    mov qword [rbx + linnea_tls_client_hs.hs_plain_len], 0
    mov qword [rbx + linnea_tls_client_hs.parse_off], 0
    mov r13, [rbx + linnea_tls_client_hs.rbuf_len]
    ; --- ServerHello (first record) ---
    cmp r13, 5
    jb .more
    movzx eax, byte [rbx + linnea_tls_client_hs.rbuf + 3]
    shl eax, 8
    movzx ecx, byte [rbx + linnea_tls_client_hs.rbuf + 4]
    or eax, ecx
    lea rdx, [rax + 5]
    cmp rdx, r13
    ja .more
    cmp byte [rbx + linnea_tls_client_hs.rbuf], 22
    jne .fail
    mov r12, rax                     ; reclen0
    lea rdi, [rbx + linnea_tls_client_hs.rbuf + 5 + 6]   ; ServerHello.random
    lea rsi, [hrr_random]
    call eq32
    test eax, eax
    jnz .fail                        ; HelloRetryRequest
    lea rsi, [rbx + linnea_tls_client_hs.rbuf + 5]
    mov rdx, r12
    call hs_tr_add                   ; absorb SH
    lea rsi, [rbx + linnea_tls_client_hs.rbuf + 5]
    mov rdx, r12
    call parse_serverhello
    test rax, rax
    js .fail
    call derive_hs_keys
    lea r12, [r12 + 5]               ; cursor past SH
.rloop:
    cmp r12, r13
    jae .more
    lea rax, [r12 + 5]
    cmp rax, r13
    ja .more
    movzx eax, byte [rbx + linnea_tls_client_hs.rbuf + r12 + 3]
    shl eax, 8
    movzx ecx, byte [rbx + linnea_tls_client_hs.rbuf + r12 + 4]
    or eax, ecx                      ; reclen
    lea rdx, [r12 + 5]
    add rdx, rax
    cmp rdx, r13
    ja .more                         ; partial record
    movzx ecx, byte [rbx + linnea_tls_client_hs.rbuf + r12]
    cmp ecx, 20
    je .ccs
    cmp ecx, 23
    jne .fail
    lea r14, [rax + 5]               ; record total length
    mov rdi, [rbx + linnea_tls_client_hs.hs_plain_len]
    lea rcx, [rbx + linnea_tls_client_hs.hs_plain + rdi]
    lea rdi, [rbx + linnea_tls_client_hs.rkeys]
    lea rsi, [rbx + linnea_tls_client_hs.rbuf + r12]
    mov rdx, r14
    call linnea_tls_open             ; rax = len, rdx = inner type
    test rax, rax
    js .fail
    cmp rdx, 22
    jne .fail
    add [rbx + linnea_tls_client_hs.hs_plain_len], rax
    add r12, r14
    call walk_flight
    cmp qword [rbx + linnea_tls_client_hs.state], LINNEA_CLIENT_HS_FAILED
    je .fail
    cmp qword [rbx + linnea_tls_client_hs.state], LINNEA_CLIENT_HS_DONE
    je .done
    jmp .rloop
.ccs:
    lea rax, [rax + 5]
    add r12, rax
    jmp .rloop
.more:
    xor eax, eax
    jmp .ret
.done:
    mov eax, 1
    jmp .ret
.fail:
    mov qword [rbx + linnea_tls_client_hs.state], LINNEA_CLIENT_HS_FAILED
    mov rax, -1
.ret:
    lea rsp, [rbp - 24]
    pop r14
    pop r13
    pop r12
    pop rbp
    ret

; ============================================================================
; Public driver entry points.
; ============================================================================

; linnea_tls_client_start(rdi=hs, rsi=pin(32), rdx=sni_ptr, rcx=sni_len). Builds
; the ClientHello into hs.out (send it) and readies hs for input().
linnea_tls_client_start:
    push rbp
    mov rbp, rsp
    push rbx
    and rsp, -16
    mov rbx, rdi
    mov rax, [rsi]                    ; copy the pin
    mov [rbx + linnea_tls_client_hs.pin], rax
    mov rax, [rsi + 8]
    mov [rbx + linnea_tls_client_hs.pin + 8], rax
    mov rax, [rsi + 16]
    mov [rbx + linnea_tls_client_hs.pin + 16], rax
    mov rax, [rsi + 24]
    mov [rbx + linnea_tls_client_hs.pin + 24], rax
    mov [rbx + linnea_tls_client_hs.sni_ptr], rdx
    mov [rbx + linnea_tls_client_hs.sni_len], rcx
    ; ALPN offer: "h2" when the caller set alpn_sel, else "http/1.1".
    cmp qword [rbx + linnea_tls_client_hs.alpn_sel], 0
    je .alpn_h1
    lea rax, [alpn_h2]
    mov [rbx + linnea_tls_client_hs.alpn_ptr], rax
    mov qword [rbx + linnea_tls_client_hs.alpn_len], alpn_h2_len
    jmp .alpn_done
.alpn_h1:
    lea rax, [alpn_h1]
    mov [rbx + linnea_tls_client_hs.alpn_ptr], rax
    mov qword [rbx + linnea_tls_client_hs.alpn_len], alpn_h1_len
.alpn_done:
    mov qword [rbx + linnea_tls_client_hs.tr_len], 0
    mov qword [rbx + linnea_tls_client_hs.rbuf_len], 0
    mov qword [rbx + linnea_tls_client_hs.hs_plain_len], 0
    mov qword [rbx + linnea_tls_client_hs.parse_off], 0
    mov qword [rbx + linnea_tls_client_hs.out_len], 0
    ; x25519 keypair
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [rbx + linnea_tls_client_hs.priv]
    mov esi, 32
    xor edx, edx
    syscall
    and byte [rbx + linnea_tls_client_hs.priv], 248
    and byte [rbx + linnea_tls_client_hs.priv + 31], 127
    or byte [rbx + linnea_tls_client_hs.priv + 31], 64
    lea rdi, [rbx + linnea_tls_client_hs.pub]
    lea rsi, [rbx + linnea_tls_client_hs.priv]
    lea rdx, [x25519_base]
    call linnea_x25519
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [rbx + linnea_tls_client_hs.random]
    mov esi, 32
    xor edx, edx
    syscall
    mov eax, LINNEA_SYS_GETRANDOM
    lea rdi, [rbx + linnea_tls_client_hs.sessid]
    mov esi, 32
    xor edx, edx
    syscall
    call build_clienthello
    mov rax, [rbx + linnea_tls_client_hs.tr_len]
    mov [rbx + linnea_tls_client_hs.tr_ch_len], rax
    mov qword [rbx + linnea_tls_client_hs.state], LINNEA_CLIENT_HS_WAIT_FLIGHT
    lea rsp, [rbp - 8]
    pop rbx
    pop rbp
    ret

; linnea_tls_client_input(rdi=hs, rsi=in, rdx=inlen) -> rax = MORE/DONE/FAIL.
linnea_tls_client_input:
    push rbp
    mov rbp, rsp
    push rbx
    and rsp, -16
    mov rbx, rdi
    cmp qword [rbx + linnea_tls_client_hs.state], LINNEA_CLIENT_HS_FAILED
    je .fail
    cmp qword [rbx + linnea_tls_client_hs.state], LINNEA_CLIENT_HS_DONE
    je .done
    ; append in -> rbuf (bounded)
    mov rax, [rbx + linnea_tls_client_hs.rbuf_len]
    lea rcx, [rax + rdx]
    cmp rcx, LINNEA_CLIENT_REC_CAP
    ja .fail
    lea rdi, [rbx + linnea_tls_client_hs.rbuf + rax]
    mov rcx, rdx
    rep movsb
    add [rbx + linnea_tls_client_hs.rbuf_len], rdx
    call process_flight
    jmp .ret
.done:
    mov eax, 1
    jmp .ret
.fail:
    mov qword [rbx + linnea_tls_client_hs.state], LINNEA_CLIENT_HS_FAILED
    mov rax, -1
.ret:
    lea rsp, [rbp - 8]
    pop rbx
    pop rbp
    ret

; ============================================================================
; Blocking driver + application data, for the test harness. The proxy uses
; kTLS for app data and drives start/input from io_uring instead.
; ============================================================================

; recv_some(edi=fd, rsi=buf, edx=cap) -> rax = bytes read (one read syscall),
; capped by cli_chunk_cap when it is nonzero (a test knob for resumability).
recv_some:
    mov rax, [cli_chunk_cap]
    test rax, rax
    jz .go
    cmp rax, rdx
    jae .go
    mov edx, eax
.go:
    mov eax, LINNEA_SYS_READ
    syscall
    ret

; linnea_tls_client_handshake(rdi=fd, rsi=pin, rdx=sni, rcx=snilen, r8=out64).
linnea_tls_client_handshake:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    and rsp, -16
    mov r12d, edi
    mov r13, r8
    lea rdi, [cli_hs]
    call linnea_tls_client_start
    mov edi, r12d
    lea rsi, [cli_hs + linnea_tls_client_hs.out]
    mov rdx, [cli_hs + linnea_tls_client_hs.out_len]
    call send_all
    test rax, rax
    js .fail
.rx:
    mov edi, r12d
    lea rsi, [hs_tmp]
    mov edx, HS_TMP_CAP
    call recv_some
    test rax, rax
    jle .fail
    lea rdi, [cli_hs]
    lea rsi, [hs_tmp]
    mov rdx, rax
    call linnea_tls_client_input
    cmp rax, -1
    je .fail
    cmp rax, 1
    je .rxdone
    jmp .rx
.rxdone:
    mov edi, r12d
    lea rsi, [cli_hs + linnea_tls_client_hs.out]
    mov rdx, [cli_hs + linnea_tls_client_hs.out_len]
    call send_all
    test rax, rax
    js .fail
    ; switch to application keys for the harness's app I/O
    lea rdi, [cli_hs + linnea_tls_client_hs.wkeys]
    lea rsi, [cli_hs + linnea_tls_client_hs.c_ap]
    call linnea_tls_keys_init
    lea rdi, [cli_hs + linnea_tls_client_hs.rkeys]
    lea rsi, [cli_hs + linnea_tls_client_hs.s_ap]
    call linnea_tls_keys_init
    lea rsi, [cli_hs + linnea_tls_client_hs.c_ap]
    mov rdi, r13
    mov ecx, 32
    rep movsb
    lea rsi, [cli_hs + linnea_tls_client_hs.s_ap]
    mov rdi, r13
    add rdi, 32
    mov ecx, 32
    rep movsb
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

; linnea_tls_client_app_send(rdi=fd, rsi=buf, rdx=len) -> rax = 0 / -1.
linnea_tls_client_app_send:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    and rsp, -16
    mov ebx, edi
    mov r12, rsi
    mov r13, rdx
    lea rdi, [cli_hs + linnea_tls_client_hs.wkeys]
    mov esi, 23
    mov rdx, r12
    mov rcx, r13
    lea r8, [app_out]
    call linnea_tls_seal
    mov edi, ebx
    lea rsi, [app_out]
    mov rdx, rax
    call send_all
    lea rsp, [rbp - 24]
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; linnea_tls_client_app_recv(rdi=fd, rsi=out, rdx=outcap) -> rax = plaintext
; length (>=0; 0 = a post-handshake/CCS record), or -1.
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
    lea rsi, [app_rec]
    call recv_record
    test rax, rax
    js .fail
    cmp byte [app_rec], 23
    jne .zero
    lea rdi, [cli_hs + linnea_tls_client_hs.rkeys]
    lea rsi, [app_rec]
    mov rdx, rax
    lea rcx, [app_plain]
    call linnea_tls_open
    test rax, rax
    js .fail
    cmp rdx, 23
    jne .zero
    mov rcx, rax
    cmp rcx, r13
    ja .fail
    mov rdi, r12
    lea rsi, [app_plain]
    rep movsb
    mov rax, rcx
    jmp .ret
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
