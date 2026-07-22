; linnea_quic_crypto.asm — QUIC (RFC 9001) packet-protection crypto.
;
; QUIC reuses TLS 1.3's HKDF-Expand-Label (with the "tls13 " prefix), so the
; Initial keys, header-protection keys and per-packet AEAD all build on the
; existing crypto. This module derives the Initial secrets from a client's
; Destination Connection ID and computes the header-protection mask. The AEAD
; itself is linnea_aesgcm_seal/open with the QUIC nonce (iv XOR packet number).
;
; Everything here is deterministic and checked against RFC 9001 Appendix A.

default rel

%include "linnea_quic.inc"
%include "linnea_aesgcm.inc"
%include "linnea_syscall.inc"

global linnea_quic_initial_secrets
global linnea_quic_hp_mask
global linnea_quic_hs_secrets
global linnea_quic_app_secrets
global linnea_quic_resumption_psk
global linnea_quic_ticket_setup
global linnea_quic_ticket_seal
global linnea_quic_ticket_open

extern linnea_hkdf_extract
extern linnea_tls_hkdf_expand_label
extern linnea_tls_derive_secret
extern linnea_x25519
extern linnea_aesgcm_init
extern linnea_aesgcm_seal
extern linnea_aesgcm_open
extern linnea_aes128_ecb

section .rodata
; QUIC v1 Initial salt (RFC 9001 5.2)
quic_initial_salt:
    db 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17
    db 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
lbl_client_in: db "client in"
lbl_server_in: db "server in"
lbl_quic_key:  db "quic key"
lbl_quic_iv:   db "quic iv"
lbl_quic_hp:   db "quic hp"
lbl_derived:   db "derived"
lbl_c_hs:      db "c hs traffic"
lbl_s_hs:      db "s hs traffic"
lbl_c_ap:      db "c ap traffic"
lbl_s_ap:      db "s ap traffic"
lbl_res_master: db "res master"
lbl_resumption: db "resumption"
q_ticket_nonce: db 0, 0          ; the (fixed) resumption ticket_nonce
zeros32:       times 32 db 0
; SHA-256 of the empty string (Derive-Secret's context for "derived").
empty_hash:
    db 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24
    db 0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55

section .text

; quic_pp_keys(rdi=secret32, rsi=out linnea_quic_keys) — derive the packet
; key (16), iv (12) and header-protection key (16) from a traffic secret.
quic_pp_keys:
    push rbx
    push r12
    mov rbx, rdi                     ; secret
    mov r12, rsi                     ; out
    sub rsp, 8                       ; keep rsp 16-aligned before the calls
    ; key = HKDF-Expand-Label(secret, "quic key", "", 16)
    mov rdi, rbx
    lea rsi, [lbl_quic_key]
    mov edx, 8
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [r12 + linnea_quic_keys.key]
    sub rsp, 16
    mov qword [rsp], 16
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    ; iv = HKDF-Expand-Label(secret, "quic iv", "", 12)
    mov rdi, rbx
    lea rsi, [lbl_quic_iv]
    mov edx, 7
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [r12 + linnea_quic_keys.iv]
    sub rsp, 16
    mov qword [rsp], 12
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    ; hp = HKDF-Expand-Label(secret, "quic hp", "", 16)
    mov rdi, rbx
    lea rsi, [lbl_quic_hp]
    mov edx, 7
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [r12 + linnea_quic_keys.hp]
    sub rsp, 16
    mov qword [rsp], 16
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    add rsp, 8
    pop r12
    pop rbx
    ret

; linnea_quic_initial_secrets(rdi=dcid ptr, rsi=dcid len,
;                             rdx=out client keys, rcx=out server keys)
; Derives both directions' Initial packet-protection keys (RFC 9001 5.2).
linnea_quic_initial_secrets:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 136                     ; [0]=initial_secret, [32]=client, [64]=server
    mov rbx, rdi                     ; dcid ptr
    mov r12, rsi                     ; dcid len
    mov r14, rdx                     ; out client
    mov r15, rcx                     ; out server
    ; initial_secret = HKDF-Extract(initial_salt, dcid)
    lea rdi, [quic_initial_salt]
    mov esi, 20
    mov rdx, rbx
    mov rcx, r12
    lea r8, [rsp]
    call linnea_hkdf_extract
    ; client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    lea rdi, [rsp]
    lea rsi, [lbl_client_in]
    mov edx, 9
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rsp + 32]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    lea rdi, [rsp + 32]
    mov rsi, r14
    call quic_pp_keys
    ; server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
    lea rdi, [rsp]
    lea rsi, [lbl_server_in]
    mov edx, 9
    xor ecx, ecx
    xor r8d, r8d
    lea r9, [rsp + 64]
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    lea rdi, [rsp + 64]
    mov rsi, r15
    call quic_pp_keys
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; linnea_quic_hs_secrets(rdi=client_pub32, rsi=server_priv32, rdx=transcript
;   hash H(CH..SH), rcx=out client keys, r8=out server keys)
; TLS 1.3 handshake key schedule (fresh, no PSK) reused for QUIC: ECDHE, then
; early -> derived -> handshake secret -> c/s hs traffic secrets, and from each
; the QUIC handshake packet keys. The primitives are the same the TLS handshake
; uses; only the final key labels ("quic ...") differ. r9 (out secrets, 96 bytes)
; also receives c_hs || s_hs || handshake_secret — the traffic secrets for the
; Finished MACs and the handshake secret to chain into the 1-RTT keys.
linnea_quic_hs_secrets:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 232                     ; [0]shared [32]early [64]derived
                                     ; [96]hs [128]c_hs [160]s_hs
    mov rbx, rdi                     ; client_pub
    mov r12, rsi                     ; server_priv
    mov r13, rdx                     ; transcript hash
    mov r14, rcx                     ; out client keys
    mov r15, r8                      ; out server keys
    mov rbp, r9                      ; out traffic secrets (c_hs || s_hs)
    ; shared = X25519(server_priv, client_pub)
    lea rdi, [rsp]
    mov rsi, r12
    mov rdx, rbx
    call linnea_x25519
    ; early = HKDF-Extract("", zeros32)
    lea rdi, [zeros32]
    xor esi, esi
    lea rdx, [zeros32]
    mov ecx, 32
    lea r8, [rsp + 32]
    call linnea_hkdf_extract
    ; derived = Derive-Secret(early, "derived", H(""))
    lea rdi, [rsp + 32]
    lea rsi, [lbl_derived]
    mov edx, 7
    lea rcx, [empty_hash]
    lea r8, [rsp + 64]
    call linnea_tls_derive_secret
    ; hs_secret = HKDF-Extract(derived, shared)
    lea rdi, [rsp + 64]
    mov esi, 32
    lea rdx, [rsp]
    mov ecx, 32
    lea r8, [rsp + 96]
    call linnea_hkdf_extract
    ; c_hs = Derive-Secret(hs, "c hs traffic", th)
    lea rdi, [rsp + 96]
    lea rsi, [lbl_c_hs]
    mov edx, 12
    mov rcx, r13
    lea r8, [rsp + 128]
    call linnea_tls_derive_secret
    ; s_hs = Derive-Secret(hs, "s hs traffic", th)
    lea rdi, [rsp + 96]
    lea rsi, [lbl_s_hs]
    mov edx, 12
    mov rcx, r13
    lea r8, [rsp + 160]
    call linnea_tls_derive_secret
    ; export the traffic secrets and the handshake secret (c_hs, s_hs, hs)
    lea rsi, [rsp + 128]
    mov rdi, rbp
    mov ecx, 32
    rep movsb
    lea rsi, [rsp + 160]
    mov ecx, 32
    rep movsb
    lea rsi, [rsp + 96]
    mov ecx, 32
    rep movsb
    ; QUIC handshake packet keys from each traffic secret
    lea rdi, [rsp + 128]
    mov rsi, r14
    call quic_pp_keys
    lea rdi, [rsp + 160]
    mov rsi, r15
    call quic_pp_keys
    add rsp, 232
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_app_secrets(rdi=handshake_secret32, rsi=transcript hash through the
;   server Finished, rdx=out client 1-RTT keys, rcx=out server 1-RTT keys).
; master = HKDF-Extract(Derive-Secret(hs, "derived", H("")), zeros32); then the
; c/s application traffic secrets over the transcript, and the QUIC 1-RTT keys.
linnea_quic_app_secrets:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 144                     ; [0]derived [32]master [64]c_ap [96]s_ap
    mov rbx, rdi                     ; handshake secret
    mov r13, rsi                     ; transcript hash
    mov r14, rdx                     ; out client keys
    mov r15, rcx                     ; out server keys
    ; derived = Derive-Secret(hs, "derived", H(""))
    mov rdi, rbx
    lea rsi, [lbl_derived]
    mov edx, 7
    lea rcx, [empty_hash]
    lea r8, [rsp]
    call linnea_tls_derive_secret
    ; master = HKDF-Extract(derived, zeros32)
    lea rdi, [rsp]
    mov esi, 32
    lea rdx, [zeros32]
    mov ecx, 32
    lea r8, [rsp + 32]
    call linnea_hkdf_extract
    ; c_ap = Derive-Secret(master, "c ap traffic", th)
    lea rdi, [rsp + 32]
    lea rsi, [lbl_c_ap]
    mov edx, 12
    mov rcx, r13
    lea r8, [rsp + 64]
    call linnea_tls_derive_secret
    ; s_ap = Derive-Secret(master, "s ap traffic", th)
    lea rdi, [rsp + 32]
    lea rsi, [lbl_s_ap]
    mov edx, 12
    mov rcx, r13
    lea r8, [rsp + 96]
    call linnea_tls_derive_secret
    ; QUIC 1-RTT packet keys from each traffic secret
    lea rdi, [rsp + 64]
    mov rsi, r14
    call quic_pp_keys
    lea rdi, [rsp + 96]
    mov rsi, r15
    call quic_pp_keys
    add rsp, 144
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_hp_mask(rdi=hp key16, rsi=sample16, rdx=out mask5)
; mask = AES-ECB(hp, sample)[0..4] (RFC 9001 5.4.1).
linnea_quic_hp_mask:
    push rbx
    push r13
    push r14
    mov r13, rsi                     ; sample
    mov r14, rdx                     ; out
    sub rsp, 208                     ; [0..191]=aes ctx, [192..207]=ecb block
    mov rbx, rsp
    ; expand the hp key (rdi still = hp key)
    mov rsi, rdi
    mov rdi, rbx
    call linnea_aesgcm_init
    ; block = AES-ECB(hp, sample)
    mov rdi, rbx
    mov rsi, r13
    lea rdx, [rbx + 192]
    call linnea_aes128_ecb
    ; mask = block[0..4]
    mov eax, [rbx + 192]
    mov [r14], eax
    mov al, [rbx + 196]
    mov [r14 + 4], al
    add rsp, 208
    pop r14
    pop r13
    pop rbx
    ret

; ===================================================================
; Session resumption (RFC 8446 4.6.1) — QUIC side. The resumption PSK a
; ticket carries, and the stateless-ticket sealing that stores it.
; ===================================================================

; linnea_quic_resumption_psk(rdi=handshake_secret32,
;   rsi=transcript hash through the CLIENT Finished, rdx=out psk32).
; master = HKDF-Extract(Derive-Secret(hs,"derived",H("")), zeros); res_master =
; Derive-Secret(master, "res master", th); psk = Expand-Label(res_master,
; "resumption", ticket_nonce, 32). The client derives the same PSK from its own
; transcript, so a ticket carrying this value lets it resume / send 0-RTT.
linnea_quic_resumption_psk:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 104                     ; [0]derived [32]master [64]res_master (aligns)
    mov rbx, rdi                     ; handshake secret
    mov r12, rsi                     ; th through client Finished
    mov r13, rdx                     ; out psk
    ; derived = Derive-Secret(hs, "derived", H(""))
    mov rdi, rbx
    lea rsi, [lbl_derived]
    mov edx, 7
    lea rcx, [empty_hash]
    lea r8, [rsp]
    call linnea_tls_derive_secret
    ; master = HKDF-Extract(derived, zeros32)
    lea rdi, [rsp]
    mov esi, 32
    lea rdx, [zeros32]
    mov ecx, 32
    lea r8, [rsp + 32]
    call linnea_hkdf_extract
    ; res_master = Derive-Secret(master, "res master", th)
    lea rdi, [rsp + 32]
    lea rsi, [lbl_res_master]
    mov edx, 10
    mov rcx, r12
    lea r8, [rsp + 64]
    call linnea_tls_derive_secret
    ; psk = Expand-Label(res_master, "resumption", ticket_nonce{0,0}, 32)
    lea rdi, [rsp + 64]
    lea rsi, [lbl_resumption]
    mov edx, 10
    lea rcx, [q_ticket_nonce]
    mov r8d, 2
    mov r9, r13
    sub rsp, 16
    mov qword [rsp], 32
    call linnea_tls_hkdf_expand_label
    add rsp, 16
    add rsp, 104
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_ticket_setup() — one stateless-ticket key for the whole run, its
; AES schedule built here. Called in the master before the workers fork, so every
; worker seals and opens the same tickets (the key is inherited copy-on-write).
; Separate from the TLS-over-TCP ticket key: a QUIC session never resumes a TCP
; one (different transport, different ALPN), so they need not share a key.
linnea_quic_ticket_setup:
.again:
    lea rdi, [q_ticket_key]
    mov esi, 16
    xor edx, edx
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    cmp rax, 16
    jne .again
    lea rdi, [q_ticket_ctx]
    lea rsi, [q_ticket_key]
    jmp linnea_aesgcm_init

; linnea_quic_ticket_seal(rdi=pt, esi=pt_len, rdx=out) -> rax = sealed length.
; Writes nonce(12) || AES-GCM(pt) [ct || tag(16)] to out. No AAD.
linnea_quic_ticket_seal:
    push rbx
    push r12
    push r13
    mov rbx, rdi                     ; pt
    mov r12d, esi                    ; pt_len (zero-extended)
    mov r13, rdx                     ; out
    lea rdi, [r13]                   ; nonce -> out[0..11]
    mov esi, 12
    xor edx, edx
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    lea rdi, [q_ticket_ctx]
    mov rsi, r13                     ; nonce
    xor edx, edx                     ; aad
    xor ecx, ecx                     ; aadlen
    mov r8, rbx                      ; pt
    mov r9d, r12d                    ; pt_len
    sub rsp, 16
    lea rax, [r13 + 12]              ; ct||tag -> out[12..]
    mov [rsp], rax
    call linnea_aesgcm_seal
    add rsp, 16
    lea rax, [r12 + 28]              ; 12 nonce + pt_len + 16 tag
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_ticket_open(rdi=in, esi=in_len, rdx=out_pt) -> rax = plaintext
; length, or 0 if the ticket is too short or the tag fails (forged/foreign key).
linnea_quic_ticket_open:
    push rbx
    push r12
    push r13
    mov rbx, rdi                     ; in
    mov r12d, esi                    ; in_len
    mov r13, rdx                     ; out_pt
    cmp r12d, 28                     ; nonce(12) + tag(16)
    jb .open_fail
    lea rdi, [q_ticket_ctx]
    mov rsi, rbx                     ; nonce = in[0..11]
    xor edx, edx
    xor ecx, ecx
    lea r8, [rbx + 12]               ; ct||tag
    mov r9d, r12d
    sub r9d, 12                      ; ctlen incl. tag
    sub rsp, 16
    mov [rsp], r13                   ; out
    call linnea_aesgcm_open
    add rsp, 16
    test rax, rax
    jnz .open_fail                   ; bad tag
    lea rax, [r12 - 28]              ; plaintext length
    pop r13
    pop r12
    pop rbx
    ret
.open_fail:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret

section .bss
alignb 16
q_ticket_key:  resb 16                    ; per-run QUIC stateless-ticket key
q_ticket_ctx:  resb linnea_aesgcm_ctx_size
