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

global linnea_quic_initial_secrets
global linnea_quic_hp_mask

extern linnea_hkdf_extract
extern linnea_tls_hkdf_expand_label
extern linnea_aesgcm_init
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
