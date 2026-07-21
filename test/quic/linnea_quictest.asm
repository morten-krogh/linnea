; linnea_quictest.asm — QUIC crypto known-answer tests (RFC 9001 Appendix A).
; Derives the Initial packet-protection keys from the example DCID and checks
; the client/server key/iv/hp and the header-protection mask against the RFC.
; Prints "quic-crypto <pass>/<total>" and exits 1 if any check fails.

default rel

%include "linnea_quic.inc"

global _start

extern linnea_quic_initial_secrets
extern linnea_quic_hp_mask
extern linnea_quic_varint_decode
extern linnea_quic_varint_encode
extern linnea_quic_unprotect
extern linnea_quic_crypto_frame
extern linnea_quic_protect
extern linnea_print_stdout
extern linnea_print_u64_stdout

%include "quic_vectors.inc"

; CHECK dst, expected, len — compare and tally into r14d (total) / r15d (pass).
%macro CHECK 3
    lea rdi, [%1]
    lea rsi, [%2]
    mov edx, %3
    call bytes_eq
    inc r14d
    add r15d, eax
%endmacro

; VIDEC bytes, value, len — decode a varint and check its value + consumed len.
%macro VIDEC 3
    lea rdi, [%1]
    lea rsi, [%1 + 8]
    call linnea_quic_varint_decode
    inc r14d
    mov r10, %2
    cmp rax, r10
    jne %%bad
    cmp rdx, %3
    jne %%bad
    inc r15d
%%bad:
%endmacro

; VIENC bytes, value, len — encode a varint and check the bytes + length.
%macro VIENC 3
    lea rdi, [enc_buf]
    mov rsi, %2
    call linnea_quic_varint_encode
    inc r14d
    cmp rax, %3
    jne %%bad
    lea rdi, [enc_buf]
    lea rsi, [%1]
    mov edx, %3
    call bytes_eq
    test eax, eax
    jz %%bad
    inc r15d
%%bad:
%endmacro

section .rodata
; RFC 9001 A.1: DCID and the derived secrets.
dcid:        db 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08
exp_ckey:    db 0x1f,0x36,0x96,0x13,0xdd,0x76,0xd5,0x46,0x77,0x30,0xef,0xcb,0xe3,0xb1,0xa2,0x2d
exp_civ:     db 0xfa,0x04,0x4b,0x2f,0x42,0xa3,0xfd,0x3b,0x46,0xfb,0x25,0x5c
exp_chp:     db 0x9f,0x50,0x44,0x9e,0x04,0xa0,0xe8,0x10,0x28,0x3a,0x1e,0x99,0x33,0xad,0xed,0xd2
exp_skey:    db 0xcf,0x3a,0x53,0x31,0x65,0x3c,0x36,0x4c,0x88,0xf0,0xf3,0x79,0xb6,0x06,0x7e,0x37
exp_siv:     db 0x0a,0xc1,0x49,0x3c,0xa1,0x90,0x58,0x53,0xb0,0xbb,0xa0,0x3e
exp_shp:     db 0xc2,0x06,0xb8,0xd9,0xb9,0xf0,0xf3,0x76,0x44,0x43,0x0b,0x49,0x0e,0xea,0xa3,0x14
; RFC 9001 A.2: header-protection sample and the resulting mask.
sample:      db 0xd1,0xb1,0xc9,0x8d,0xd7,0x68,0x9f,0xb8,0xec,0x11,0xd2,0x42,0xb1,0x23,0xdc,0x9b
exp_mask:    db 0x43,0x7b,0x9a,0xec,0x36
; RFC 9000 16: varint worked examples (padded to 8 bytes for the decoder end).
vi1: db 0x25, 0,0,0,0,0,0,0
vi2: db 0x7b,0xbd, 0,0,0,0,0,0
vi4: db 0x9d,0x7f,0x3e,0x7d, 0,0,0,0
vi8: db 0xc2,0x19,0x7c,0x5e,0xff,0x14,0xe8,0x8c
msg_head:    db "quic-crypto "
msg_head_len equ $ - msg_head
msg_slash:   db "/"
msg_nl:      db 10

section .bss
out_client:  resb linnea_quic_keys_size
out_server:  resb linnea_quic_keys_size
mask_out:    resb 5
enc_buf:     resb 8
a2_client:   resb linnea_quic_keys_size
a2_server:   resb linnea_quic_keys_size
plain_buf:   resb 1500
plain_len:   resq 1
prot_buf:    resb 256

section .text
_start:
    lea rdi, [dcid]
    mov esi, 8
    lea rdx, [out_client]
    lea rcx, [out_server]
    call linnea_quic_initial_secrets

    lea rdi, [out_client + linnea_quic_keys.hp]
    lea rsi, [sample]
    lea rdx, [mask_out]
    call linnea_quic_hp_mask

    xor r14d, r14d                   ; total
    xor r15d, r15d                   ; pass

    CHECK out_client + linnea_quic_keys.key, exp_ckey, 16
    CHECK out_client + linnea_quic_keys.iv,  exp_civ,  12
    CHECK out_client + linnea_quic_keys.hp,  exp_chp,  16
    CHECK out_server + linnea_quic_keys.key, exp_skey, 16
    CHECK out_server + linnea_quic_keys.iv,  exp_siv,  12
    CHECK out_server + linnea_quic_keys.hp,  exp_shp,  16
    CHECK mask_out, exp_mask, 5

    VIDEC vi1, 37, 1
    VIDEC vi2, 15293, 2
    VIDEC vi4, 494878333, 4
    VIDEC vi8, 151288809941952652, 8
    VIENC vi1, 37, 1
    VIENC vi2, 15293, 2
    VIENC vi4, 494878333, 4
    VIENC vi8, 151288809941952652, 8

    ; --- RFC 9001 A.2: unprotect the real client Initial packet ---
    lea rdi, [quic_a2_dcid]
    mov esi, 8
    lea rdx, [a2_client]
    lea rcx, [a2_server]
    call linnea_quic_initial_secrets
    lea rdi, [quic_a2_packet]
    mov esi, quic_a2_packet_len
    lea rdx, [a2_client]
    lea rcx, [plain_buf]
    call linnea_quic_unprotect
    mov [plain_len], rax
    ; the AEAD-open must succeed (a valid tag returns a non-negative length)
    inc r14d
    test rax, rax
    js .a2_done
    inc r15d
    ; and the recovered frame bytes match the expected prefix
    CHECK plain_buf, quic_a2_plain_prefix, quic_a2_plain_prefix_len
    ; the first CRYPTO frame carries the ClientHello (handshake type 0x01)
    lea rdi, [plain_buf]
    mov rsi, [plain_len]
    call linnea_quic_crypto_frame
    inc r14d
    test rax, rax
    jz .a2_done
    cmp byte [rax], 0x01
    jne .a2_done
    inc r15d
.a2_done:

    ; --- RFC 9001 A.3: protect the server Initial, match the RFC bytes ---
    ; a2_server holds the server Initial keys (derived from the A.2 DCID).
    sub rsp, 16
    lea rax, [a2_server]
    mov [rsp], rax                   ; keys (stack argument)
    lea rdi, [prot_buf]
    lea rsi, [quic_a3_header]
    mov edx, quic_a3_header_len
    mov ecx, quic_a3_pn_len
    lea r8, [quic_a3_payload]
    mov r9d, quic_a3_payload_len
    call linnea_quic_protect         ; rax = total protected length
    add rsp, 16
    inc r14d
    cmp rax, quic_a3_protected_len
    jne .a3_done
    inc r15d
.a3_done:
    CHECK prot_buf, quic_a3_protected, quic_a3_protected_len

    ; print "quic-crypto <pass>/<total>\n"
    lea rdi, [msg_head]
    mov esi, msg_head_len
    call linnea_print_stdout
    mov edi, r15d
    call linnea_print_u64_stdout
    lea rdi, [msg_slash]
    mov esi, 1
    call linnea_print_stdout
    mov edi, r14d
    call linnea_print_u64_stdout
    lea rdi, [msg_nl]
    mov esi, 1
    call linnea_print_stdout

    ; exit(pass == total ? 0 : 1)
    xor edi, edi
    cmp r15d, r14d
    je .exit
    mov edi, 1
.exit:
    mov eax, 60
    syscall

; bytes_eq(rdi=a, rsi=b, rdx=len) -> eax = 1 if equal else 0
bytes_eq:
    mov rcx, rdx
    repe cmpsb
    sete al
    movzx eax, al
    ret
