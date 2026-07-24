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
extern linnea_quic_unprotect_short
extern linnea_quic_crypto_frame
extern linnea_quic_stream_frame
extern linnea_quic_protect
extern linnea_quic_hs_secrets
extern linnea_quic_app_secrets
extern linnea_print_stdout
extern linnea_print_u64_stdout

%include "quic_vectors.inc"
%include "quic_hs_vectors.inc"

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
; Frame-length bounds tests. A STREAM|LEN frame (type 0x0a: STREAM 0x08 | LEN
; 0x02) and a CRYPTO frame (0x06), each declaring 8 data bytes after a 3-byte
; header. Passed with the honest length (11) the parser returns the frame; passed
; a shorter buffer length (7) the declared 8 bytes overrun it and the frame must
; be rejected (rax = 0) rather than read past the buffer.
tf_stream:   db 0x0a, 0x00, 0x08, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88
tf_stream_len equ $ - tf_stream
tf_crypto:   db 0x06, 0x00, 0x08, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88
tf_crypto_len equ $ - tf_crypto
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
hs_client:   resb linnea_quic_keys_size
hs_server:   resb linnea_quic_keys_size
hs_secrets_out: resb 96
ap_client:   resb linnea_quic_keys_size
ap_server:   resb linnea_quic_keys_size
rt_hdr:      resb 16
rt_pay:      resb 32
rt_out:      resb 64
rt_protlen:  resq 1

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
    mov qword [rsp + 8], 1           ; full pn for the nonce (A.3 server Initial pn = 1)
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

    ; --- 1-RTT nonce past the 2-byte pn truncation (regression for the ~65536-
    ; packet death). Protect a short-header packet at pn 65537, then unprotect it:
    ; the header carries only the low 16 bits (0x0001), so the nonce must be built
    ; from the FULL pn on both sides or the AEAD fails to open. Before the fix,
    ; protect used the truncated header value (1) while unprotect expands to 65537
    ; -> nonce mismatch -> open fails, which is exactly how a real connection died
    ; once its packet number crossed 65536.
    mov byte [rt_hdr], 0x41                    ; short header, 2-byte pn
    mov qword [rt_hdr + 1], 0x1122334455667788 ; 8-byte DCID
    mov byte [rt_hdr + 9], 0x00                ; pn low 16 bits of 65537 = 0x0001,
    mov byte [rt_hdr + 10], 0x01               ; big-endian
    mov qword [rt_pay], 0x0102030405060708
    mov qword [rt_pay + 8], 0x1112131415161718
    mov qword [rt_pay + 16], 0x2122232425262728
    sub rsp, 16
    lea rax, [a2_server]
    mov [rsp], rax                             ; keys
    mov qword [rsp + 8], 65537                 ; FULL pn for the nonce
    lea rdi, [prot_buf]
    lea rsi, [rt_hdr]
    mov edx, 11                                ; hdr_len = 1 + 8 + 2
    mov ecx, 2                                 ; pn_len
    lea r8, [rt_pay]
    mov r9d, 24                                ; payload_len
    call linnea_quic_protect
    add rsp, 16
    mov [rt_protlen], rax
    lea rdi, [prot_buf]
    mov rsi, [rt_protlen]
    lea rdx, [a2_server]
    lea rcx, [rt_out]
    mov r8d, 8                                 ; dcid_len
    mov r9d, 65537                             ; expected pn (A.3 recovers 65537)
    call linnea_quic_unprotect_short           ; rax = plaintext len, rdx = pn
    inc r14d
    cmp rax, 24                                ; opened: nonce matched at pn > 65536
    jne .rt_done
    cmp rdx, 65537                             ; recovered the full packet number
    jne .rt_done
    inc r15d
.rt_done:

    ; --- frame Length must be clamped to the packet (OOB-read regression) ---
    ; STREAM|LEN, honest length: the frame is returned with data length 8.
    lea rdi, [tf_stream]
    mov esi, tf_stream_len                     ; 11 = 3 header + 8 data
    call linnea_quic_stream_frame
    inc r14d
    test rax, rax                              ; a frame was returned
    jz .fl1_done
    cmp rdx, 8                                 ; with the declared data length
    jne .fl1_done
    inc r15d
.fl1_done:
    ; STREAM|LEN declaring 8 bytes but only 4 present: must be REJECTED, not read
    ; past the buffer (before the fix this returned a length running 4 bytes over).
    lea rdi, [tf_stream]
    mov esi, 7                                 ; header(3) + only 4 data bytes
    call linnea_quic_stream_frame
    inc r14d
    test rax, rax
    jnz .fl2_done                              ; non-zero = accepted = BUG
    inc r15d
.fl2_done:
    ; CRYPTO, honest length: returned with data length 8.
    lea rdi, [tf_crypto]
    mov esi, tf_crypto_len
    call linnea_quic_crypto_frame
    inc r14d
    test rax, rax
    jz .fl3_done
    cmp rdx, 8
    jne .fl3_done
    inc r15d
.fl3_done:
    ; CRYPTO declaring 8 bytes but only 4 present: must be rejected.
    lea rdi, [tf_crypto]
    mov esi, 7
    call linnea_quic_crypto_frame
    inc r14d
    test rax, rax
    jnz .fl4_done
    inc r15d
.fl4_done:

    ; --- handshake key derivation: ECDHE + TLS key schedule -> QUIC keys ---
    ; verified against the Python `cryptography` reference (fixed inputs).
    lea rdi, [qhs_client_pub]
    lea rsi, [qhs_server_priv]
    lea rdx, [qhs_th]
    lea rcx, [hs_client]
    lea r8, [hs_server]
    lea r9, [hs_secrets_out]
    call linnea_quic_hs_secrets
    CHECK hs_client, qhs_exp_client, 44
    CHECK hs_server, qhs_exp_server, 44
    ; the handshake secret is exported (bytes 64..96 of the secrets buffer)
    CHECK hs_secrets_out + 64, qhs_hs_secret, 32

    ; --- 1-RTT (application) key derivation from the handshake secret ---
    lea rdi, [qhs_hs_secret]
    lea rsi, [qhs_th_app]
    lea rdx, [ap_client]
    lea rcx, [ap_server]
    call linnea_quic_app_secrets
    CHECK ap_client, qhs_exp_client_app, 44
    CHECK ap_server, qhs_exp_server_app, 44

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
