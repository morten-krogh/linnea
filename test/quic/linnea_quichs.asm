; linnea_quichs.asm — test-only: a minimal QUIC handshake responder. It
; receives a client Initial, and replies with a server Initial that ACKs it
; and carries the ServerHello in a CRYPTO frame, protected with the server
; Initial keys. This is the first packet of the handshake flight on the wire;
; a real client (aioquic) should decrypt it and process the ServerHello.
;
; Fixed server ephemeral key / random / connection id (deterministic test).
; Binds 127.0.0.1:47501.

%include "linnea_syscall.inc"
%include "linnea_quic.inc"

global _start

extern linnea_quic_initial_dcid
extern linnea_quic_initial_secrets
extern linnea_quic_recv_initial
extern linnea_quic_ch_parse
extern linnea_quic_build_sh
extern linnea_quic_protect
extern linnea_x25519

%define SOCK_DGRAM   2
%define SYS_RECVFROM 45
%define SYS_SENDTO   44

section .rodata
x25519_base:  db 9
              times 31 db 0
server_priv:  db 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f
              db 0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
server_srand: db 0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f
              db 0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f
server_scid:  db 0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58

section .bss
sa:          resb 16
salen:       resq 1
dgram:       resb 2048
plaintext:   resb 2048
ini_client:  resb linnea_quic_keys_size
ini_server:  resb linnea_quic_keys_size
ch_out:      resb linnea_quic_ch_size
server_pub:  resb 32
sh_buf:      resb 128
payload:     resb 256
hdr:         resb 64
outpkt:      resb 2048

section .text
_start:
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET
    mov esi, SOCK_DGRAM
    xor edx, edx
    syscall
    test eax, eax
    js .fail
    mov r12d, eax                    ; udp fd
    mov word [sa], LINNEA_AF_INET
    mov word [sa + 2], 0x8db9        ; htons(47501)
    mov dword [sa + 4], 0x0100007f   ; 127.0.0.1
    mov qword [sa + 8], 0
    mov eax, LINNEA_SYS_BIND
    mov edi, r12d
    lea rsi, [sa]
    mov edx, 16
    syscall
    test eax, eax
    js .fail
.loop:
    mov qword [salen], 16
    mov eax, SYS_RECVFROM
    mov edi, r12d
    lea rsi, [dgram]
    mov edx, 2048
    xor r10d, r10d
    lea r8, [sa]
    lea r9, [salen]
    syscall
    test rax, rax
    jle .fail
    mov r13, rax                     ; datagram length
    ; server Initial keys from the client's DCID
    lea rdi, [dgram]
    mov rsi, r13
    call linnea_quic_initial_dcid    ; rax = DCID ptr, rdx = DCID len
    test rax, rax
    jz .loop
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [ini_client]
    lea rcx, [ini_server]
    call linnea_quic_initial_secrets
    ; recover + parse the ClientHello (for the key_share)
    lea rdi, [dgram]
    mov rsi, r13
    lea rdx, [plaintext]
    call linnea_quic_recv_initial    ; rax = CH ptr, rdx = CH len
    test rax, rax
    jz .loop
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [ch_out]
    call linnea_quic_ch_parse
    ; server_pub = X25519(server_priv, base)
    lea rdi, [server_pub]
    lea rsi, [server_priv]
    lea rdx, [x25519_base]
    call linnea_x25519
    ; ServerHello
    lea rdi, [sh_buf]
    lea rsi, [server_pub]
    lea rdx, [server_srand]
    call linnea_quic_build_sh        ; rax = 90

    ; --- payload: ACK(client pn 0) + CRYPTO(ServerHello) ---
    mov byte [payload], 0x02         ; ACK: largest=0, delay=0, ranges=0, first=0
    mov dword [payload + 1], 0
    mov byte [payload + 5], 0x06     ; CRYPTO: offset 0, length 90
    mov byte [payload + 6], 0x00
    mov word [payload + 7], 0x5a40   ; varint(90)
    lea rdi, [payload + 9]
    lea rsi, [sh_buf]
    mov ecx, 90
    rep movsb                        ; payload length = 99

    ; --- Initial long header (DCID = client SCID, SCID = ours) ---
    mov byte [hdr], 0xc0             ; long, Initial, 1-byte packet number
    mov dword [hdr + 1], 0x01000000  ; version 1
    ; the client's SCID sits after its DCID in the received header
    movzx eax, byte [dgram + 5]      ; client DCID length
    lea rsi, [dgram + 6 + rax]       ; -> client SCID length
    movzx ecx, byte [rsi]            ; client SCID length
    lea rsi, [rsi + 1]               ; -> client SCID bytes
    mov [hdr + 5], cl                ; our DCID length = client SCID length
    lea rdi, [hdr + 6]
    rep movsb                        ; copy the client SCID as our DCID (advances rdi)
    mov byte [rdi], 8                ; our SCID length
    inc rdi
    lea rsi, [server_scid]
    mov ecx, 8
    rep movsb                        ; copy our SCID (advances rdi to the SCID end)
    ; token length 0, length varint (pn+payload+tag = 1+99+16 = 116), pn 0
    mov byte [rdi], 0x00
    mov word [rdi + 1], 0x7440       ; varint(116)
    mov byte [rdi + 3], 0x00         ; packet number 0
    lea rcx, [rdi + 4]               ; header end
    lea rdx, [hdr]
    sub rcx, rdx                     ; header length

    ; --- protect and send ---
    sub rsp, 16
    lea rax, [ini_server]
    mov [rsp], rax                   ; keys (stack arg)
    lea rdi, [outpkt]
    lea rsi, [hdr]
    mov rdx, rcx                     ; header length
    mov ecx, 1                       ; packet-number length
    lea r8, [payload]
    mov r9d, 99                      ; payload length
    call linnea_quic_protect         ; rax = protected packet length
    add rsp, 16
    mov r14, rax                     ; response length
    mov eax, SYS_SENDTO
    mov edi, r12d
    lea rsi, [outpkt]
    mov rdx, r14
    xor r10d, r10d
    lea r8, [sa]
    mov r9d, 16
    syscall
    jmp .loop
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall
