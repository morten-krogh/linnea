; linnea_quicserver.asm — a minimal, test-only QUIC receiver. Binds a UDP
; socket, and for each datagram tries to decrypt it as a QUIC Initial: derive
; the Initial keys from its DCID, remove protection, AEAD-open, and recover the
; ClientHello. On the first success it prints "quic-initial clienthello=<len>
; type=<byte>" and exits 0. It proves the receive path works on the wire against
; a real client (aioquic); the reusable handler is linnea_quic_recv_initial.
;
; Usage: linnea-quicserver  (binds 127.0.0.1:47500)

%include "linnea_syscall.inc"
%include "linnea_quic.inc"

global _start

extern linnea_quic_recv_initial
extern linnea_quic_ch_parse
extern linnea_quic_alpn_has
extern linnea_print_stdout
extern linnea_print_u64_stdout

%define SOCK_DGRAM   2
%define SYS_RECVFROM 45

section .rodata
msg_sni:  db "quic-initial sni="
msg_sni_len equ $ - msg_sni
msg_alpn: db " alpn-h3="
msg_alpn_len equ $ - msg_alpn
proto_h3: db "h3"
msg_nl:   db 10

section .bss
sa:        resb 16
dgram:     resb 2048
plaintext: resb 2048
ch_out:    resb linnea_quic_ch_size

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
    ; sockaddr_in = { AF_INET, htons(47500), 127.0.0.1, 0 }
    mov word [sa], LINNEA_AF_INET
    mov word [sa + 2], 0x8cb9        ; htons(47500)
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
    mov eax, SYS_RECVFROM
    mov edi, r12d
    lea rsi, [dgram]
    mov edx, 2048
    xor r10d, r10d                   ; flags
    xor r8d, r8d                     ; src addr: not needed
    xor r9d, r9d
    syscall
    test rax, rax
    jle .fail
    lea rdi, [dgram]
    mov rsi, rax
    lea rdx, [plaintext]
    call linnea_quic_recv_initial    ; rax = CH ptr, rdx = CH len
    test rax, rax
    jz .loop                         ; not a decryptable Initial; keep listening
    ; parse the ClientHello for SNI and ALPN
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [ch_out]
    call linnea_quic_ch_parse
    ; "quic-initial sni=<sni>"
    lea rdi, [msg_sni]
    mov esi, msg_sni_len
    call linnea_print_stdout
    mov rdi, [ch_out + linnea_quic_ch.sni_ptr]
    mov rsi, [ch_out + linnea_quic_ch.sni_len]
    test rdi, rdi
    jz .no_sni
    call linnea_print_stdout
.no_sni:
    ; " alpn-h3=<0|1>"
    lea rdi, [msg_alpn]
    mov esi, msg_alpn_len
    call linnea_print_stdout
    mov rdi, [ch_out + linnea_quic_ch.alpn_ptr]
    mov rsi, [ch_out + linnea_quic_ch.alpn_len]
    lea rdx, [proto_h3]
    mov ecx, 2
    call linnea_quic_alpn_has
    mov edi, eax
    call linnea_print_u64_stdout
    lea rdi, [msg_nl]
    mov esi, 1
    call linnea_print_stdout
    mov eax, LINNEA_SYS_CLOSE
    mov edi, r12d
    syscall
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall
