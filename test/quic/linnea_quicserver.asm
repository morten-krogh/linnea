; linnea_quicserver.asm — a minimal, test-only QUIC receiver. Binds a UDP
; socket, and for each datagram tries to decrypt it as a QUIC Initial: derive
; the Initial keys from its DCID, remove protection, AEAD-open, and recover the
; ClientHello. On the first success it prints "quic-initial clienthello=<len>
; type=<byte>" and exits 0. It proves the receive path works on the wire against
; a real client (aioquic); the reusable handler is linnea_quic_recv_initial.
;
; Usage: linnea-quicserver  (binds 127.0.0.1:47500)

%include "linnea_syscall.inc"

global _start

extern linnea_quic_recv_initial
extern linnea_print_stdout
extern linnea_print_u64_stdout

%define SOCK_DGRAM   2
%define SYS_RECVFROM 45

section .rodata
msg_ok:   db "quic-initial clienthello="
msg_ok_len equ $ - msg_ok
msg_type: db " type="
msg_type_len equ $ - msg_type
msg_nl:   db 10

section .bss
sa:        resb 16
dgram:     resb 2048
plaintext: resb 2048

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
    mov r14, rax                     ; ClientHello ptr
    mov r15, rdx                     ; ClientHello length
    lea rdi, [msg_ok]
    mov esi, msg_ok_len
    call linnea_print_stdout
    mov edi, r15d
    call linnea_print_u64_stdout
    lea rdi, [msg_type]
    mov esi, msg_type_len
    call linnea_print_stdout
    movzx edi, byte [r14]            ; the ClientHello handshake type (0x01)
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
