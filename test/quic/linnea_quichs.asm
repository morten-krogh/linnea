; linnea_quichs.asm — test-only driver for the QUIC/HTTP/3 server handler.
;
; Binds 127.0.0.1:47501, reads datagrams with a blocking recvfrom, and hands
; each to linnea_quic_server_datagram. All the protocol work — connection
; demultiplexing, the handshake, and serving HTTP/3 — lives in
; src/linnea_quic_server.asm, which the io_uring event loop drives the same way.
;
; The certificate chain and signing key are embedded; requests are served from
; test/www.

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global _start

extern linnea_quic_server_init
extern linnea_quic_add_vhost
extern linnea_quic_server_datagram
extern linnea_quic_ticket_setup
extern linnea_quic_rxbuf
extern linnea_pem_cert_list
extern linnea_pem_p256_key

%define SOCK_DGRAM   2
%define SYS_RECVFROM 45

section .rodata
cert_pem:     incbin "test/tls/server.crt"
cert_pem_len  equ $ - cert_pem
key_pem:      incbin "test/tls/server.key"
key_pem_len   equ $ - key_pem
docroot:      db "test/www/"
docroot_len   equ $ - docroot
host_name:    db "localhost"
host_name_len equ $ - host_name

section .bss
sa:        resb 16
salen:     resq 1
cert_list: resb 4096
; a minimal config server + root location, just enough for the vhost
; registration the real config parser would provide
fake_srv:  resb linnea_config_server_size
fake_loc:  resb linnea_config_location_size

section .text
_start:
    ; frame the chain and decode the key, then hand them to the handler
    lea rdi, [cert_pem]
    mov esi, cert_pem_len
    lea rdx, [cert_list]
    mov ecx, 4096
    call linnea_pem_cert_list
    test rax, rax
    js .fail
    mov r13, rax                     ; certificate_list length
    lea rdi, [key_pem]
    mov esi, key_pem_len
    call linnea_pem_p256_key
    test rax, rax
    js .fail
    mov r14, rax                     ; private scalar
    ; fill the minimal config server + location and register the vhost
    lea rdi, [fake_srv + linnea_config_server.hostname]
    lea rsi, [host_name]
    mov ecx, host_name_len
    rep movsb
    mov qword [fake_srv + linnea_config_server.hostname_len], host_name_len
    lea rax, [cert_list]
    mov [fake_srv + linnea_config_server.cert_list], rax
    mov [fake_srv + linnea_config_server.cert_list_len], r13
    mov [fake_srv + linnea_config_server.key_priv], r14
    lea rdi, [fake_loc + linnea_config_location.root]
    lea rsi, [docroot]
    mov ecx, docroot_len
    rep movsb
    mov qword [fake_loc + linnea_config_location.root_len], docroot_len
    call linnea_quic_server_init
    lea rdi, [fake_srv]
    lea rsi, [fake_loc]
    call linnea_quic_add_vhost
    call linnea_quic_ticket_setup    ; session-ticket key for the NewSessionTicket
    ; udp socket bound to 127.0.0.1:47501
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET
    mov esi, SOCK_DGRAM
    xor edx, edx
    syscall
    test eax, eax
    js .fail
    mov r12d, eax
    mov word [sa], LINNEA_AF_INET
    mov word [sa + 2], 0x8db9        ; port 47501
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
    lea rsi, [linnea_quic_rxbuf]
    mov edx, 2048
    xor r10d, r10d
    lea r8, [sa]
    lea r9, [salen]
    syscall
    test rax, rax
    jle .loop
    mov rdi, rax                     ; datagram length
    lea rsi, [sa]
    mov rdx, [salen]
    mov ecx, r12d
    call linnea_quic_server_datagram
    jmp .loop
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall
