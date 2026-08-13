; linnea_quichs.asm — test-only driver for the QUIC/HTTP/3 server handler.
;
; Binds 127.0.0.1:61501, reads datagrams with a blocking recvfrom, and hands
; each to linnea_quic_server_datagram. All the protocol work — connection
; demultiplexing, the handshake, and serving HTTP/3 — lives in
; src/linnea_quic_server.asm, which the io_uring event loop drives the same way.
;
; The certificate chain and signing key are embedded; requests are served from
; test/www.

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global _start

extern linnea_quic_cfin_echo
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

section .text
_start:
    mov qword [linnea_quic_cfin_echo], 1   ; this binary's caller greps CFIN-OK
    mov r14, [rsp]                   ; argc
    mov r15, [rsp + 16]              ; argv[1], if there is one
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
    ; The location is the server's own locations[0], not a loose struct beside
    ; it. Since h3 routes by location (the vhost's config server is what it
    ; matches against), a server declaring none has nothing for a request to
    ; match and every path 404s — which is exactly what this harness did when
    ; the two were kept apart.
    lea rdi, [fake_srv + linnea_config_server.locations + linnea_config_location.root]
    lea rsi, [docroot]
    mov ecx, docroot_len
    rep movsb
    mov qword [fake_srv + linnea_config_server.locations + linnea_config_location.root_len], docroot_len
    mov byte [fake_srv + linnea_config_server.locations + linnea_config_location.prefix], '/'
    mov qword [fake_srv + linnea_config_server.locations + linnea_config_location.prefix_len], 1
    mov qword [fake_srv + linnea_config_server.locations + linnea_config_location.kind], LINNEA_LOC_KIND_ROOT
    mov qword [fake_srv + linnea_config_server.location_count], 1
    call linnea_quic_server_init
    lea rdi, [fake_srv]
    lea rsi, [fake_srv + linnea_config_server.locations]
    call linnea_quic_add_vhost
    call linnea_quic_ticket_setup    ; session-ticket key for the NewSessionTicket
    ; udp socket bound to 127.0.0.1:61501
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET
    mov esi, SOCK_DGRAM
    xor edx, edx
    syscall
    test eax, eax
    js .fail
    mov r12d, eax
    mov word [sa], LINNEA_AF_INET
    mov word [sa + 2], 0x3df0        ; the default: htons(61501)
    cmp r14, 2
    jb .port_set
    mov rsi, r15
    call parse_port
    mov [sa + 2], ax
    .port_set:
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

; parse_port(rsi = NUL-terminated decimal) -> ax = the port in NETWORK order.
; A test server with a compiled-in port cannot be run twice at once, and the
; suite's whole port scheme exists so two runs can. argv[1] overrides the
; default; no argument keeps the number this file has always used.
parse_port:
    xor eax, eax
.pp_digit:
    movzx ecx, byte [rsi]
    sub ecx, '0'
    cmp ecx, 9
    ja .pp_done
    imul eax, eax, 10
    add eax, ecx
    inc rsi
    jmp .pp_digit
.pp_done:
    xchg al, ah                      ; host order -> network order
    ret
