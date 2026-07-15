; linnea_network.asm — listening sockets, one per configured server.
; IPv4 literal addresses only for now; hostnames and IPv6 are rejected.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global linnea_network_listen_all
global linnea_network_peer_format

extern linnea_error_server
extern linnea_string_equal
extern linnea_string_from_u64
extern linnea_log_write
extern linnea_log_u64
extern linnea_log_stamp

section .rodata

msg_bad_host:       db "invalid host address (IPv4 literal required) for"
msg_bad_host_len    equ $ - msg_bad_host
msg_socket:         db "cannot create socket for"
msg_socket_len      equ $ - msg_socket
msg_sockopt:        db "cannot set SO_REUSEADDR for"
msg_sockopt_len     equ $ - msg_sockopt
msg_bind:           db "cannot bind to"
msg_bind_len        equ $ - msg_bind
msg_listen:         db "cannot listen on"
msg_listen_len      equ $ - msg_listen

log_listen:         db "listening on "
log_listen_len      equ $ - log_listen
log_colon:          db ":"
log_open:           db " ("
log_open_len        equ $ - log_open
log_close:          db ")", 10
log_close_len       equ $ - log_close

sockopt_one:        dd 1

section .bss

sockaddr_scratch:   resb LINNEA_SOCKADDR_IN_SIZE

section .text

; linnea_network_listen_all(rdi=config*) — create every listener or exit.
; Servers with the same host:port share one listening socket: only the
; first binds (listener_owner=1); later ones copy its fd (vhosts).
linnea_network_listen_all:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    xor r12d, r12d             ; server index i
.loop:
    cmp r12, [rbx + linnea_config.server_count]
    jae .done
    imul r14, r12, linnea_config_server_size
    lea r14, [rbx + r14 + linnea_config.servers]   ; server i
    xor r13d, r13d             ; earlier server index j
.scan_prior:
    cmp r13, r12
    jae .no_share
    imul r15, r13, linnea_config_server_size
    lea r15, [rbx + r15 + linnea_config.servers]   ; server j
    mov ax, [r14 + linnea_config_server.port]
    cmp ax, [r15 + linnea_config_server.port]
    jne .next_prior
    lea rdi, [r14 + linnea_config_server.host]
    mov rsi, [r14 + linnea_config_server.host_len]
    lea rdx, [r15 + linnea_config_server.host]
    mov rcx, [r15 + linnea_config_server.host_len]
    call linnea_string_equal
    test eax, eax
    jz .next_prior
    mov eax, [r15 + linnea_config_server.listen_fd]
    mov [r14 + linnea_config_server.listen_fd], eax
    mov dword [r14 + linnea_config_server.listener_owner], 0
    jmp .next_server
.next_prior:
    inc r13
    jmp .scan_prior
.no_share:
    mov rdi, r14
    call linnea_network_listener_create
    mov dword [r14 + linnea_config_server.listener_owner], 1
.next_server:
    inc r12
    jmp .loop
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_network_listener_create(rdi=server*)
; socket + SO_REUSEADDR + bind + listen. Stores the fd in server.listen_fd
; and logs "listening on <host>:<port> (<hostname>)". Exits on any failure.
linnea_network_listener_create:
    push rbx
    push r12
    mov rbx, rdi
    lea rdi, [rbx + linnea_config_server.host]
    call linnea_network_parse_ipv4
    cmp rax, -1
    je .bad_host
    mov word [sockaddr_scratch], LINNEA_AF_INET
    movzx ecx, word [rbx + linnea_config_server.port]
    xchg cl, ch                ; htons
    mov [sockaddr_scratch + 2], cx
    mov [sockaddr_scratch + 4], eax
    mov qword [sockaddr_scratch + 8], 0
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET
    mov esi, LINNEA_SOCK_STREAM
    xor edx, edx
    syscall
    cmp rax, -4095
    jae .socket_fail
    mov r12, rax               ; fd
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_SOL_SOCKET
    mov edx, LINNEA_SO_REUSEADDR
    lea r10, [sockopt_one]
    mov r8d, 4
    syscall
    cmp rax, -4095
    jae .sockopt_fail
    mov eax, LINNEA_SYS_BIND
    mov rdi, r12
    lea rsi, [sockaddr_scratch]
    mov edx, LINNEA_SOCKADDR_IN_SIZE
    syscall
    cmp rax, -4095
    jae .bind_fail
    mov eax, LINNEA_SYS_LISTEN
    mov rdi, r12
    mov esi, LINNEA_BACKLOG
    syscall
    cmp rax, -4095
    jae .listen_fail
    mov [rbx + linnea_config_server.listen_fd], r12d
    call linnea_log_stamp
    lea rdi, [log_listen]
    mov esi, log_listen_len
    call linnea_log_write
    lea rdi, [rbx + linnea_config_server.host]
    mov rsi, [rbx + linnea_config_server.host_len]
    call linnea_log_write
    lea rdi, [log_colon]
    mov esi, 1
    call linnea_log_write
    movzx edi, word [rbx + linnea_config_server.port]
    call linnea_log_u64
    lea rdi, [log_open]
    mov esi, log_open_len
    call linnea_log_write
    lea rdi, [rbx + linnea_config_server.hostname]
    mov rsi, [rbx + linnea_config_server.hostname_len]
    call linnea_log_write
    lea rdi, [log_close]
    mov esi, log_close_len
    call linnea_log_write
    pop r12
    pop rbx
    ret
.bad_host:
    lea rdi, [msg_bad_host]
    mov esi, msg_bad_host_len
    mov rdx, rbx
    xor ecx, ecx
    jmp linnea_error_server
.socket_fail:
    neg rax
    mov rcx, rax
    lea rdi, [msg_socket]
    mov esi, msg_socket_len
    mov rdx, rbx
    jmp linnea_error_server
.sockopt_fail:
    neg rax
    mov rcx, rax
    lea rdi, [msg_sockopt]
    mov esi, msg_sockopt_len
    mov rdx, rbx
    jmp linnea_error_server
.bind_fail:
    neg rax
    mov rcx, rax
    lea rdi, [msg_bind]
    mov esi, msg_bind_len
    mov rdx, rbx
    jmp linnea_error_server
.listen_fail:
    neg rax
    mov rcx, rax
    lea rdi, [msg_listen]
    mov esi, msg_listen_len
    mov rdx, rbx
    jmp linnea_error_server

; linnea_network_peer_format(rdi=socket fd, rsi=out buffer) -> rax=len
; Writes the connected peer as "a.b.c.d:port". The buffer must have room
; for linnea_string_from_u64's 20-byte scratch past the write cursor
; (48 bytes is plenty). On any failure writes "-" and returns 1.
linnea_network_peer_format:
    push rbx
    push r12
    sub rsp, 40                ; sockaddr (16) + socklen (8); keeps calls aligned
    mov rbx, rsi               ; out buffer
    mov eax, LINNEA_SYS_GETPEERNAME
    mov rsi, rsp
    lea rdx, [rsp + 16]
    mov qword [rsp + 16], LINNEA_SOCKADDR_IN_SIZE
    syscall
    cmp rax, -4095
    jae .unknown
    cmp word [rsp], LINNEA_AF_INET
    jne .unknown
    mov r12, rbx               ; write cursor
    movzx edi, byte [rsp + 4]
    mov rsi, r12
    call linnea_string_from_u64
    add r12, rax
    mov byte [r12], '.'
    inc r12
    movzx edi, byte [rsp + 5]
    mov rsi, r12
    call linnea_string_from_u64
    add r12, rax
    mov byte [r12], '.'
    inc r12
    movzx edi, byte [rsp + 6]
    mov rsi, r12
    call linnea_string_from_u64
    add r12, rax
    mov byte [r12], '.'
    inc r12
    movzx edi, byte [rsp + 7]
    mov rsi, r12
    call linnea_string_from_u64
    add r12, rax
    mov byte [r12], ':'
    inc r12
    movzx eax, word [rsp + 2]
    xchg al, ah                ; network to host order
    movzx edi, ax
    mov rsi, r12
    call linnea_string_from_u64
    add r12, rax
    mov rax, r12
    sub rax, rbx
    add rsp, 40
    pop r12
    pop rbx
    ret
.unknown:
    mov byte [rbx], '-'
    mov eax, 1
    add rsp, 40
    pop r12
    pop rbx
    ret

; linnea_network_parse_ipv4(rdi=cstr) -> rax
; Parses a dotted-quad IPv4 literal. Returns the address as a 32-bit value
; whose in-memory store is network byte order (first octet at lowest
; address); returns -1 on invalid input. Octets 0-255, exactly 4, dots
; between, nothing after.
linnea_network_parse_ipv4:
    xor r8d, r8d               ; result
    xor r9d, r9d               ; octet index
.octet:
    xor r11d, r11d             ; octet value
    xor r10d, r10d             ; digit count
.digit:
    movzx eax, byte [rdi]
    sub eax, '0'
    cmp eax, 9
    ja .end_digits
    imul r11d, r11d, 10
    add r11d, eax
    cmp r11d, 255
    ja .fail
    inc r10d
    inc rdi
    jmp .digit
.end_digits:
    test r10d, r10d
    jz .fail
    mov ecx, r9d
    shl ecx, 3
    shl r11d, cl
    or r8d, r11d
    inc r9d
    movzx eax, byte [rdi]
    cmp r9d, 4
    je .last
    cmp al, '.'
    jne .fail
    inc rdi
    jmp .octet
.last:
    test al, al
    jnz .fail
    mov eax, r8d
    ret
.fail:
    mov rax, -1
    ret
