; linnea_network.asm — listening sockets, one per configured server.
; Every listener is a dual-stack AF_INET6 socket with IPV6_V6ONLY cleared, so a
; single socket serves both IPv6 clients and IPv4 clients (the latter arriving
; as IPv4-mapped ::ffff:a.b.c.d). The configured host is still an IPv4 literal,
; "0.0.0.0", or "::"; hostnames are rejected.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global linnea_network_listen_all
global linnea_network_peer_format
global linnea_network_parse_ipv4
global linnea_network_quic_listener

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
log_adopt:          db "adopted listener "
log_adopt_len       equ $ - log_adopt
log_colon:          db ":"
log_open:           db " ("
log_open_len        equ $ - log_open
log_close:          db ")", 10
log_close_len       equ $ - log_close

sockopt_one:        dd 1
sockopt_zero:       dd 0

section .bss

sockaddr_scratch:   resb LINNEA_SOCKADDR_IN6_SIZE
adopt_fds:          resq 1     ; fd array for a hot upgrade, or 0

section .text

; linnea_network_listen_all(rdi=config*, rsi=fd_array|0) — set up every
; listener or exit. Servers with the same host:port share one listening
; socket: only the first owns it (listener_owner=1); later ones copy its
; fd (vhosts). With rsi=0 the owner binds a fresh socket. With rsi
; non-null (a hot binary upgrade) the owner instead adopts the inherited
; fd fd_array[i] — the listeners never close, so no connection is
; refused across the exec.
linnea_network_listen_all:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [adopt_fds], rsi
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
    cmp qword [adopt_fds], 0
    jne .adopt
    mov rdi, r14
    call linnea_network_listener_create
    mov dword [r14 + linnea_config_server.listener_owner], 1
    jmp .next_server
.adopt:
    mov rax, [adopt_fds]        ; fd_array[i], inherited across the exec
    mov ecx, [rax + r12 * 4]
    mov [r14 + linnea_config_server.listen_fd], ecx
    mov dword [r14 + linnea_config_server.listener_owner], 1
    mov rdi, r14
    call linnea_network_listener_adopt
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
; linnea_network_quic_listener(rdi=server*) -> rax = udp fd, or -1 on failure.
; The HTTP/3 counterpart of the TCP listener: the same host and port, but a
; datagram socket and no listen(2). Failure is not fatal — the server keeps
; serving TCP and simply offers no HTTP/3.
linnea_network_quic_listener:
    push rbx
    push r12
    mov rbx, rdi
    mov rdi, rbx
    lea rsi, [sockaddr_scratch]
    call linnea_network_fill_sockaddr6
    cmp rax, -1
    je .qfail
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET6
    mov esi, LINNEA_SOCK_DGRAM
    xor edx, edx
    syscall
    cmp rax, -4095
    jae .qfail
    mov r12, rax
    ; IPV6_V6ONLY = 0: accept IPv4 (as ::ffff:x) on this AF_INET6 socket too.
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_IPPROTO_IPV6
    mov edx, LINNEA_IPV6_V6ONLY
    lea r10, [sockopt_zero]
    mov r8d, 4
    syscall
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_SOL_SOCKET
    mov edx, LINNEA_SO_REUSEADDR
    lea r10, [sockopt_one]
    mov r8d, 4
    syscall
    ; SO_REUSEPORT: every worker binds this port and the kernel hands each
    ; datagram to one socket by hashing its 4-tuple, so all packets from a
    ; given client reach the same worker — the affinity a QUIC connection
    ; needs, since each worker holds its own connection pool. The TCP
    ; listener is still bound once, by the master, without SO_REUSEPORT, so
    ; a second linnea on the same port still fails fast there.
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_SOL_SOCKET
    mov edx, LINNEA_SO_REUSEPORT
    lea r10, [sockopt_one]
    mov r8d, 4
    syscall
    cmp rax, -4095
    jae .qclose
    mov eax, LINNEA_SYS_BIND
    mov rdi, r12
    lea rsi, [sockaddr_scratch]
    mov edx, LINNEA_SOCKADDR_IN6_SIZE
    syscall
    cmp rax, -4095
    jae .qclose
    mov rax, r12
    jmp .qret
.qclose:
    mov rdi, r12
    mov eax, LINNEA_SYS_CLOSE
    syscall
.qfail:
    mov rax, -1
.qret:
    pop r12
    pop rbx
    ret

; socket + SO_REUSEADDR + bind + listen. Stores the fd in server.listen_fd
; and logs "listening on <host>:<port> (<hostname>)". Exits on any failure.
linnea_network_listener_create:
    push rbx
    push r12
    mov rbx, rdi
    mov rdi, rbx
    lea rsi, [sockaddr_scratch]
    call linnea_network_fill_sockaddr6
    cmp rax, -1
    je .bad_host
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET6
    mov esi, LINNEA_SOCK_STREAM
    xor edx, edx
    syscall
    cmp rax, -4095
    jae .socket_fail
    mov r12, rax               ; fd
    ; IPV6_V6ONLY = 0: accept IPv4 (as ::ffff:x) on this AF_INET6 socket too.
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_IPPROTO_IPV6
    mov edx, LINNEA_IPV6_V6ONLY
    lea r10, [sockopt_zero]
    mov r8d, 4
    syscall
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
    mov edx, LINNEA_SOCKADDR_IN6_SIZE
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

; linnea_network_listener_adopt(rdi=server*) — the listen_fd is already
; set to an inherited socket; just log "adopted listener host:port
; (hostname)", mirroring listener_create's line.
linnea_network_listener_adopt:
    push rbx
    mov rbx, rdi
    call linnea_log_stamp
    lea rdi, [log_adopt]
    mov esi, log_adopt_len
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
    pop rbx
    ret

; linnea_network_peer_format(rdi=socket fd, rsi=out buffer) -> rax=len
; Writes the connected peer. An IPv4 or IPv4-mapped peer is "a.b.c.d:port"; a
; native IPv6 peer is "[h:h:h:h:h:h:h:h]:port" (eight hex groups, minimal
; digits). The port shares offset 2 in sockaddr_in and sockaddr_in6. The buffer
; must have room for linnea_string_from_u64's 20-byte scratch past the write
; cursor (72 bytes is plenty). On any failure writes "-" and returns 1.
linnea_network_peer_format:
    push rbx
    push r12
    push r13
    sub rsp, 48                ; sockaddr (28) + socklen (8); keeps calls aligned
    mov rbx, rsi               ; out buffer
    mov eax, LINNEA_SYS_GETPEERNAME
    mov rsi, rsp
    lea rdx, [rsp + 32]
    mov qword [rsp + 32], LINNEA_SOCKADDR_IN6_SIZE
    syscall
    cmp rax, -4095
    jae .unknown
    mov r12, rbx               ; write cursor
    movzx eax, word [rsp]
    cmp eax, LINNEA_AF_INET6
    je .v6maybe
    cmp eax, LINNEA_AF_INET
    jne .unknown
    lea r13, [rsp + 4]         ; native IPv4: octets at offset 4
    jmp .fmt_v4
.v6maybe:
    ; IPv4-mapped ::ffff:a.b.c.d has addr bytes 0..9 = 0, 10,11 = 0xff
    cmp qword [rsp + 8], 0
    jne .v6
    cmp dword [rsp + 16], 0xffff0000
    jne .v6
    lea r13, [rsp + 20]        ; the mapped IPv4 octets
    ; fall through
.fmt_v4:
    movzx edi, byte [r13]
    mov rsi, r12
    call linnea_string_from_u64
    add r12, rax
    mov byte [r12], '.'
    inc r12
    movzx edi, byte [r13 + 1]
    mov rsi, r12
    call linnea_string_from_u64
    add r12, rax
    mov byte [r12], '.'
    inc r12
    movzx edi, byte [r13 + 2]
    mov rsi, r12
    call linnea_string_from_u64
    add r12, rax
    mov byte [r12], '.'
    inc r12
    movzx edi, byte [r13 + 3]
    mov rsi, r12
    call linnea_string_from_u64
    add r12, rax
    jmp .port
.v6:
    ; "[h:h:h:h:h:h:h:h]" — eight big-endian 16-bit groups, minimal hex digits
    mov byte [r12], '['
    inc r12
    lea r13, [rsp + 8]         ; 16 address bytes
    xor r9d, r9d               ; group index 0..7
.v6_group:
    test r9d, r9d
    jz .v6_nocolon
    mov byte [r12], ':'
    inc r12
.v6_nocolon:
    movzx eax, byte [r13]      ; high byte
    shl eax, 8
    movzx ecx, byte [r13 + 1]
    or eax, ecx                ; 16-bit group value
    mov ecx, 12                ; shift of the top nibble
.v6_skip:
    test ecx, ecx
    jz .v6_emit                ; keep the last nibble even if zero
    mov edx, eax
    shr edx, cl
    and edx, 0xf
    jnz .v6_emit
    sub ecx, 4
    jmp .v6_skip
.v6_emit:
    mov edx, eax
    shr edx, cl
    and edx, 0xf
    cmp edx, 10
    jb .v6_dec
    add edx, 'a' - 10
    jmp .v6_put
.v6_dec:
    add edx, '0'
.v6_put:
    mov [r12], dl
    inc r12
    sub ecx, 4
    jns .v6_emit
    add r13, 2
    inc r9d
    cmp r9d, 8
    jb .v6_group
    mov byte [r12], ']'
    inc r12
.port:
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
    add rsp, 48
    pop r13
    pop r12
    pop rbx
    ret
.unknown:
    mov byte [rbx], '-'
    mov eax, 1
    add rsp, 48
    pop r13
    pop r12
    pop rbx
    ret

; linnea_network_fill_sockaddr6(rdi=server*, rsi=out sockaddr_in6) -> rax 0/-1
; Builds a 28-byte sockaddr_in6 for a dual-stack listener bind. "0.0.0.0" and
; "::" become the unspecified address (::), which — with IPV6_V6ONLY cleared —
; accepts native IPv6 and IPv4 (as ::ffff:x); a specific IPv4 literal binds that
; address IPv4-mapped (::ffff:a.b.c.d). Returns -1 for anything else.
linnea_network_fill_sockaddr6:
    push rbx
    mov rbx, rsi               ; out
    xor eax, eax
    mov [rbx], rax             ; zero all 28 bytes
    mov [rbx + 8], rax
    mov [rbx + 16], rax
    mov [rbx + 24], eax
    mov word [rbx], LINNEA_AF_INET6
    movzx ecx, word [rdi + linnea_config_server.port]
    xchg cl, ch                ; htons
    mov [rbx + 2], cx
    push rdi                    ; parse_ipv4 walks rdi; keep server*
    lea rdi, [rdi + linnea_config_server.host]
    call linnea_network_parse_ipv4
    pop rdi
    cmp rax, -1
    je .maybe_v6any
    test eax, eax
    jz .anyaddr                ; "0.0.0.0" -> unspecified (::)
    ; specific IPv4 -> ::ffff:a.b.c.d  (addr at rbx+8: bytes 10,11=0xff, 12..15=octets)
    mov word [rbx + 18], 0xffff
    mov [rbx + 20], eax
    jmp .ok
.maybe_v6any:
    ; the only non-IPv4 host we accept is the literal "::" (unspecified)
    cmp qword [rdi + linnea_config_server.host_len], 2
    jne .bad
    cmp word [rdi + linnea_config_server.host], 0x3a3a   ; "::"
    jne .bad
.anyaddr:
    ; unspecified address :: — the 16 addr bytes are already zero
.ok:
    xor eax, eax
    pop rbx
    ret
.bad:
    mov rax, -1
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
