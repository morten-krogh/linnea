; linnea_network.asm — listening sockets, one per configured server.
; Every listener is a dual-stack AF_INET6 socket with IPV6_V6ONLY cleared, so a
; single socket serves both IPv6 clients and IPv4 clients (the latter arriving
; as IPv4-mapped ::ffff:a.b.c.d). The configured host is still an IPv4 literal,
; "0.0.0.0", or "::"; hostnames are rejected.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global linnea_network_listen_all
global linnea_network_write_port_file
global linnea_network_probe_owner
global linnea_listen_reuseport
global linnea_listen_quiet
global linnea_network_peer_format
global linnea_network_addr_format
global linnea_network_peer_addr
global linnea_network_parse_ipv4
global linnea_network_parse_ipv6
global linnea_network_fill_sockaddr6
global linnea_network_quic_listener

extern linnea_error_server
extern linnea_string_equal
extern linnea_string_from_u64
extern linnea_log_write
extern linnea_log_u64
extern linnea_log_stamp
extern linnea_print_stderr
extern linnea_print_u64_stderr

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
msg_getsockname:    db "bound but could not read back the kernel-chosen port for"
msg_getsockname_len equ $ - msg_getsockname
msg_port_file:      db "linnea: cannot write port_file "
msg_port_file_len   equ $ - msg_port_file
msg_pf_errno:       db " (errno "
msg_pf_errno_len    equ $ - msg_pf_errno
msg_pf_close:       db ")", 10
msg_pf_close_len    equ $ - msg_pf_close

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
; 4 MiB of QUIC receive buffer, shared by every connection on this worker. The
; kernel clamps this to net.core.rmem_max (4 MiB on a stock kernel) and doubles
; what it stores for its own bookkeeping.
sockopt_rcvbuf:     dd 4194304

section .bss

; port_file scratch. One line is a hostname, a host, a port and two spaces plus
; the newline; linnea_string_from_u64 writes into 20 bytes from the cursor it is
; given, so the per-line allowance carries that rather than the 5 digits a port
; needs, and the whole buffer carries one more for the last line.
PF_LINE_MAX equ LINNEA_MAX_HOSTNAME + LINNEA_MAX_HOST + 24
pf_buf:     resb PF_LINE_MAX * LINNEA_MAX_SERVERS + 32
pf_tmp:     resb LINNEA_MAX_ROOT + 8      ; the path plus ".tmp" and a NUL

; 1 = listener_create binds SO_REUSEPORT: one listener set per worker, so the
; kernel spreads accepted connections across the workers instead of one ring
; winning them all. Off for the legacy adopted-fd path.
;
; NOT close-on-exec, whatever this line used to claim: the hot upgrade hands
; these fds to the next generation by number and it adopts the same sockets, so
; they have to survive the execve. Nothing here sets FD_CLOEXEC.
linnea_listen_reuseport: resd 1
; 1 = bind silently. The per-worker listener sets are the same sockets from
; the operator's point of view, so only the first pass logs "listening on".
linnea_listen_quiet: resd 1
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

; linnea_network_write_port_file(rdi=config*) — report the ports actually bound,
; one line per server in declaration order:
;
;   <hostname> <host> <port>
;
; Nothing is written when no port_file is configured. It goes to "<path>.tmp"
; and is renamed into place, so a reader polling for the file sees either
; nothing or the finished contents — never a truncated first line, which is
; exactly the race a test would hit, once in a hundred runs, on the very
; mechanism meant to remove races.
;
; Called from the master after every listener exists and before any worker is
; forked, so the file is there by the time anything can connect.
linnea_network_write_port_file:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    cmp qword [rbx + linnea_config.port_file_len], 0
    je .wp_done
    ; --- build the contents ---
    lea r12, [pf_buf]                       ; write cursor
    xor r13d, r13d                          ; server index
.wp_loop:
    cmp r13, [rbx + linnea_config.server_count]
    jae .wp_built
    imul r14, r13, linnea_config_server_size
    lea r14, [rbx + r14 + linnea_config.servers]
    lea rdi, [r14 + linnea_config_server.hostname]
    mov rsi, [r14 + linnea_config_server.hostname_len]
    mov rdx, r12
    call pf_append
    mov r12, rax
    mov byte [r12], ' '
    inc r12
    lea rdi, [r14 + linnea_config_server.host]
    mov rsi, [r14 + linnea_config_server.host_len]
    mov rdx, r12
    call pf_append
    mov r12, rax
    mov byte [r12], ' '
    inc r12
    movzx edi, word [r14 + linnea_config_server.port]
    mov rsi, r12
    call linnea_string_from_u64
    add r12, rax
    mov byte [r12], 10
    inc r12
    inc r13
    jmp .wp_loop
.wp_built:
    ; --- <path>.tmp, then rename ---
    lea rdi, [rbx + linnea_config.port_file]
    mov rsi, [rbx + linnea_config.port_file_len]
    lea rdx, [pf_tmp]
    call pf_append                          ; rax = end of the copied path
    mov dword [rax], '.tmp'                 ; 4 bytes plus the NUL below
    mov byte [rax + 4], 0
    lea rdi, [pf_tmp]
    mov esi, LINNEA_O_WRONLY | LINNEA_O_CREAT | LINNEA_O_TRUNC | LINNEA_O_CLOEXEC
    mov edx, 0o644
    mov eax, LINNEA_SYS_OPEN
    syscall
    cmp rax, -4095
    jae .wp_fail
    mov r13d, eax                           ; fd
    lea rsi, [pf_buf]
    mov r14, r12
    sub r14, rsi                            ; bytes still to write
    ; LOOP over it. write(2) returns a COUNT, and a caller that takes a short
    ; write for a whole one truncates the file — which the rename below would
    ; then publish as complete, defeating the one thing the rename is for. A
    ; regular file writes short only on a full filesystem or a signal, so this
    ; is for correctness rather than the common case, exactly as
    ; linnea_spill_write's loop is.
.wp_write:
    test r14, r14
    jz .wp_written
    mov eax, LINNEA_SYS_WRITE
    mov edi, r13d
    mov rdx, r14
    syscall
    cmp rax, -4095
    jae .wp_wclose                          ; a real error: close, then fail
    test rax, rax
    jz .wp_wclose                           ; no progress: a full filesystem
    add rsi, rax
    sub r14, rax
    jmp .wp_write
.wp_written:
    mov eax, LINNEA_SYS_CLOSE
    mov edi, r13d
    syscall
    jmp .wp_renamed
.wp_wclose:
    mov r14, rax                            ; keep the errno (or 0 for no space)
    mov eax, LINNEA_SYS_CLOSE
    mov edi, r13d
    syscall
    mov rax, r14
    test rax, rax
    jnz .wp_fail
    mov rax, -LINNEA_ENOSPC                 ; no progress: say so, not "errno 0"
    jmp .wp_fail
.wp_renamed:
    mov eax, LINNEA_SYS_RENAME
    lea rdi, [pf_tmp]
    lea rsi, [rbx + linnea_config.port_file]
    syscall
    cmp rax, -4095
    jae .wp_fail
.wp_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.wp_fail:
    ; A port_file nobody can write is a silent failure for whoever is waiting on
    ; it, so it stops the start rather than leaving them to time out. The errno
    ; is carried, not collapsed: ENOENT (a directory that is not there) and
    ; EACCES are different mistakes and the reader has to be told which.
    neg rax
    mov r13, rax
    lea rdi, [msg_port_file]
    mov esi, msg_port_file_len
    call linnea_print_stderr
    lea rdi, [rbx + linnea_config.port_file]
    mov rsi, [rbx + linnea_config.port_file_len]
    call linnea_print_stderr
    lea rdi, [msg_pf_errno]
    mov esi, msg_pf_errno_len
    call linnea_print_stderr
    mov rdi, r13
    call linnea_print_u64_stderr
    lea rdi, [msg_pf_close]
    mov esi, msg_pf_close_len
    call linnea_print_stderr
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall

; pf_append(rdi = src, rsi = len, rdx = dst) -> rax = dst + len.
; A plain copy; the buffer is sized for the worst case in .bss below.
pf_append:
    push rcx
    mov rcx, rsi
    mov rax, rdx
    add rax, rsi
    test rcx, rcx
    jz .pa_done
.pa_copy:
    mov r8b, [rdi]
    mov [rdx], r8b
    inc rdi
    inc rdx
    dec rcx
    jnz .pa_copy
.pa_done:
    pop rcx
    ret

; linnea_network_probe_owner(rdi=server*) — bind the server's port WITHOUT
; SO_REUSEPORT and close the socket at once. A reuseport bind happily joins
; any same-uid group, so it alone would never notice a port that some other
; program already holds; this plain bind is the fail-fast check the shared
; listener used to provide. Only called on a fresh start — during a hot
; upgrade the previous generation legitimately holds the port.
linnea_network_probe_owner:
    push rbx
    push r12
    mov rbx, rdi
    lea rsi, [sockaddr_scratch]
    call linnea_network_fill_sockaddr6
    cmp rax, -1
    je .pr_bad_host
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET6
    mov esi, LINNEA_SOCK_STREAM
    xor edx, edx
    syscall
    cmp rax, -4095
    jae .pr_socket_fail
    mov r12, rax
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_IPPROTO_IPV6
    mov edx, LINNEA_IPV6_V6ONLY
    lea r10, [sockopt_zero]                 ; dual-stack by default...
    cmp qword [rbx + linnea_config_server.v6only], 0
    je .v6only_done
    lea r10, [sockopt_one]                  ; ...or IPv6-only when the server asked
.v6only_done:
    mov r8d, 4
    syscall
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_SOL_SOCKET
    mov edx, LINNEA_SO_REUSEADDR
    lea r10, [sockopt_one]
    mov r8d, 4
    syscall
    mov eax, LINNEA_SYS_BIND
    mov rdi, r12
    lea rsi, [sockaddr_scratch]
    mov edx, LINNEA_SOCKADDR_IN6_SIZE
    syscall
    cmp rax, -4095
    jae .pr_bind_fail
    mov edi, r12d
    mov eax, LINNEA_SYS_CLOSE
    syscall
    pop r12
    pop rbx
    ret
.pr_bad_host:
    lea rdi, [msg_bad_host]
    mov esi, msg_bad_host_len
    mov rdx, rbx
    xor ecx, ecx
    jmp linnea_error_server
.pr_socket_fail:
    neg rax
    mov rcx, rax
    lea rdi, [msg_socket]
    mov esi, msg_socket_len
    mov rdx, rbx
    jmp linnea_error_server
.pr_bind_fail:
    neg rax
    mov rcx, rax
    lea rdi, [msg_bind]
    mov esi, msg_bind_len
    mov rdx, rbx
    jmp linnea_error_server

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
    lea r10, [sockopt_zero]                 ; dual-stack by default...
    cmp qword [rbx + linnea_config_server.v6only], 0
    je .v6only_done
    lea r10, [sockopt_one]                  ; ...or IPv6-only when the server asked
.v6only_done:
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
    ; listeners work the same way since Q122; the master's port PROBE (a
    ; plain bind, immediately closed) is what still fails fast when some
    ; other program holds the port.
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_SOL_SOCKET
    mov edx, LINNEA_SO_REUSEPORT
    lea r10, [sockopt_one]
    mov r8d, 4
    syscall
    cmp rax, -4095
    jae .qclose
    ; Every QUIC connection this worker serves shares this one socket, so its
    ; receive buffer is a resource they all draw on: a burst spread across many
    ; connections concentrates here, and whatever does not fit is dropped by the
    ; kernel before the server ever sees it. The default (net.core.rmem_default,
    ; ~208KB) is a couple of hundred datagrams. Ask for more; the kernel clamps
    ; to net.core.rmem_max, so this is a request, not a demand, and a failure
    ; costs nothing.
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_SOL_SOCKET
    mov edx, LINNEA_SO_RCVBUF
    lea r10, [sockopt_rcvbuf]
    mov r8d, 4
    syscall
    ; Ask the kernel to coalesce. With UDP_GRO a run of same-sized datagrams
    ; from one flow arrives in a single recvmsg, with the segment size attached
    ; as a control message, instead of one completion apiece. An h3 upload is
    ; exactly that shape -- measured at 31,772 datagrams of ~630 bytes for
    ; 20 MB, against 1,310 reads for the same bytes over TCP, where the kernel
    ; had already coalesced for us. It is a request: an old kernel refuses it,
    ; the cmsg then never appears, and the receive path handles its absence by
    ; treating the read as the single datagram it used to be.
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_SOL_UDP
    mov edx, LINNEA_UDP_GRO
    lea r10, [sockopt_one]
    mov r8d, 4
    syscall
    ; and count what is dropped anyway: SO_RXQ_OVFL attaches the socket's
    ; running overflow counter to each recvmsg as a control message. Without it
    ; the loss is completely invisible — the datagrams simply never arrive.
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_SOL_SOCKET
    mov edx, LINNEA_SO_RXQ_OVFL
    lea r10, [sockopt_one]
    mov r8d, 4
    syscall
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
    lea r10, [sockopt_zero]                 ; dual-stack by default...
    cmp qword [rbx + linnea_config_server.v6only], 0
    je .v6only_done
    lea r10, [sockopt_one]                  ; ...or IPv6-only when the server asked
.v6only_done:
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
    cmp dword [linnea_listen_reuseport], 0
    je .no_rp
    ; one listener per worker: SO_REUSEPORT groups them and the kernel hashes
    ; each connection to one, spreading the accepts. Deliberately NOT
    ; close-on-exec: a hot upgrade hands the whole matrix to the next
    ; generation, which keeps every socket open, so a connection already
    ; queued on one is still accepted (closing it would reset that client).
    mov eax, LINNEA_SYS_SETSOCKOPT
    mov rdi, r12
    mov esi, LINNEA_SOL_SOCKET
    mov edx, LINNEA_SO_REUSEPORT
    lea r10, [sockopt_one]
    mov r8d, 4
    syscall
    cmp rax, -4095
    jae .sockopt_fail
.no_rp:
    mov eax, LINNEA_SYS_BIND
    mov rdi, r12
    lea rsi, [sockaddr_scratch]
    mov edx, LINNEA_SOCKADDR_IN6_SIZE
    syscall
    cmp rax, -4095
    jae .bind_fail
    ; "port": 0 asked the kernel to choose. Write its answer back into the
    ; config, because every later reader takes the port from this field: the
    ; shared-listener scan in listen_all, the log line below, Alt-Svc, the
    ; port_file. Above all, the NEXT worker's listener binds from here too —
    ; without the write-back each worker in a SO_REUSEPORT set would ask for 0
    ; again and get a different port, which is not a set at all.
    cmp word [rbx + linnea_config_server.port], 0
    jne .have_port
    mov rdi, r12
    call resolve_bound_port
    test ax, ax
    jz .getsockname_fail
    mov [rbx + linnea_config_server.port], ax
.have_port:
    mov eax, LINNEA_SYS_LISTEN
    mov rdi, r12
    mov esi, LINNEA_BACKLOG
    syscall
    cmp rax, -4095
    jae .listen_fail
    mov [rbx + linnea_config_server.listen_fd], r12d
    cmp dword [linnea_listen_quiet], 0
    jne .lc_quiet
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
.lc_quiet:
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
.getsockname_fail:
    xor ecx, ecx
    lea rdi, [msg_getsockname]
    mov esi, msg_getsockname_len
    mov rdx, rbx
    jmp linnea_error_server

; resolve_bound_port(rdi = a bound socket fd) -> ax = the port in host byte
; order, or 0 if the kernel would not say. sin6_port sits at offset 2 of
; sockaddr_in6, network order, exactly as in sockaddr_in.
resolve_bound_port:
    sub rsp, 48                ; sockaddr (28) + socklen (8); keeps calls aligned
    mov qword [rsp + 32], LINNEA_SOCKADDR_IN6_SIZE
    mov eax, LINNEA_SYS_GETSOCKNAME
    mov rsi, rsp
    lea rdx, [rsp + 32]
    syscall
    cmp rax, -4095
    jae .rbp_none
    movzx eax, word [rsp + 2]
    xchg al, ah                ; network to host order
    add rsp, 48
    ret
.rbp_none:
    xor eax, eax
    add rsp, 48
    ret

; linnea_network_listener_adopt(rdi=server*) — the listen_fd is already
; set to an inherited socket; just log "adopted listener host:port
; (hostname)", mirroring listener_create's line.
linnea_network_listener_adopt:
    push rbx
    mov rbx, rdi
    ; A config that said "port": 0 still says 0 in the next generation, but the
    ; inherited socket already carries the port the previous one was given —
    ; ask it, so a hot upgrade keeps serving on the same number rather than
    ; logging and reporting a 0.
    cmp word [rbx + linnea_config_server.port], 0
    jne .la_have_port
    mov edi, [rbx + linnea_config_server.listen_fd]
    call resolve_bound_port
    mov [rbx + linnea_config_server.port], ax
.la_have_port:
    cmp dword [linnea_listen_quiet], 0
    jne .la_quiet
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
.la_quiet:
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
    sub rsp, 48                ; sockaddr (28) + socklen (8); keeps calls aligned
    mov rbx, rsi               ; out buffer
    mov eax, LINNEA_SYS_GETPEERNAME
    mov rsi, rsp
    lea rdx, [rsp + 32]
    mov qword [rsp + 32], LINNEA_SOCKADDR_IN6_SIZE
    syscall
    cmp rax, -4095
    jae .pf_unknown
    mov rdi, rsp
    mov rsi, rbx
    call linnea_network_addr_format
    add rsp, 48
    pop rbx
    ret
.pf_unknown:
    mov byte [rbx], '-'
    mov eax, 1
    add rsp, 48
    pop rbx
    ret

; linnea_network_addr_format(rdi=sockaddr*, rsi=out buffer) -> rax = length.
; The address text: "a.b.c.d:port" for IPv4 (native or v6-mapped),
; "[h:h:h:h:h:h:h:h]:port" for IPv6, "-" for any other family. Split from
; peer_format so the QUIC side can log a peer from its stored sockaddr —
; a UDP socket has no connected fd for getpeername to ask about.
linnea_network_addr_format:
    push rbx
    push r12
    push r13
    push rbp
    sub rsp, 8                 ; keep the number-formatter calls 16-aligned
    mov rbp, rdi               ; the sockaddr
    mov rbx, rsi               ; out buffer start
    mov r12, rsi               ; write cursor
    movzx eax, word [rbp]
    cmp eax, LINNEA_AF_INET6
    je .v6maybe
    cmp eax, LINNEA_AF_INET
    jne .unknown
    lea r13, [rbp + 4]         ; native IPv4: octets at offset 4
    jmp .fmt_v4
.v6maybe:
    ; IPv4-mapped ::ffff:a.b.c.d has addr bytes 0..9 = 0, 10,11 = 0xff
    cmp qword [rbp + 8], 0
    jne .v6
    cmp dword [rbp + 16], 0xffff0000
    jne .v6
    lea r13, [rbp + 20]        ; the mapped IPv4 octets
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
    lea r13, [rbp + 8]         ; 16 address bytes
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
    movzx eax, word [rbp + 2]
    xchg al, ah                ; network to host order
    movzx edi, ax
    mov rsi, r12
    call linnea_string_from_u64
    add r12, rax
    mov rax, r12
    sub rax, rbx
    add rsp, 8
    pop rbp
    pop r13
    pop r12
    pop rbx
    ret
.unknown:
    mov byte [rbx], '-'
    mov eax, 1
    add rsp, 8
    pop rbp
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
    ; "::" (unspecified) is the dual-stack wildcard; any other valid IPv6 literal
    ; binds that specific address (v6-only for it, since a v4 client arrives as a
    ; different ::ffff:x address). parse_ipv6 preserves rbx (our sockaddr).
    cmp qword [rdi + linnea_config_server.host_len], 2
    jne .try_v6literal
    cmp word [rdi + linnea_config_server.host], 0x3a3a   ; "::"
    je .anyaddr
.try_v6literal:
    lea rdi, [rdi + linnea_config_server.host]
    lea rsi, [rbx + 8]                                   ; sin6_addr
    call linnea_network_parse_ipv6
    cmp rax, -1
    je .bad
    jmp .ok
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


; linnea_network_parse_ipv6(rdi = NUL-terminated string, rsi = out 16 bytes)
;   -> rax = 0 on success (out holds the address in network order), else -1.
;
; inet_pton(AF_INET6): up to eight colon-separated groups of 1-4 hex digits, at
; most one "::" standing for a run of zero groups, and an optional trailing IPv4
; dotted-quad occupying the low 32 bits (parsed by linnea_network_parse_ipv4,
; which reuses the same NUL-terminated string). A zone id ("%eth0") is not
; accepted -- '%' is not a hex digit, so it simply fails the group parse.
;
; State: r12 = out, r13 = cursor, r14 = w (bytes written 0..16), r15 = colonp
; (the byte offset the "::" marks, or -1), ebp = the group value so far, ebx =
; its digit count, [rsp] = curtok (the token start, for a dotted-quad).
linnea_network_parse_ipv6:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 8                     ; [rsp] = curtok
    mov r12, rsi                   ; out base
    xor eax, eax
    mov [r12], rax                 ; zero all 16 output bytes
    mov [r12 + 8], rax
    mov r13, rdi                   ; cursor
    xor r14d, r14d                 ; w = 0
    mov r15, -1                    ; colonp = none
    xor ebp, ebp                   ; group value
    xor ebx, ebx                   ; group digits
    mov [rsp], r13                 ; curtok = start
    ; a leading ':' is legal only as the first colon of "::"
    cmp byte [r13], ':'
    jne .p6_loop
    inc r13
    cmp byte [r13], ':'
    jne .p6_bad                    ; ":x..." — a lone leading colon
    mov [rsp], r13                 ; curtok; the loop sees the second ':' as "::"
.p6_loop:
    movzx eax, byte [r13]
    test al, al
    jz .p6_end
    cmp al, ':'
    je .p6_colon
    cmp al, '.'
    je .p6_dot
    ; a hex digit, else invalid
    movzx edx, al
    sub edx, '0'
    cmp edx, 9
    jbe .p6_digit                  ; '0'-'9'
    movzx edx, al
    or  edx, 0x20                  ; tolower
    sub edx, 'a'
    cmp edx, 5
    ja  .p6_bad                    ; not 'a'-'f' (and not ':' '.' handled above)
    add edx, 10
.p6_digit:
    inc ebx
    cmp ebx, 4
    ja  .p6_bad                    ; more than four hex digits in a group
    shl ebp, 4
    or  ebp, edx
    inc r13
    jmp .p6_loop
.p6_colon:
    inc r13
    mov [rsp], r13                 ; curtok = just past this ':'
    test ebx, ebx
    jnz .p6_flush                  ; a real group precedes this ':': store it
    ; empty group -> "::"
    cmp r15, -1
    jne .p6_bad                    ; a second "::"
    mov r15, r14                   ; colonp marks where the zero-run belongs
    jmp .p6_loop
.p6_flush:
    lea rax, [r14 + 2]
    cmp rax, 16
    ja  .p6_bad
    mov edx, ebp                   ; store the u16 big-endian
    mov [r12 + r14 + 1], dl        ; low byte
    shr edx, 8
    mov [r12 + r14], dl            ; high byte
    mov r14, rax
    xor ebp, ebp
    xor ebx, ebx
    ; a ':' that separated a real group must be followed by more input; a ':' at
    ; the very end (e.g. "1:2:") is a dangling separator, not a legal "::"
    cmp byte [r13], 0
    je  .p6_bad
    jmp .p6_loop
.p6_dot:
    ; a dotted-quad from curtok to the string's NUL, into the low 32 bits
    lea rax, [r14 + 4]
    cmp rax, 16
    ja  .p6_bad
    mov rdi, [rsp]                 ; curtok
    call linnea_network_parse_ipv4 ; eax = 4 bytes network-order, or -1 (preserves r12-r15/rbp/rbx)
    cmp eax, -1
    je  .p6_bad
    mov [r12 + r14], eax           ; already network order
    add r14, 4
    xor ebx, ebx                   ; nothing left to flush; the quad ended at NUL
    jmp .p6_end
.p6_end:
    ; flush a trailing hex group, if the string did not end on a ':'
    test ebx, ebx
    jz  .p6_gap
    lea rax, [r14 + 2]
    cmp rax, 16
    ja  .p6_bad
    mov edx, ebp
    mov [r12 + r14 + 1], dl
    shr edx, 8
    mov [r12 + r14], dl
    mov r14, rax
.p6_gap:
    cmp r15, -1
    je  .p6_exact
    ; "::" present: slide the [colonp, w) tail to the end and zero the hole.
    ; n = w - colonp bytes move to [16-n, 16); [colonp, 16-n) becomes zero.
    mov rcx, r14
    sub rcx, r15                   ; n = bytes after the gap
    test rcx, rcx
    jz  .p6_gap_zero               ; "::" at the very end (e.g. "1::")
    lea rdi, [r12 + 16]
    sub rdi, rcx                   ; dst = out + 16 - n
    lea rsi, [r12 + r15]           ; src = out + colonp
    mov rdx, rcx                   ; copy backward (dst > src may overlap)
.p6_gap_copy:
    dec rdx
    mov al, [rsi + rdx]
    mov [rdi + rdx], al
    test rdx, rdx
    jnz .p6_gap_copy
.p6_gap_zero:
    ; zero (16 - w) bytes at colonp -- the space the moved tail vacated
    lea rdi, [r12 + r15]
    mov rcx, 16
    sub rcx, r14                   ; shift = 16 - w
    xor eax, eax
    rep stosb
    jmp .p6_ok
.p6_exact:
    cmp r14, 16
    jne .p6_bad                    ; no "::" and not exactly eight groups
.p6_ok:
    add rsp, 8
    xor eax, eax
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.p6_bad:
    add rsp, 8
    mov rax, -1
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; linnea_network_peer_addr(rdi = fd, rsi = out, 16 bytes) -> rax = address length
;   (4 for IPv4, 16 for IPv6), or 0 if the peer cannot be read.
; The address only — no port — because this identifies the host behind a
; connection, and a host opening many connections uses many ports.
linnea_network_peer_addr:
    push rbx
    sub rsp, 48                ; sockaddr (28) + socklen (8); keeps calls aligned
    mov rbx, rsi
    mov eax, LINNEA_SYS_GETPEERNAME
    mov rsi, rsp
    lea rdx, [rsp + 32]
    mov qword [rsp + 32], LINNEA_SOCKADDR_IN6_SIZE
    syscall
    cmp rax, -4095
    jae .none
    movzx eax, word [rsp]
    cmp eax, LINNEA_AF_INET6
    je .v6
    mov eax, [rsp + 4]         ; sockaddr_in: 4 address bytes
    mov [rbx], eax
    mov eax, 4
    jmp .ret
.v6:
    mov rax, [rsp + 8]         ; sockaddr_in6: 16 address bytes
    mov [rbx], rax
    mov rax, [rsp + 16]
    mov [rbx + 8], rax
    mov eax, 16
    jmp .ret
.none:
    xor eax, eax
.ret:
    add rsp, 48
    pop rbx
    ret
