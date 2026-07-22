; linnea_uring.asm — io_uring event loop built on liburing (vendored,
; nolibc build). One multishot accept is armed per listening socket.
; Accepted connections get a pool slot and a recv with a linked idle
; timeout; complete request heads are answered by linnea_http (headers
; from out_buf, then the mmap'd file if any). Keep-alive connections
; consume the request bytes and continue; others are closed.
;
; A request routed to a proxy location instead runs an upstream exchange:
; connect -> send the rewritten request -> read the response head -> relay
; the body to the client, a bufferful at a time. Every step is driven from
; the completion of the step before, so a connection still has exactly one
; operation in flight at any moment (recv, send, connect, or an upstream
; send/recv — never two). That invariant is what makes closing a
; connection safe without cancelling anything: the only completion that
; can outlive it is a linked timeout, and those are dropped at dispatch
; before the pool index is ever resolved. Nothing is armed on the client
; socket while the upstream exchange runs, so a client that disappears
; mid-exchange surfaces on the next send to it — and every operation,
; sends included, carries a linked idle timeout, so no dead or stalled
; peer can pin a connection slot beyond it. Partial progress re-arms the
; op with a fresh timeout: only a peer making no progress at all is cut.
;
; A 101 from the upstream turns the connection into a full-duplex tunnel
; (websockets): two independent recv->send chains, one per direction, so
; the invariant becomes one op per DIRECTION. Teardown still cancels
; nothing: both sockets are shut down and the slot is freed once the
; other direction's op has drained (see the tunnel section).
;
; CQE user_data encodes (index << 8) | op tag — see linnea_uring.inc.
; Listener/ring errors are fatal; per-connection errors just close and
; free that connection; accept errors are logged and the accept re-armed.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"
%include "linnea_connection.inc"
%include "linnea_http.inc"
%include "linnea_uring.inc"
%include "linnea_quic.inc"
%include "linnea_quic_conn.inc"
%include "linnea_tls.inc"
%include "linnea_http2.inc"

global linnea_uring_run
global drain_flag

extern io_uring_queue_init
extern io_uring_get_sqe
extern io_uring_submit
extern __io_uring_get_cqe

extern linnea_config_instance
extern linnea_network_peer_format
extern linnea_connection_alloc
extern linnea_connection_free
extern linnea_connection_at
extern linnea_connection_active
extern linnea_http_handle
extern linnea_http_proxy_error
extern linnea_http_proxy_head
extern linnea_http_proxy_log
extern linnea_error_exit
extern linnea_print_stderr
extern linnea_print_u64_stderr
extern linnea_log_write
extern linnea_log_u64
extern linnea_log_stamp
extern linnea_tls_hs_init
extern linnea_tls_hs_input
extern linnea_tls_drain_early
extern linnea_ktls_enable
extern linnea_h2_init
extern linnea_h2_handle
extern linnea_h2_after_send
extern linnea_h2_conn_free
extern linnea_string_iequal
extern linnea_network_quic_listener
extern linnea_quic_server_init
extern linnea_quic_altsvc_set
extern linnea_h3_server
extern linnea_quic_server_datagram
extern linnea_quic_server_rtx_sweep
extern linnea_quic_server_goaway_all
extern linnea_quic_rxbuf
extern linnea_bpf_map_fd
extern linnea_bpf_prog_fd
extern linnea_bpf_map_add
extern linnea_bpf_attach
extern linnea_worker_index

section .rodata

msg_init:           db "io_uring_queue_init failed"
msg_init_len        equ $ - msg_init
msg_sqe:            db "io_uring submission queue full"
msg_sqe_len         equ $ - msg_sqe
msg_submit:         db "io_uring_submit failed"
msg_submit_len      equ $ - msg_submit
msg_wait:           db "io_uring wait failed"
msg_wait_len        equ $ - msg_wait

warn_accept:        db "linnea: accept failed (errno "
warn_accept_len     equ $ - warn_accept
warn_accept_end:    db ")", 10
warn_accept_end_len equ $ - warn_accept_end
warn_full:          db "linnea: connection limit reached, dropping connection", 10
warn_full_len       equ $ - warn_full

log_accept:         db "accepted connection on "
log_accept_len      equ $ - log_accept
log_closed:         db "closed connection on "
log_closed_len      equ $ - log_closed
log_from:           db " from "
log_from_len        equ $ - log_from
log_colon:          db ":"
log_fd:             db " (fd "
log_fd_len          equ $ - log_fd
log_close:          db ")", 10
log_close_len       equ $ - log_close
log_reason:         db "): "
log_reason_len      equ $ - log_reason
log_nl:             db 10

reason_peer:        db "peer closed"
reason_peer_len     equ $ - reason_peer
reason_timeout:     db "idle timeout"
reason_timeout_len  equ $ - reason_timeout
reason_recv_err:    db "recv error"
reason_recv_err_len equ $ - reason_recv_err
reason_send_err:    db "send error"
reason_send_err_len equ $ - reason_send_err
reason_send_timeout: db "send timeout"
reason_send_timeout_len equ $ - reason_send_timeout
reason_done:        db "close after response"
reason_done_len     equ $ - reason_done
reason_up_early:    db "upstream closed early"
reason_up_early_len equ $ - reason_up_early
reason_up_timeout:  db "upstream timeout"
reason_up_timeout_len equ $ - reason_up_timeout
reason_drain:       db "draining"
reason_drain_len    equ $ - reason_drain

log_drain:          db "worker draining: accepts closed, finishing open connections", 10
log_drain_len       equ $ - log_drain
log_drained:        db "worker drained", 10
log_drained_len     equ $ - log_drained

msg_signalfd:       db "signalfd failed"
msg_signalfd_len    equ $ - msg_signalfd
reason_up_recv_err: db "upstream recv error"
reason_up_recv_err_len equ $ - reason_up_recv_err
reason_up_closed:   db "upstream closed"
reason_up_closed_len equ $ - reason_up_closed
reason_up_send_err: db "upstream send error"
reason_up_send_err_len equ $ - reason_up_send_err
reason_tls_failed:  db "tls handshake failed"
reason_tls_failed_len equ $ - reason_tls_failed
reason_tls_badrec:  db "tls bad record"
reason_tls_badrec_len equ $ - reason_tls_badrec
reason_tls_split:   db "tls pipelined record too large to buffer"
reason_tls_split_len equ $ - reason_tls_split
reason_tls_ktls:    db "tls kernel handoff failed"
reason_tls_ktls_len equ $ - reason_tls_ktls

section .data

idle_timeout:       dq LINNEA_DEFAULT_TIMEOUT, 0    ; struct __kernel_timespec
; QUIC probe-timeout tick. A relative one-shot timeout re-armed on every fire;
; each tick runs the retransmission sweep. 50 ms bounds how late a lost reply is
; resent past its probe timeout, and how often a worker wakes when idle.
pto_timer:          dq 0, 50000000                  ; {sec, nsec} = 50 ms

section .bss

ring:               resb LINNEA_URING_RING_SIZE
cqe_ptr:            resq 1
idle_timeout_ns:    resq 1     ; the idle timeout as nanoseconds, for the
                               ; tunnel's last_activity comparison
sig_mask:           resq 1     ; blocked-signal set: SIGTERM
sig_fd:             resd 1
drain_flag:         resd 1     ; 1 = draining: no accepts, close after serve
quic_fd:    resd 1
            resd 1
qrecv_msg:  resb LINNEA_MSGHDR_SIZE
qrecv_iov:  resb LINNEA_IOVEC_SIZE
qrecv_peer: resb LINNEA_SOCKADDR_IN_SIZE
sig_buf:            resb 128   ; struct signalfd_siginfo

section .text

; A TLS connection's handshake state is overlaid on its up_buf (see the
; accept path): nothing is proxied until the handshake is done, so the two
; never coexist. That overlay is load-bearing — msg_buf's own bounds are
; derived from it — so assert it here rather than trust the comment on
; LINNEA_TLS_MSG_BUF. Emits no bytes; a struc that outgrows up_buf makes
; the divisor zero and fails the assembly.
[absolute 0]
    resb 1 / (LINNEA_CONN_UP_BUF >= linnea_tls_hs_size)
    ; .tls_handoff hands out_buf to linnea_tls_drain_early as the scratch a
    ; record's plaintext is decrypted into, bounded only by in_buf's size —
    ; and decryption happens before the tag is checked, so this bound has to
    ; hold for a peer that knows no keys. The two buffers are sized
    ; independently, so state the relationship instead of relying on it.
    resb 1 / (LINNEA_CONN_OUT_BUF >= LINNEA_CONN_IN_BUF)
__?SECT?__

; linnea_uring_run(rdi=config*) — set up the ring, arm accepts, loop forever.
; Only returns by exiting the process on error.
linnea_uring_run:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi               ; config*
    mov rax, [rbx + linnea_config.timeout]
    mov [idle_timeout], rax
    imul rax, rax, 1000000000
    mov [idle_timeout_ns], rax

    mov edi, LINNEA_URING_ENTRIES
    lea rsi, [ring]
    xor edx, edx
    call io_uring_queue_init
    test eax, eax
    js .init_fail

    ; SIGTERM means drain, and arrives as a cqe like everything else:
    ; block it, open a signalfd for it, and arm a read on the ring. The
    ; master's death delivers it too (PR_SET_PDEATHSIG in linnea_start).
    mov qword [sig_mask], 1 << (LINNEA_SIGTERM - 1)
    mov eax, LINNEA_SYS_RT_SIGPROCMASK
    mov edi, LINNEA_SIG_BLOCK
    lea rsi, [sig_mask]
    xor edx, edx
    mov r10d, 8
    syscall
    mov eax, LINNEA_SYS_SIGNALFD4
    mov edi, -1
    lea rsi, [sig_mask]
    mov edx, 8
    xor r10d, r10d
    syscall
    cmp rax, -4095
    jae .signalfd_fail
    mov [sig_fd], eax
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_READ
    mov ecx, [sig_fd]
    mov [rax + LINNEA_SQE_FD], ecx
    lea rcx, [sig_buf]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], 128
    mov qword [rax + LINNEA_SQE_USER_DATA], LINNEA_UD_SIGNAL

    ; HTTP/3 listener: the first TLS server with usable key material gets a
    ; UDP socket on its own host and port. Failure is not fatal — we simply
    ; serve no HTTP/3.
    mov dword [quic_fd], -1
    xor r12d, r12d
.quic_scan:
    cmp r12, [rbx + linnea_config.server_count]
    jae .quic_done
    imul rdx, r12, linnea_config_server_size
    lea rdx, [rbx + rdx + linnea_config.servers]
    cmp dword [rdx + linnea_config_server.tls], 0
    je .quic_next
    cmp qword [rdx + linnea_config_server.cert_list], 0
    je .quic_next
    cmp qword [rdx + linnea_config_server.location_count], 0
    je .quic_next
    lea rcx, [rdx + linnea_config_server.locations]
    cmp qword [rcx + linnea_config_location.kind], LINNEA_LOC_KIND_ROOT
    jne .quic_next             ; only a static root is served over h3 so far
    push rdx
    push rcx
    mov rdi, rdx
    call linnea_network_quic_listener
    pop rcx
    pop rdx
    cmp rax, -1
    je .quic_next
    mov [quic_fd], eax
    ; hand the handler the framed chain, the key and the document root
    mov rdi, [rdx + linnea_config_server.cert_list]
    mov rsi, [rdx + linnea_config_server.cert_list_len]
    mov r8, [rcx + linnea_config_location.root_len]
    lea rcx, [rcx + linnea_config_location.root]
    mov rdx, [rdx + linnea_config_server.key_priv]
    call linnea_quic_server_init
    ; advertise HTTP/3 on this port from the TCP responses
    imul rdx, r12, linnea_config_server_size
    lea rdx, [rbx + rdx + linnea_config.servers]
    movzx edi, word [rdx + linnea_config_server.port]
    mov [linnea_h3_server], r12      ; only this server advertises it
    call linnea_quic_altsvc_set
    call linnea_uring_arm_qrecv
    call linnea_uring_arm_qtimer
    ; if the BPF steering program loaded, register this worker's QUIC socket at
    ; its index in the reuseport map and attach the program to the group, so a
    ; connection's later packets are routed here by its id even if the client
    ; migrates to a new address (which would otherwise re-hash to another worker).
    ; Done last: it clobbers the scratch the QUIC setup above still needed.
    cmp qword [linnea_bpf_prog_fd], 0
    jl .quic_done
    mov edi, [linnea_worker_index]
    mov esi, [quic_fd]
    call linnea_bpf_map_add
    mov edi, [quic_fd]
    mov esi, [linnea_bpf_prog_fd]
    call linnea_bpf_attach
    jmp .quic_done
.quic_next:
    inc r12
    jmp .quic_scan
.quic_done:

    xor r12d, r12d             ; server index
.arm_loop:
    cmp r12, [rbx + linnea_config.server_count]
    jae .armed
    imul rdx, r12, linnea_config_server_size
    lea rdx, [rbx + rdx + linnea_config.servers]
    cmp dword [rdx + linnea_config_server.listener_owner], 0
    je .arm_next               ; shares another server's listener
    mov rdi, r12
    call linnea_uring_arm_accept
.arm_next:
    inc r12
    jmp .arm_loop
.armed:
    call linnea_uring_submit_now

.wait:
    lea rdi, [ring]
    lea rsi, [cqe_ptr]
    xor edx, edx               ; submit = 0
    mov ecx, 1                 ; wait_nr = 1
    xor r8d, r8d               ; sigmask = NULL
    call __io_uring_get_cqe
    cmp eax, -LINNEA_EINTR
    je .wait
    test eax, eax
    js .wait_fail

    mov r12, [cqe_ptr]
    mov r13, [r12 + LINNEA_CQE_USER_DATA]
    mov r14d, [r12 + LINNEA_CQE_FLAGS]
    mov r15d, [r12 + LINNEA_CQE_RES]
    ; mark the cqe seen: *cq.khead += 1 (x86 stores have release ordering)
    lea rax, [ring]
    mov rcx, [rax + LINNEA_URING_CQ_KHEAD]
    mov edx, [rcx]
    inc edx
    mov [rcx], edx

    mov eax, r13d
    and eax, 0xff              ; op tag
    shr r13, 8                 ; index
    cmp eax, LINNEA_UD_TIMEOUT
    je .wait                   ; timeout cqes carry no work
    cmp eax, LINNEA_UD_CANCEL
    je .wait                   ; accept-cancel result: nothing to do
    cmp eax, LINNEA_UD_SIGNAL
    je .on_signal
    cmp eax, LINNEA_UD_RECV
    je .on_recv
    cmp eax, LINNEA_UD_SEND
    je .on_send
    cmp eax, LINNEA_UD_CONNECT
    je .on_connect
    cmp eax, LINNEA_UD_UP_SEND
    je .on_up_send
    cmp eax, LINNEA_UD_UP_RECV
    je .on_up_recv
    cmp eax, LINNEA_UD_QRECV
    je .on_qrecv
    cmp eax, LINNEA_UD_QTIMER
    je .on_qtimer
    jmp .on_accept             ; tag 0: no longer the textual fall-through

; --- QUIC datagram on the UDP listener: r15d = bytes or -errno ---------
; The handler owns the receive buffer and replies on the socket itself, so the
; loop only has to pass on the length and the sender, then re-arm.
.on_qrecv:
    test r15d, r15d
    jle .qrecv_rearm
    mov edi, r15d
    lea rsi, [qrecv_peer]
    mov edx, [qrecv_msg + LINNEA_MSGHDR_NAMELEN]   ; kernel-updated length
    mov ecx, [quic_fd]
    call linnea_quic_server_datagram
.qrecv_rearm:
    cmp dword [drain_flag], 0
    jne .wait                  ; draining: take no new datagrams
    call linnea_uring_arm_qrecv
    call linnea_uring_submit_now
    jmp .wait

; --- QUIC probe-timeout tick: resend anything unacknowledged past its PTO ---
; The timeout completes (with -ETIME) on every tick; res carries no work. Run
; the retransmission sweep over the pool, then re-arm unless draining.
.on_qtimer:
    mov edi, [quic_fd]
    call linnea_quic_server_rtx_sweep
    cmp dword [drain_flag], 0
    jne .wait                  ; draining: no more ticks
    call linnea_uring_arm_qtimer
    call linnea_uring_submit_now
    jmp .wait

; --- SIGTERM arrived on the signalfd: drain --------------------------
; Stop taking new work but finish what is open: cancel every armed
; accept (their completions close our copies of the listener fds, which
; releases the port once every worker has done the same), let in-flight
; requests run to their end, close instead of keep-alive afterwards,
; and exit when the last connection is freed.
.on_signal:
    cmp dword [drain_flag], 0
    jnz .wait                  ; a second SIGTERM changes nothing
    mov dword [drain_flag], 1
    call linnea_log_stamp
    lea rdi, [log_drain]
    mov esi, log_drain_len
    call linnea_log_write
    ; tell connected h3 peers we are going away before anything else — even a
    ; worker with no TCP connections (which exits below) gets the GOAWAY out
    cmp dword [quic_fd], 0
    jl .no_goaway
    mov edi, [quic_fd]
    call linnea_quic_server_goaway_all
.no_goaway:
    cmp qword [linnea_connection_active], 0
    je .drained_exit
    xor r13d, r13d             ; server index
.cancel_loop:
    cmp r13, [rbx + linnea_config.server_count]
    jae .cancel_submit
    imul rax, r13, linnea_config_server_size
    lea rax, [rbx + rax + linnea_config.servers]
    cmp dword [rax + linnea_config_server.listener_owner], 0
    je .cancel_next
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_ASYNC_CANCEL
    mov r14, r13
    shl r14, 8
    or r14, LINNEA_UD_ACCEPT
    mov [rax + LINNEA_SQE_ADDR], r14   ; the accept's user_data
    mov qword [rax + LINNEA_SQE_USER_DATA], LINNEA_UD_CANCEL
.cancel_next:
    inc r13
    jmp .cancel_loop
.cancel_submit:
    call linnea_uring_submit_now
    jmp .wait
.drained_exit:
    call linnea_log_stamp
    lea rdi, [log_drained]
    mov esi, log_drained_len
    call linnea_log_write
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; --- accept completion: r13 = server index, r15d = connection fd ------
.on_accept:
    cmp dword [drain_flag], 0
    jnz .accept_drain
    test r15d, r15d
    js .accept_err
    call linnea_connection_alloc
    test rax, rax
    jz .conn_limit
    mov r12, rax               ; connection*
    mov [r12 + linnea_connection.fd], r15d
    mov [r12 + linnea_connection.server], r13d
    mov edi, r15d
    lea rsi, [r12 + linnea_connection.peer]
    call linnea_network_peer_format
    mov [r12 + linnea_connection.peer_len], rax
    mov rdi, r12
    call linnea_uring_log_accept
    ; TLS listeners begin a userspace handshake before any HTTP; its state
    ; overlays up_buf (no proxying can be active yet). The accepting server
    ; is the listener owner; its cert is the default until the ClientHello
    ; names a vhost and the SNI hook below picks that vhost's cert instead.
    mov eax, [r12 + linnea_connection.server]
    imul rax, rax, linnea_config_server_size
    lea rax, [rbx + rax + linnea_config.servers]
    cmp dword [rax + linnea_config_server.tls], 0
    je .accept_recv
    lea rdi, [r12 + linnea_connection.up_buf]
    mov rsi, [rax + linnea_config_server.cert_list]
    mov rdx, [rax + linnea_config_server.cert_list_len]
    mov rcx, [rax + linnea_config_server.key_priv]
    xor r8d, r8d
    call linnea_tls_hs_init
    lea rax, [linnea_uring_sni_select]
    mov [r12 + linnea_connection.up_buf + linnea_tls_hs.select_cb], rax
    mov [r12 + linnea_connection.up_buf + linnea_tls_hs.select_ctx], r12
    ; Offer h2 in ALPN only when enabled AND the accepting server has no
    ; proxy location — proxy-over-h2 is not implemented yet, so a proxy vhost
    ; must keep speaking HTTP/1.1.
    mov eax, [rbx + linnea_config.http2]
    test eax, eax
    jz .set_alpn
    mov ecx, [r12 + linnea_connection.server]
    imul rcx, rcx, linnea_config_server_size
    lea rdx, [rbx + rcx + linnea_config.servers]
    mov r8, [rdx + linnea_config_server.location_count]
    lea r9, [rdx + linnea_config_server.locations]
    xor ecx, ecx
.h2_loc_scan:
    cmp rcx, r8
    jae .set_alpn                          ; no proxy: eax stays 1
    cmp qword [r9 + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY
    je .h2_off
    add r9, linnea_config_location_size
    inc rcx
    jmp .h2_loc_scan
.h2_off:
    xor eax, eax
.set_alpn:
    mov [r12 + linnea_connection.up_buf + linnea_tls_hs.alpn_h2_ok], eax
    mov qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_HS
.accept_recv:
    mov rdi, r12
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
.accept_rearm:
    test r14d, LINNEA_IORING_CQE_F_MORE
    jnz .wait
    mov rdi, r13               ; kernel disarmed the multishot: re-arm
    call linnea_uring_arm_accept
    call linnea_uring_submit_now
    jmp .wait
.accept_drain:
    ; draining: refuse a raced-in connection, and once this accept is
    ; finished (the cancel's -ECANCELED, or any final completion) close
    ; our copy of the listening socket instead of re-arming
    test r15d, r15d
    js .accept_drain_done
    mov edi, r15d
    mov eax, LINNEA_SYS_CLOSE
    syscall
    test r14d, LINNEA_IORING_CQE_F_MORE
    jnz .wait                  ; multishot still armed; the cancel ends it
.accept_drain_done:
    imul rax, r13, linnea_config_server_size
    lea rax, [rbx + rax + linnea_config.servers]
    mov edi, [rax + linnea_config_server.listen_fd]
    mov eax, LINNEA_SYS_CLOSE
    syscall
    jmp .wait
.accept_err:
    lea rdi, [warn_accept]
    mov esi, warn_accept_len
    call linnea_print_stderr
    mov edi, r15d
    neg edi
    call linnea_print_u64_stderr
    lea rdi, [warn_accept_end]
    mov esi, warn_accept_end_len
    call linnea_print_stderr
    jmp .accept_rearm
.conn_limit:
    mov edi, r15d
    mov eax, LINNEA_SYS_CLOSE
    syscall
    lea rdi, [warn_full]
    mov esi, warn_full_len
    call linnea_print_stderr
    jmp .accept_rearm

; --- recv completion: r13 = connection index, r15d = bytes or -errno --
; A fired idle timeout surfaces here as -ECANCELED and closes the
; connection like any other recv failure.
.on_recv:
    mov rdi, r13
    call linnea_connection_at
    mov r12, rax               ; connection*
    cmp qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_HS
    je .tls_recv
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_TUNNEL
    je .tunnel_client_recv
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CLOSING
    je .closing_c2u
    test r15d, r15d
    jg .recv_data
    jz .recv_eof
    cmp r15d, -LINNEA_ECANCELED
    je .recv_timeout
    call tls_recv_is_eof
    test eax, eax
    jnz .recv_eof
    lea r14, [reason_recv_err]
    mov r15d, reason_recv_err_len
    jmp .conn_close
.recv_eof:
    lea r14, [reason_peer]
    mov r15d, reason_peer_len
    jmp .conn_close
.recv_timeout:
    lea r14, [reason_timeout]
    mov r15d, reason_timeout_len
    jmp .conn_close
.recv_data:
    mov eax, r15d
    add [r12 + linnea_connection.in_len], rax
    cmp qword [r12 + linnea_connection.is_h2], 0
    jne .h2_process
.process:
    mov rdi, r12
    call linnea_http_handle
    test eax, eax
    jz .recv_more
    cmp eax, LINNEA_HTTP_PROXY
    je .proxy_connect
    mov rdi, r12               ; response ready
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
; --- HTTP/2: process buffered frames, then send / read / close --------
.h2_process:
    mov rdi, r12
    call linnea_h2_handle
    cmp eax, LINNEA_H2_CLOSE
    je .h2_close
    test eax, eax              ; LINNEA_H2_MORE
    jz .recv_more
    mov rdi, r12               ; LINNEA_H2_SEND: flush response frames
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.h2_close:
    lea r14, [reason_done]
    mov r15d, reason_done_len
    jmp .conn_close
.proxy_connect:
    mov rdi, r12               ; the request goes to an upstream first
    call linnea_uring_arm_connect
    call linnea_uring_submit_now
    jmp .wait
.recv_more:
    mov rdi, r12
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .wait

; --- send completion: r13 = connection index, r15d = bytes or -errno --
; A send that moved no bytes for the idle timeout completes -ECANCELED:
; the client has stopped reading, so the connection is torn down.
.on_send:
    mov rdi, r13
    call linnea_connection_at
    mov r12, rax
    cmp qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_HS
    je .tls_on_send
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_TUNNEL
    je .tunnel_client_send
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CLOSING
    je .closing_u2c
    test r15d, r15d
    jns .send_ok
    cmp r15d, -LINNEA_ECANCELED
    je .send_timeout
    lea r14, [reason_send_err]
    mov r15d, reason_send_err_len
    jmp .conn_close
.send_timeout:
    lea r14, [reason_send_timeout]
    mov r15d, reason_send_timeout_len
    jmp .conn_close
.send_ok:
    mov eax, r15d
    add [r12 + linnea_connection.out_ptr], rax
    sub [r12 + linnea_connection.out_rem], rax
    cmp qword [r12 + linnea_connection.out_rem], 0
    jne .send_more
    ; current segment done; is the file body still queued?
    mov rax, [r12 + linnea_connection.file_rem]
    test rax, rax
    jz .send_drained
    mov [r12 + linnea_connection.out_rem], rax
    mov rax, [r12 + linnea_connection.file_ptr]
    mov [r12 + linnea_connection.out_ptr], rax
    mov qword [r12 + linnea_connection.file_rem], 0
.send_more:
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.send_drained:
    ; HTTP/2: a flight of frames finished going out. Continue streaming a
    ; response body if one is in flight (or a WINDOW_UPDATE has unblocked
    ; it); otherwise, if we queued a GOAWAY close, else process any frames
    ; still buffered or read more (this also picks up the client preface
    ; after our SETTINGS).
    cmp qword [r12 + linnea_connection.is_h2], 0
    je .not_h2_send
    mov rdi, r12
    call linnea_h2_after_send
    cmp eax, LINNEA_H2_SEND
    je .h2_send_more
    cmp eax, LINNEA_H2_CLOSE
    je .h2_close
    cmp qword [r12 + linnea_connection.in_len], 0
    jne .h2_process
    mov rdi, r12
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .wait
.h2_send_more:
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.not_h2_send:
    ; a relayed response continues with the next chunk from the upstream
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_RELAY
    je .relay_next
    ; a drained 101 head switches the connection to the tunnel
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_UPGRADE
    je .tunnel_start

.response_done:
    mov rdi, [r12 + linnea_connection.file_base]
    test rdi, rdi
    jz .no_unmap
    mov rsi, [r12 + linnea_connection.file_size]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    mov qword [r12 + linnea_connection.file_base], 0
    mov qword [r12 + linnea_connection.file_size], 0
.no_unmap:
    cmp dword [drain_flag], 0
    jne .drain_close           ; draining: no keep-alive, no pipelining
    cmp qword [r12 + linnea_connection.keep_alive], 0
    jne .keep_alive_continue
    lea r14, [reason_done]
    mov r15d, reason_done_len
    jmp .conn_close
.drain_close:
    lea r14, [reason_drain]
    mov r15d, reason_drain_len
    jmp .conn_close
.keep_alive_continue:
    ; keep-alive: drop the consumed head, keep any pipelined bytes
    mov rax, [r12 + linnea_connection.in_len]
    sub rax, [r12 + linnea_connection.head_len]
    mov [r12 + linnea_connection.in_len], rax
    lea rdi, [r12 + linnea_connection.in_buf]
    mov rsi, rdi
    add rsi, [r12 + linnea_connection.head_len]
    mov rcx, rax
    rep movsb                  ; forward copy, dst < src
    cmp qword [r12 + linnea_connection.in_len], 0
    jne .process               ; a pipelined request is already buffered
    mov rdi, r12
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .wait

; --- TLS handshake phase: r12 = connection*, r15d = bytes or -errno -----
; While tls_phase is set, client recv/send drive the userspace handshake
; (state overlaid on up_buf) instead of HTTP. On completion the app keys
; go to the kernel (kTLS) and the connection becomes an ordinary plaintext
; one — the rest of the loop never learns it was ever encrypted.
.tls_recv:
    test r15d, r15d
    jg .tls_recv_data
    jz .tls_peer_closed
    cmp r15d, -LINNEA_ECANCELED
    je .tls_recv_timeout
    lea r14, [reason_recv_err]
    mov r15d, reason_recv_err_len
    jmp .conn_close
.tls_peer_closed:
    lea r14, [reason_peer]
    mov r15d, reason_peer_len
    jmp .conn_close
.tls_recv_timeout:
    lea r14, [reason_timeout]
    mov r15d, reason_timeout_len
    jmp .conn_close
.tls_recv_data:
    mov eax, r15d
    add [r12 + linnea_connection.in_len], rax
    ; Already DONE: the handshake is over and we are only here to collect
    ; the rest of a record the client pipelined behind its Finished, which
    ; must be whole before the kernel can take the socket over.
    cmp dword [r12 + linnea_connection.up_buf + linnea_tls_hs.state], LINNEA_TLS_DONE
    je .tls_handoff
.tls_process:
    lea rdi, [r12 + linnea_connection.up_buf]
    lea rsi, [r12 + linnea_connection.in_buf]
    mov rdx, [r12 + linnea_connection.in_len]
    lea rcx, [r12 + linnea_connection.out_buf]
    mov r8, LINNEA_CONN_OUT_BUF
    call linnea_tls_hs_input       ; rax = state
    mov r10, rax                   ; not r13: the loop's r13 is the
                                   ; connection index and shared code below
                                   ; still expects it
    ; drop the consumed bytes from the front of in_buf
    mov rcx, [r12 + linnea_connection.up_buf + linnea_tls_hs.consumed]
    test rcx, rcx
    jz .tls_after_consume
    mov rax, [r12 + linnea_connection.in_len]
    sub rax, rcx                   ; bytes kept
    mov [r12 + linnea_connection.in_len], rax
    lea rdi, [r12 + linnea_connection.in_buf]
    lea rsi, [rdi + rcx]
    mov rcx, rax
    rep movsb                      ; forward copy, dst < src
.tls_after_consume:
    mov rax, [r12 + linnea_connection.up_buf + linnea_tls_hs.out_len]
    test rax, rax
    jz .tls_no_out
    lea rcx, [r12 + linnea_connection.out_buf]
    mov [r12 + linnea_connection.out_ptr], rcx
    mov [r12 + linnea_connection.out_rem], rax
    mov qword [r12 + linnea_connection.file_rem], 0
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.tls_no_out:
    cmp r10, LINNEA_TLS_DONE
    je .tls_handoff
    mov rdi, r12                   ; WAIT_CH/WAIT_FIN: need more client bytes
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .wait

.tls_on_send:
    test r15d, r15d
    js .tls_send_err
    mov eax, r15d
    add [r12 + linnea_connection.out_ptr], rax
    sub [r12 + linnea_connection.out_rem], rax
    cmp qword [r12 + linnea_connection.out_rem], 0
    jne .tls_send_more
    cmp dword [r12 + linnea_connection.up_buf + linnea_tls_hs.state], LINNEA_TLS_FAILED
    je .tls_send_failed
    ; the flight is out (WAIT_FIN): process buffered bytes or read more
    cmp qword [r12 + linnea_connection.in_len], 0
    jne .tls_process
    mov rdi, r12
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .wait
.tls_send_more:
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.tls_send_failed:
    lea r14, [reason_tls_failed]
    mov r15d, reason_tls_failed_len
    jmp .conn_close
.tls_send_err:
    cmp r15d, -LINNEA_ECANCELED
    je .tls_send_stall
    lea r14, [reason_send_err]
    mov r15d, reason_send_err_len
    jmp .conn_close
.tls_send_stall:
    lea r14, [reason_send_timeout]
    mov r15d, reason_send_timeout_len
    jmp .conn_close

; handshake complete: decrypt any pipelined early data, then hand the
; application keys to the kernel and fall into the ordinary HTTP path.
.tls_handoff:
    lea rdi, [r12 + linnea_connection.up_buf]
    lea rsi, [r12 + linnea_connection.in_buf]
    mov rdx, [r12 + linnea_connection.in_len]
    lea rcx, [r12 + linnea_connection.out_buf]
    mov r8, LINNEA_CONN_IN_BUF
    call linnea_tls_drain_early    ; rax = plaintext len / -1 / -2 / -3
    cmp rax, -1
    je .tls_badrec
    cmp rax, -2
    je .tls_early_more
    cmp rax, -3
    je .tls_split
    mov [r12 + linnea_connection.in_len], rax
    mov r10, rdx                   ; client RX sequence = records drained
                                   ; (r10, not r13: .process below is shared
                                   ; code and still wants the index)
    mov edi, [r12 + linnea_connection.fd]
    lea rsi, [r12 + linnea_connection.up_buf + linnea_tls_hs.s_ap]
    lea rdx, [r12 + linnea_connection.up_buf + linnea_tls_hs.c_ap]
    ; server TX sequence = records already sent under the app key in
    ; userspace: 0, or 1 when a NewSessionTicket went out after Finished
    mov rcx, [r12 + linnea_connection.up_buf + linnea_tls_hs.wkeys + linnea_tls_keys.seq]
    mov r8, r10
    call linnea_ktls_enable
    test rax, rax
    js .tls_ktls_fail
    mov qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_KTLS
    cmp dword [r12 + linnea_connection.up_buf + linnea_tls_hs.alpn_is_h2], 0
    jne .h2_handoff                ; ALPN chose h2: speak frames, not HTTP/1
    cmp qword [r12 + linnea_connection.in_len], 0
    jne .process                   ; HTTP on the pipelined request
    mov rdi, r12
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .wait
.h2_handoff:
    ; HTTP/2: send the server's initial SETTINGS; the client preface and
    ; its SETTINGS (pipelined in in_buf, or arriving next) are processed
    ; once that send drains (.h2_after_send).
    mov qword [r12 + linnea_connection.is_h2], 1
    mov rdi, r12
    call linnea_h2_init
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.tls_early_more:
    ; A pipelined record arrived in pieces (its first segment came in with
    ; the Finished). Stay in the handshake phase and read the rest: the
    ; recv carries the usual linked timeout, so a client that never sends
    ; it is cut like any other idle one.
    mov rdi, r12
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .wait
.tls_badrec:
    lea r14, [reason_tls_badrec]
    mov r15d, reason_tls_badrec_len
    jmp .conn_close
.tls_split:
    lea r14, [reason_tls_split]
    mov r15d, reason_tls_split_len
    jmp .conn_close
.tls_ktls_fail:
    lea r14, [reason_tls_ktls]
    mov r15d, reason_tls_ktls_len
    jmp .conn_close

; --- connect completion: r13 = connection index, r15d = 0 or -errno -----
; Nothing has been sent to the client yet, so a failure here can still be
; answered with a status of our own.
.on_connect:
    mov rdi, r13
    call linnea_connection_at
    mov r12, rax
    test r15d, r15d
    jz .connect_ok
    cmp r15d, -LINNEA_ECANCELED
    je .connect_timeout
    mov esi, 502               ; refused, unreachable, no route
    jmp .proxy_fail
.connect_timeout:
    mov esi, 504
    jmp .proxy_fail
.connect_ok:
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_SENDING
    mov rdi, r12
    call linnea_uring_arm_up_send
    call linnea_uring_submit_now
    jmp .wait

; give up on the upstream and answer the client instead; esi = 502 or 504
.proxy_fail:
    mov rdi, r12
    call linnea_http_proxy_error
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait

; --- upstream send completion: r15d = bytes or -errno ------------------
.on_up_send:
    mov rdi, r13
    call linnea_connection_at
    mov r12, rax
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_TUNNEL
    je .tunnel_up_send
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CLOSING
    je .closing_c2u
    test r15d, r15d
    js .up_send_err
    mov eax, r15d
    add [r12 + linnea_connection.out_ptr], rax
    sub [r12 + linnea_connection.out_rem], rax
    cmp qword [r12 + linnea_connection.out_rem], 0
    jne .up_send_more
    ; head sent; is the request body still queued behind it?
    mov rax, [r12 + linnea_connection.file_rem]
    test rax, rax
    jz .up_send_done
    mov [r12 + linnea_connection.out_rem], rax
    mov rax, [r12 + linnea_connection.file_ptr]
    mov [r12 + linnea_connection.out_ptr], rax
    mov qword [r12 + linnea_connection.file_rem], 0
.up_send_more:
    mov rdi, r12
    call linnea_uring_arm_up_send
    call linnea_uring_submit_now
    jmp .wait
.up_send_err:
    mov esi, 502               ; nothing sent to the client yet either way
    cmp r15d, -LINNEA_ECANCELED
    jne .proxy_fail
    mov esi, 504               ; backend accepted but stopped reading
    jmp .proxy_fail
.up_send_done:
    ; the whole request is out; read the response head back into up_buf
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_HEAD
    mov qword [r12 + linnea_connection.up_len], 0
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.up_buf]
    mov edx, LINNEA_CONN_UP_BUF
    call linnea_uring_arm_up_recv
    call linnea_uring_submit_now
    jmp .wait

; --- upstream recv completion: r15d = bytes or -errno ------------------
.on_up_recv:
    mov rdi, r13
    call linnea_connection_at
    mov r12, rax
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_TUNNEL
    je .tunnel_up_recv
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CLOSING
    je .closing_u2c
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_RELAY
    je .relay_recv
    ; reading the response head
    test r15d, r15d
    jg .head_data
    jz .head_eof
    cmp r15d, -LINNEA_ECANCELED
    je .head_timeout
    mov esi, 502
    jmp .proxy_fail
.head_eof:
    mov esi, 502               ; upstream closed without a response
    jmp .proxy_fail
.head_timeout:
    mov esi, 504
    jmp .proxy_fail
.head_data:
    mov eax, r15d
    add [r12 + linnea_connection.up_len], rax
    mov rdi, r12
    call linnea_http_proxy_head
    cmp eax, LINNEA_HTTP_HEAD_READY
    je .head_ready
    test eax, eax
    js .head_bad
    ; incomplete: read more, unless the head has filled the buffer
    mov rax, [r12 + linnea_connection.up_len]
    cmp rax, LINNEA_CONN_UP_BUF
    jae .head_bad
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.up_buf]
    add rsi, rax
    mov edx, LINNEA_CONN_UP_BUF
    sub edx, eax
    call linnea_uring_arm_up_recv
    call linnea_uring_submit_now
    jmp .wait
.head_bad:
    mov esi, 502
    jmp .proxy_fail
.head_ready:
    mov rdi, r12               ; the rewritten head goes out to the client
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait

; relaying the body: whatever arrives is forwarded as the next send
.relay_recv:
    test r15d, r15d
    jg .relay_data
    jz .relay_eof
    cmp r15d, -LINNEA_ECANCELED
    je .relay_timeout
    lea r14, [reason_up_recv_err]
    mov r15d, reason_up_recv_err_len
    jmp .conn_close
.relay_timeout:
    lea r14, [reason_up_timeout]
    mov r15d, reason_up_timeout_len
    jmp .conn_close
.relay_eof:
    cmp qword [r12 + linnea_connection.body_rem], 0
    je .proxy_finish           ; a counted body ended exactly here
    cmp qword [r12 + linnea_connection.body_rem], -1
    je .proxy_finish           ; close-delimited: the close is the end
    lea r14, [reason_up_early]  ; short of the promised Content-Length
    mov r15d, reason_up_early_len
    jmp .conn_close
.relay_data:
    mov eax, r15d              ; bytes read
    mov rcx, [r12 + linnea_connection.body_rem]
    cmp rcx, -1
    je .relay_send             ; until EOF: forward everything
    cmp rax, rcx
    jbe .relay_count
    mov rax, rcx               ; upstream overshot its Content-Length
.relay_count:
    sub [r12 + linnea_connection.body_rem], rax
.relay_send:
    lea rcx, [r12 + linnea_connection.up_buf]
    mov [r12 + linnea_connection.out_ptr], rcx
    mov [r12 + linnea_connection.out_rem], rax
    add [r12 + linnea_connection.relayed], rax
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait

; the client is up to date; either the body is complete or more is coming
.relay_next:
    cmp qword [r12 + linnea_connection.body_rem], 0
    je .proxy_finish
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.up_buf]
    mov edx, LINNEA_CONN_UP_BUF
    call linnea_uring_arm_up_recv
    call linnea_uring_submit_now
    jmp .wait

; the exchange is over: close the upstream, log it, then finish the
; response the same way a static one finishes (keep-alive or close)
.proxy_finish:
    mov edi, [r12 + linnea_connection.up_fd]
    cmp edi, -1
    je .proxy_logged
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov dword [r12 + linnea_connection.up_fd], -1
.proxy_logged:
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_IDLE
    mov rdi, r12
    call linnea_http_proxy_log
    jmp .response_done

; --- upgrade tunnel ------------------------------------------------------
; After a 101 the connection is a blind byte relay. Each direction runs
; its own recv -> send chain: client->upstream through in_buf and the
; ws_c2u cursor, upstream->client through up_buf and out_ptr/out_rem, so
; exactly one op per DIRECTION is in flight. Data in either direction
; refreshes last_activity; a recv that times out re-arms unless the whole
; tunnel has been idle for the timeout. Teardown shuts down both sockets
; so the other direction's op (if any) completes promptly, and the slot
; is freed only once both chains are idle — still no cancellation.

; the 101 head (plus any first server bytes behind it) has drained: log
; the request line while in_buf still holds it, then start both chains
.tunnel_start:
    mov rdi, r12
    call linnea_http_proxy_log
    call linnea_uring_now
    mov [r12 + linnea_connection.last_activity], rax
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_TUNNEL
    mov qword [r12 + linnea_connection.ws_u2c_busy], 1
    mov qword [r12 + linnea_connection.ws_c2u_busy], 1
    mov rdi, r12               ; upstream->client: wait for tunnel bytes
    lea rsi, [r12 + linnea_connection.up_buf]
    mov edx, LINNEA_CONN_UP_BUF
    call linnea_uring_arm_up_recv
    ; client->upstream: bytes sent ahead of the 101 are already buffered
    ; behind the request head; forward them before reading the client
    mov rax, [r12 + linnea_connection.in_len]
    sub rax, [r12 + linnea_connection.head_len]
    mov qword [r12 + linnea_connection.in_len], 0  ; in_buf is a plain
    test rax, rax                                  ; tunnel buffer now
    jz .tunnel_arm_client_recv
    lea rcx, [r12 + linnea_connection.in_buf]
    add rcx, [r12 + linnea_connection.head_len]
    mov [r12 + linnea_connection.ws_c2u_ptr], rcx
    mov [r12 + linnea_connection.ws_c2u_rem], rax
    mov rdi, r12
    mov rsi, rcx
    mov rdx, rax
    call linnea_uring_arm_up_send_buf
    call linnea_uring_submit_now
    jmp .wait
.tunnel_arm_client_recv:
    mov rdi, r12               ; in_len is 0: recv gets the whole buffer
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .wait

; client recv completed: r15d = bytes or -errno; forward bytes upstream
.tunnel_client_recv:
    mov qword [r12 + linnea_connection.ws_c2u_busy], 0
    test r15d, r15d
    jg .tunnel_c2u_data
    jz .tunnel_client_eof
    cmp r15d, -LINNEA_ECANCELED
    je .tunnel_c2u_idle
    call tls_recv_is_eof
    test eax, eax
    jnz .tunnel_client_eof
    lea r14, [reason_recv_err]
    mov r15d, reason_recv_err_len
    jmp .tunnel_close
.tunnel_client_eof:
    lea r14, [reason_peer]
    mov r15d, reason_peer_len
    jmp .tunnel_close
.tunnel_c2u_data:
    call linnea_uring_now
    mov [r12 + linnea_connection.last_activity], rax
    mov eax, r15d
    lea rcx, [r12 + linnea_connection.in_buf]
    mov [r12 + linnea_connection.ws_c2u_ptr], rcx
    mov [r12 + linnea_connection.ws_c2u_rem], rax
    mov qword [r12 + linnea_connection.ws_c2u_busy], 1
    mov rdi, r12
    mov rsi, rcx
    mov rdx, rax
    call linnea_uring_arm_up_send_buf
    call linnea_uring_submit_now
    jmp .wait
.tunnel_c2u_idle:
    call linnea_uring_now
    sub rax, [r12 + linnea_connection.last_activity]
    cmp rax, [idle_timeout_ns]
    jge .tunnel_idle_close
    mov qword [r12 + linnea_connection.ws_c2u_busy], 1
    mov rdi, r12               ; the other direction was active: re-arm
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .wait
.tunnel_idle_close:
    lea r14, [reason_timeout]
    mov r15d, reason_timeout_len
    jmp .tunnel_close

; forward to the upstream completed: r15d = bytes or -errno
.tunnel_up_send:
    mov qword [r12 + linnea_connection.ws_c2u_busy], 0
    test r15d, r15d
    js .tunnel_up_send_err
    mov eax, r15d
    add [r12 + linnea_connection.ws_c2u_ptr], rax
    sub [r12 + linnea_connection.ws_c2u_rem], rax
    mov qword [r12 + linnea_connection.ws_c2u_busy], 1
    cmp qword [r12 + linnea_connection.ws_c2u_rem], 0
    jne .tunnel_up_send_more
    mov rdi, r12               ; all forwarded: read the client again
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .wait
.tunnel_up_send_more:
    mov rdi, r12
    mov rsi, [r12 + linnea_connection.ws_c2u_ptr]
    mov rdx, [r12 + linnea_connection.ws_c2u_rem]
    call linnea_uring_arm_up_send_buf
    call linnea_uring_submit_now
    jmp .wait
.tunnel_up_send_err:
    cmp r15d, -LINNEA_ECANCELED
    je .tunnel_up_send_stall
    lea r14, [reason_up_send_err]
    mov r15d, reason_up_send_err_len
    jmp .tunnel_close
.tunnel_up_send_stall:
    lea r14, [reason_up_timeout]
    mov r15d, reason_up_timeout_len
    jmp .tunnel_close

; upstream recv completed: r15d = bytes or -errno; forward to the client
.tunnel_up_recv:
    mov qword [r12 + linnea_connection.ws_u2c_busy], 0
    test r15d, r15d
    jg .tunnel_u2c_data
    jz .tunnel_up_eof
    cmp r15d, -LINNEA_ECANCELED
    je .tunnel_u2c_idle
    lea r14, [reason_up_recv_err]
    mov r15d, reason_up_recv_err_len
    jmp .tunnel_close
.tunnel_up_eof:
    lea r14, [reason_up_closed]
    mov r15d, reason_up_closed_len
    jmp .tunnel_close
.tunnel_u2c_data:
    call linnea_uring_now
    mov [r12 + linnea_connection.last_activity], rax
    mov eax, r15d
    lea rcx, [r12 + linnea_connection.up_buf]
    mov [r12 + linnea_connection.out_ptr], rcx
    mov [r12 + linnea_connection.out_rem], rax
    add [r12 + linnea_connection.relayed], rax
    mov qword [r12 + linnea_connection.ws_u2c_busy], 1
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.tunnel_u2c_idle:
    call linnea_uring_now
    sub rax, [r12 + linnea_connection.last_activity]
    cmp rax, [idle_timeout_ns]
    jge .tunnel_idle_close
    mov qword [r12 + linnea_connection.ws_u2c_busy], 1
    mov rdi, r12               ; the other direction was active: re-arm
    lea rsi, [r12 + linnea_connection.up_buf]
    mov edx, LINNEA_CONN_UP_BUF
    call linnea_uring_arm_up_recv
    call linnea_uring_submit_now
    jmp .wait

; client send completed: r15d = bytes or -errno
.tunnel_client_send:
    mov qword [r12 + linnea_connection.ws_u2c_busy], 0
    test r15d, r15d
    js .tunnel_client_send_err
    mov eax, r15d
    add [r12 + linnea_connection.out_ptr], rax
    sub [r12 + linnea_connection.out_rem], rax
    mov qword [r12 + linnea_connection.ws_u2c_busy], 1
    cmp qword [r12 + linnea_connection.out_rem], 0
    jne .tunnel_client_send_more
    mov rdi, r12               ; all delivered: read the upstream again
    lea rsi, [r12 + linnea_connection.up_buf]
    mov edx, LINNEA_CONN_UP_BUF
    call linnea_uring_arm_up_recv
    call linnea_uring_submit_now
    jmp .wait
.tunnel_client_send_more:
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.tunnel_client_send_err:
    cmp r15d, -LINNEA_ECANCELED
    je .tunnel_client_send_stall
    lea r14, [reason_send_err]
    mov r15d, reason_send_err_len
    jmp .tunnel_close
.tunnel_client_send_stall:
    lea r14, [reason_send_timeout]
    mov r15d, reason_send_timeout_len
    jmp .tunnel_close

; tunnel teardown; r14/r15 = reason. The op that got us here is done, but
; the other direction may still have one in flight: shut both sockets
; down so it completes promptly, and free only when both chains are idle.
.tunnel_close:
    mov edi, [r12 + linnea_connection.fd]
    mov esi, LINNEA_SHUT_RDWR
    mov eax, LINNEA_SYS_SHUTDOWN
    syscall
    mov edi, [r12 + linnea_connection.up_fd]
    mov esi, LINNEA_SHUT_RDWR
    mov eax, LINNEA_SYS_SHUTDOWN
    syscall
    mov rax, [r12 + linnea_connection.ws_c2u_busy]
    or rax, [r12 + linnea_connection.ws_u2c_busy]
    test rax, rax
    jz .conn_close
    mov [r12 + linnea_connection.close_reason], r14
    mov [r12 + linnea_connection.close_reason_len], r15
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CLOSING
    jmp .wait

; a straggler op of a torn-down tunnel completed (its result no longer
; matters: both sockets are shut down); free once both chains are idle
.closing_c2u:
    mov qword [r12 + linnea_connection.ws_c2u_busy], 0
    jmp .closing_check
.closing_u2c:
    mov qword [r12 + linnea_connection.ws_u2c_busy], 0
.closing_check:
    mov rax, [r12 + linnea_connection.ws_c2u_busy]
    or rax, [r12 + linnea_connection.ws_u2c_busy]
    test rax, rax
    jnz .wait
    mov r14, [r12 + linnea_connection.close_reason]
    mov r15, [r12 + linnea_connection.close_reason_len]
    jmp .conn_close

; connection teardown; r12 = connection*, r14/r15 = reason string ptr/len
.conn_close:
    call linnea_log_stamp
    lea rdi, [log_closed]
    mov esi, log_closed_len
    call linnea_log_write
    mov eax, [r12 + linnea_connection.server]
    imul rax, rax, linnea_config_server_size
    lea r13, [rbx + rax + linnea_config.servers]   ; server*
    lea rdi, [r13 + linnea_config_server.host]
    mov rsi, [r13 + linnea_config_server.host_len]
    call linnea_log_write
    lea rdi, [log_colon]
    mov esi, 1
    call linnea_log_write
    movzx edi, word [r13 + linnea_config_server.port]
    call linnea_log_u64
    lea rdi, [log_fd]
    mov esi, log_fd_len
    call linnea_log_write
    mov edi, [r12 + linnea_connection.fd]
    call linnea_log_u64
    lea rdi, [log_reason]
    mov esi, log_reason_len
    call linnea_log_write
    mov rdi, r14
    mov rsi, r15
    call linnea_log_write
    lea rdi, [log_nl]
    mov esi, 1
    call linnea_log_write
    ; free any in-flight HTTP/2 stream body mappings (M18 pool lives in up_buf)
    cmp qword [r12 + linnea_connection.is_h2], 0
    je .close_file
    mov rdi, r12
    call linnea_h2_conn_free
.close_file:
    mov rdi, [r12 + linnea_connection.file_base]
    test rdi, rdi
    jz .close_no_file
    mov rsi, [r12 + linnea_connection.file_size]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    mov qword [r12 + linnea_connection.file_base], 0
.close_no_file:
    mov edi, [r12 + linnea_connection.up_fd]
    cmp edi, -1
    je .close_no_up
    mov eax, LINNEA_SYS_CLOSE  ; an upstream exchange died with it
    syscall
    mov dword [r12 + linnea_connection.up_fd], -1
.close_no_up:
    mov edi, [r12 + linnea_connection.fd]
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov rdi, r12
    call linnea_connection_free
    cmp dword [drain_flag], 0
    je .wait
    cmp qword [linnea_connection_active], 0
    jne .wait
    jmp .drained_exit          ; draining and that was the last one

.init_fail:
    lea rdi, [msg_init]
    mov esi, msg_init_len
    jmp linnea_error_exit
.signalfd_fail:
    lea rdi, [msg_signalfd]
    mov esi, msg_signalfd_len
    jmp linnea_error_exit
.wait_fail:
    lea rdi, [msg_wait]
    mov esi, msg_wait_len
    jmp linnea_error_exit

; tls_recv_is_eof(r12 = connection*, r15d = -errno) -> eax = 1 when a failed
; client recv is really an orderly TLS shutdown.
;
; kTLS reports a record that is not application data by attaching a
; TLS_GET_RECORD_TYPE control message. Our recvs are plain IORING_OP_RECV
; with no cmsg buffer, so the kernel has nowhere to put the record type and
; fails the read with -EIO instead (net/tls/tls_sw.c tls_record_content_type).
; That record is the peer's close_notify -- the TLS spelling of the EOF a
; plaintext connection reports as 0 -- so it must not be logged as an error.
; A KeyUpdate would surface identically; v1 does not support one and closing
; is the intended response to it either way.
; Clobbers rax only.
tls_recv_is_eof:
    xor eax, eax
    cmp r15d, -LINNEA_EIO
    jne .not_eof
    cmp qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_KTLS
    jne .not_eof
    mov eax, 1
.not_eof:
    ret

; linnea_uring_now() -> rax = CLOCK_MONOTONIC nanoseconds, for tunnel
; idleness. Nanoseconds, not seconds: whole-second truncation could call
; a tunnel idle up to a second early.
linnea_uring_now:
    sub rsp, 24
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    mov edi, LINNEA_CLOCK_MONOTONIC
    mov rsi, rsp
    syscall
    mov rax, [rsp]
    imul rax, rax, 1000000000
    add rax, [rsp + 8]
    add rsp, 24
    ret

; linnea_uring_submit_now() — submit queued sqes, fatal on error.
linnea_uring_submit_now:
    sub rsp, 8                 ; keep calls 16-byte aligned
    lea rdi, [ring]
    call io_uring_submit
    add rsp, 8
    test eax, eax
    js .fail
    ret
.fail:
    lea rdi, [msg_submit]
    mov esi, msg_submit_len
    jmp linnea_error_exit

; linnea_uring_get_sqe_zeroed() — fetch an sqe and zero all 64 bytes.
linnea_uring_get_sqe_zeroed:
    sub rsp, 8
    lea rdi, [ring]
    call io_uring_get_sqe
    add rsp, 8
    test rax, rax
    jz .full
    mov qword [rax], 0
    mov qword [rax + 8], 0
    mov qword [rax + 16], 0
    mov qword [rax + 24], 0
    mov qword [rax + 32], 0
    mov qword [rax + 40], 0
    mov qword [rax + 48], 0
    mov qword [rax + 56], 0
    ret
.full:
    lea rdi, [msg_sqe]
    mov esi, msg_sqe_len
    jmp linnea_error_exit

; linnea_uring_arm_link_timeout(rdi=connection*)
; Queue the idle timeout sqe linked to the sqe queued just before, which
; must have IOSQE_IO_LINK set. If the linked op makes no progress before
; the timeout it completes with -ECANCELED; the timeout's own cqe carries
; LINNEA_UD_TIMEOUT and is dropped at dispatch. Caller submits.
linnea_uring_arm_link_timeout:
    push rbx
    mov rbx, rdi
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_LINK_TIMEOUT
    mov dword [rax + LINNEA_SQE_FD], -1
    lea rcx, [idle_timeout]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], 1
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_TIMEOUT
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    pop rbx
    ret

; linnea_uring_arm_accept(rdi=server index)
; Queue a multishot accept for the server's listener. Caller submits.
linnea_uring_arm_accept:
    push rbx
    mov rbx, rdi
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_ACCEPT
    mov word [rax + LINNEA_SQE_IOPRIO], LINNEA_IORING_ACCEPT_MULTISHOT
    lea rdx, [linnea_config_instance]
    imul rcx, rbx, linnea_config_server_size
    lea rdx, [rdx + rcx + linnea_config.servers]
    mov ecx, [rdx + linnea_config_server.listen_fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov rcx, rbx
    shl rcx, 8
    or rcx, LINNEA_UD_ACCEPT
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    pop rbx
    ret

; linnea_uring_arm_recv(rdi=connection*)
; Queue a recv into the free tail of the connection's input buffer, with
; a linked idle timeout: if the peer stays silent the recv completes with
; -ECANCELED and the connection is closed.
linnea_uring_arm_recv:
    push rbx
    mov rbx, rdi
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_RECV
    mov byte [rax + LINNEA_SQE_FLAGS], LINNEA_IOSQE_IO_LINK
    mov ecx, [rbx + linnea_connection.fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov rcx, [rbx + linnea_connection.in_len]
    lea rdx, [rbx + rcx + linnea_connection.in_buf]
    mov [rax + LINNEA_SQE_ADDR], rdx
    mov edx, LINNEA_CONN_IN_BUF
    sub edx, ecx               ; in_len <= LINNEA_CONN_IN_BUF
    mov [rax + LINNEA_SQE_LEN], edx
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_RECV
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    mov rdi, rbx               ; the timeout sqe must immediately follow
    pop rbx
    jmp linnea_uring_arm_link_timeout

; linnea_uring_arm_send(rdi=connection*)
; Queue a send of the unsent response bytes (out_ptr/out_rem), with a
; linked idle timeout: a client that stops reading closes instead of
; pinning the slot. Partial sends re-arm with a fresh timeout, so slow
; readers are unaffected.
linnea_uring_arm_send:
    mov rsi, [rdi + linnea_connection.out_ptr]
    mov rdx, [rdi + linnea_connection.out_rem]
    ; fall through
; linnea_uring_arm_send_buf(rdi=connection*, rsi=ptr, rdx=len)
linnea_uring_arm_send_buf:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_SEND
    mov byte [rax + LINNEA_SQE_FLAGS], LINNEA_IOSQE_IO_LINK
    mov ecx, [rbx + linnea_connection.fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov [rax + LINNEA_SQE_ADDR], r12
    mov [rax + LINNEA_SQE_LEN], r13d
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_SEND
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    mov rdi, rbx               ; the timeout sqe must immediately follow
    pop r13
    pop r12
    pop rbx
    jmp linnea_uring_arm_link_timeout

; linnea_uring_arm_connect(rdi=connection*)
; Queue a connect to the matched proxy location's upstream, with a linked
; idle timeout so an unresponsive upstream cannot pin the connection. The
; sockaddr lives in the parsed config, so it outlives the operation.
linnea_uring_arm_connect:
    push rbx
    mov rbx, rdi
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_CONNECT
    mov byte [rax + LINNEA_SQE_FLAGS], LINNEA_IOSQE_IO_LINK
    mov ecx, [rbx + linnea_connection.up_fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov rcx, [rbx + linnea_connection.location]
    lea rcx, [rcx + linnea_config_location.proxy_addr]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov qword [rax + LINNEA_SQE_OFF], LINNEA_SOCKADDR_IN_SIZE
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_CONNECT
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    mov rdi, rbx               ; the timeout sqe must immediately follow
    pop rbx
    jmp linnea_uring_arm_link_timeout

; linnea_uring_arm_up_send(rdi=connection*)
; Queue a send of the unsent request bytes (out_ptr/out_rem) to the
; upstream, with a linked idle timeout: a backend that accepts but never
; reads fails the request with a 504 instead of pinning the slot.
linnea_uring_arm_up_send:
    mov rsi, [rdi + linnea_connection.out_ptr]
    mov rdx, [rdi + linnea_connection.out_rem]
    ; fall through
; linnea_uring_arm_up_send_buf(rdi=connection*, rsi=ptr, rdx=len)
linnea_uring_arm_up_send_buf:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_SEND
    mov byte [rax + LINNEA_SQE_FLAGS], LINNEA_IOSQE_IO_LINK
    mov ecx, [rbx + linnea_connection.up_fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov [rax + LINNEA_SQE_ADDR], r12
    mov [rax + LINNEA_SQE_LEN], r13d
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_UP_SEND
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    mov rdi, rbx               ; the timeout sqe must immediately follow
    pop r13
    pop r12
    pop rbx
    jmp linnea_uring_arm_link_timeout

; linnea_uring_arm_up_recv(rdi=connection*, rsi=buffer, rdx=len)
; Queue a recv from the upstream with a linked idle timeout, so a silent
; backend fails the request instead of hanging it.
linnea_uring_arm_up_recv:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_RECV
    mov byte [rax + LINNEA_SQE_FLAGS], LINNEA_IOSQE_IO_LINK
    mov ecx, [rbx + linnea_connection.up_fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov [rax + LINNEA_SQE_ADDR], r12
    mov [rax + LINNEA_SQE_LEN], r13d
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_UP_RECV
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    mov rdi, rbx               ; the timeout sqe must immediately follow
    pop r13
    pop r12
    pop rbx
    jmp linnea_uring_arm_link_timeout

; linnea_uring_arm_qrecv() — queue a recvmsg on the QUIC listener. UDP needs
; the sender's address to reply, which plain recv does not report, so the
; msghdr is rebuilt each time: the kernel overwrites msg_namelen with the
; length it actually filled in. No linked timeout — like an accept, this op
; stays armed for the life of the listener.
linnea_uring_arm_qrecv:
    cmp dword [quic_fd], 0
    jl .noq
    lea rcx, [qrecv_peer]
    mov [qrecv_msg + LINNEA_MSGHDR_NAME], rcx
    mov dword [qrecv_msg + LINNEA_MSGHDR_NAMELEN], LINNEA_SOCKADDR_IN_SIZE
    lea rcx, [qrecv_iov]
    mov [qrecv_msg + LINNEA_MSGHDR_IOV], rcx
    mov qword [qrecv_msg + LINNEA_MSGHDR_IOVLEN], 1
    mov qword [qrecv_msg + LINNEA_MSGHDR_CONTROL], 0
    mov qword [qrecv_msg + LINNEA_MSGHDR_CONTROLLEN], 0
    mov dword [qrecv_msg + LINNEA_MSGHDR_FLAGS], 0
    lea rcx, [linnea_quic_rxbuf]
    mov [qrecv_iov + LINNEA_IOVEC_BASE], rcx
    mov qword [qrecv_iov + LINNEA_IOVEC_LEN], LINNEA_QUIC_RXBUF_SIZE
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_RECVMSG
    mov ecx, [quic_fd]
    mov [rax + LINNEA_SQE_FD], ecx
    lea rcx, [qrecv_msg]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], 1
    mov qword [rax + LINNEA_SQE_USER_DATA], LINNEA_UD_QRECV
.noq:
    ret

; linnea_uring_arm_qtimer() — queue the QUIC probe-timeout tick: a relative
; one-shot IORING_OP_TIMEOUT that fires after pto_timer and is re-armed on each
; completion. Only armed when a QUIC listener exists. Caller submits.
linnea_uring_arm_qtimer:
    cmp dword [quic_fd], 0
    jl .noqt
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_TIMEOUT
    mov dword [rax + LINNEA_SQE_FD], -1
    lea rcx, [pto_timer]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], 1        ; one timespec
    mov qword [rax + LINNEA_SQE_OFF], 0        ; fire on the timer, not a count
    mov qword [rax + LINNEA_SQE_USER_DATA], LINNEA_UD_QTIMER
.noqt:
    ret

; linnea_uring_log_accept(rdi=connection*)
; linnea_uring_sni_select(rdi=connection*, rsi=sni, rdx=sni_len)
; -> rax = cert_list (with rdx = cert_list_len, rcx = key_priv), or
;    rax = 0 to keep the accepting server's cert.
; Installed as hs.select_cb at accept; the TLS layer calls it between
; the ClientHello parse and the server flight. The walk mirrors HTTP
; Host routing: TLS servers sharing the accepting listener, hostnames
; compared case-insensitively; no server_name or no match falls back to
; the listener owner (RFC 6066 leaves that choice to the server).
linnea_uring_sni_select:
    push rbx
    push r12
    push r13
    push r14
    push r15
    test rdx, rdx
    jz .none                   ; no server_name offered
    mov r14, rsi               ; sni ptr
    mov r15, rdx               ; sni len
    mov eax, [rdi + linnea_connection.server]
    imul rax, rax, linnea_config_server_size
    lea rcx, [linnea_config_instance]
    lea r12, [rcx + rax + linnea_config.servers]   ; accepting server*
    lea rcx, [linnea_config_instance]
    mov r13, [rcx + linnea_config.server_count]
    xor ebx, ebx               ; candidate index
.loop:
    cmp rbx, r13
    jae .none
    imul rdx, rbx, linnea_config_server_size
    lea rcx, [linnea_config_instance]
    lea rdx, [rcx + rdx + linnea_config.servers]
    mov eax, [rdx + linnea_config_server.listen_fd]
    cmp eax, [r12 + linnea_config_server.listen_fd]
    jne .next
    cmp dword [rdx + linnea_config_server.tls], 0
    je .next
    mov rdi, r14
    mov rsi, r15
    mov rcx, [rdx + linnea_config_server.hostname_len]
    push rdx
    lea rdx, [rdx + linnea_config_server.hostname]
    call linnea_string_iequal
    pop rdx
    test eax, eax
    jz .next
    mov rax, [rdx + linnea_config_server.cert_list]
    mov rcx, [rdx + linnea_config_server.key_priv]
    mov rdx, [rdx + linnea_config_server.cert_list_len]
    jmp .ret
.next:
    inc rbx
    jmp .loop
.none:
    xor eax, eax
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Logs "accepted connection on <host>:<port> from <peer> (fd N)".
linnea_uring_log_accept:
    push rbx
    push r12
    push r13
    mov rbx, rdi               ; connection*
    mov eax, [rbx + linnea_connection.server]
    imul rax, rax, linnea_config_server_size
    lea rcx, [linnea_config_instance]
    lea r12, [rcx + rax + linnea_config.servers]   ; server*
    call linnea_log_stamp
    lea rdi, [log_accept]
    mov esi, log_accept_len
    call linnea_log_write
    lea rdi, [r12 + linnea_config_server.host]
    mov rsi, [r12 + linnea_config_server.host_len]
    call linnea_log_write
    lea rdi, [log_colon]
    mov esi, 1
    call linnea_log_write
    movzx edi, word [r12 + linnea_config_server.port]
    call linnea_log_u64
    lea rdi, [log_from]
    mov esi, log_from_len
    call linnea_log_write
    lea rdi, [rbx + linnea_connection.peer]
    mov rsi, [rbx + linnea_connection.peer_len]
    call linnea_log_write
    lea rdi, [log_fd]
    mov esi, log_fd_len
    call linnea_log_write
    mov edi, [rbx + linnea_connection.fd]
    call linnea_log_u64
    lea rdi, [log_close]
    mov esi, log_close_len
    call linnea_log_write
    pop r13
    pop r12
    pop rbx
    ret
