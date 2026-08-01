; linnea_uring.asm — the io_uring event loop. The rings themselves are set up and
; driven by linnea_ring.asm, straight against the kernel (no liburing): this file
; fills sqes and dispatches cqes. One multishot accept is armed per listening socket.
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
%include "linnea_http2.inc"
%include "linnea_uring.inc"
%include "linnea_quic.inc"
%include "linnea_quic_conn.inc"
%include "linnea_tls.inc"
%include "linnea_http2.inc"

global linnea_uring_run
global drain_flag
global head_timeout_ns
global linnea_uring_now

extern linnea_ring_init
extern linnea_ring_get_sqe
extern linnea_ring_submit
extern linnea_ring_get_cqe
extern linnea_ring_cq_overflows

extern linnea_config_instance
extern linnea_network_peer_format
extern linnea_network_peer_addr
extern linnea_connection_count_ip
extern linnea_upstream_closed
extern linnea_upstream_limit
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
extern linnea_log_reopen
extern linnea_tls_hs_init
extern linnea_tls_hs_input
extern linnea_tls_drain_early
extern linnea_ktls_enable
extern linnea_ktls_close_notify
extern linnea_h2_init
extern linnea_h2_busy
extern linnea_h2_handle
extern linnea_h2_after_send
extern linnea_h2_conn_free
extern linnea_h2_pool_active
extern h2_queue_goaway_pub
extern linnea_h2p_at
extern linnea_h2p_event
extern linnea_h2p_service
extern linnea_h2p_conn_close
extern h2p_compact
extern linnea_string_iequal
extern linnea_network_quic_listener
extern linnea_quic_server_init
extern linnea_quic_add_vhost
extern linnea_h3_advert
extern linnea_quic_altsvc_set
extern linnea_h3_server
extern linnea_quic_server_datagram
extern linnea_quic_server_rtx_sweep
extern linnea_quic_server_goaway_all
extern linnea_quic_server_drain_sweep
extern linnea_quic_conn_active
extern linnea_quic_draining
extern linnea_quic_rxbuf
extern linnea_bpf_map_fd
extern linnea_bpf_prog_fd
extern linnea_bpf_map_add
extern linnea_bpf_attach
extern linnea_worker_index

section .rodata

msg_init:           db "io_uring setup failed"
msg_init_len        equ $ - msg_init
msg_sqe:            db "io_uring submission queue full"
msg_sqe_len         equ $ - msg_sqe
msg_submit:         db "io_uring submit failed"
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
log_cqovf:          db "completion ring backlogged "
log_cqovf_len       equ $ - log_cqovf
log_cqovf_end:      db " times (cq too small for the load; nothing lost)", 10
log_cqovf_end_len   equ $ - log_cqovf_end
log_qdrop:          db "quic receive overflow: "
log_qdrop_len       equ $ - log_qdrop
log_qdrop_end:      db " datagrams dropped by the kernel (socket buffer full)", 10
log_qdrop_end_len   equ $ - log_qdrop_end
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
reason_slow_head:   db "request head too slow"
reason_slow_head_len equ $ - reason_slow_head
reason_slow_body:   db "request body too slow"
reason_slow_body_len equ $ - reason_slow_body
reason_per_ip:      db "per-address connection limit"
reason_per_ip_len   equ $ - reason_per_ip
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

dbgsplit:           db "DBG split in_len "
dbgsplit_len        equ $ - dbgsplit
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
; How long a lingering close waits between signs of life from the peer — a
; client consuming the response tail keeps sending WINDOW_UPDATEs, so only a
; vanished one goes this quiet. LINNEA_LINGER_TOTAL_NS bounds the linger as a
; whole, however lively the peer.
linger_timeout:     dq 2, 0                         ; struct __kernel_timespec
LINNEA_LINGER_TOTAL_NS equ 30000000000              ; 30 s
; QUIC probe-timeout tick. A relative one-shot timeout re-armed on every fire;
; each tick runs the retransmission sweep. 50 ms bounds how late a lost reply is
; resent past its probe timeout, and how often a worker wakes when idle.
pto_timer:          dq 0, 50000000                  ; {sec, nsec} = 50 ms
; How long to wait before retrying an accept that keeps failing. A multishot
; accept the kernel disarms with an error is otherwise re-armed at once, and a
; standing error (EMFILE above all: the fd limit is reached before the
; connection pool fills) turns the loop into a spin.
accept_retry_timer: dq 0, 100000000                 ; {sec, nsec} = 100 ms

section .bss

ring:               resb LINNEA_RING_SIZE
cqe_ptr:            resq 1
head_timeout_ns:    resq 1     ; head_timeout as nanoseconds (same units as
                               ; linnea_uring_now), for the request-head deadline
max_per_ip:         resq 1     ; connections one source address may hold
sni_select_conn:    resq 1     ; the connection the SNI callback is deciding for
idle_timeout_ns:    resq 1     ; the idle timeout as nanoseconds, for the
                               ; tunnel's last_activity comparison
sig_mask:           resq 1     ; blocked-signal set: SIGTERM + SIGHUP
sig_fd:             resd 1
drain_flag:         resd 1     ; 1 = draining: no accepts, close after serve
fast_drain:         resd 1     ; 1 = also close connections that are merely idle
accept_err_streak:  resd 1     ; consecutive failed accepts; drives the backoff
conn_full_warned:   resd 1     ; the pool-full warning has been logged already
quic_fd:    resd 1
            resd 1
qrecv_msg:  resb LINNEA_MSGHDR_SIZE
qrecv_iov:  resb LINNEA_IOVEC_SIZE
; control buffer for the SO_RXQ_OVFL cmsg: cmsghdr(16) + u32, rounded up
qrecv_cmsg: resb LINNEA_QRECV_CMSG_SIZE
qrecv_drops: resq 1        ; last overflow count seen, to report only the delta
ring_ovf_seen: resq 1      ; likewise for the completion ring's backlog count
cqe_tag:       resd 1      ; the completing op's tag, kept past the shift
cqe_gen:       resd 1      ; and the connection incarnation it was armed for
qrecv_peer: resb LINNEA_SOCKADDR_IN6_SIZE
sig_buf:            resb 128   ; struct signalfd_siginfo
; one record's plaintext during the TLS handoff (see the assertion above)
tls_early_scratch:  resb LINNEA_CONN_IN_BUF
tls_early_scratch_size equ LINNEA_CONN_IN_BUF

section .text

; A TLS connection's handshake state is overlaid on its up_buf (see the
; accept path): nothing is proxied until the handshake is done, so the two
; never coexist. That overlay is load-bearing — msg_buf's own bounds are
; derived from it — so assert it here rather than trust the comment on
; LINNEA_TLS_MSG_BUF. Emits no bytes; a struc that outgrows up_buf makes
; the divisor zero and fails the assembly.
[absolute 0]
    resb 1 / (LINNEA_CONN_UP_BUF >= linnea_tls_hs_size)
    ; .tls_handoff decrypts a record's plaintext into tls_early_scratch,
    ; bounded only by in_buf's size — and decryption happens before the tag
    ; is checked, so the bound has to hold for a peer that knows no keys.
    ; The scratch is per worker rather than per connection: only one
    ; connection is ever mid-handoff at a time, and at a maximum TLS record
    ; it would be the largest thing in the connection struct.
    resb 1 / (tls_early_scratch_size >= LINNEA_CONN_IN_BUF)
    ; out_buf has to hold the largest single frame either builder can emit,
    ; or the overflow lands in up_buf — whose first bytes are the HTTP/2
    ; stream pool, so the damage shows up as refused streams elsewhere.
    resb 1 / (LINNEA_CONN_OUT_BUF >= LINNEA_H2P_HEAD_ROOM)
    resb 1 / (LINNEA_CONN_OUT_BUF >= LINNEA_H2_RESP_ROOM)
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
    mov rax, [rbx + linnea_config.head_timeout]
    imul rax, rax, 1000000000
    mov [head_timeout_ns], rax
    mov rax, [rbx + linnea_config.max_per_ip]
    mov [max_per_ip], rax
    mov rax, [rbx + linnea_config.max_upstream]
    mov [linnea_upstream_limit], rax

    mov edi, LINNEA_URING_ENTRIES
    lea rsi, [ring]
    xor edx, edx
    mov ecx, LINNEA_URING_CQ_ENTRIES
    call linnea_ring_init
    test eax, eax
    js .init_fail

    ; Signals arrive as cqes like everything else: block them, open a
    ; signalfd, and arm a read on the ring.
    ;   SIGTERM  stop: finish what is in flight, close the rest at once
    ;   SIGQUIT  drain: also let idle connections live out their keep-alive,
    ;            used when a new generation is already serving (hot upgrade)
    ;   SIGHUP   reopen the log after a rotation
    ; The master's death delivers SIGTERM too (PR_SET_PDEATHSIG in
    ; linnea_start).
    mov qword [sig_mask], (1 << (LINNEA_SIGTERM - 1)) | (1 << (LINNEA_SIGHUP - 1)) \
                        | (1 << (LINNEA_SIGQUIT - 1))
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
    call linnea_uring_arm_signal

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
    ; the owner must be a PURE static vhost, like every h3 vhost (see the
    ; registration loop below) — otherwise a mixed config could bind a QUIC
    ; listener that no vhost ever registers on
    lea rcx, [rdx + linnea_config_server.locations]
    mov rax, [rdx + linnea_config_server.location_count]
    xor r9d, r9d
.quic_owner_kinds:
    cmp r9, rax
    jae .quic_owner_ok
    cmp qword [rcx + linnea_config_location.kind], LINNEA_LOC_KIND_ROOT
    jne .quic_next             ; proxy/redirect location: not an h3 owner
    add rcx, linnea_config_location_size
    inc r9
    jmp .quic_owner_kinds
.quic_owner_ok:
    lea rcx, [rdx + linnea_config_server.locations]
    push rdx
    push rcx
    mov rdi, rdx
    call linnea_network_quic_listener
    pop rcx
    pop rdx
    cmp rax, -1
    je .quic_next
    mov [quic_fd], eax
    ; Register every TLS vhost sharing this listener's port so the SNI can select
    ; the right certificate, key and document root. The one that owns the socket is
    ; registered first, as the default for an absent or unknown SNI.
    push r13
    push r14
    call linnea_quic_server_init                        ; clears the vhost table
    movzx r13d, word [rdx + linnea_config_server.port]  ; the QUIC listener's port
    xor r14d, r14d
.quic_vhost:
    cmp r14, [rbx + linnea_config.server_count]
    jae .quic_vhost_done
    imul rax, r14, linnea_config_server_size
    lea rax, [rbx + rax + linnea_config.servers]
    cmp dword [rax + linnea_config_server.tls], 0
    je .quic_vhost_next
    cmp qword [rax + linnea_config_server.cert_list], 0
    je .quic_vhost_next
    cmp qword [rax + linnea_config_server.location_count], 0
    je .quic_vhost_next
    cmp word [rax + linnea_config_server.port], r13w
    jne .quic_vhost_next                                ; a vhost on another port
    ; Only a PURE static vhost is served over h3: h3 has no location routing,
    ; so a proxy or redirect location would resolve under the static root and
    ; 404 — and Alt-Svc migration is per-origin, so a browser that switched
    ; would break those paths with no fallback. Such a vhost keeps h1/h2.
    lea rcx, [rax + linnea_config_server.locations]
    mov r8, [rax + linnea_config_server.location_count]
    xor r9d, r9d
.quic_vhost_kinds:
    cmp r9, r8
    jae .quic_vhost_static                              ; every location is a root
    cmp qword [rcx + linnea_config_location.kind], LINNEA_LOC_KIND_ROOT
    jne .quic_vhost_next                                ; proxy/redirect: no h3
    add rcx, linnea_config_location_size
    inc r9
    jmp .quic_vhost_kinds
.quic_vhost_static:
    lea rcx, [rax + linnea_config_server.locations]     ; the first (root) location
    mov rdi, rax
    mov rsi, rcx
    call linnea_quic_add_vhost
    mov byte [linnea_h3_advert + r14], 1        ; this origin advertises h3
.quic_vhost_next:
    inc r14
    jmp .quic_vhost
.quic_vhost_done:
    pop r14
    pop r13
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
    call linnea_ring_get_cqe
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
    mov rcx, [rax + linnea_ring.cq_khead]
    mov edx, [rcx]
    inc edx
    mov [rcx], edx

    mov eax, r13d
    and eax, 0xff              ; op tag
    mov [cqe_tag], eax
    mov rcx, r13               ; ud_pack: gen(32) | index(24) | tag(8). The
    shr rcx, 32                ; generation says which incarnation of the
    mov [cqe_gen], ecx         ; connection slot armed this operation.
    shr r13, 8
    and r13, 0xffffff          ; index
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
    cmp eax, LINNEA_UD_ARETRY
    je .on_aretry
    cmp eax, LINNEA_UD_H2UP_CONNECT
    je .on_h2up
    cmp eax, LINNEA_UD_H2UP_SEND
    je .on_h2up
    cmp eax, LINNEA_UD_H2UP_RECV
    je .on_h2up
    jmp .on_accept             ; tag 0: no longer the textual fall-through

; --- proxy-over-h2 upstream completion --------------------------------
; The index carries (connection index << 3) | slot. The handler advances the
; exchange and reports whether client-bound frames are now queued; then any
; slot still wanting an upstream op is armed. A connection whose slot went
; ZOMBIE may already be freed and reused — h2p_event handles that case by
; freeing the slot and reporting nothing to send.
.on_h2up:
    mov r14, r13
    and r14, 7                 ; slot index
    shr r13, 3                 ; connection index
    mov rdi, r13
    call linnea_connection_at
    mov r12, rax
    ; A lingering close owns this connection's teardown and arms exactly one
    ; recv at a time; running the h2p machinery here could arm a second client
    ; op, which would still be in flight when .linger_done frees the slot — the
    ; kernel would then write into a recycled buffer. During linger the upstream
    ; completion is left to the close path (conn_close_now closes the fd and
    ; frees the h2p slots), so just wait.
    cmp qword [r12 + linnea_connection.linger], 0
    jne .wait
    mov rdi, r12
    mov rsi, r14
    mov edx, [cqe_tag]         ; which upstream op completed
    mov ecx, r15d
    call linnea_h2p_event      ; -> 1 = frames queued, 0 = nothing, -1 = stale
    cmp eax, -1
    je .wait                   ; the connection is gone (or now another's)
    test eax, eax
    jnz .h2up_send
    ; no head/error to emit, but body bytes may have arrived: run the shared
    ; idle decision, which schedules the next DATA frame for any stream
    cmp qword [r12 + linnea_connection.h2_tx_busy], 0
    jne .h2up_arm              ; a send owns out_buf; it resumes on drain
    mov rdi, r12
    call linnea_h2_after_send
    cmp eax, LINNEA_H2_SEND
    je .h2up_send
    mov rdi, r12               ; nothing to send: make sure a recv is armed
    call h2_arm_recv_once
    jmp .h2up_arm
.h2up_send:
    mov rdi, r12
    call linnea_uring_arm_send
.h2up_arm:
    mov rdi, r12
    call linnea_uring_arm_h2p_ops
    call linnea_uring_submit_now
    jmp .wait

; A completion whose generation does not match the slot's belongs to a
; connection that has since closed. Nothing to do: the socket it referred to
; is closed, the buffers it used belong to whoever holds the slot now, and
; acting on it would corrupt them.
.stale_completion:
    jmp .wait

; --- QUIC datagram on the UDP listener: r15d = bytes or -errno ---------
; The handler owns the receive buffer and replies on the socket itself, so the
; loop only has to pass on the length and the sender, then re-arm.
.on_qrecv:
    test r15d, r15d
    jle .qrecv_rearm
    call qrecv_check_drops
    mov edi, r15d
    lea rsi, [qrecv_peer]
    mov edx, [qrecv_msg + LINNEA_MSGHDR_NAMELEN]   ; kernel-updated length
    mov ecx, [quic_fd]
    call linnea_quic_server_datagram
.qrecv_rearm:
    ; the recv stays armed while draining — the in-flight responses the drain
    ; waits on need the peer's ACKs and flow-control credit to finish, and a
    ; handler may just have freed the last connection (the peer said goodbye)
    call drain_all_done
    test eax, eax
    jnz .drained_exit
    call linnea_uring_arm_qrecv
    call linnea_uring_submit_now
    jmp .wait

; --- QUIC probe-timeout tick: resend anything unacknowledged past its PTO ---
; The timeout completes (with -ETIME) on every tick; res carries no work. Run
; the retransmission sweep over the pool, then re-arm. The tick keeps running
; during a drain: retransmission is what finishes the in-flight responses the
; drain waits on, and the drain sweep closes each connection (CONNECTION_CLOSE,
; H3_NO_ERROR) the moment it has nothing left in flight.
.on_qtimer:
    mov edi, [quic_fd]
    call linnea_quic_server_rtx_sweep
    cmp dword [drain_flag], 0
    je .qtimer_rearm
    mov edi, [quic_fd]
    call linnea_quic_server_drain_sweep
    call drain_all_done
    test eax, eax
    jnz .drained_exit
.qtimer_rearm:
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
    ; A short or failed read leaves the PREVIOUS siginfo in the buffer (or
    ; zeros on the first one), and zero is not SIGHUP — it would fall straight
    ; through to the stop path and begin a drain nobody asked for. Only a
    ; whole struct is a signal.
    cmp r15d, 128                   ; sizeof(struct signalfd_siginfo)
    jne .signal_reread
    ; struct signalfd_siginfo starts with the signal number
    cmp dword [sig_buf], LINNEA_SIGHUP
    jne .on_stop_signal
    call linnea_log_reopen     ; rotated: write into the new file from here
.signal_reread:
    call linnea_uring_arm_signal
    call linnea_uring_submit_now
    jmp .wait
.on_stop_signal:
    cmp dword [drain_flag], 0
    jnz .wait                  ; a second stop signal changes nothing
    mov dword [drain_flag], 1
    mov dword [linnea_quic_draining], 1  ; the QUIC module's copy: refuse new conns
    ; SIGQUIT is the patient drain: leave idle connections to their
    ; keep-alive timeout. SIGTERM means the unit is stopping, so an idle
    ; connection — one with no request in flight — is closed now rather
    ; than waited on; otherwise `systemctl stop` takes as long as the idle
    ; timeout, since a browser almost always has one open.
    mov dword [fast_drain], 1
    cmp dword [sig_buf], LINNEA_SIGQUIT
    jne .drain_go
    mov dword [fast_drain], 0
.drain_go:
    call linnea_log_stamp
    lea rdi, [log_drain]
    mov esi, log_drain_len
    call linnea_log_write
    ; Leave the reuseport group FIRST: until this worker's listeners are
    ; closed the kernel keeps hashing new connections to them, and a draining
    ; worker refuses what it accepts — during a hot upgrade those are exactly
    ; the requests the new generation should have got. Closing hands the group
    ; back to the sockets still serving. (Anything already queued on these
    ; sockets is reset; that window is microseconds, against a whole drain.)
    ; The fd is cleared so the accept completion below does not close it a
    ; second time — by then the number may belong to someone else entirely.
    xor r13d, r13d
.close_listeners:
    cmp r13, [rbx + linnea_config.server_count]
    jae .listeners_closed
    imul rax, r13, linnea_config_server_size
    lea rax, [rbx + rax + linnea_config.servers]
    cmp dword [rax + linnea_config_server.listener_owner], 0
    je .close_listeners_next
    mov edi, [rax + linnea_config_server.listen_fd]
    cmp edi, -1
    je .close_listeners_next
    mov dword [rax + linnea_config_server.listen_fd], -1
    push rax
    mov eax, LINNEA_SYS_CLOSE
    syscall
    pop rax
.close_listeners_next:
    inc r13
    jmp .close_listeners
.listeners_closed:
    ; tell connected h3 peers we are going away before anything else, then
    ; close the ones with nothing in flight right now — a `systemctl stop`
    ; with only an idle browser tab connected should say goodbye and exit
    ; immediately, not leave the peer to its idle timeout
    cmp dword [quic_fd], 0
    jl .no_goaway
    mov edi, [quic_fd]
    call linnea_quic_server_goaway_all
    mov edi, [quic_fd]
    call linnea_quic_server_drain_sweep
.no_goaway:
    call drain_all_done
    test eax, eax
    jnz .drained_exit
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
    cmp dword [fast_drain], 0
    je .cancel_done
    call linnea_uring_submit_now   ; flush the accept cancels before the idle
                                   ; loop queues potentially hundreds more
    ; cancel the read each idle connection is parked on; the cancellation
    ; lands as -ECANCELED on that connection, which closes it
    xor r13d, r13d
.idle_loop:
    cmp r13, [rbx + linnea_config.max_connections]
    jae .cancel_done
    mov rdi, r13
    call linnea_connection_at
    mov r12, rax
    cmp qword [r12 + linnea_connection.in_use], 0
    je .idle_next
    mov rdi, r12
    call conn_is_idle
    test eax, eax
    jz .idle_next
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_ASYNC_CANCEL
    mov r14, r13
    shl r14, 8
    or r14, LINNEA_UD_RECV     ; the recv this connection is parked on
    mov rcx, [r12 + linnea_connection.gen]     ; same packing as the arm
    shl rcx, 32
    or r14, rcx
    mov [rax + LINNEA_SQE_ADDR], r14
    mov qword [rax + LINNEA_SQE_USER_DATA], LINNEA_UD_CANCEL
.idle_next:
    inc r13
    test r13d, 127
    jnz .idle_loop
    call linnea_uring_submit_now   ; bound the SQ (256 entries): a server holding
                                   ; many idle connections would otherwise overflow
    jmp .idle_loop                 ; it before .cancel_done gets to submit
.cancel_done:
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
    test r15d, r15d
    js .accept_failed
    ; A connection the kernel has ALREADY handed us is an open connection, and
    ; a drain finishes open connections — so serve it. Refusing it (close on an
    ; accepted fd, which the peer sees as a reset) is what made the hot upgrade
    ; drop about one request in ten right at the handover: multishot accept
    ; keeps completing into the CQ ring, and every completion that landed after
    ; the drain flag went up was thrown away. The only difference from a normal
    ; accept is that we never re-arm afterwards; see .accept_rearm.
    cmp dword [drain_flag], 0
    jnz .accept_alloc
    mov dword [accept_err_streak], 0   ; accepting again: end any backoff
.accept_alloc:
    call linnea_connection_alloc
    test rax, rax
    jz .conn_limit
    mov dword [conn_full_warned], 0
    mov r12, rax               ; connection*
    mov [r12 + linnea_connection.fd], r15d
    mov [r12 + linnea_connection.server], r13d
    mov qword [r12 + linnea_connection.sni_vhost], 0
    mov edi, r15d
    lea rsi, [r12 + linnea_connection.peer]
    call linnea_network_peer_format
    mov [r12 + linnea_connection.peer_len], rax
    ; the source address alone (no port), and how many connections it already
    ; holds. Without this one host can take the whole pool with perfectly
    ; well-formed traffic and everyone else is refused.
    mov edi, [r12 + linnea_connection.fd]
    lea rsi, [r12 + linnea_connection.peer_ip]
    call linnea_network_peer_addr
    mov [r12 + linnea_connection.peer_ip_len], rax
    test rax, rax
    jz .accept_counted         ; address unreadable: nothing to count it against
    lea rdi, [r12 + linnea_connection.peer_ip]
    mov rsi, rax
    call linnea_connection_count_ip    ; this connection is already among them
    cmp rax, [max_per_ip]
    jbe .accept_counted
    ; over the cap: hand the slot back and drop the connection without a log
    ; line — logging every refusal would turn a flood into disk exhaustion
    mov rdi, r12
    call linnea_connection_free
    mov edi, r15d
    mov eax, LINNEA_SYS_CLOSE
    syscall
    jmp .accept_rearm
.accept_counted:
    ; the head clock starts now: it covers the TLS handshake and the first
    ; request head, and is rearmed per head below
    call linnea_uring_now
    mov [r12 + linnea_connection.req_start], rax
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
    ; Offer h2 in ALPN whenever it is enabled: since Q86 a proxy location is
    ; served over h2 too (each stream runs its own HTTP/1.1 upstream
    ; exchange), so a proxy vhost no longer has to stay on HTTP/1.1. A
    ; WebSocket upgrade still arrives on its own h1 connection, because we do
    ; not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441).
    mov eax, [rbx + linnea_config.http2]
.set_alpn:
    mov [r12 + linnea_connection.up_buf + linnea_tls_hs.alpn_h2_ok], eax
    mov qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_HS
.accept_recv:
    mov rdi, r12
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
.accept_rearm:
    cmp dword [drain_flag], 0
    jnz .accept_drain_tail     ; draining: serve what we took, but take no more
    test r14d, LINNEA_IORING_CQE_F_MORE
    jnz .wait
    mov rdi, r13               ; kernel disarmed the multishot: re-arm
    call linnea_uring_arm_accept
    call linnea_uring_submit_now
    jmp .wait
.accept_failed:
    ; during a drain a negative result is the cancel's -ECANCELED, which is how
    ; the accept ends; outside one it is a real accept error
    cmp dword [drain_flag], 0
    je .accept_err
.accept_drain_tail:
    ; once this accept is finished (the cancel's -ECANCELED, or any final
    ; completion) close our copy of the listening socket instead of re-arming
    test r14d, LINNEA_IORING_CQE_F_MORE
    jnz .wait                  ; multishot still armed; the cancel ends it
.accept_drain_done:
    imul rax, r13, linnea_config_server_size
    lea rax, [rbx + rax + linnea_config.servers]
    mov edi, [rax + linnea_config_server.listen_fd]
    cmp edi, -1
    je .accept_drain_closed    ; the drain already closed it
    mov dword [rax + linnea_config_server.listen_fd], -1
    mov eax, LINNEA_SYS_CLOSE
    syscall
.accept_drain_closed:
    jmp .wait
.accept_err:
    ; Report the first failure of a streak only: the peer chooses how often it
    ; connects, so a line per failure is a write-to-disk-on-demand amplifier
    ; (the same class Q98 closed for the request log).
    inc dword [accept_err_streak]
    cmp dword [accept_err_streak], 1
    jne .accept_backoff
    lea rdi, [warn_accept]
    mov esi, warn_accept_len
    call linnea_print_stderr
    mov edi, r15d
    neg edi
    call linnea_print_u64_stderr
    lea rdi, [warn_accept_end]
    mov esi, warn_accept_end_len
    call linnea_print_stderr
    jmp .accept_rearm          ; a one-off (ECONNABORTED): retry immediately
.accept_backoff:
    ; failing repeatedly with nothing accepted in between: the cause is
    ; standing (EMFILE/ENFILE/ENOBUFS), so re-arm on a timer instead of
    ; spinning the loop at 100% CPU until something happens to free an fd
    mov rdi, r13
    call linnea_uring_arm_accept_retry
    call linnea_uring_submit_now
    jmp .wait
.on_aretry:
    mov rdi, r13               ; the listener whose accept we backed off
    call linnea_uring_arm_accept
    call linnea_uring_submit_now
    jmp .wait
.conn_limit:
    mov edi, r15d
    mov eax, LINNEA_SYS_CLOSE
    syscall
    ; warn once per spell of fullness, not once per refused connection
    cmp dword [conn_full_warned], 0
    jne .accept_rearm
    mov dword [conn_full_warned], 1
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
    mov r12, rax
    mov ecx, [cqe_gen]         ; a completion for an earlier incarnation of
    cmp ecx, [r12 + linnea_connection.gen]   ; this slot: the connection it
    jne .stale_completion      ; belonged to is gone, and the slot may now
                               ; be serving someone else               ; connection*
    mov qword [r12 + linnea_connection.h2_rx_busy], 0
    cmp qword [r12 + linnea_connection.h2_closing], 0
    jne .h2_closing_check      ; a straggler of a torn-down h2 connection
    cmp qword [r12 + linnea_connection.linger], 0
    jne .linger_recv           ; a lingering close: reads are drained, not served
    cmp qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_HS
    je .tls_recv
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_TUNNEL
    je .tunnel_client_recv
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CLOSING
    je .closing_c2u
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_REQ_BODY
    je .req_body_recv
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
    cmp dword [drain_flag], 0
    jne .recv_drain            ; we cancelled it: the unit is stopping
    ; The idle clock only counts silence from the CLIENT, so a connection whose
    ; work is all server-side looks idle. A proxied response goes quiet between
    ; upstream chunks; closing here truncated it and killed every other stream
    ; on the connection. Rearm instead while this connection still owes work —
    ; the head deadline and the upstream's own timeouts still bound it.
    cmp qword [r12 + linnea_connection.is_h2], 0
    je .recv_timeout_close
    mov rdi, r12
    call linnea_h2_busy
    test rax, rax
    jz .recv_timeout_close
    ; Run a service pass before re-arming: this timeout is the only clock a
    ; SILENT streaming upload ever sees (no frames arrive, so no pass would
    ; otherwise run), and the pass is what fails one that has overrun the body
    ; deadline — its 408 goes out here rather than never.
    cmp qword [r12 + linnea_connection.h2_tx_busy], 0
    jne .recv_timeout_rearm    ; the in-flight send's drain runs the same pass
    mov rdi, r12
    call linnea_h2_after_send
    cmp eax, LINNEA_H2_SEND
    jne .recv_timeout_rearm
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.recv_timeout_rearm:
    mov rdi, r12
    call h2_arm_recv_once
    call linnea_uring_submit_now
    jmp .wait
.recv_timeout_close:
    lea r14, [reason_timeout]
    mov r15d, reason_timeout_len
    jmp .conn_close
.recv_drain:
    ; An HTTP/2 peer is owed a GOAWAY before the connection goes. The read we
    ; cancelled is usually this connection's only op — but not always: we also
    ; get here when an h2 connection's own idle timeout fires while a response
    ; send is still in flight. Building the GOAWAY would rewrite out_buf under
    ; that send and arm a second one on the same socket, splicing a GOAWAY into
    ; the middle of a DATA frame and double-advancing out_ptr on both
    ; completions. The send's own drain runs the drain-aware idle decision
    ; (linnea_h2_after_send), so leaving it to that loses nothing.
    cmp qword [r12 + linnea_connection.is_h2], 0
    je .drain_close
    cmp qword [r12 + linnea_connection.h2_tx_busy], 0
    jne .wait
    cmp qword [r12 + linnea_connection.h2_state], LINNEA_H2_DRAINING
    je .drain_close
    mov rdi, r12
    call h2_queue_goaway_pub
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.recv_data:
    ; A head must arrive within head_timeout, however slowly it is fed. The idle
    ; timeout cannot do this: it is armed per operation and every byte rearms it,
    ; so a client sending one byte per timeout period holds its slot forever.
    ; req_start is zero between requests, so an idle keep-alive connection — which
    ; is legitimate and may sit for a long time — is not on any clock.
    call linnea_uring_now
    mov rcx, [r12 + linnea_connection.req_start]
    test rcx, rcx
    jnz .recv_head_age
    mov [r12 + linnea_connection.req_start], rax   ; first bytes of a new head
    jmp .recv_head_ok
.recv_head_age:
    sub rax, rcx
    jb .recv_head_ok           ; stamped ahead of now: never close on a wrap
    cmp rax, [head_timeout_ns]
    jbe .recv_head_ok
    lea r14, [reason_slow_head]
    mov r15d, reason_slow_head_len
    jmp .conn_close
.recv_head_ok:
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
    ; Since proxying, an upstream completion can arm client ops too, so both
    ; directions may be busy at once. Frame processing owns both buffers — it
    ; builds from out_buf's base, and consuming frames compacts in_buf — so it
    ; must not run while either is in flight: a recv would be writing into
    ; in_buf as we move its tail down, and a send would be reading out_buf as
    ; we overwrite it. Whichever op is outstanding comes back here when it
    ; completes (.on_recv, or .send_drained while in_len is nonzero).
    cmp qword [r12 + linnea_connection.h2_tx_busy], 0
    jne .h2_park
    cmp qword [r12 + linnea_connection.h2_rx_busy], 0
    jne .h2_park
    mov rdi, r12
    call linnea_h2_handle
    push rax
    mov rdi, r12               ; a proxied stream may now want an upstream op
    call linnea_uring_arm_h2p_ops
    pop rax
    cmp eax, LINNEA_H2_CLOSE
    je .h2_close
    test eax, eax              ; LINNEA_H2_MORE
    jz .recv_more
    mov rdi, r12               ; LINNEA_H2_SEND: flush response frames
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
; Reached with upstream sqes possibly prepared but the SQ tail not yet
; published: our caller queued them and only then learned the connection is
; done. Publishing costs nothing (the teardown parks an in-flight slot as a
; ZOMBIE and shuts its socket down, so it completes and releases promptly),
; whereas leaving them unsubmitted holds the upstream fd and its slot in the
; ceiling until some unrelated connection happens to submit.
.h2_park:
    call linnea_uring_submit_now
    jmp .wait
.h2_close:
    call linnea_uring_submit_now
    cmp dword [drain_flag], 0
    jne .drain_finish          ; the GOAWAY and final frames must not be lost
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
    call h2_arm_recv_once
    call linnea_uring_submit_now
    jmp .wait

; --- streaming a request body: the client's bytes go straight upstream ---
; The client stopping early (EOF, error or the idle timeout) means the body
; will never be complete, so the exchange is over: the upstream sees a short
; request and the connection is torn down. Nothing has been sent to the
; client yet, so there is no half-response to worry about.
.req_body_recv:
    test r15d, r15d
    jle .req_body_gone
    ; The body clock: the head deadline keeps running here, paid forward by
    ; progress — every received byte buys LINNEA_BODY_NS_PER_BYTE. A real
    ; uploader keeps the clock pinned to now; a client trickling a byte per
    ; idle period — which holds this connection's upstream slot — falls
    ; behind and is cut about head_timeout after its last honest burst.
    ; req_start can be ZERO here: a head that arrived pipelined behind the
    ; TLS handshake (or a previous response) reaches .process without ever
    ; passing .recv_data's stamp, and the last send's arm zeroed the clock.
    ; Then it starts with this first relayed chunk.
    mov rcx, [r12 + linnea_connection.req_start]
    test rcx, rcx
    jnz .req_body_pay
    call linnea_uring_now
    mov [r12 + linnea_connection.req_start], rax
    jmp .req_body_take
.req_body_pay:
    mov eax, r15d
    imul rax, rax, LINNEA_BODY_NS_PER_BYTE
    add rax, rcx
    mov [r12 + linnea_connection.req_start], rax
    call linnea_uring_now
    mov rcx, [r12 + linnea_connection.req_start]
    cmp rcx, rax
    jbe .req_body_age
    mov [r12 + linnea_connection.req_start], rax   ; no credit banked ahead of now
    jmp .req_body_take
.req_body_age:
    sub rax, rcx
    cmp rax, [head_timeout_ns]
    ja .req_body_slow
.req_body_take:
    mov eax, r15d
    cmp rax, [r12 + linnea_connection.req_body_rem]
    jbe .req_body_have
    mov rax, [r12 + linnea_connection.req_body_rem]   ; ignore anything past
.req_body_have:                                       ; the declared length
    sub [r12 + linnea_connection.req_body_rem], rax
    lea rcx, [r12 + linnea_connection.up_buf]     ; the chunk landed here
    mov [r12 + linnea_connection.out_ptr], rcx
    mov [r12 + linnea_connection.out_rem], rax
    mov qword [r12 + linnea_connection.file_rem], 0
    mov rdi, r12
    call linnea_uring_arm_up_send
    call linnea_uring_submit_now
    jmp .wait
.req_body_gone:
    lea r14, [reason_peer]
    mov r15d, reason_peer_len
    jmp .conn_close
.req_body_slow:
    lea r14, [reason_slow_body]
    mov r15d, reason_slow_body_len
    jmp .conn_close

; --- send completion: r13 = connection index, r15d = bytes or -errno --
; A send that moved no bytes for the idle timeout completes -ECANCELED:
; the client has stopped reading, so the connection is torn down.
.on_send:
    mov rdi, r13
    call linnea_connection_at
    mov r12, rax
    mov ecx, [cqe_gen]         ; a completion for an earlier incarnation of
    cmp ecx, [r12 + linnea_connection.gen]   ; this slot: the connection it
    jne .stale_completion      ; belonged to is gone, and the slot may now
                               ; be serving someone else
    cmp qword [r12 + linnea_connection.h2_closing], 0
    jne .h2_closing_send       ; a straggler of a torn-down h2 connection
    cmp qword [r12 + linnea_connection.linger], 0
    jne .linger_straggler      ; a send finishing during a lingering close: the
                               ; linger recv loop owns the teardown, so this
                               ; completion only clears its busy flag and waits
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
    mov qword [r12 + linnea_connection.h2_tx_busy], 0   ; this send is over
    lea r14, [reason_send_err]
    mov r15d, reason_send_err_len
    jmp .conn_close
.send_timeout:
    mov qword [r12 + linnea_connection.h2_tx_busy], 0   ; this send is over
    lea r14, [reason_send_timeout]
    mov r15d, reason_send_timeout_len
    jmp .conn_close
.send_ok:
    mov eax, r15d
    add [r12 + linnea_connection.out_ptr], rax
    mov rcx, [r12 + linnea_connection.out_rem]
    sub rcx, rax
    jae .send_acct             ; a count that would wrap is treated as drained:
    xor ecx, ecx               ; the alternative is a send of ~4 GiB from a
.send_acct:                    ; buffer inside the connection pool
    mov [r12 + linnea_connection.out_rem], rcx
    test rcx, rcx
    jnz .send_more
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
    mov qword [r12 + linnea_connection.h2_tx_busy], 0   ; out_buf is free again
    mov rdi, r12               ; buffer space freed may unblock an upstream read
    call linnea_uring_arm_h2p_ops
    mov rdi, r12
    call linnea_h2_after_send
    cmp eax, LINNEA_H2_SEND
    je .h2_send_more
    cmp eax, LINNEA_H2_CLOSE
    je .h2_close
    cmp qword [r12 + linnea_connection.in_len], 0
    jne .h2_process
    mov rdi, r12
    call h2_arm_recv_once
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
    jne .drain_finish          ; draining: no keep-alive — deliver, then close
    cmp qword [r12 + linnea_connection.keep_alive], 0
    jne .keep_alive_continue
    lea r14, [reason_done]
    mov r15d, reason_done_len
    jmp .conn_close
.drain_close:
    lea r14, [reason_drain]
    mov r15d, reason_drain_len
    jmp .conn_close

; --- lingering close: the drain just delivered a response's last bytes -----
; They are in the kernel's send buffer, not at the client — and close(2) on a
; socket with unread inbound (a downloading h2 client is always sending
; WINDOW_UPDATEs) answers with an RST that discards that untransmitted tail.
; So: shut down the write side (the FIN queues behind the data), then keep
; reading and dropping until the peer sees it all and closes; only then close.
.drain_finish:
    lea r14, [reason_drain]
    mov r15d, reason_drain_len
.drain_linger:
    mov edi, [r12 + linnea_connection.fd]
    mov esi, LINNEA_SHUT_WR
    mov eax, LINNEA_SYS_SHUTDOWN
    syscall
    mov [r12 + linnea_connection.close_reason], r14
    mov [r12 + linnea_connection.close_reason_len], r15
    mov qword [r12 + linnea_connection.linger], 1
    call linnea_uring_now      ; req_start is free here (arm_send zeroed it):
    mov [r12 + linnea_connection.req_start], rax   ; it bounds the whole linger
    cmp qword [r12 + linnea_connection.h2_rx_busy], 0
    je .linger_arm
    ; a recv is already parked (h2 keeps one armed for WINDOW_UPDATEs), but
    ; under the long idle timeout. Cancel it: its -ECANCELED lands below with
    ; linger still 1, which re-arms under the short linger timeout instead.
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_ASYNC_CANCEL
    mov rcx, [r12 + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_RECV
    mov rdx, [r12 + linnea_connection.gen]
    shl rdx, 32
    or rcx, rdx
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov qword [rax + LINNEA_SQE_USER_DATA], LINNEA_UD_CANCEL
    call linnea_uring_submit_now
    jmp .wait
.linger_recv:
    ; the linger read came back: data (a consuming client's WINDOW_UPDATEs) is
    ; dropped and the read re-armed; EOF or an error ends the connection
    test r15d, r15d
    jz .linger_done            ; EOF: the peer read everything and closed
    js .linger_err
.linger_arm:
    ; a fresh silence window per read, but a hard bound on the whole linger:
    ; a peer feeding us a byte every second must not hold the slot forever
    call linnea_uring_now
    sub rax, [r12 + linnea_connection.req_start]
    mov rcx, LINNEA_LINGER_TOTAL_NS
    cmp rax, rcx
    ja .linger_done
    mov qword [r12 + linnea_connection.linger], 2   ; the linger read is armed
    mov rdi, r12
    call arm_linger_recv
    call linnea_uring_submit_now
    jmp .wait
.linger_err:
    cmp r15d, -LINNEA_ECANCELED
    jne .linger_done           ; a real error: nothing more will be delivered
    cmp qword [r12 + linnea_connection.linger], 1
    je .linger_arm             ; our own cancel of the pre-drain recv
.linger_done:                  ; else the linger timeout: the peer fell silent
    mov r14, [r12 + linnea_connection.close_reason]
    mov r15, [r12 + linnea_connection.close_reason_len]
    jmp .conn_close_now
.linger_straggler:             ; a send completed during linger: clear its flag
    mov qword [r12 + linnea_connection.h2_tx_busy], 0   ; and let the recv loop
    jmp .wait                                           ; finish the teardown (a
                                                        ; dead-end: reached only by
                                                        ; the explicit jump in .on_send)
.keep_alive_continue:
    ; keep-alive: drop the consumed head, keep any pipelined bytes. The
    ; subtraction is guarded: an in_len below head_len would wrap into a
    ; gigabyte-scale rep movsb that walks off the end of the pool, and a
    ; state where that is even briefly true is a bug elsewhere, not a
    ; reason to corrupt memory.
    mov rax, [r12 + linnea_connection.in_len]
    sub rax, [r12 + linnea_connection.head_len]
    jae .ka_have
    xor eax, eax
.ka_have:
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
    ; the head clock (stamped at accept) must bound the handshake too, or a
    ; client that drips ClientHello/Finished bytes rearms only the per-op idle
    ; timeout and holds its slot forever — slowloris on 443. Same check as the
    ; plaintext head at .recv_data.
    call linnea_uring_now
    mov rcx, [r12 + linnea_connection.req_start]
    test rcx, rcx
    jz .tls_deadline_ok            ; not on a clock (should not happen pre-DONE)
    sub rax, rcx
    jb .tls_deadline_ok            ; stamped ahead of now: never close on a wrap
    cmp rax, [head_timeout_ns]
    jbe .tls_deadline_ok
    lea r14, [reason_slow_head]
    mov r15d, reason_slow_head_len
    jmp .conn_close
.tls_deadline_ok:
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
    lea rcx, [tls_early_scratch]
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
    push r12
    call linnea_log_stamp
    lea rdi, [dbgsplit]
    mov esi, dbgsplit_len
    call linnea_log_write
    pop r12
    push r12
    mov rdi, [r12 + linnea_connection.in_len]
    call linnea_log_u64
    lea rdi, [log_nl]
    mov esi, 1
    call linnea_log_write
    pop r12
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
    mov ecx, [cqe_gen]         ; a completion for an earlier incarnation of
    cmp ecx, [r12 + linnea_connection.gen]   ; this slot: the connection it
    jne .stale_completion      ; belonged to is gone, and the slot may now
                               ; be serving someone else
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
    mov ecx, [cqe_gen]         ; a completion for an earlier incarnation of
    cmp ecx, [r12 + linnea_connection.gen]   ; this slot: the connection it
    jne .stale_completion      ; belonged to is gone, and the slot may now
                               ; be serving someone else
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
    ; more request body still to come from the client? Relay it a chunk at a
    ; time — recv into in_buf, send that upstream, repeat — so an upload is
    ; bounded by the buffer rather than having to fit in it.
    cmp qword [r12 + linnea_connection.req_body_rem], 0
    je .up_send_response
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_REQ_BODY
    ; The rest of the body is relayed through up_buf, which is idle between
    ; sending the request head and reading the response head. in_buf is left
    ; exactly as the parser saw it — the head still readable for the access
    ; log, in_len still consistent with head_len for the keep-alive
    ; bookkeeping below, and the whole buffer available as a chunk window.
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.up_buf]
    mov edx, LINNEA_CONN_UP_BUF
    call linnea_uring_arm_recv_buf
    call linnea_uring_submit_now
    jmp .wait
.up_send_response:
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
    mov ecx, [cqe_gen]         ; a completion for an earlier incarnation of
    cmp ecx, [r12 + linnea_connection.gen]   ; this slot: the connection it
    jne .stale_completion      ; belonged to is gone, and the slot may now
                               ; be serving someone else
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
    call linnea_upstream_closed
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

; a straggler op of a torn-down h2 connection completed; its result no longer
; matters (the socket is shut down). Free once both directions are idle.
.h2_closing_send:
    mov qword [r12 + linnea_connection.h2_tx_busy], 0
.h2_closing_check:
    mov rax, [r12 + linnea_connection.h2_rx_busy]
    or rax, [r12 + linnea_connection.h2_tx_busy]
    test rax, rax
    jnz .wait
    mov r14, [r12 + linnea_connection.close_reason]
    mov r15, [r12 + linnea_connection.close_reason_len]
    jmp .conn_close_now

; connection teardown; r12 = connection*, r14/r15 = reason string ptr/len
;
; HTTP/2 drives both directions at once — an upstream completion can arm a
; client send while a client recv is still outstanding — so unlike h1 the op
; that got us here need not be the only one. The kernel holds in_buf/out_buf
; and any stream body mapping until the other op completes, and close(2) does
; not cancel it; the slot is reused LIFO, so freeing now would let the kernel
; write into the next connection's in_buf or send it a freed out_buf. Shut the
; socket down so the straggler completes, and defer, exactly as a tunnel does.
.conn_close:
    cmp qword [r12 + linnea_connection.is_h2], 0
    je .conn_close_now
    mov rax, [r12 + linnea_connection.h2_rx_busy]
    or rax, [r12 + linnea_connection.h2_tx_busy]
    test rax, rax
    jz .conn_close_now
    mov edi, [r12 + linnea_connection.fd]
    mov esi, LINNEA_SHUT_RDWR
    mov eax, LINNEA_SYS_SHUTDOWN
    syscall
    mov [r12 + linnea_connection.close_reason], r14
    mov [r12 + linnea_connection.close_reason_len], r15
    mov qword [r12 + linnea_connection.h2_closing], 1
    jmp .wait
.conn_close_now:
    ; Say goodbye (RFC 8446 6.1). This is the ONLY safe point: reaching here
    ; means the h2 busy check above has already passed, so no recv or send of
    ; ours is outstanding on this socket, and an HTTP/1 connection is one
    ; operation at a time by construction. An earlier attempt sent the alert
    ; from the branch just above — which is entered precisely BECAUSE ops are in
    ; flight — and spliced it into the middle of a record the kernel was still
    ; framing. The suite came apart differently on every run until this moved.
    ;
    ; Only where kTLS is carrying records: on a plaintext listener these two
    ; bytes would be two bytes of garbage on the end of the response.
    cmp qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_KTLS
    jne .cn_sent
    cmp qword [r12 + linnea_connection.close_notified], 0
    jne .cn_sent
    mov qword [r12 + linnea_connection.close_notified], 1
    mov edi, [r12 + linnea_connection.fd]
    call linnea_ktls_close_notify
.cn_sent:
    mov qword [r12 + linnea_connection.h2_closing], 0
    mov qword [r12 + linnea_connection.linger], 0
    call ring_check_overflow   ; a teardown is a regular, cheap place to notice
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
    mov rdi, r12               ; and any upstream proxy exchange it owned
    call linnea_h2p_conn_close
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
    call linnea_upstream_closed
    mov dword [r12 + linnea_connection.up_fd], -1
.close_no_up:
    mov edi, [r12 + linnea_connection.fd]
    mov eax, LINNEA_SYS_CLOSE
    syscall
    ; a late completion (a proxy upstream op armed before this close) must
    ; not arm anything on the socket we just closed
    mov dword [r12 + linnea_connection.fd], -1
    mov rdi, r12
    call linnea_connection_free
    call drain_all_done
    test eax, eax
    jz .wait
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
    call linnea_ring_submit
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
    call linnea_ring_get_sqe
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
    ; During the userspace handshake, read no further than the end of the
    ; record being assembled. A client may append its whole request to the
    ; Finished — a large upload is megabytes — and everything we pull into
    ; this buffer we must decrypt ourselves before the kernel takes over.
    ; Stopping at the record boundary leaves that data in the socket, where
    ; kTLS decrypts it after the handoff, so the request size stops being
    ; bounded by this buffer.
    cmp qword [rbx + linnea_connection.tls_phase], LINNEA_TLS_PHASE_HS
    jne .ar_len
    cmp rcx, 5
    jb .ar_hdr                 ; still assembling the 5-byte record header
    movzx r8d, byte [rbx + linnea_connection.in_buf + 3]
    shl r8d, 8
    mov r8b, [rbx + linnea_connection.in_buf + 4]
    add r8d, 5                 ; whole record = header + fragment
    sub r8d, ecx               ; what is missing of it
    jbe .ar_len                ; already whole (or past): leave the bound
    cmp r8d, edx
    ja .ar_len                 ; a record too large for the buffer: the
    mov edx, r8d               ; existing "too large" path reports it
    jmp .ar_len
.ar_hdr:
    mov edx, 5
    sub edx, ecx
.ar_len:
    mov [rax + LINNEA_SQE_LEN], edx
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_RECV
    mov rdx, [rbx + linnea_connection.gen]      ; see ud_pack
    shl rdx, 32
    or rcx, rdx
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    mov rdi, rbx               ; the timeout sqe must immediately follow
    pop rbx
    jmp linnea_uring_arm_link_timeout

; arm_linger_recv(rdi=connection*)
; The read that drains a lingering close: into in_buf from the top (the bytes
; are dropped, in_len is not advanced), linked to the short linger timeout
; rather than the idle one — the peer has our FIN and the whole response, so
; all that is being waited for is its close.
arm_linger_recv:
    push rbx
    mov rbx, rdi
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_RECV
    mov byte [rax + LINNEA_SQE_FLAGS], LINNEA_IOSQE_IO_LINK
    mov ecx, [rbx + linnea_connection.fd]
    mov [rax + LINNEA_SQE_FD], ecx
    lea rcx, [rbx + linnea_connection.in_buf]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], LINNEA_CONN_IN_BUF
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_RECV
    mov rdx, [rbx + linnea_connection.gen]      ; see ud_pack
    shl rdx, 32
    or rcx, rdx
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    call linnea_uring_get_sqe_zeroed            ; the linked linger timeout
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_LINK_TIMEOUT
    mov dword [rax + LINNEA_SQE_FD], -1
    lea rcx, [linger_timeout]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], 1
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_TIMEOUT
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    pop rbx
    ret

; drain_all_done() -> eax = 1 when the worker is draining and nothing is left
; to wait for: no TCP connection holds a slot, and no QUIC connection either.
; The two pools drain independently, so the exit test must consult both — the
; QUIC pool was once left out, and a worker with in-flight h3 responses exited
; the moment its last TCP connection closed, hanging the peers mid-download.
drain_all_done:
    xor eax, eax
    cmp dword [drain_flag], 0
    je .dad_ret
    cmp qword [linnea_connection_active], 0
    jne .dad_ret
    call linnea_quic_conn_active
    test rax, rax
    setz al
    movzx eax, al
.dad_ret:
    ret

; linnea_uring_arm_recv_buf(rdi=connection*, rsi=buffer, rdx=len)
; A client recv into somewhere other than in_buf — the request-body relay
; uses up_buf so the parsed head stays intact. Same linked idle timeout as
; any other client read.
linnea_uring_arm_recv_buf:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_RECV
    mov byte [rax + LINNEA_SQE_FLAGS], LINNEA_IOSQE_IO_LINK
    mov ecx, [rbx + linnea_connection.fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov [rax + LINNEA_SQE_ADDR], r12
    mov [rax + LINNEA_SQE_LEN], r13d
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_RECV
    mov rdx, [rbx + linnea_connection.gen]
    shl rdx, 32
    or rcx, rdx
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    mov rdi, rbx
    pop r13
    pop r12
    pop rbx
    jmp linnea_uring_arm_link_timeout

; linnea_uring_arm_send(rdi=connection*)
; Queue a send of the unsent response bytes (out_ptr/out_rem), with a
; linked idle timeout: a client that stops reading closes instead of
; pinning the slot. Partial sends re-arm with a fresh timeout, so slow
; readers are unaffected.
linnea_uring_arm_send:
    ; a response is on its way, so this head is done — the next one starts its
    ; own clock when its first bytes arrive
    mov qword [rdi + linnea_connection.req_start], 0
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
    mov rdx, [rbx + linnea_connection.gen]
    shl rdx, 32
    or rcx, rdx
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
    mov rdx, [rbx + linnea_connection.gen]
    shl rdx, 32
    or rcx, rdx
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
    mov rdx, [rbx + linnea_connection.gen]
    shl rdx, 32
    or rcx, rdx
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
    mov rdx, [rbx + linnea_connection.gen]
    shl rdx, 32
    or rcx, rdx
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    mov rdi, rbx               ; the timeout sqe must immediately follow
    pop r13
    pop r12
    pop rbx
    jmp linnea_uring_arm_link_timeout

; conn_is_idle(rdi = connection*) -> eax = 1 when the connection has no work
; in flight: nothing half-received, nothing queued to send, no upstream
; exchange or tunnel, and for HTTP/2 no open stream. Such a connection is
; only holding its keep-alive open, so a stop can close it at once; anything
; else is finished first.
conn_is_idle:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + linnea_connection.in_len], 0
    jne .ci_busy
    cmp qword [rbx + linnea_connection.out_rem], 0
    jne .ci_busy
    cmp qword [rbx + linnea_connection.file_rem], 0
    jne .ci_busy
    cmp qword [rbx + linnea_connection.proxy_state], LINNEA_PROXY_IDLE
    jne .ci_busy
    cmp qword [rbx + linnea_connection.is_h2], 0
    je .ci_idle
    mov rdi, rbx               ; an h2 connection with a stream open is busy
    call linnea_h2_pool_active
    test rax, rax
    jnz .ci_busy
.ci_idle:
    mov eax, 1
    pop rbx
    ret
.ci_busy:
    xor eax, eax
    pop rbx
    ret

; h2_arm_recv_once(rdi = connection*) — arm a client recv unless one is
; already in flight. An HTTP/2 connection can be driven from either side (a
; client frame or an upstream completion), so without this the two paths
; could arm two recvs on the same socket, whose linked timeouts would then
; tear the connection down under a working exchange.
h2_arm_recv_once:
    cmp qword [rdi + linnea_connection.is_h2], 0
    je .aro_arm
    cmp qword [rdi + linnea_connection.h2_rx_busy], 0
    jne .aro_skip
    mov qword [rdi + linnea_connection.h2_rx_busy], 1
.aro_arm:
    jmp linnea_uring_arm_recv
.aro_skip:
    ret

; linnea_uring_arm_h2p_ops(rdi = connection*) — arm the upstream op each
; proxy slot is waiting for (connect / send / recv), at most one per slot.
; The slot's WANT flag is consumed as the op is queued and F_INFLIGHT marks
; that the kernel owns its buffer, which is what makes a late completion on a
; dead connection safe (the slot goes ZOMBIE rather than being reused).
linnea_uring_arm_h2p_ops:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r13, [rdi + linnea_connection.index]
    xor r14d, r14d                    ; slot index
.ao_loop:
    mov rdi, r13
    mov rsi, r14
    call linnea_h2p_at
    mov r12, rax
    cmp qword [r12 + linnea_h2p.state], LINNEA_H2P_FREE
    je .ao_next                       ; nothing to arm for a free slot
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_INFLIGHT
    jnz .ao_next                      ; already has an op out
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_WANT_CONN
    jnz .ao_connect
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND
    jnz .ao_send
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV
    jnz .ao_recv
.ao_next:
    inc r14
    cmp r14d, LINNEA_H2P_SLOTS
    jb .ao_loop
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.ao_connect:
    and qword [r12 + linnea_h2p.flags], ~LINNEA_H2P_F_WANT_CONN
    or qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_INFLIGHT
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_CONNECT
    mov byte [rax + LINNEA_SQE_FLAGS], LINNEA_IOSQE_IO_LINK
    mov ecx, [r12 + linnea_h2p.fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov rcx, [r12 + linnea_h2p.location]
    lea rcx, [rcx + linnea_config_location.proxy_addr]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov qword [rax + LINNEA_SQE_OFF], LINNEA_SOCKADDR_IN_SIZE
    mov edx, LINNEA_UD_H2UP_CONNECT
    jmp .ao_finish

.ao_send:
    and qword [r12 + linnea_h2p.flags], ~LINNEA_H2P_F_WANT_SEND
    or qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_INFLIGHT
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_SEND
    mov byte [rax + LINNEA_SQE_FLAGS], LINNEA_IOSQE_IO_LINK
    mov ecx, [r12 + linnea_h2p.fd]
    mov [rax + LINNEA_SQE_FD], ecx
    ; the head comes from the front of the buffer; once it is out, a
    ; streamed body comes from the FIFO further in
    mov rcx, [r12 + linnea_h2p.sent]
    cmp rcx, [r12 + linnea_h2p.req_len]
    jb .ao_send_head
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_REQ_STREAM
    jz .ao_send_head                 ; nothing left; the send is a no-op
    mov rcx, [r12 + linnea_h2p.rq_buf]
    add rcx, [r12 + linnea_h2p.rq_rd]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov rcx, [r12 + linnea_h2p.rq_wr]
    sub rcx, [r12 + linnea_h2p.rq_rd]
    mov [rax + LINNEA_SQE_LEN], ecx
    mov edx, LINNEA_UD_H2UP_SEND
    jmp .ao_finish
.ao_send_head:
    lea rcx, [r12 + linnea_h2p.buf]
    add rcx, [r12 + linnea_h2p.sent]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov rcx, [r12 + linnea_h2p.req_len]
    sub rcx, [r12 + linnea_h2p.sent]
    mov [rax + LINNEA_SQE_LEN], ecx
    mov edx, LINNEA_UD_H2UP_SEND
    jmp .ao_finish

.ao_recv:
    ; recycle what the client has already taken, so a body larger than the
    ; buffer keeps streaming — but not while a send is reading those bytes
    cmp qword [rbx + linnea_connection.h2_tx_busy], 0
    jne .ao_room
    mov rdi, r12
    call h2p_compact
.ao_room:
    ; still no room: wait for the client to take what is queued (every send
    ; drain runs this again)
    mov rcx, LINNEA_H2P_BUF
    sub rcx, [r12 + linnea_h2p.len]
    cmp rcx, 512
    jb .ao_next
    and qword [r12 + linnea_h2p.flags], ~LINNEA_H2P_F_WANT_RECV
    or qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_INFLIGHT
    push rcx
    call linnea_uring_get_sqe_zeroed
    pop rcx
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_RECV
    mov byte [rax + LINNEA_SQE_FLAGS], LINNEA_IOSQE_IO_LINK
    mov edx, [r12 + linnea_h2p.fd]
    mov [rax + LINNEA_SQE_FD], edx
    lea rdx, [r12 + linnea_h2p.buf]
    add rdx, [r12 + linnea_h2p.len]
    mov [rax + LINNEA_SQE_ADDR], rdx
    mov [rax + LINNEA_SQE_LEN], ecx
    mov edx, LINNEA_UD_H2UP_RECV

.ao_finish:
    ; user_data = ((conn index << 3 | slot) << 8) | tag
    mov rcx, r13
    shl rcx, 3
    or rcx, r14
    shl rcx, 8
    or rcx, rdx
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    mov rdi, rbx                      ; the linked timeout must follow it
    call linnea_uring_arm_link_timeout
    jmp .ao_next


; linnea_uring_arm_signal() — queue the signalfd read. Re-armed after a
; SIGHUP (a drain never needs another signal).
linnea_uring_arm_signal:
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_READ
    mov ecx, [sig_fd]
    mov [rax + LINNEA_SQE_FD], ecx
    lea rcx, [sig_buf]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], 128
    mov qword [rax + LINNEA_SQE_USER_DATA], LINNEA_UD_SIGNAL
    ret

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
    mov dword [qrecv_msg + LINNEA_MSGHDR_NAMELEN], LINNEA_SOCKADDR_IN6_SIZE
    lea rcx, [qrecv_iov]
    mov [qrecv_msg + LINNEA_MSGHDR_IOV], rcx
    mov qword [qrecv_msg + LINNEA_MSGHDR_IOVLEN], 1
    lea rcx, [qrecv_cmsg]      ; room for the SO_RXQ_OVFL counter
    mov [qrecv_msg + LINNEA_MSGHDR_CONTROL], rcx
    mov qword [qrecv_msg + LINNEA_MSGHDR_CONTROLLEN], LINNEA_QRECV_CMSG_SIZE
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

; qrecv_check_drops() — read the SO_RXQ_OVFL counter the kernel attached to the
; datagram we just received, and log any increase. Every QUIC connection on this
; worker shares one socket, so an overflow is not one connection's problem: the
; datagrams are gone before the server sees them, and without this the loss
; leaves no trace anywhere. Only the delta is reported, and only when it moves,
; so a healthy server says nothing. Clobbers only caller-saved registers.
; ring_check_overflow() — report a completion-queue backlog if one has happened
; since the last check. Nothing is lost when it does (linnea_ring_get_cqe
; flushes the kernel's backlog with an enter), but it means the ring is
; undersized for the load, and it is otherwise visible nowhere at all.
ring_check_overflow:
    mov rax, [linnea_ring_cq_overflows]
    cmp rax, [ring_ovf_seen]
    jbe .rco_done
    mov rcx, rax
    sub rcx, [ring_ovf_seen]
    mov [ring_ovf_seen], rax
    push rcx
    call linnea_log_stamp
    lea rdi, [log_cqovf]
    mov esi, log_cqovf_len
    call linnea_log_write
    pop rdi
    call linnea_log_u64
    lea rdi, [log_cqovf_end]
    mov esi, log_cqovf_end_len
    call linnea_log_write
.rco_done:
    ret

qrecv_check_drops:
    cmp qword [qrecv_msg + LINNEA_MSGHDR_CONTROLLEN], LINNEA_CMSG_DATA + 4
    jb .qcd_done                       ; no control data: the option is not on
    cmp dword [qrecv_cmsg + LINNEA_CMSG_LEVEL], LINNEA_SOL_SOCKET
    jne .qcd_done
    cmp dword [qrecv_cmsg + LINNEA_CMSG_TYPE], LINNEA_SO_RXQ_OVFL
    jne .qcd_done
    mov eax, [qrecv_cmsg + LINNEA_CMSG_DATA]     ; the socket's running total
    cmp rax, [qrecv_drops]
    jbe .qcd_done                      ; unchanged (or wrapped): nothing to say
    mov rcx, rax
    sub rcx, [qrecv_drops]             ; how many since the last report
    mov [qrecv_drops], rax
    push rcx
    call linnea_log_stamp
    lea rdi, [log_qdrop]
    mov esi, log_qdrop_len
    call linnea_log_write
    pop rdi
    call linnea_log_u64
    lea rdi, [log_qdrop_end]
    mov esi, log_qdrop_end_len
    call linnea_log_write
.qcd_done:
    ret

; linnea_uring_arm_accept_retry(rdi = listener index) — queue a one-shot
; IORING_OP_TIMEOUT that re-arms this listener's accept once the backoff
; elapses. The listener index rides in the user_data exactly as the accept's
; does, so the completion knows which listener to bring back. Caller submits.
linnea_uring_arm_accept_retry:
    push rdi
    call linnea_uring_get_sqe_zeroed
    pop rdi
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_TIMEOUT
    mov dword [rax + LINNEA_SQE_FD], -1
    lea rcx, [accept_retry_timer]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], 1        ; one timespec
    mov qword [rax + LINNEA_SQE_OFF], 0        ; fire on the timer, not a count
    shl rdi, 8
    or rdi, LINNEA_UD_ARETRY
    mov [rax + LINNEA_SQE_USER_DATA], rdi
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
    mov [sni_select_conn], rdi     ; every register is spoken for below, and
                                   ; rdi becomes the SNI text inside the loop
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
    mov rcx, [sni_select_conn]                     ; rdi is the SNI text by now
    mov [rcx + linnea_connection.sni_vhost], rdx   ; whose cert we present
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
