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
extern linnea_crash_install
extern linnea_ratelimit_init
extern linnea_upstream_open
extern linnea_upstream_park
extern linnea_upstream_closed
extern linnea_upstream_addr
extern linnea_upstream_pick
extern linnea_upstream_mark_ok
extern linnea_upstream_mark_fail
extern linnea_upstream_limit
extern linnea_connection_alloc
extern linnea_connection_free
extern linnea_spill_release
extern linnea_spill_write
extern linnea_spill_finish
extern linnea_spill_chunked
extern linnea_spill_reset
extern linnea_connection_at
extern linnea_connection_active
extern linnea_http_handle
extern linnea_http_proxy_error
extern linnea_quic_idle_ms
extern linnea_quic_conn_idle_secs
extern linnea_http_request_timeout
extern linnea_http_proxy_head
; an upstream leg owned by an HTTP/3 stream: the same completions, diverted
extern linnea_h3_proxy_start
extern linnea_h3_proxy_head
extern linnea_h3_proxy_body
extern linnea_h3_proxy_deliver
extern linnea_h3_proxy_fail
extern linnea_h3_proxy_arm_hook
extern linnea_h3_proxy_cancel
extern linnea_h3_cancel_hook
extern linnea_h3_proxy_release
extern linnea_h3_proxy_hook
extern linnea_http_proxy_log
extern linnea_error_exit
extern linnea_print_stderr
extern linnea_print_u64_stderr
extern linnea_log_write
extern linnea_log_u64
extern linnea_log_stamp
extern linnea_log_reopen
extern linnea_ktls_fail_step
extern linnea_ktls_fail_errno
extern linnea_tls_hs_init
extern linnea_tls_hs_input
extern linnea_tls_drain_early
extern linnea_ktls_enable
extern linnea_ktls_rekey_rx
extern linnea_ktls_rekey_tx
extern linnea_ktls_key_update
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
extern linnea_quic_server_close_all
extern linnea_quic_conn_active
extern linnea_quic_draining
extern linnea_quic_rxbuf
extern linnea_quic_rxbatch
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
log_bpfmap:         db "bpf steering: worker index could not be registered in the reuseport map (errno "
log_bpfmap_len      equ $ - log_bpfmap
log_bpfmap_end:     db "); this worker falls back to the kernel 4-tuple hash", 10
log_bpfmap_end_len  equ $ - log_bpfmap_end
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
reason_spill_err:   db "cannot capture request body"
reason_spill_err_len equ $ - reason_spill_err
reason_pipeline_big: db "pipelined request too large to buffer"
reason_pipeline_big_len equ $ - reason_pipeline_big
reason_per_ip:      db "per-address connection limit"
reason_per_ip_len   equ $ - reason_per_ip
reason_timeout:     db "idle timeout"
reason_timeout_len  equ $ - reason_timeout
reason_recv_err:    db "recv error"
reason_recv_err_len equ $ - reason_recv_err
reason_peer_reset:  db "peer reset"
reason_peer_reset_len equ $ - reason_peer_reset
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
reason_up_chunk:    db "upstream chunked framing"
reason_up_chunk_len equ $ - reason_up_chunk
reason_up_chunk_early: db "upstream chunked body ended early"
reason_up_chunk_early_len equ $ - reason_up_chunk_early
reason_drain:       db "draining"
reason_drain_len    equ $ - reason_drain

log_drain:          db "worker draining: accepts closed, finishing open connections", 10
log_drain_len       equ $ - log_drain
log_drained:        db "worker drained", 10
log_drained_len     equ $ - log_drained
log_stopped:        db "worker stopping: connections dropped", 10
log_stopped_len     equ $ - log_stopped
log_h3cap:          db "http3: more distinct host addresses on the port than the QUIC listener cap; the excess serve TCP only", 10
log_h3cap_len       equ $ - log_h3cap
log_drain_late:     db "worker drain deadline reached, dropping what is left", 10
log_drain_late_len  equ $ - log_drain_late

dbgrecv:            db "recv failed, errno "
dbgrecv_len         equ $ - dbgrecv
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
dbgsend:            db "send failed, errno "
dbgsend_len         equ $ - dbgsend
dbgtlsalert:        db "tls handshake failed, alert "
dbgtlsalert_len     equ $ - dbgtlsalert
reason_tls_failed:  db "tls handshake failed"
reason_tls_failed_len equ $ - reason_tls_failed
reason_tls_badrec:  db "tls bad record"
reason_tls_badrec_len equ $ - reason_tls_badrec
reason_tls_split:   db "tls pipelined record too large to buffer"
reason_tls_split_len equ $ - reason_tls_split
reason_tls_ktls:    db "tls kernel handoff failed"
reason_tls_ktls_len equ $ - reason_tls_ktls
; The close reason alone never said WHICH setsockopt refused the handoff or
; why, which is the only thing worth knowing when it happens in production.
dbgktls:            db "ktls handoff failed: step "
dbgktls_len         equ $ - dbgktls
dbgktls_errno:      db " errno "
dbgktls_errno_len   equ $ - dbgktls_errno

section .data

idle_timeout:       dq LINNEA_DEFAULT_TIMEOUT, 0    ; struct __kernel_timespec
; The same shape for the UPSTREAM half. A backend that stops making progress
; is a different question from a client that has gone quiet, and they want
; different answers: a browser may idle a minute between requests, while a
; backend that has not answered in five seconds is holding an upstream slot
; for nothing. Both were this one timespec until proxy_timeout existed.
proxy_timeout_ts:   dq LINNEA_DEFAULT_TIMEOUT, 0    ; struct __kernel_timespec
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
; How long a retiring generation is given to finish what it holds. Only the
; hot upgrade drains (SIGQUIT); a stop does not, so this never delays one.
; Without it a WebSocket tunnel pins an old worker for as long as the browser
; tab stays open, because a tunnel is never idle and never finishes on its
; own — measured: one worker still alive indefinitely after the new
; generation had taken over. tv_sec is overwritten from the config's
; drain_timeout at startup; the value here is only what a worker would use if
; it somehow ran before that.
drain_deadline:     dq LINNEA_DEFAULT_DRAIN_TIMEOUT, 0   ; struct timespec
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
idle_timeout_ns:    resq 1     ; the idle timeout as nanoseconds
; ...and the tunnel's own, which is what the two WebSocket idle comparisons use.
; An upgraded connection is not a request and does not inherit the request's
; deadline: an idle tunnel is normal, and silence cannot distinguish a quiet
; peer from a vanished one — that is what the backend's Ping/Pong is for. This
; is the backstop for a tunnelled backend that does NOT heartbeat.
tunnel_timeout_ns:  resq 1
sig_mask:           resq 1     ; blocked-signal set: SIGTERM + SIGQUIT + SIGHUP
sig_fd:             resd 1
drain_flag:         resd 1     ; 1 = draining: no accepts, close after serve
accept_err_streak:  resd 1     ; consecutive failed accepts; drives the backoff
conn_full_warned:   resd 1     ; the pool-full warning has been logged already
quic_fd:    resd 1                 ; the PRIMARY h3 socket (index 0): BPF, Alt-Svc, "is h3 on" guard
quic_fds:   resd LINNEA_QUIC_MAX_LISTENERS   ; every h3 UDP socket on the port (index 0 == quic_fd)
quic_nfd:   resd 1                 ; how many of quic_fds are live
qrecv_cur_sock: resd 1            ; the socket index .on_qrecv is draining, for the re-arm
qrecv_msg: resb LINNEA_QUIC_MAX_LISTENERS * (LINNEA_MSGHDR_SIZE)
qrecv_iov: resb LINNEA_QUIC_MAX_LISTENERS * (LINNEA_IOVEC_SIZE)
; control buffer for the SO_RXQ_OVFL cmsg: cmsghdr(16) + u32, rounded up
qrecv_cmsg: resb LINNEA_QUIC_MAX_LISTENERS * (LINNEA_QRECV_CMSG_SIZE)
; The GRO segment size the kernel reported for the run just received, or 0 when
; it reported none -- an old kernel, a refused sockopt, or simply nothing to
; coalesce. Zero means "the read is one datagram", which is what it always was.
qrecv_gso:    resd 1
qrecv_left:   resd 1               ; bytes of the run not yet handed over
qrecv_seglen: resd 1               ; this segment's length on the wire
qrecv_copied: resd 1               ; ...clamped to one datagram's buffer
qrecv_off:    resq 1               ; where this segment starts in the batch
qrecv_drops: resq LINNEA_QUIC_MAX_LISTENERS  ; per-socket last overflow count, to report only the delta
ring_ovf_seen: resq 1      ; likewise for the completion ring's backlog count
cqe_tag:       resd 1      ; the completing op's tag, kept past the shift
cqe_gen:       resd 1      ; and the connection incarnation it was armed for
qrecv_peer: resb LINNEA_QUIC_MAX_LISTENERS * (LINNEA_SOCKADDR_IN6_SIZE)
sig_buf:            resb 128   ; struct signalfd_siginfo
; one record's plaintext during the TLS handoff (see the assertion above)
tls_early_scratch:  resb LINNEA_CONN_IN_BUF
tls_early_scratch_size equ LINNEA_CONN_IN_BUF

; CLAMP_IO_LEN reg — an op may not be given more than LINNEA_IO_MAX bytes.
%macro CLAMP_IO_LEN 1
    cmp %1, LINNEA_IO_MAX
    jbe %%len_ok
    mov %1, LINNEA_IO_MAX
%%len_ok:
%endmacro

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
    mov rax, [rbx + linnea_config.proxy_timeout]   ; already resolved: never 0
    mov [proxy_timeout_ts], rax
    mov rax, [rbx + linnea_config.tunnel_timeout]  ; likewise resolved
    imul rax, rax, 1000000000
    mov [tunnel_timeout_ns], rax
    mov rax, [rbx + linnea_config.head_timeout]
    imul rax, rax, 1000000000
    mov [head_timeout_ns], rax
    ; ...and the same idle clock for QUIC, which used to ignore the config
    ; entirely and advertise a hardcoded 30 s. `timeout` is documented as the
    ; seconds an idle CLIENT connection is held, with no protocol qualifier, so
    ; h3 honouring it is the key doing what it says. Two variables rather than
    ; one: src/lib/linnea_quic.o is linked by linnea-probe (no config) and
    ; linnea_quic_conn.o by linnea-pooltest (no config, no libquic), so neither
    ; can reach the other or the config -- each keeps its own default and the
    ; server, which has all three, is what makes them agree.
    mov rax, [rbx + linnea_config.timeout]
    mov [linnea_quic_conn_idle_secs], rax        ; the pool sweep, in seconds
    imul rax, rax, 1000                          ; ...and what we advertise, ms
    mov [linnea_quic_idle_ms], rax
    mov rax, [rbx + linnea_config.drain_timeout]
    mov [drain_deadline], rax  ; tv_sec of the timespec; tv_nsec stays 0
    mov rax, [rbx + linnea_config.max_per_ip]
    mov [max_per_ip], rax
    mov rdi, [rbx + linnea_config.rate_limit]
    call linnea_ratelimit_init
    mov rax, [rbx + linnea_config.max_upstream]
    mov [linnea_upstream_limit], rax
    ; A proxied HTTP/3 request builds its upstream leg in linnea_h3_proxy.asm
    ; and needs the connect queued; queuing an SQE is ours alone, so the module
    ; is handed the one entry point it needs rather than the ring.
    lea rax, [h3p_arm]
    mov [linnea_h3_proxy_arm_hook], rax
    lea rax, [linnea_h3_proxy_start]   ; ...and the serve path is told where the
    mov [linnea_h3_proxy_hook], rax    ; upstream machinery lives
    lea rax, [linnea_h3_proxy_cancel]  ; ...and the QUIC side how to drop a leg
    mov [linnea_h3_cancel_hook], rax   ; whose stream is gone

    mov edi, LINNEA_URING_ENTRIES
    lea rsi, [ring]
    xor edx, edx
    mov ecx, LINNEA_URING_CQ_ENTRIES
    call linnea_ring_init
    test eax, eax
    js .init_fail

    ; Report a memory fault before dying. Installed in the WORKER — the master
    ; has no request handling to fault in — and after the ring and the log are
    ; up, so the line has somewhere to go.
    call linnea_crash_install

    ; Signals arrive as cqes like everything else: block them, open a
    ; signalfd, and arm a read on the ring.
    ;   SIGTERM  stop: exit at once, dropping whatever is open
    ;   SIGQUIT  drain: stop accepting and finish what is open, on a
    ;            deadline; used when a new generation is already serving
    ;            (hot upgrade)
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
    mov dword [quic_nfd], 0
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
    ; The owner must be a vhost that h3 can actually serve. It once had to have
    ; no redirect location either, because h3 could not emit a Location header —
    ; so a single "/old" redirect silently cost the WHOLE server its QUIC
    ; listener, every other location included. h3 serves redirects now (QPACK
    ; static index 12), so nothing here disqualifies a vhost.
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
    mov [quic_fds], eax            ; the primary IS listener index 0
    mov dword [quic_nfd], 1
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
    ; Neither a proxy nor a redirect location disqualifies a vhost any more.
    ; h3 routes to locations, reaches upstreams, and emits Location for a
    ; redirect (QPACK static index 12), so every kind can be served.
    ;
    ; Leaving a vhost UNREGISTERED was the worse failure by far: its h3 requests
    ; fell through to whichever vhost owned the listener and were served from
    ; THAT one's document root, under THAT one's certificate. A redirect vhost
    ; kept its h1 and h2, so the loss was quiet — the browser simply never used
    ; h3 for it, or worse, used it and got another vhost's pages.
.quic_vhost_static:
    ; Register with the first ROOT location as the default. Every request
    ; routes for itself now, so this only matters when routing is unavailable.
    lea rcx, [rax + linnea_config_server.locations]
    mov r8, [rax + linnea_config_server.location_count]
    xor r9d, r9d
.quic_vhost_root:
    cmp r9, r8
    jae .quic_vhost_add                                 ; none: register the first
    cmp qword [rcx + linnea_config_location.kind], LINNEA_LOC_KIND_ROOT
    je .quic_vhost_add
    add rcx, linnea_config_location_size
    inc r9
    jmp .quic_vhost_root
.quic_vhost_add:
    cmp r9, r8
    jb .quic_vhost_have
    lea rcx, [rax + linnea_config_server.locations]
.quic_vhost_have:
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

    ; --- additional QUIC sockets: one per OTHER distinct host on this port ---
    ; The primary listener above binds the first eligible TLS server's host. A
    ; second server with a DIFFERENT host on the same port -- the classic case
    ; being a wildcard 0.0.0.0 primary beside a specific IPv6 literal -- needs
    ; its own UDP socket, or h3 simply never answers on that address (its TCP
    ; still does, so the loss is quiet: the browser just never upgrades). One
    ; socket per host that OWNS a listener (listener_owner!=0 dedups the SNI
    ; vhosts that share a host:port), capped at LINNEA_QUIC_MAX_LISTENERS. The
    ; vhost table is port-based and already registered once above, so every
    ; socket serves the same set of certificates and roots. When there is only
    ; one host (nfd stays 1) none of this runs and the path is the old one.
    imul rdx, r12, linnea_config_server_size
    lea rdx, [rbx + rdx + linnea_config.servers]
    movzx r15d, word [rdx + linnea_config_server.port]   ; the h3 port
    mov r14, r12                                          ; primary index, to skip
    xor r13d, r13d
.quic_more:
    cmp r13, [rbx + linnea_config.server_count]
    jae .quic_arm_all
    cmp r13, r14
    je .quic_more_next                                    ; the primary, already bound
    imul rdx, r13, linnea_config_server_size
    lea rdx, [rbx + rdx + linnea_config.servers]
    cmp dword [rdx + linnea_config_server.tls], 0
    je .quic_more_next
    cmp qword [rdx + linnea_config_server.cert_list], 0
    je .quic_more_next
    cmp qword [rdx + linnea_config_server.location_count], 0
    je .quic_more_next
    cmp dword [rdx + linnea_config_server.listener_owner], 0
    je .quic_more_next                                    ; SNI-shares another host:port
    cmp word [rdx + linnea_config_server.port], r15w
    jne .quic_more_next                                  ; a TLS server on another port
    ; an eligible distinct host on the h3 port. Is there room in the array?
    cmp dword [quic_nfd], LINNEA_QUIC_MAX_LISTENERS
    jb .quic_more_bind
    ; no room: this host -- and any after it -- gets no h3. Say so ONCE (the
    ; jump ends the scan), so an over-capacity config is visible in the log
    ; rather than silently short of a listener.
    call linnea_log_stamp
    lea rdi, [log_h3cap]
    mov esi, log_h3cap_len
    call linnea_log_write
    jmp .quic_arm_all
.quic_more_bind:
    mov rdi, rdx
    call linnea_network_quic_listener
    cmp rax, -1
    je .quic_more_next                                    ; could not bind: no h3 here
    mov ecx, [quic_nfd]
    mov [quic_fds + rcx*4], eax
    inc dword [quic_nfd]
.quic_more_next:
    inc r13
    jmp .quic_more

.quic_arm_all:
    ; one armed recvmsg per socket; each re-arms itself from its own completion
    xor r13d, r13d
.quic_arm_loop:
    cmp r13d, [quic_nfd]
    jae .quic_arm_done
    mov edi, r13d
    call linnea_uring_arm_qrecv
    inc r13d
    jmp .quic_arm_loop
.quic_arm_done:
    call linnea_uring_arm_qtimer     ; one timer drives the rtx/drain sweeps for all

    ; if the BPF steering program loaded, register this worker's PRIMARY QUIC
    ; socket at its index in the reuseport map and attach the program to that
    ; group, so a connection's later packets are routed here by its id even if
    ; the client migrates to a new address (which would otherwise re-hash to
    ; another worker). Only the primary's reuseport group is steered; a
    ; specific-host secondary socket is its own group, left on the kernel's
    ; 4-tuple hash -- correct for a non-migrating client, which is every browser
    ; that reaches a literal address. Done last: it clobbers the scratch above.
    cmp qword [linnea_bpf_prog_fd], 0
    jl .quic_done
    mov edi, [linnea_worker_index]
    mov esi, [quic_fd]
    call linnea_bpf_map_add
    test rax, rax
    jns .bpf_map_ok
    ; the registration failed -- this worker's connections steer nowhere by id
    ; and fall to the 4-tuple hash. With the map sized to the whole index range
    ; this only happens on an unexpected kernel error, but ignoring it was how a
    ; too-small map dropped steering for high worker indices in silence.
    push rax
    call linnea_log_stamp
    lea rdi, [log_bpfmap]
    mov esi, log_bpfmap_len
    call linnea_log_write
    pop rdi
    neg rdi
    call linnea_log_u64
    lea rdi, [log_bpfmap_end]
    mov esi, log_bpfmap_end_len
    call linnea_log_write
.bpf_map_ok:
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
    cmp eax, LINNEA_UD_DRAINTIMER
    je .on_drain_deadline
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
    mov [qrecv_cur_sock], r13d         ; which of the h3 sockets fired; the
                                       ; handler calls below clobber r13, and the
                                       ; re-arm at the end must bring back THIS one
    test r15d, r15d
    jle .qrecv_rearm
    mov edi, r13d
    call qrecv_check_drops             ; ...and reads UDP_GRO's segment size
    mov [qrecv_left], r15d
    ; One completion can now carry a run of datagrams from one flow. They are
    ; handed over one at a time, each copied down to linnea_quic_rxbuf, because
    ; forty-three places in the QUIC server read that buffer by name and the h3
    ; proxy's unchecked copy is bounded by its size. A ~1200-byte copy is a
    ; fraction of the completion it saves.
    ; The peer address applies to every segment: GRO only ever coalesces one
    ; flow, which is exactly why it can hand back a single msg_name.
.qrecv_seg:
    mov eax, [qrecv_left]
    test eax, eax
    jz .qrecv_rearm
    mov ecx, [qrecv_gso]
    test ecx, ecx
    jz .qrecv_tail                     ; no coalescing: the read is one datagram
    cmp eax, ecx
    ja .qrecv_have
.qrecv_tail:
    mov ecx, eax                       ; the last segment of a run is short
.qrecv_have:
    mov [qrecv_seglen], ecx
    ; Clamp to one datagram's buffer. Nothing should exceed it — a GRO segment
    ; is a path-MTU datagram — but the old iov was 2048 and the kernel enforced
    ; it by truncating, so an oversized one is truncated here rather than
    ; written past the end of rxbuf.
    cmp ecx, LINNEA_QUIC_RXBUF_SIZE
    jbe .qrecv_fits
    mov ecx, LINNEA_QUIC_RXBUF_SIZE
.qrecv_fits:
    mov [qrecv_copied], ecx
    mov eax, [qrecv_cur_sock]
    imul rax, rax, LINNEA_QUIC_RXBATCH_SIZE
    lea rsi, [linnea_quic_rxbatch + rax]
    add rsi, [qrecv_off]
    lea rdi, [linnea_quic_rxbuf]
    rep movsb
    ; advance BEFORE handing over: the handler clobbers everything and may
    ; re-enter this file
    mov eax, [qrecv_seglen]
    add [qrecv_off], rax
    sub [qrecv_left], eax
    mov edi, [qrecv_copied]
    mov r8d, [qrecv_cur_sock]
    imul rax, r8, LINNEA_SOCKADDR_IN6_SIZE
    lea rsi, [qrecv_peer + rax]
    imul rax, r8, LINNEA_MSGHDR_SIZE
    mov edx, [qrecv_msg + rax + LINNEA_MSGHDR_NAMELEN]   ; kernel-updated length
    mov ecx, [quic_fds + r8*4]         ; reply on the socket the datagram arrived on
    call linnea_quic_server_datagram
    jmp .qrecv_seg
.qrecv_rearm:
    ; the recv stays armed while draining — the in-flight responses the drain
    ; waits on need the peer's ACKs and flow-control credit to finish, and a
    ; handler may just have freed the last connection (the peer said goodbye)
    call drain_all_done
    test eax, eax
    jnz .drained_exit
    mov edi, [qrecv_cur_sock]          ; re-arm only the socket whose recv completed
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

; --- a signal arrived on the signalfd ---------------------------------
; SIGHUP reopens the log. SIGTERM exits at once. SIGQUIT drains: stop
; taking new work but finish what is open — cancel every armed accept
; (their completions close our copies of the listener fds, which releases
; the port once every worker has done the same), let in-flight requests
; run to their end, close instead of keep-alive afterwards, and exit when
; the last connection is freed or the drain deadline fires.
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
    ; The two stop signals mean different things and are answered
    ; differently.
    ;
    ; SIGTERM is the unit going down. systemd sends it to every process in
    ; the cgroup and SIGKILLs whatever is still there at TimeoutStopSec.
    ; Nothing open outlives a stop whichever way we do it, so there is
    ; nothing to buy by draining first: exit now. Clients reconnect to the
    ; server that comes back, which is what a restart is. Draining here is
    ; what made `systemctl restart` slow — a browser almost always holds an
    ; idle keep-alive, and a WebSocket tunnel is never idle at all, so a
    ; stop ran to the ten-second kill with a page open.
    ;
    ; SIGQUIT is the hot upgrade retiring the previous generation, where
    ; finishing open connections IS the point: the new workers already have
    ; everything arriving, and these last requests are all the old ones have
    ; left to do. So that path still drains — but against a deadline, since
    ; a tunnel never goes idle and would otherwise pin an old worker for as
    ; long as its browser tab is open.
    cmp dword [sig_buf], LINNEA_SIGQUIT
    jne .stop_now
    mov dword [drain_flag], 1
    mov dword [linnea_quic_draining], 1  ; the QUIC module's copy: refuse new conns
    call linnea_uring_arm_drain_deadline
    call linnea_log_stamp
    lea rdi, [log_drain]
    mov esi, log_drain_len
    call linnea_log_write
    ; Leave the reuseport group FIRST: until this worker's listeners are
    ; closed the kernel keeps hashing new connections to them, and during a hot
    ; upgrade those are exactly the requests the new generation should have got.
    ; Closing hands the group back to the sockets still serving.
    ; The fd is cleared so the accept completion below does not close it a
    ; second time — by then the number may belong to someone else entirely.
    ;
    ; But close() on a listening socket RESETS everything still sitting in its
    ; accept queue, and those are live requests — a client that connected and
    ; sent a request it will never get an answer to. So sweep the queue first
    ; and set each one up as an ordinary connection; the drain then finishes
    ; them like any other open connection. What is left is the gap between the
    ; sweep coming up empty and the close on the next line, which really is the
    ; couple of microseconds the old comment here claimed for the whole thing.
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
    mov r14d, edi              ; the listening fd, across the sweep's calls
    ; accept() would block on an empty queue, and the queue is empty exactly
    ; when we want to stop. The socket is about to be closed, so nothing here
    ; outlives the next few instructions.
    mov eax, LINNEA_SYS_FCNTL
    mov esi, LINNEA_F_SETFL
    mov edx, LINNEA_O_NONBLOCK
    syscall
.drain_queue:
    mov eax, LINNEA_SYS_ACCEPT
    mov edi, r14d
    xor esi, esi               ; the peer address is read back from the fd
    xor edx, edx
    syscall
    test eax, eax
    js .drain_queue_done       ; EAGAIN: nothing left queued
    mov r15d, eax
    call setup_accepted_conn   ; r13d is already this server's index
    jmp .drain_queue
.drain_queue_done:
    mov edi, r14d
    mov eax, LINNEA_SYS_CLOSE
    syscall
.close_listeners_next:
    inc r13
    jmp .close_listeners
.listeners_closed:
    ; tell connected h3 peers we are going away before anything else, then
    ; close the ones with nothing in flight right now, so a retiring
    ; generation holding only idle browser tabs says goodbye and goes
    ; instead of waiting out their idle timeouts
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
    call linnea_uring_submit_now
    jmp .wait
.drained_exit:
    ; THIS is the exit a reload takes, and it was the black hole. An idle QUIC
    ; connection does not hold a drain open -- drain_all_done counts work in
    ; flight, and a browser sitting on an established connection has none -- so
    ; the old worker declares itself drained AT ONCE and leaves, with every h3
    ; peer still pointed at it and nothing said. The peer then meets silence,
    ; which is how a browser decides an origin's h3 is unreliable.
    ;
    ; Found by probing all three exits rather than the one that looked likely:
    ; the deadline below had the same hole and is the one the symptom named, but
    ; locally it never fires at all -- "worker drained" is logged in the same
    ; second as the upgrade. Fixing only that would have changed nothing and
    ; looked right.
    cmp dword [quic_fd], 0
    jl .drained_go
    mov edi, [quic_fd]
    call linnea_quic_server_close_all
.drained_go:
    call linnea_log_stamp
    lea rdi, [log_drained]
    mov esi, log_drained_len
    call linnea_log_write
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; SIGTERM: the unit is stopping, so stop. Nothing is cancelled or waited on —
; exit closes every socket, and the log line is flushed by its own newline
; before we go.
.stop_now:
    ; Say goodbye to h3 peers before going. A QUIC connection that just stops
    ; answering leaves its client to an idle timeout and reads as the protocol
    ; failing — which is how a browser decides an origin's HTTP/3 is
    ; unreliable and stops offering it. One datagram each, so the stop is
    ; still immediate. TCP needs nothing here: exit closes those sockets and
    ; the peer sees it at once.
    cmp dword [quic_fd], 0
    jl .stop_log
    mov edi, [quic_fd]
    call linnea_quic_server_close_all
.stop_log:
    call linnea_log_stamp
    lea rdi, [log_stopped]
    mov esi, log_stopped_len
    call linnea_log_write
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall

; The hot upgrade's drain ran out of time: whatever is still open is not
; going to finish on its own. Go, rather than stay for ever holding it.
;
; ...but SAY SO FIRST, exactly as the stop path above does. The reasoning is
; already written out over linnea_quic_server_close_all: a QUIC connection that
; simply stops answering is how a browser decides an origin's h3 is unreliable
; and quietly stops offering it. It was applied to the stop and not to this
; exit, which is the same defect shape as always -- one of several ways out,
; and the one nobody was looking at.
;
; It is this exit that a browser actually meets. A stop happens when someone
; stops the service; this fires on every RELOAD, ten seconds after it, for any
; peer still holding a connection -- which is every browser that has the site
; open, because an idle browser connection never "finishes" and so always runs
; the deadline out. Measured on the live site: two reloads, two deadline lines,
; and Safari left h3 for h2 and stayed there.
.on_drain_deadline:
    call linnea_log_stamp
    lea rdi, [log_drain_late]
    mov esi, log_drain_late_len
    call linnea_log_write
    cmp dword [quic_fd], 0
    jl .drain_late_go
    mov edi, [quic_fd]
    call linnea_quic_server_close_all
.drain_late_go:
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
    jnz .accept_setup
    mov dword [accept_err_streak], 0   ; accepting again: end any backoff
.accept_setup:
    call setup_accepted_conn           ; r15d = fd, r13d = server index
    jmp .accept_rearm
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
    call ktls_rx_record_type   ; a kTLS read names the record it delivered; a
                               ; record that is not application data becomes the
                               ; EOF the -EIO path used to report, EXCEPT a
                               ; KeyUpdate, which is answered by rekeying
    test eax, eax
    jnz .ktls_rekeyed
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
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CAPTURE
    je .req_body_recv
    test r15d, r15d
    jg .recv_data
    jz .recv_eof
    cmp r15d, -LINNEA_ECANCELED
    je .recv_timeout
    call tls_recv_is_eof
    test eax, eax
    jnz .recv_eof
    call recv_fail_reason
    jmp .conn_close
.ktls_rekeyed:
    ; The receive keys have moved on. Re-arm the very read the KeyUpdate
    ; consumed -- same buffer, same length -- rather than assuming it was the
    ; ordinary in_buf one: it may have been a request-body relay into up_buf,
    ; and a KeyUpdate can arrive at any moment, including mid-upload.
    mov rdi, r12
    mov rsi, [r12 + linnea_connection.rx_iov + LINNEA_IOVEC_BASE]
    mov rdx, [r12 + linnea_connection.rx_iov + LINNEA_IOVEC_LEN]
    call linnea_uring_arm_recv_buf
    call linnea_uring_submit_now
    jmp .wait
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
    ; An HTTP/1 connection with a request PARTLY received is owed an answer
    ; (RFC 9110 15.5.9). It used to get none: a client whose declared body
    ; stalled had the connection dropped in silence, so it could not tell a
    ; server that gave up from a network that ate the connection. h1 waits for a
    ; declared body BEFORE it routes, and a body that stops short is
    ; indistinguishable from a slow one on a byte stream, so this timeout is the
    ; only answer h1 can ever give -- it just has to be given.
    ;
    ; in_len is what says a request is PARTLY received: the keep-alive path
    ; above leaves it holding exactly the pipelined bytes a response did not
    ; consume, so it is zero on a connection sitting idle between requests --
    ; legitimate, possibly for a long time, and owed silence rather than a
    ; complaint. It is req_start that cannot answer this question, though the
    ; head clock uses it: the handshake's own sends zero it, so a TLS
    ; connection reaches its first request with req_start already 0 (the same
    ; hole .req_body_recv documents from the other side).
    ;
    ; h2 is excluded: it answers an overrun body deadline itself with a 408 on
    ; the stream (see the service pass above), and writing a bare HTTP/1
    ; response onto an h2 connection would be a framing error. So is anything
    ; mid-proxy -- a response may be in flight from the upstream, and a 408
    ; spliced into it is the framing error we refuse everywhere else. (A
    ; stalled handshake and a stalled capture never reach here at all: .on_recv
    ; dispatches both before the -ECANCELED test.)
    cmp qword [r12 + linnea_connection.is_h2], 0
    jne .recv_timeout_silent
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_IDLE
    jne .recv_timeout_silent
    cmp qword [r12 + linnea_connection.in_len], 0
    je .recv_timeout_silent
    ; Nothing has gone to the client yet, so the exchange can still be answered
    ; honestly -- but the client is mid-send and does not know it is over, so
    ; the close has to linger or the RST discards the answer just written. Same
    ; shape as .capture_answer.
    mov qword [r12 + linnea_connection.answer_linger], 1
    mov rdi, r12
    call linnea_http_request_timeout
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.recv_timeout_silent:
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
    cmp eax, LINNEA_HTTP_CAPTURE
    je .capture_chunked_start
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
    ; A body too large to buffer with the head is captured in full before the
    ; upstream is touched at all — not even connected. The backend therefore
    ; only ever sees requests that are already complete, and a client that
    ; abandons its upload costs it nothing.
    cmp qword [r12 + linnea_connection.req_body_rem], 0
    jne .capture_start
.proxy_connect_now:
    ; A leg taken from the idle pool is already connected, so its exchange
    ; starts at the send; linnea_http_proxy left proxy_state saying which.
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_SENDING
    je .proxy_send_pooled
    mov rdi, r12               ; the request goes to an upstream first
    call linnea_uring_arm_connect
    call linnea_uring_submit_now
    jmp .wait
.proxy_send_pooled:
    mov rdi, r12
    call linnea_uring_arm_up_send
    call linnea_uring_submit_now
    jmp .wait
.capture_start:
    ; the body bytes that arrived with the head are queued behind it in
    ; file_ptr/file_rem; they open the capture file instead
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CAPTURE
    mov rdi, r12
    mov rsi, [r12 + linnea_connection.file_ptr]
    mov rdx, [r12 + linnea_connection.file_rem]
    call linnea_spill_write
    mov qword [r12 + linnea_connection.file_rem], 0
    test eax, eax
    js .capture_fail
    jmp .capture_more          ; a counted body: its length says when it ends
.capture_chunked_start:
    ; A chunked body has no declared length, so the decoder is what says when
    ; it ends. Whatever arrived with the head goes through it first; in_buf is
    ; left holding the head alone, which is what the second parse pass reads.
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CAPTURE
    mov qword [r12 + linnea_connection.capture_chunked], 1
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.in_buf]
    add rsi, [r12 + linnea_connection.head_len]
    ; Guarded like the one at .keep_alive_continue, and for the same reason: an
    ; in_len below head_len would wrap into a length no buffer has, and hand it
    ; to a decoder that walks it. It cannot be below here — this path is only
    ; entered with in_buf full, so in_len is LINNEA_CONN_IN_BUF and head_len is
    ; a prefix of it — but that argument lives in linnea_http.asm, three
    ; functions away, and is the sort that stops being true without anyone
    ; editing this line. Zero is the honest reading of "no body bytes in hand".
    mov rdx, [r12 + linnea_connection.in_len]
    sub rdx, [r12 + linnea_connection.head_len]
    jae .cap_ch_have
    xor edx, edx
.cap_ch_have:
    lea rcx, [r12 + linnea_connection.chunk_state]   ; the capture's own state
    mov r8d, LINNEA_CHUNK_CAPTURE
    call linnea_spill_chunked
    mov rcx, [r12 + linnea_connection.head_len]
    mov [r12 + linnea_connection.in_len], rcx
.capture_verdict:
    cmp eax, 1
    je .capture_complete
    test eax, eax
    jz .capture_more
    cmp eax, -2
    je .capture_too_large
    cmp eax, -3
    je .capture_pipeline_big
    jmp .capture_malformed
.capture_pipeline_big:
    ; The body decoded cleanly, but the request pipelined behind it is larger
    ; than the room left after the head, so it cannot be stashed. Dropping it
    ; would desync the stream silently; close instead, and the client re-sends
    ; it on a fresh connection. Only reachable with a pathologically large head.
    lea r14, [reason_pipeline_big]
    mov r15d, reason_pipeline_big_len
    jmp .conn_close
.capture_complete:
    ; The body is whole. Parse the same head again: this time it sees a
    ; complete counted body and rewrites the request head with the length the
    ; decode counted, which is why the head could not be built up front.
    mov qword [r12 + linnea_connection.capture_done], 1
    mov rdi, r12
    call linnea_http_handle
    cmp eax, LINNEA_HTTP_PROXY
    je .capture_upstream
    test eax, eax
    jz .capture_fail           ; NEED_MORE is impossible: the body is complete
    mov rdi, r12               ; the second pass answered the client instead
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.capture_upstream:
    mov rdi, r12               ; the mapping replaces whatever was queued
    call linnea_spill_finish
    test eax, eax
    js .capture_fail
    jmp .proxy_connect_now
.capture_malformed:
    mov esi, 400
    jmp .capture_answer
.capture_too_large:
    mov esi, 413
.capture_answer:
    ; Nothing has been sent to the client and no upstream was ever contacted,
    ; so the whole exchange can still be answered honestly. The client is
    ; mid-upload, though, and does not know it is over: the close after this
    ; has to linger, or the RST discards the answer we just wrote.
    mov qword [r12 + linnea_connection.answer_linger], 1
    mov rdi, r12
    call linnea_http_proxy_error
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.capture_more:
    ; The capture window is out_buf. NOT up_buf: that already holds the
    ; rewritten request head, waiting to go out the moment the body is
    ; complete. NOT in_buf either — the parser's head is still there for the
    ; access log. out_buf is idle until the response head is rewritten into
    ; it, which cannot happen before the request has even been sent.
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.out_buf]
    mov edx, LINNEA_CONN_OUT_BUF
    ; A COUNTED body's length is known, so read at most what is still owed:
    ; without this cap a client that pipelines its next request behind the
    ; body's final bytes lands both in one recv, and the suffix (out_buf past
    ; req_body_rem) is dropped — the pipelined request goes unanswered. Capped,
    ; the tail read stops at the body's end and the suffix stays in the kernel,
    ; where keep-alive's fresh recv into in_buf reads it as the next request.
    ; req_body_rem is always > 0 here (a completed body goes to .proxy_connect_now,
    ; not here), so the clamp never asks for a zero-length read. Chunked has no
    ; declared length to cap against and preserves its suffix in the decoder.
    cmp qword [r12 + linnea_connection.capture_chunked], 0
    jne .capture_more_arm
    mov rax, [r12 + linnea_connection.req_body_rem]
    cmp rax, rdx
    jae .capture_more_arm
    mov edx, eax
.capture_more_arm:
    call linnea_uring_arm_recv_buf
    call linnea_uring_submit_now
    jmp .wait
.capture_fail:
    lea r14, [reason_spill_err]
    mov r15d, reason_spill_err_len
    jmp .conn_close
.recv_more:
    mov rdi, r12
    call h2_arm_recv_once
    call linnea_uring_submit_now
    jmp .wait

; --- capturing a request body: the client's bytes go to the spill file ---
; The client stopping early (EOF, error or the idle timeout) means the body
; will never be complete, so the exchange is over — and since nothing has been
; forwarded, it ends with the upstream never having heard of the request at
; all. Nothing has been sent to the client either, so there is no half of
; anything to worry about.
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
    cmp qword [r12 + linnea_connection.capture_chunked], 0
    je .req_body_counted
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.out_buf]
    mov edx, r15d
    lea rcx, [r12 + linnea_connection.chunk_state]   ; the capture's own state
    mov r8d, LINNEA_CHUNK_CAPTURE
    call linnea_spill_chunked
    jmp .capture_verdict
.req_body_counted:
    mov eax, r15d
    cmp rax, [r12 + linnea_connection.req_body_rem]
    jbe .req_body_have
    ; Defensive now that .capture_more caps the recv at req_body_rem: a recv can
    ; no longer return more than the body owes, so this branch is unreachable.
    ; Kept so the write below can never run past the declared length even if
    ; that invariant is ever weakened — but the suffix it once dropped is now
    ; left in the kernel by the cap, not silently discarded here.
    mov rax, [r12 + linnea_connection.req_body_rem]
.req_body_have:
    sub [r12 + linnea_connection.req_body_rem], rax
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.out_buf]    ; the chunk landed here
    mov rdx, rax
    call linnea_spill_write
    test eax, eax
    js .capture_fail
    cmp qword [r12 + linnea_connection.req_body_rem], 0
    jne .capture_more
    ; the body is complete. Map it behind file_ptr/file_rem — where the head
    ; send already knows to find a queued body — and only now open the
    ; upstream, with the whole request in hand.
    mov rdi, r12
    call linnea_spill_finish
    test eax, eax
    js .capture_fail
    jmp .proxy_connect_now
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
    cmp qword [r12 + linnea_connection.tx_inflight], 0
    je .tx_counted             ; never below zero, whatever the completion is
    dec qword [r12 + linnea_connection.tx_inflight]
.tx_counted:
    call ktls_flush_key_update ; a KeyUpdate the peer asked for waits here for
                               ; the socket to go quiet: nothing of ours is
                               ; outstanding at this instant, which is the whole
                               ; requirement for switching the transmit key
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
    call send_fail_reason
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
    cmp qword [r12 + linnea_connection.answer_linger], 0
    jne .drain_linger          ; refused mid-upload: linger or the RST takes
    jmp .conn_close            ; the answer with it
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
    mov rdi, r12               ; whatever this request captured is finished
    call linnea_spill_reset    ; with; the next one starts from nothing
    ; A streamed body's capture may have parked the next request at
    ; in_buf[head_len] (it arrived in the same recv as the body's tail, so it
    ; could not stay in the kernel the way a counted body's suffix does). Make
    ; in_len span it, so the slide below carries it down like any pipelined
    ; bytes. spill_reset does not touch pend_len, so this reads it intact.
    mov rcx, [r12 + linnea_connection.pend_len]
    test rcx, rcx
    jz .ka_no_pend
    mov rax, [r12 + linnea_connection.head_len]
    add rax, rcx
    mov [r12 + linnea_connection.in_len], rax
    mov qword [r12 + linnea_connection.pend_len], 0
.ka_no_pend:
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
    call recv_fail_reason
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
    ; WHICH failure. The alert we just sent the client says exactly that, and
    ; dropping it made "tls handshake failed" the single largest close reason
    ; in the production log -- 4018 of them in eighteen days, every one
    ; indistinguishable from the next, covering a bad ClientHello, no shared
    ; cipher, an unsupported version and a client that simply went away. The
    ; same lesson as the discarded recv errno, one layer up.
    call log_tls_alert
    lea r14, [reason_tls_failed]
    mov r15d, reason_tls_failed_len
    jmp .conn_close
.tls_send_err:
    cmp r15d, -LINNEA_ECANCELED
    je .tls_send_stall
    call send_fail_reason
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
    ; Keep both application traffic secrets before the handshake state they live
    ; in is lost: it is overlaid on up_buf, which is a buffer again from here on.
    ; A KeyUpdate derives the next generation from the current secret, so without
    ; this copy the connection could never follow one.
    lea rdi, [r12 + linnea_connection.s_ap_secret]
    lea rsi, [r12 + linnea_connection.up_buf + linnea_tls_hs.s_ap]
    mov ecx, 32
    rep movsb
    lea rdi, [r12 + linnea_connection.c_ap_secret]
    lea rsi, [r12 + linnea_connection.up_buf + linnea_tls_hs.c_ap]
    mov ecx, 32
    rep movsb
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
    ; A peer that hangs up during the handshake takes the socket out of
    ; ESTABLISHED, and attaching the TLS ULP to it then fails with ENOTCONN
    ; (confirmed against the kernel: alive -> OK, after FIN or RST -> ENOTCONN).
    ; That is the client leaving, not a handoff we got wrong — there is nothing
    ; left to serve either way, but calling it a failure buried the real thing
    ; this log line is for under hundreds of routine disconnects. Report it as
    ; the peer closing, and keep the loud reason for a handoff the kernel
    ; actually refused (bad keys, no ULP, resource pressure).
    cmp qword [linnea_ktls_fail_step], 1
    jne .tls_ktls_real
    cmp qword [linnea_ktls_fail_errno], -107      ; -ENOTCONN
    jne .tls_ktls_real
    lea r14, [reason_peer]
    mov r15d, reason_peer_len
    jmp .conn_close
.tls_ktls_real:
    ; record which of the three setsockopts refused it, and the errno, before
    ; the connection goes: "handoff failed" on its own is undiagnosable
    push r12
    call linnea_log_stamp
    lea rdi, [dbgktls]
    mov esi, dbgktls_len
    call linnea_log_write
    mov rdi, [linnea_ktls_fail_step]
    call linnea_log_u64
    lea rdi, [dbgktls_errno]
    mov esi, dbgktls_errno_len
    call linnea_log_write
    xor rdi, rdi
    sub rdi, [linnea_ktls_fail_errno]    ; -errno -> errno
    call linnea_log_u64
    lea rdi, [log_nl]
    mov esi, 1
    call linnea_log_write
    pop r12
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
    cmp qword [r12 + linnea_connection.h3_cancel], 0
    jne .h3_leg_reap           ; the stream it answers is gone
    test r15d, r15d
    jz .connect_ok
    ; This backend did not answer. Count it against its health, then move the
    ; request to the next one if the location names another that has not been
    ; tried. Safe HERE AND ONLY HERE: no byte of the request has been sent, so
    ; the request cannot arrive twice. Past this point a silent backend is a
    ; slow backend, not an absent one, and belongs to proxy_timeout.
    mov rdi, [r12 + linnea_connection.location]
    mov rsi, [r12 + linnea_connection.up_backend]
    call linnea_upstream_mark_fail
    cmp r15d, -LINNEA_ECANCELED
    je .connect_timeout
    mov esi, 502               ; refused, unreachable, no route
    jmp .connect_failover
.connect_timeout:
    mov esi, 504
.connect_failover:
    mov rax, [r12 + linnea_connection.location]
    mov rax, [rax + linnea_config_location.proxy_count]
    cmp [r12 + linnea_connection.up_tries], rax
    jae .proxy_fail            ; every backend this location names has been tried
    push rsi                   ; keep the status, in case the retry cannot start
    mov rdi, r12
    call linnea_uring_up_reconnect
    pop rsi
    test eax, eax
    js .proxy_fail
    jmp .wait
.connect_ok:
    ; it answered: whatever it did before, this backend is up
    mov rdi, [r12 + linnea_connection.location]
    mov rsi, [r12 + linnea_connection.up_backend]
    call linnea_upstream_mark_ok
    mov qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_SENDING
    mov rdi, r12
    call linnea_uring_arm_up_send
    call linnea_uring_submit_now
    jmp .wait

; give up on the upstream and answer the client instead; esi = 502 or 504
.proxy_fail:
    ; An HTTP/3 leg has no client socket to send on: its answer goes out as a
    ; QUIC stream, and the leg is freed rather than kept for a keep-alive that
    ; does not exist.
    cmp qword [r12 + linnea_connection.h3_owner], 0
    jne .h3_proxy_fail
    mov rdi, r12
    call linnea_http_proxy_error
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.h3_proxy_fail:
    mov rdi, r12
    mov edx, [quic_fd]                ; vestigial: linnea_quic_h3_deliver replaces
                                      ; this with the connection's own udp_fd
    call linnea_h3_proxy_fail
    call linnea_uring_submit_now
    jmp .wait

; An upstream leg whose stream was cancelled, or whose whole QUIC connection
; went away, while this operation was in flight. The kernel has finished with
; the buffer now — that is the whole reason the free waited for this completion
; rather than happening at the cancel — so the leg can go. Nothing is sent:
; there is no longer a stream to send it on.
.h3_leg_reap:
    mov rdi, r12
    call linnea_h3_proxy_release
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
    cmp qword [r12 + linnea_connection.h3_cancel], 0
    jne .h3_leg_reap           ; the stream it answers is gone
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
    ; The request is always complete by the time any of it is sent: a body too
    ; large to buffer was captured before the upstream was even connected, and
    ; the head send drained it out of file_ptr/file_rem just above. So there is
    ; never more of it to come here.
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
    cmp qword [r12 + linnea_connection.h3_cancel], 0
    jne .h3_leg_reap           ; the stream it answers is gone
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_TUNNEL
    je .tunnel_up_recv
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_CLOSING
    je .closing_u2c
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_RELAY
    je .relay_recv
    cmp qword [r12 + linnea_connection.proxy_state], LINNEA_PROXY_H3BODY
    je .h3_body_recv
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
    cmp qword [r12 + linnea_connection.h3_owner], 0
    jne .h3_head_parse
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

; --- an HTTP/3 leg: the head is kept for the QPACK re-encode and the body is
; captured whole before any of the response is sent, so there is no relay ---
.h3_head_parse:
    call linnea_h3_proxy_head
    cmp eax, LINNEA_HTTP_HEAD_READY
    je .h3_head_ready
    test eax, eax
    js .head_bad               ; malformed: 502, on the stream
    mov rax, [r12 + linnea_connection.up_len]   ; incomplete: read more, unless
    cmp rax, LINNEA_CONN_UP_BUF                 ; the head has filled the buffer
    jae .head_bad
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.up_buf]
    add rsi, rax
    mov edx, LINNEA_CONN_UP_BUF
    sub edx, eax
    call linnea_uring_arm_up_recv
    call linnea_uring_submit_now
    jmp .wait
.h3_head_ready:
    ; Whatever arrived behind the head is the body's first bytes. up_buf stays
    ; untouched from here — the response head has to survive until it is
    ; re-encoded — so the capture reads into out_buf, which an h3 leg never
    ; uses for anything else.
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.up_buf]
    add rsi, [r12 + linnea_connection.h3_hoff]   ; past any interim heads...
    add rsi, [r12 + linnea_connection.h3_hlen]   ; ...and past the final one
    mov rdx, [r12 + linnea_connection.up_len]
    sub rdx, [r12 + linnea_connection.h3_hoff]
    sub rdx, [r12 + linnea_connection.h3_hlen]
    call linnea_h3_proxy_body
    jmp .h3_body_verdict
.h3_body_recv:
    test r15d, r15d
    jg .h3_body_data
    jz .h3_body_eof
    cmp r15d, -LINNEA_ECANCELED
    je .h3_body_timeout
    mov esi, 502
    jmp .proxy_fail
.h3_body_eof:
    ; A CHUNKED body ends at its terminal chunk, never at a closed socket. It
    ; reaches here with body_rem = -1, the same as a close-delimited one, so it
    ; used to be accepted as complete: /api/chunktrunc -- "4\r\nbo" then close --
    ; was delivered as a 200 carrying the two bytes that had arrived, and a
    ; chunk size larger than any body produced a clean empty 200. HTTP/3
    ; captures the whole body before it sends anything, so unlike HTTP/2 it can
    ; still refuse at this point, and it should (audit-report-17, found beside
    ; Finding 1 rather than in it).
    cmp qword [r12 + linnea_connection.capture_chunked], 0
    je .h3_body_eof_plain
    cmp qword [r12 + linnea_connection.chunk_state], LINNEA_CHUNK_DONE
    je .h3_body_done
    mov esi, 502
    jmp .proxy_fail
.h3_body_eof_plain:
    ; A close-delimited body ends exactly here; a counted one that is still
    ; short was cut off, and half a response is not one we can send.
    cmp qword [r12 + linnea_connection.body_rem], -1
    jne .h3_body_short
    mov qword [r12 + linnea_connection.body_rem], 0
    jmp .h3_body_done
.h3_body_short:
    cmp qword [r12 + linnea_connection.body_rem], 0
    je .h3_body_done
    mov esi, 502
    jmp .proxy_fail
.h3_body_timeout:
    mov esi, 504
    jmp .proxy_fail
.h3_body_data:
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.out_buf]
    mov edx, r15d
    call linnea_h3_proxy_body
.h3_body_verdict:
    cmp eax, 1
    je .h3_body_done
    test eax, eax
    js .h3_body_fail
    mov rdi, r12               ; more of it to come
    lea rsi, [r12 + linnea_connection.out_buf]
    mov edx, LINNEA_CONN_OUT_BUF
    call linnea_uring_arm_up_recv
    call linnea_uring_submit_now
    jmp .wait
.h3_body_fail:
    mov esi, 502
    jmp .proxy_fail
.h3_body_done:
    mov rdi, r12
    mov esi, [quic_fd]                ; vestigial: linnea_quic_h3_deliver replaces
                                      ; this with the connection's own udp_fd
    call linnea_h3_proxy_deliver
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
.relay_chunk_bad:
    lea r14, [reason_up_chunk]
    mov r15d, reason_up_chunk_len
    jmp .conn_close
.relay_eof:
    cmp qword [r12 + linnea_connection.body_rem], 0
    je .proxy_finish           ; a counted body ended exactly here
    cmp qword [r12 + linnea_connection.body_rem], -1
    jne .relay_short
    ; body_rem's -1 means two things: close-delimited, where the close IS the
    ; end, and chunked, where it is not -- the terminal chunk is. Now that the
    ; relay decodes as it forwards, the two can be told apart: a chunked
    ; response that stops before LINNEA_CHUNK_DONE ended early, and saying so
    ; is the difference between a truncated relay and a completed one in the
    ; log (audit-report-24). The client sees the same FIN either way, since a
    ; chunked relay never keeps the connection alive.
    cmp qword [r12 + linnea_connection.resp_chunked], 0
    je .proxy_finish
    cmp qword [r12 + linnea_connection.resp_chunk_state], LINNEA_CHUNK_DONE
    je .proxy_finish
    lea r14, [reason_up_chunk_early]
    mov r15d, reason_up_chunk_early_len
    jmp .conn_close
.relay_short:
    lea r14, [reason_up_early]  ; short of the promised Content-Length
    mov r15d, reason_up_early_len
    jmp .conn_close
.relay_data:
    ; A chunked upstream response is relayed byte for byte, so the client -- and
    ; anything caching for it -- reads the upstream's own framing. Judge it
    ; first, with the decoder h3's capture path uses, over the exact bytes about
    ; to go out. h2 and h3 answer 502 to a malformed chunk; h1 has already sent
    ; this head and cannot, but it can decline to finish: closing here leaves
    ; the client an unterminated chunked message rather than a clean, complete
    ; 200 carrying framing another parser may read differently (audit-report-24).
    cmp qword [r12 + linnea_connection.resp_chunked], 0
    je .relay_framed
    push r15                   ; the completion's byte count
    mov rdi, r12
    lea rsi, [r12 + linnea_connection.up_buf]
    mov edx, r15d
    lea rcx, [r12 + linnea_connection.resp_chunk_state]
    mov r8d, LINNEA_CHUNK_VALIDATE
    call linnea_spill_chunked
    pop r15
    cmp eax, -1
    je .relay_chunk_bad
.relay_framed:
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
    ; body_rem is -1 for a chunked response as well as for a close-delimited
    ; one, and only the second of those ends at the upstream's close: a chunked
    ; message ends at its TERMINAL CHUNK. Asking body_rem alone meant reading
    ; on after a message that was already complete, which a backend closing the
    ; connection then hid -- linnea sends Connection: close upstream, so almost
    ; every backend does. One that does not left the exchange sitting until
    ; proxy_timeout: the client had its whole body in 0 ms and the connection
    ; was held 10 s, closed as "upstream timeout", and the 200 it had already
    ; been served NEVER REACHED THE ACCESS LOG (audit-report-26).
    ;
    ; The EOF path has asked this since report 24; it just asked too late to
    ; matter, because reaching it depends on the upstream doing something.
    cmp qword [r12 + linnea_connection.resp_chunked], 0
    je .relay_read_on
    cmp qword [r12 + linnea_connection.resp_chunk_state], LINNEA_CHUNK_DONE
    je .proxy_finish
.relay_read_on:
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
    ; Keep it only if this exchange ended EXACTLY where its framing said it
    ; would. "Connection: close" used to hide a length we got wrong -- the close
    ; ended the message whatever we believed. A pooled connection hides nothing:
    ; the next request on it would read the remainder of this response as its
    ; own head. So the bar is all four of: the location opted in and the method
    ; was safe (both in up_reusable), the backend did not say close, and the
    ; body was delimited and fully consumed. A close-delimited response cannot
    ; pass it -- body_rem stays -1 and it ends at the very close that makes the
    ; socket unusable.
    cmp qword [r12 + linnea_connection.up_reusable], 0
    je .proxy_close_up
    cmp qword [r12 + linnea_connection.up_no_reuse], 0
    jne .proxy_close_up
    cmp qword [r12 + linnea_connection.resp_chunked], 0
    je .proxy_park_counted
    cmp qword [r12 + linnea_connection.resp_chunk_state], LINNEA_CHUNK_DONE
    jne .proxy_close_up        ; chunked, but not through the terminal chunk
    jmp .proxy_park
.proxy_park_counted:
    cmp qword [r12 + linnea_connection.body_rem], 0
    jne .proxy_close_up        ; -1 = close-delimited, > 0 = short
.proxy_park:
    mov rdi, [r12 + linnea_connection.location]
    mov rsi, [r12 + linnea_connection.up_backend]
    mov edx, [r12 + linnea_connection.up_fd]
    call linnea_upstream_park
    test eax, eax
    jz .proxy_close_up         ; pool full: close it, exactly as before
    mov dword [r12 + linnea_connection.up_fd], -1
    jmp .proxy_logged
.proxy_close_up:
    mov edi, [r12 + linnea_connection.up_fd]
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
    call recv_fail_reason
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
    cmp rax, [tunnel_timeout_ns]
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
    cmp rax, [tunnel_timeout_ns]
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
    call send_fail_reason
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
    mov rdi, r12               ; a captured request body's fd; the mapping it
    call linnea_spill_release  ; may have handed to file_base goes just below
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
; linnea_uring_arm_link_timeout_up(rdi = connection*) — the same, bounded by
; proxy_timeout instead of the client idle timeout. Every op that talks to a
; BACKEND arms through here: connect, the request send, the response recv.
linnea_uring_arm_link_timeout_up:
    push rbx
    mov rbx, rdi
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_LINK_TIMEOUT
    mov dword [rax + LINNEA_SQE_FD], -1
    lea rcx, [proxy_timeout_ts]
    jmp linnea_uring_arm_link_timeout.lt_fill

linnea_uring_arm_link_timeout:
    push rbx
    mov rbx, rdi
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_LINK_TIMEOUT
    mov dword [rax + LINNEA_SQE_FD], -1
    lea rcx, [idle_timeout]
.lt_fill:
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], 1
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_TIMEOUT
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    pop rbx
    ret

; setup_accepted_conn(r15d = accepted fd, r13d = server index)
;
; Everything that turns a freshly accepted socket into a live connection:
; take a slot, format the peer, enforce the per-address cap, start the head
; clock, begin a TLS handshake if this listener wants one, and arm the first
; recv. It is a routine rather than straight-line code inside the accept
; completion because there are now TWO ways in -- that completion, and the
; sweep of the accept queue a draining worker makes before it closes its
; listening socket (Q178).
;
; Reads r13d/r15d and leaves both alone; rbx and r12 are saved and restored.
setup_accepted_conn:
    push r12
    push rbx
    sub rsp, 8                 ; 2 pushes + the return address: re-align to 16
    lea rbx, [linnea_config_instance]
    call linnea_connection_alloc
    test rax, rax
    jz .su_full
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
    jz .su_counted         ; address unreadable: nothing to count it against
    lea rdi, [r12 + linnea_connection.peer_ip]
    mov rsi, rax
    call linnea_connection_count_ip    ; this connection is already among them
    cmp rax, [max_per_ip]
    jbe .su_counted
    ; over the cap: hand the slot back and drop the connection without a log
    ; line — logging every refusal would turn a flood into disk exhaustion
    mov rdi, r12
    call linnea_connection_free
    mov edi, r15d
    mov eax, LINNEA_SYS_CLOSE
    syscall
    jmp .su_done
.su_counted:
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
    je .su_recv
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
    mov [r12 + linnea_connection.up_buf + linnea_tls_hs.alpn_h2_ok], eax
    mov qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_HS
.su_recv:
    mov rdi, r12
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .su_done
.su_full:
    mov edi, r15d
    mov eax, LINNEA_SYS_CLOSE
    syscall
    ; warn once per spell of fullness, not once per refused connection
    cmp dword [conn_full_warned], 0
    jne .su_done
    mov dword [conn_full_warned], 1
    lea rdi, [warn_full]
    mov esi, warn_full_len
    call linnea_print_stderr
.su_done:
    add rsp, 8
    pop rbx
    pop r12
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

; ktls_flush_key_update(r12 = connection*)
; Answer a KeyUpdate the peer asked us to reciprocate (RFC 8446 4.6.3: when
; request_update is update_requested, the receiver MUST send a KeyUpdate of its
; own before its next Application Data record).
;
; Ordering is the whole difficulty. Our KeyUpdate goes out under the CURRENT
; transmit key and everything after it under the next one, so nothing of ours may
; be in flight across that boundary: a send the kernel is still framing would be
; encrypted under whichever key won the race, and the peer would fail to decrypt
; a record it had no reason to doubt. So this runs only with tx_inflight == 0 --
; either straight away, when the KeyUpdate arrived on an idle connection, or from
; the send completion, where the socket has just gone quiet.
;
; Failure is not fatal and not silent-by-accident: if the send or the rekey is
; refused, the flag stays set and the next quiet moment tries again. The peer
; keeps decrypting our records with the key it already has, because a peer only
; switches its receive key when our KeyUpdate actually arrives.
; Clobbers rax, rcx, rdx, rdi, rsi, r8, r9, r10, r11.
ktls_flush_key_update:
    cmp qword [r12 + linnea_connection.ku_pending], 0
    je .fku_ret
    cmp qword [r12 + linnea_connection.tx_inflight], 0
    jne .fku_ret                      ; still busy: the next completion retries
    cmp qword [r12 + linnea_connection.tls_phase], LINNEA_TLS_PHASE_KTLS
    jne .fku_clear                    ; not ours to send any more
    push r12
    push r13
    mov edi, [r12 + linnea_connection.fd]
    call linnea_ktls_key_update
    test rax, rax
    js .fku_done                      ; the write failed: try again when quiet
    mov edi, [r12 + linnea_connection.fd]
    lea rsi, [r12 + linnea_connection.s_ap_secret]
    call linnea_ktls_rekey_tx         ; only after the record is on the wire
    test rax, rax
    js .fku_done
    mov qword [r12 + linnea_connection.ku_pending], 0
.fku_done:
    pop r13
    pop r12
    ret
.fku_clear:
    mov qword [r12 + linnea_connection.ku_pending], 0
.fku_ret:
    ret

; ktls_rx_record_type(r12 = connection*, r15d = the read's result)
;   -> r15d may be forced to 0 (EOF)
; A kTLS read carries the type of the record it delivered. Application data is
; the only type the rest of the server can do anything with; anything else --
; today a close_notify alert, or a KeyUpdate -- is turned into the EOF that a
; plain recv used to report by failing with -EIO. Behaviour is unchanged by this
; alone: the SAME connections close, for the same reasons. What changes is that
; the type is now KNOWN, which is what a KeyUpdate needs.
; Clobbers rax, rcx.
ktls_rx_record_type:
    cmp qword [r12 + linnea_connection.rx_msg_armed], 0
    je .krt_ret                       ; a plain recv: nothing was asked for
    mov qword [r12 + linnea_connection.rx_msg_armed], 0
    mov qword [r12 + linnea_connection.rx_rectype], 0
    test r15d, r15d
    jle .krt_ret                      ; an error or EOF delivers no record
    cmp qword [r12 + linnea_connection.rx_msg + LINNEA_MSGHDR_CONTROLLEN], 16
    jb .krt_ret                       ; no cmsg came back: application data, the
                                      ; same assumption a plain recv makes
    lea rcx, [r12 + linnea_connection.rx_cmsg]
    cmp dword [rcx + 8], LINNEA_SOL_TLS          ; struct cmsghdr: len, level, type
    jne .krt_ret
    cmp dword [rcx + 12], LINNEA_TLS_GET_RECORD_TYPE
    jne .krt_ret
    movzx eax, byte [rcx + 16]
    mov [r12 + linnea_connection.rx_rectype], rax
    cmp eax, LINNEA_TLS_REC_APPDATA
    je .krt_ret
    cmp eax, LINNEA_TLS_REC_HANDSHAKE
    je .krt_handshake
.krt_eof:
    xor r15d, r15d                    ; not application data: EOF, as before
.krt_ret:
    xor eax, eax
    ret
.krt_handshake:
    ; A post-handshake handshake message. The only one a client sends that we
    ; can act on is KeyUpdate (RFC 8446 4.6.3): 0x18, a 3-byte length of 1, then
    ; the request_update byte. Anything else -- post-handshake authentication,
    ; a message split across records -- is closed on, as every non-application
    ; record was before this.
    cmp r15d, 5
    jne .krt_eof
    lea rcx, [r12 + linnea_connection.rx_iov]
    mov rcx, [rcx + LINNEA_IOVEC_BASE]        ; where the record landed
    cmp byte [rcx], 0x18                      ; key_update
    jne .krt_eof
    cmp dword [rcx + 1], 0x00010000           ; length 1, over the 3 length bytes;
    je .krt_ku                                ; payload 0 = update_not_requested
    cmp dword [rcx + 1], 0x01010000           ; payload 1 = update_requested: the
    jne .krt_eof                              ; peer wants one of ours back
    mov qword [r12 + linnea_connection.ku_pending], 1
.krt_ku:
    ; Lingering or tearing down: there is nothing left to receive, so the old
    ; answer (close) is still the right one and is cheaper than a rekey.
    cmp qword [r12 + linnea_connection.linger], 0
    jne .krt_eof
    cmp qword [r12 + linnea_connection.h2_closing], 0
    jne .krt_eof
    mov edi, [r12 + linnea_connection.fd]
    lea rsi, [r12 + linnea_connection.c_ap_secret]
    call linnea_ktls_rekey_rx
    test rax, rax
    js .krt_eof                       ; the kernel refused: close, as before
    call ktls_flush_key_update        ; if one was asked for, and the socket is
                                      ; quiet, answer it now
    mov eax, 1                        ; handled: the caller re-arms the read
    ret

; ktls_prep_rx(rdi = connection*, rsi = buffer, edx = length) -> rax = msghdr*
; Fill this connection's msghdr for a kTLS read: one iovec over the caller's
; buffer, plus control space for the record type the kernel attaches to every
; record it delivers. A plain recv has nowhere to put that cmsg, so the kernel
; fails such a read with -EIO -- AND CONSUMES THE RECORD, after which the socket
; yields nothing further. There is therefore no way to notice a KeyUpdate after
; the fact; the type has to be asked for on every read. Sets rx_msg_armed so the
; completion knows rx_cmsg holds something.
ktls_prep_rx:
    mov [rdi + linnea_connection.rx_iov + LINNEA_IOVEC_BASE], rsi
    mov ecx, edx                      ; zero-extends: the length is a u32
    mov [rdi + linnea_connection.rx_iov + LINNEA_IOVEC_LEN], rcx
    lea rax, [rdi + linnea_connection.rx_msg]
    mov qword [rax + LINNEA_MSGHDR_NAME], 0
    mov dword [rax + LINNEA_MSGHDR_NAMELEN], 0
    lea rcx, [rdi + linnea_connection.rx_iov]
    mov [rax + LINNEA_MSGHDR_IOV], rcx
    mov qword [rax + LINNEA_MSGHDR_IOVLEN], 1
    lea rcx, [rdi + linnea_connection.rx_cmsg]
    mov [rax + LINNEA_MSGHDR_CONTROL], rcx
    mov qword [rax + LINNEA_MSGHDR_CONTROLLEN], LINNEA_KTLS_CMSG_SIZE
    mov dword [rax + LINNEA_MSGHDR_FLAGS], 0
    mov qword [rdi + linnea_connection.rx_msg_armed], 1
    ret

; ktls_sqe_to_recvmsg(rbx = connection*, rax = sqe*) — turn a prepared RECV sqe
; into the RECVMSG this connection needs, reusing the buffer and length already
; written into it. Called only when the connection is past the kTLS handoff.
; Preserves rax (the sqe), which every caller goes on to use.
ktls_sqe_to_recvmsg:
    push rax
    push rax                          ; twice: keep rsp 16-byte aligned
    mov rdi, rbx
    mov rsi, [rax + LINNEA_SQE_ADDR]  ; the buffer the caller chose
    mov edx, [rax + LINNEA_SQE_LEN]   ; and how much of it
    call ktls_prep_rx                 ; rax = msghdr*
    mov rcx, rax
    pop rax
    pop rax
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_RECVMSG
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], 1   ; one msghdr, not a byte count
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
    mov qword [rbx + linnea_connection.rx_msg_armed], 0
    cmp qword [rbx + linnea_connection.tls_phase], LINNEA_TLS_PHASE_KTLS
    jne .ar_ud
    call ktls_sqe_to_recvmsg          ; the kernel owns the decryption now, so
                                      ; the record type has to come with the data
.ar_ud:
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
    mov qword [rbx + linnea_connection.rx_msg_armed], 0
    cmp qword [rbx + linnea_connection.tls_phase], LINNEA_TLS_PHASE_KTLS
    jne .lr_ud
    call ktls_sqe_to_recvmsg          ; these bytes are dropped, but the read
                                      ; still has to carry control space
.lr_ud:
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
    CLAMP_IO_LEN r13
    mov [rax + LINNEA_SQE_LEN], r13d
    mov qword [rbx + linnea_connection.rx_msg_armed], 0
    cmp qword [rbx + linnea_connection.tls_phase], LINNEA_TLS_PHASE_KTLS
    jne .arb_ud
    call ktls_sqe_to_recvmsg
.arb_ud:
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
    inc qword [rbx + linnea_connection.tx_inflight]   ; see .tx_inflight: this is
                                                      ; the one funnel every client
                                                      ; send passes through
    mov r12, rsi
    mov r13, rdx
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_SEND
    mov byte [rax + LINNEA_SQE_FLAGS], LINNEA_IOSQE_IO_LINK
    mov ecx, [rbx + linnea_connection.fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov [rax + LINNEA_SQE_ADDR], r12
    CLAMP_IO_LEN r13
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

; h3p_arm(rdi = an upstream leg an HTTP/3 request just built) — the arm hook
; linnea_h3_proxy.asm calls. Submitting at once matters: the leg was created
; while a QUIC datagram was being processed, and nothing else on that path
; publishes the SQ, so the connect would otherwise sit unqueued until some
; unrelated connection happened to submit.
h3p_arm:
    ; a leg that took a parked connection is already connected, so its first
    ; operation is the send, not the connect
    cmp qword [rdi + linnea_connection.proxy_state], LINNEA_PROXY_SENDING
    je .h3p_send
    call linnea_uring_arm_connect
    jmp linnea_uring_submit_now
.h3p_send:
    call linnea_uring_arm_up_send
    jmp linnea_uring_submit_now

; linnea_uring_up_reconnect(rdi = connection*) -> eax = 0 armed, -1 could not
; Close the upstream socket whose connect failed, take a fresh one, move to the
; next backend and connect again. The old fd must go first: it is in a failed
; state and holding it would leak a descriptor for the life of the request.
linnea_uring_up_reconnect:
    push rbx
    mov rbx, rdi
    mov edi, [rbx + linnea_connection.up_fd]
    cmp edi, -1
    je .no_old
    mov eax, LINNEA_SYS_CLOSE
    syscall
    call linnea_upstream_closed
    mov dword [rbx + linnea_connection.up_fd], -1
.no_old:
    mov eax, LINNEA_SYS_SOCKET
    mov edi, LINNEA_AF_INET
    mov esi, LINNEA_SOCK_STREAM
    xor edx, edx
    syscall
    cmp rax, -4095
    jae .no_socket
    mov [rbx + linnea_connection.up_fd], eax
    call linnea_upstream_open
    mov rdi, [rbx + linnea_connection.location]
    call linnea_upstream_pick
    mov [rbx + linnea_connection.up_backend], rax
    inc qword [rbx + linnea_connection.up_tries]
    mov rdi, rbx
    call linnea_uring_arm_connect
    call linnea_uring_submit_now
    xor eax, eax
    pop rbx
    ret
.no_socket:
    ; out of descriptors: the caller answers with the status it already had,
    ; which is the failure of the backend rather than of this retry
    mov eax, -1
    pop rbx
    ret

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
    push rax
    mov rdi, [rbx + linnea_connection.location]
    mov rsi, [rbx + linnea_connection.up_backend]
    call linnea_upstream_addr          ; the CHOSEN backend, not the first
    mov rcx, rax
    pop rax
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
    jmp linnea_uring_arm_link_timeout_up

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
    CLAMP_IO_LEN r13
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
    jmp linnea_uring_arm_link_timeout_up

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
    CLAMP_IO_LEN r13
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
    jmp linnea_uring_arm_link_timeout_up

; recv_fail_reason(r15d = the negative errno) -> r14 = reason, r15d = its
; length. Called where a read has failed and the connection is going.
;
; ECONNRESET is not a fault: it is what a browser closing a tab, navigating
; away or trimming its connection pool looks like, and it was the bulk of the
; "recv error" lines in the log — around sixty a day, every one of them
; ordinary. It gets a reason of its own so the log stops reporting routine
; behaviour as an error.
;
; Everything else keeps "recv error" and now writes the errno alongside it.
; "recv error" on its own is undiagnosable, which is exactly what the kTLS
; handoff line taught: a discarded errno turns a question into a shrug.
recv_fail_reason:
    cmp r15d, -LINNEA_ECONNRESET
    je .rfr_reset
    push rbx
    push r12
    push r13                   ; 3 pushes: the call sites are 16-aligned
    mov ebx, r15d              ; the logging calls clobber freely
    call linnea_log_stamp
    lea rdi, [dbgrecv]
    mov esi, dbgrecv_len
    call linnea_log_write
    xor rdi, rdi
    sub edi, ebx               ; -errno -> errno
    call linnea_log_u64
    lea rdi, [log_nl]
    mov esi, 1
    call linnea_log_write
    pop r13
    pop r12
    pop rbx
    lea r14, [reason_recv_err]
    mov r15d, reason_recv_err_len
    ret
.rfr_reset:
    lea r14, [reason_peer_reset]
    mov r15d, reason_peer_reset_len
    ret

; log_tls_alert(r12 = connection*) — record the alert the handshake failed
; with. Preserves r14/r15, which the caller is about to set to its reason, and
; leaves r14/r15 alone -- they are callee-saved, so the log calls preserve
; them, and the caller sets them straight afterwards anyway.
log_tls_alert:
    push rbx
    push r12
    push r13                   ; 3 pushes: the call sites are 16-aligned
    mov ebx, [r12 + linnea_connection.up_buf + linnea_tls_hs.alert]
    call linnea_log_stamp
    lea rdi, [dbgtlsalert]
    mov esi, dbgtlsalert_len
    call linnea_log_write
    mov edi, ebx
    call linnea_log_u64
    lea rdi, [log_nl]
    mov esi, 1
    call linnea_log_write
    pop r13
    pop r12
    pop rbx
    ret

; send_fail_reason(r15d = the negative errno) -> r14 = reason, r15d = its
; length. The send-side twin of recv_fail_reason, and it exists for the same
; reason: "send error" carried no errno at all, so the 49 of them in the
; production log said only that a write had failed, never which write or why.
;
; ECONNRESET and EPIPE are not faults here either -- they are what a client
; that closed the tab looks like from the sending side -- so they get the
; reasons that describe what actually happened instead of being filed as
; errors. ECANCELED is a send timeout and is split by the callers, which have
; their own stall handling.
send_fail_reason:
    cmp r15d, -LINNEA_ECONNRESET
    je .sfr_reset
    cmp r15d, -LINNEA_EPIPE
    je .sfr_gone
    push rbx
    push r12
    push r13                   ; 3 pushes: the call sites are 16-aligned
    mov ebx, r15d
    call linnea_log_stamp
    lea rdi, [dbgsend]
    mov esi, dbgsend_len
    call linnea_log_write
    xor rdi, rdi
    sub edi, ebx               ; -errno -> errno
    call linnea_log_u64
    lea rdi, [log_nl]
    mov esi, 1
    call linnea_log_write
    pop r13
    pop r12
    pop rbx
    lea r14, [reason_send_err]
    mov r15d, reason_send_err_len
    ret
.sfr_reset:
    lea r14, [reason_peer_reset]
    mov r15d, reason_peer_reset_len
    ret
.sfr_gone:
    lea r14, [reason_peer]
    mov r15d, reason_peer_len
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
    push rax
    mov rdi, [r12 + linnea_h2p.location]
    mov rsi, [r12 + linnea_h2p.backend]
    call linnea_upstream_addr
    mov rcx, rax
    pop rax
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
    ; the head comes from the front of the buffer; once it is out, the body
    ; comes from a mapping of the file it was captured to. This used to be
    ; either that or a FIFO the body streamed through, sharing these cursors;
    ; nothing streams now, so a slot with no capture has nothing after the head.
    mov rcx, [r12 + linnea_h2p.sent]
    cmp rcx, [r12 + linnea_h2p.req_len]
    jb .ao_send_head
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_REQ_FILE
    jz .ao_send_head                 ; nothing left; the send is a no-op
    mov rcx, [r12 + linnea_h2p.rq_buf]
    add rcx, [r12 + linnea_h2p.rq_rd]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov rcx, [r12 + linnea_h2p.rq_wr]
    sub rcx, [r12 + linnea_h2p.rq_rd]
    CLAMP_IO_LEN rcx                 ; a captured body is a mapping of up to
    mov [rax + LINNEA_SQE_LEN], ecx  ; max_body, well past one io_uring send
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
    call linnea_uring_arm_link_timeout_up
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
    mov ecx, edi
    cmp ecx, [quic_nfd]
    jae .noq                   ; no such socket (index 0 with nfd 0 == no h3)
    push rbx
    mov ebx, edi               ; socket index, held across get_sqe_zeroed
    ; every buffer this recv touches is the index'th slot of its per-socket
    ; array, so N sockets never share one msghdr, iovec, control area, peer
    ; store or receive batch. For the single-listener case (index 0) each
    ; offset is zero and the arm is byte-for-byte the one it replaced.
    imul rdx, rbx, LINNEA_SOCKADDR_IN6_SIZE
    lea rcx, [qrecv_peer + rdx]
    imul r8, rbx, LINNEA_MSGHDR_SIZE
    mov [qrecv_msg + r8 + LINNEA_MSGHDR_NAME], rcx
    mov dword [qrecv_msg + r8 + LINNEA_MSGHDR_NAMELEN], LINNEA_SOCKADDR_IN6_SIZE
    imul r9, rbx, LINNEA_IOVEC_SIZE
    lea rcx, [qrecv_iov + r9]
    mov [qrecv_msg + r8 + LINNEA_MSGHDR_IOV], rcx
    mov qword [qrecv_msg + r8 + LINNEA_MSGHDR_IOVLEN], 1
    imul rdx, rbx, LINNEA_QRECV_CMSG_SIZE
    lea rcx, [qrecv_cmsg + rdx]  ; SO_RXQ_OVFL, and UDP_GRO's segment size
    mov [qrecv_msg + r8 + LINNEA_MSGHDR_CONTROL], rcx
    mov qword [qrecv_msg + r8 + LINNEA_MSGHDR_CONTROLLEN], LINNEA_QRECV_CMSG_SIZE
    mov dword [qrecv_msg + r8 + LINNEA_MSGHDR_FLAGS], 0
    imul rdx, rbx, LINNEA_QUIC_RXBATCH_SIZE
    lea rcx, [linnea_quic_rxbatch + rdx]   ; a GRO run, not one datagram
    mov [qrecv_iov + r9 + LINNEA_IOVEC_BASE], rcx
    mov qword [qrecv_iov + r9 + LINNEA_IOVEC_LEN], LINNEA_QUIC_RXBATCH_SIZE
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_RECVMSG
    mov ecx, [quic_fds + rbx*4]
    mov [rax + LINNEA_SQE_FD], ecx
    imul r8, rbx, LINNEA_MSGHDR_SIZE
    lea rcx, [qrecv_msg + r8]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], 1
    ; user_data carries the socket index (index << 8 | tag), so the completion
    ; re-arms exactly the socket that fired, not always socket 0
    mov rcx, rbx
    shl rcx, 8
    or rcx, LINNEA_UD_QRECV
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    pop rbx
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

qrecv_check_drops:                     ; edi = socket index
    mov qword [qrecv_off], 0
    mov dword [qrecv_gso], 0
    push rbx
    push r12
    push r13
    mov r13d, edi                      ; socket index, for the per-socket drop counter
    imul rax, r13, LINNEA_QRECV_CMSG_SIZE
    lea rbx, [qrecv_cmsg + rax]
    imul rax, r13, LINNEA_MSGHDR_SIZE
    mov r12, [qrecv_msg + rax + LINNEA_MSGHDR_CONTROLLEN]
.qcd_walk:
    ; A WALK, not a look at the first one. There are two control messages now
    ; and the kernel picks the order; reading offset zero and stopping was
    ; correct only while SO_RXQ_OVFL was the sole option asked for, and would
    ; silently stop reporting drops the moment UDP_GRO landed in front of it.
    cmp r12, LINNEA_CMSG_DATA
    jb .qcd_done                       ; no room for another header
    mov rcx, [rbx + LINNEA_CMSG_LEN]
    cmp rcx, LINNEA_CMSG_DATA + 4
    jb .qcd_done                       ; malformed, or carries no payload
    cmp rcx, r12
    ja .qcd_done                       ; claims to run past the buffer
    cmp dword [rbx + LINNEA_CMSG_LEVEL], LINNEA_SOL_SOCKET
    jne .qcd_try_udp
    cmp dword [rbx + LINNEA_CMSG_TYPE], LINNEA_SO_RXQ_OVFL
    jne .qcd_next
    mov eax, [rbx + LINNEA_CMSG_DATA]  ; the socket's running total
    cmp rax, [qrecv_drops + r13*8]
    jbe .qcd_next                      ; unchanged (or wrapped): nothing to say
    mov rcx, rax
    sub rcx, [qrecv_drops + r13*8]     ; how many since the last report
    mov [qrecv_drops + r13*8], rax
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
    mov rcx, [rbx + LINNEA_CMSG_LEN]   ; the logging clobbered it
    jmp .qcd_next
.qcd_try_udp:
    cmp dword [rbx + LINNEA_CMSG_LEVEL], LINNEA_SOL_UDP
    jne .qcd_next
    cmp dword [rbx + LINNEA_CMSG_TYPE], LINNEA_UDP_GRO
    jne .qcd_next
    mov eax, [rbx + LINNEA_CMSG_DATA]  ; bytes per segment in this run
    mov [qrecv_gso], eax
.qcd_next:
    add rcx, 7                         ; CMSG_ALIGN
    and rcx, -8
    cmp rcx, r12
    jae .qcd_done
    add rbx, rcx
    sub r12, rcx
    jmp .qcd_walk
.qcd_done:
    pop r13
    pop r12
    pop rbx
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

; linnea_uring_arm_drain_deadline() — one-shot IORING_OP_TIMEOUT bounding a
; hot upgrade's drain. Armed once, when the SIGQUIT arrives, and never
; re-armed: the worker is gone either way, whether by the last connection
; closing or by this firing. Caller submits.
linnea_uring_arm_drain_deadline:
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_TIMEOUT
    mov dword [rax + LINNEA_SQE_FD], -1
    lea rcx, [drain_deadline]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov dword [rax + LINNEA_SQE_LEN], 1        ; one timespec
    mov qword [rax + LINNEA_SQE_OFF], 0        ; fire on the timer, not a count
    mov qword [rax + LINNEA_SQE_USER_DATA], LINNEA_UD_DRAINTIMER
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
