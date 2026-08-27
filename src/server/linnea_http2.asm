; linnea_http2.asm — HTTP/2 connection layer (RFC 9113), milestone M15:
; connection bring-up. Validates the client preface, exchanges SETTINGS,
; answers PING, and closes cleanly on GOAWAY. Streams are not served yet
; — a HEADERS/DATA frame draws a graceful GOAWAY(NO_ERROR) and the
; connection closes. The kTLS layer below is transparent: frames ride the
; plaintext socket like any other bytes.
;
; A frame header is 9 bytes: length(24) type(8) flags(8) R+stream-id(32).
; The connection is driven half-duplex by the io_uring loop the same way
; keep-alive HTTP is: recv -> linnea_h2_handle -> maybe send -> recv.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"
%include "linnea_connection.inc"
%include "linnea_http2.inc"
%include "linnea_hpack.inc"
%include "linnea_time.inc"
%include "linnea_uring.inc"
%include "linnea_tls_client.inc"     ; proxy_h2 leg: TLS handshake state
%include "linnea_h2_client.inc"      ; proxy_h2 leg: h2 driver context + verdicts

global linnea_h2_init
global linnea_h2_handle
global linnea_h2_after_send
global linnea_h2_conn_free
global linnea_h2_pool_active
global h2_queue_goaway_pub

extern linnea_hpack_decode
extern linnea_hpack_req_check
extern linnea_http_authority_host
extern hpack_dyn_reset
extern linnea_h3_altsvc
extern linnea_h3_altsvc_len
extern linnea_h3_server
extern linnea_h3_advert
; static-file resolution lives in linnea_static.asm (shared with HTTP/3)
extern linnea_static_normalize
extern linnea_static_open
extern linnea_static_open_enc
extern linnea_static_mime
extern linnea_static_validators
extern linnea_static_mtime
extern linnea_static_etag
extern linnea_static_etag_len
extern linnea_static_lastmod
extern linnea_http_inm_match
extern linnea_http_etag_match
extern linnea_http_range_parse
extern linnea_http_ifrange_match
extern linnea_time_parse_http_date
extern linnea_time_http_now
extern linnea_config_instance
extern linnea_string_from_u64
extern linnea_string_to_u64
extern linnea_http_upstream_head_valid
extern linnea_http_head_conn_named
extern linnea_http_status_no_content
extern linnea_http_status_no_clen
extern linnea_string_iequal
extern linnea_string_trim_ows
extern linnea_string_is_tchar
extern linnea_chunk_ext_step
extern linnea_string_equal
extern linnea_string_is_token
extern linnea_quic_parse_priority
extern linnea_memory_map
extern linnea_log_stamp
extern linnea_log_write
extern linnea_log_u64
extern drain_flag
extern head_timeout_ns
extern linnea_uring_now
extern linnea_log_access
extern linnea_log_acc_host
extern linnea_log_acc_host_len
extern linnea_log_acc_peer
extern linnea_log_acc_peer_len
extern linnea_log_acc_meth
extern linnea_log_acc_meth_len
extern linnea_log_acc_tgt
extern linnea_log_acc_tgt_len
extern linnea_log_acc_proto
extern linnea_log_acc_proto_len
extern linnea_log_acc_status
extern linnea_log_acc_bytes

; proxy-over-h2: slot pool init + lookup for the io_uring loop, the upstream
; event handler, and connection teardown (see the Q86 section below)
global linnea_h2p_init
global linnea_h2p_at
global linnea_h2p_event
global linnea_h2p_service
global h2p_resp_feed                 ; proxy_h2 response feed (called from .ao_recv)
global linnea_h2p_conn_close
global h2p_compact
global linnea_h2_busy

extern linnea_spill_open_fd
extern linnea_upstream_count
extern linnea_upstream_open
extern linnea_upstream_socket
extern linnea_ratelimit_take
extern linnea_ratelimit_on
extern linnea_uring_now
extern linnea_upstream_closed
extern linnea_upstream_pick
extern linnea_upstream_reap_one
extern linnea_upstream_method_safe
extern linnea_upstream_park
extern linnea_upstream_take
extern linnea_string_has_token
extern linnea_upstream_mark_ok
extern linnea_upstream_mark_fail
extern linnea_upstream_log_oversize
extern linnea_upstream_mark_unanswered
extern linnea_upstream_limit
; proxy_h2 leg (h2 clients): TLS handshake + h2 driver on the slot .fd
extern linnea_h2p_tls_hs_for
extern linnea_h2p_h2c_for
extern linnea_tls_client_start
extern linnea_tls_client_input
extern linnea_ktls_enable
extern linnea_h2c_drv_start
extern linnea_h2c_drv_on_sent
extern linnea_h2c_drv_on_recv
extern linnea_h2c_drv_head
extern h2p_krx_rectype              ; kTLS record type of a proxy_h2 leg recv

section .rodata

; PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
h2_preface: db "PRI * HTTP/2.0", 13, 10, 13, 10, "SM", 13, 10, 13, 10
h2_preface_len equ $ - h2_preface

hdr_altsvc_name: db "alt-svc"
hdr_altsvc_name_len equ $ - hdr_altsvc_name
mime_txt_h2:    db "text/plain"
mime_txt_h2_len equ $ - mime_txt_h2

msg_h2_pre:     db "linnea h2: "
msg_h2_pre_len  equ $ - msg_h2_pre

section .text

; linnea_h2_init(rdi=conn) — queue the server's initial SETTINGS frame
; (empty) into out_buf and mark the connection awaiting the client
; preface. The caller sends out_ptr/out_rem, then reads.
%if LINNEA_H2_POOL_BYTES > LINNEA_CONN_UP_BUF
  %error "the h2 stream pool does not fit in up_buf: reduce LINNEA_H2_MAX_STREAMS"
%endif

linnea_h2_init:
    mov qword [rdi + linnea_connection.h2_state], LINNEA_H2_PREFACE
    mov qword [rdi + linnea_connection.h2_saw_settings], 0
    mov qword [rdi + linnea_connection.h2_cwnd], LINNEA_H2_INIT_WINDOW
    mov qword [rdi + linnea_connection.h2_rr_cursor], 0
    mov qword [rdi + linnea_connection.h2_last_stream], 0
    mov qword [rdi + linnea_connection.h2_rst_count], 0
    mov qword [rdi + linnea_connection.h2_done_count], 0
    mov qword [rdi + linnea_connection.h2_init_swnd], LINNEA_H2_INIT_WINDOW
    ; zero the stream pool: every slot free (id 0)
    push rdi
    lea rdi, [rdi + linnea_connection.up_buf + LINNEA_H2_POOL_OFF]
    xor eax, eax
    mov ecx, LINNEA_H2_POOL_BYTES / 8
    rep stosq
    pop rdi
    lea rax, [rdi + linnea_connection.out_buf]
    ; SETTINGS frame: length 24, type 4, flags 0, stream 0, four settings
    mov byte [rax], 0
    mov byte [rax + 1], 0
    mov byte [rax + 2], 24
    mov byte [rax + 3], LINNEA_H2_FT_SETTINGS
    mov byte [rax + 4], 0
    mov dword [rax + 5], 0          ; stream 0
    ; HEADER_TABLE_SIZE = 4096, the protocol default. The decoder has always
    ; kept a real table — it must, because an encoder may use the 4096 default
    ; until it has applied whatever we advertise — but advertising 0 told a
    ; conforming peer never to insert, which left the compression the table
    ; exists for unused: a browser's cookie and user-agent are identical on
    ; every request of a page load, and indexed they cost one byte each.
    ; This makes the table load-bearing for real traffic rather than dead
    ; state, which is why the arena had to become a ring first (Q153) and why
    ; hpack_stress.py drives eviction, the slot ceiling, the wrap and the
    ; copy-out the way an encoder using its full allowance would.
    mov byte [rax + 9], 0
    mov byte [rax + 10], LINNEA_H2_SETTINGS_HEADER_TABLE_SIZE
    mov dword [rax + 11], 0x00100000    ; value 4096, big-endian
    ; MAX_CONCURRENT_STREAMS: the size of our per-connection body-streaming
    ; pool, derived from the constant rather than restated, so the number on
    ; the wire is the number of slots we actually have.
    mov byte [rax + 15], 0
    mov byte [rax + 16], LINNEA_H2_SETTINGS_MAX_CONCURRENT_STREAMS
    mov dword [rax + 17], LINNEA_H2_BE32(LINNEA_H2_MAX_STREAMS)
    ; MAX_HEADER_LIST_SIZE = the decoder's real list bound, so a conforming
    ; client trims its cookies instead of discovering the limit as a 431.
    mov byte [rax + 21], 0
    mov byte [rax + 22], LINNEA_H2_SETTINGS_MAX_HEADER_LIST
    mov dword [rax + 23], 0x00200000    ; value 8192, big-endian
    ; INITIAL_WINDOW_SIZE: the per-stream RECEIVE window, which is exactly the
    ; upload buffer that has to hold what arrives in it — derived from the
    ; constant, like MAX_CONCURRENT_STREAMS above, so the number on the wire
    ; cannot drift from the buffer behind it. Left unsent, this defaulted to
    ; 65535 and an upload advanced one frame per round trip.
    mov byte [rax + 27], 0
    mov byte [rax + 28], LINNEA_H2_SETTINGS_INITIAL_WINDOW_SIZE
    mov dword [rax + 29], LINNEA_H2_BE32(LINNEA_H2_INITIAL_WINDOW)
    ; ...and the connection window, which SETTINGS cannot carry: RFC 9113
    ; 6.9.2 fixes it at 65535 until a WINDOW_UPDATE moves it. Without this the
    ; stream window above would be advertised and then never reachable.
    push rdi
    lea rdi, [rax + 33]
    xor esi, esi                        ; stream 0: the connection window
    mov edx, LINNEA_H2_CONN_WINDOW_INC
    call h2p_emit_window                ; -> rax = 13
    pop rdi
    lea rax, [rdi + linnea_connection.out_buf]
    mov [rdi + linnea_connection.out_ptr], rax
    mov qword [rdi + linnea_connection.out_rem], 33 + 13
    mov qword [rdi + linnea_connection.file_rem], 0
    mov qword [rdi + linnea_connection.h2_tx_busy], 1
    ret

; linnea_h2_handle(rdi=conn) -> rax = LINNEA_H2_MORE / _SEND / _CLOSE.
; Consumes whole frames from in_buf, queues any response frames into
; out_buf, compacts in_buf to the unconsumed tail.
linnea_h2_handle:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    lea r15, [rbx + linnea_connection.in_buf]
    mov r14, [rbx + linnea_connection.in_len]
    xor r12d, r12d                  ; bytes consumed
    lea r13, [rbx + linnea_connection.out_buf]   ; out write cursor

    cmp qword [rbx + linnea_connection.h2_state], LINNEA_H2_PREFACE
    jne .frames
    cmp r14, 24
    jb .more                        ; wait for the whole preface
    mov rax, [r15]
    cmp rax, [h2_preface]
    jne .close
    mov rax, [r15 + 8]
    cmp rax, [h2_preface + 8]
    jne .close
    mov rax, [r15 + 16]
    cmp rax, [h2_preface + 16]
    jne .close
    add r12, 24
    mov qword [rbx + linnea_connection.h2_state], LINNEA_H2_RUNNING

.frames:
    mov rax, r14
    sub rax, r12
    cmp rax, 9                       ; a frame header present?
    jb .flush
    ; leave room for one max response frame (17 bytes) before the buffer end
    lea rcx, [r13 + 32]
    lea rdx, [rbx + linnea_connection.out_buf + LINNEA_CONN_OUT_BUF]
    cmp rcx, rdx
    ja .flush                        ; out full: flush, resume next round
    lea rsi, [r15 + r12]             ; frame header
    movzx eax, byte [rsi]            ; length (24-bit)
    shl eax, 16
    movzx ecx, byte [rsi + 1]
    shl ecx, 8
    or eax, ecx
    movzx ecx, byte [rsi + 2]
    or eax, ecx
    ; RFC 9113 4.2: a frame larger than SETTINGS_MAX_FRAME_SIZE is a
    ; FRAME_SIZE_ERROR. We advertise no MAX_FRAME_SIZE, so the protocol default
    ; of 2^14 is what a peer must respect — but the bound here was the input
    ; buffer (17399), so a thousand bytes over the limit we publish were
    ; accepted anyway. Judged against what we advertise, not what we can hold.
    cmp eax, LINNEA_H2_MAX_FRAME
    ja .goaway_frame_size
    lea rcx, [rax + 9]               ; whole frame size
    mov rdx, r14
    sub rdx, r12
    cmp rdx, rcx
    jb .flush                        ; wait for the rest of the frame
    mov r11, rcx                     ; frame size
    movzx r9d, byte [rsi + 3]        ; type
    movzx r10d, byte [rsi + 4]       ; flags
    ; RFC 9113 3.4: the client's connection preface is the magic string AND a
    ; SETTINGS frame, and "clients and servers MUST treat an invalid connection
    ; preface as a connection error of type PROTOCOL_ERROR". Only the magic
    ; string was checked, so a client could open with anything at all and be
    ; served — including a peer that is not speaking HTTP/2 but happens to
    ; start with those 24 bytes.
    cmp qword [rbx + linnea_connection.h2_saw_settings], 0
    jne .f_dispatch
    cmp r9d, LINNEA_H2_FT_SETTINGS
    jne .goaway_close
    mov qword [rbx + linnea_connection.h2_saw_settings], 1
.f_dispatch:
    cmp r9d, LINNEA_H2_FT_SETTINGS
    je .f_settings
    cmp r9d, LINNEA_H2_FT_PING
    je .f_ping
    cmp r9d, LINNEA_H2_FT_GOAWAY
    je .f_goaway
    cmp r9d, LINNEA_H2_FT_WINDOW_UPDATE
    je .f_window
    cmp r9d, LINNEA_H2_FT_RST_STREAM
    je .f_rst
    cmp r9d, LINNEA_H2_FT_PRIORITY
    je .f_priority
    cmp r9d, LINNEA_H2_FT_DATA
    je .f_data                       ; a request body (proxying) or dropped
    cmp r9d, LINNEA_H2_FT_HEADERS
    je .f_headers
    cmp r9d, LINNEA_H2_FT_PUSH_PROMISE
    je .goaway_close                 ; RFC 9113 8.4: a client MUST NOT push
    cmp r9d, LINNEA_H2_FT_CONTINUATION
    je .goaway_close                 ; not preceded by HEADERS: a protocol error
    ; RFC 9113 4.1: an unknown or unsupported frame type MUST be discarded, not
    ; treated as an error. Extensions are negotiated per-frame-type, so a peer
    ; is entitled to send one unannounced — and clients that grease their frame
    ; types, or send PRIORITY_UPDATE (0x10), were having the connection closed
    ; on them for conforming behaviour.
    jmp .f_ignore
.f_window:
    ; WINDOW_UPDATE: grow the connection window (stream 0) or a streaming
    ; response's window. A zero increment is a protocol error.
    cmp r11, 13                      ; exactly 4 payload bytes (RFC 9113 6.9);
    jne .goaway_frame_size           ; else the read below runs past the frame
    mov eax, [rsi + 9]
    bswap eax
    and eax, 0x7fffffff              ; 31-bit increment (top bit reserved)
    movzx edx, byte [rsi + 5]        ; target stream id
    and edx, 0x7f
    shl edx, 8
    movzx ecx, byte [rsi + 6]
    or edx, ecx
    shl edx, 8
    movzx ecx, byte [rsi + 7]
    or edx, ecx
    shl edx, 8
    movzx ecx, byte [rsi + 8]
    or edx, ecx
    ; RFC 9113 6.9: an increment of 0 is a STREAM error of type PROTOCOL_ERROR;
    ; only one on the connection window is a connection error. The zero test
    ; used to run before the id was even parsed, so a single misbehaving stream
    ; took down every concurrent stream sharing the connection.
    test eax, eax
    jnz .f_window_nonzero
    test edx, edx
    jz .goaway_close                 ; on the connection window: 6.9 says fatal
    jmp .f_window_rst                ; on a stream: reset that stream alone
.f_window_nonzero:
    test edx, edx
    jnz .f_window_stream
    ; RFC 9113 6.9.1: a flow-control window may not exceed 2^31-1. The spec
    ; lets us end the stream or the connection "as appropriate"; a peer that
    ; overflows a window is broken or hostile either way, so both cases take
    ; the connection down, as the INITIAL_WINDOW_SIZE check already does.
    ; Signed throughout: a window can legitimately be negative after a
    ; SETTINGS-driven shrink.
    mov rcx, [rbx + linnea_connection.h2_cwnd]
    add rcx, rax
    cmp rcx, 0x7fffffff
    jg .goaway_flow_control          ; RFC 9113 6.9.1: window past 2^31-1
    mov [rbx + linnea_connection.h2_cwnd], rcx
    jmp .f_ignore
.f_window_rst:
    ; RST_STREAM(PROTOCOL_ERROR) for the offending stream, then straight on to
    ; the next frame. The 13 bytes fit inside the 32 the loop reserves at the
    ; top of every iteration, so this cannot run past out_buf however many bad
    ; WINDOW_UPDATEs arrive.
    mov byte [r13], 0
    mov byte [r13 + 1], 0
    mov byte [r13 + 2], 4
    mov byte [r13 + 3], LINNEA_H2_FT_RST_STREAM
    mov byte [r13 + 4], 0
    mov ecx, edx
    shr ecx, 24
    mov [r13 + 5], cl
    mov ecx, edx
    shr ecx, 16
    mov [r13 + 6], cl
    mov ecx, edx
    shr ecx, 8
    mov [r13 + 7], cl
    mov [r13 + 8], dl
    mov dword [r13 + 9], LINNEA_H2_PROTOCOL_ERROR << 24   ; big-endian
    add r13, 13
    jmp .f_ignore
.f_window_stream:
    ; WINDOW_UPDATE on an idle stream (even id, or above the highest opened) is a
    ; connection error (RFC 9113 5.1, Finding 5); on a closed one it is ignored
    ; (it may have been in flight before the stream closed).
    test dl, 1
    jz .goaway_close
    cmp rdx, [rbx + linnea_connection.h2_last_stream]
    ja .goaway_close
    push rax                         ; increment
    mov rdi, rbx
    mov esi, edx
    call h2_slot_find                ; -> rax = slot* or 0
    pop rcx                          ; increment
    test rax, rax
    jz .f_ignore                     ; closed stream: ignore
    mov rdx, [rax + linnea_h2_stream.swnd]
    add rdx, rcx
    cmp rdx, 0x7fffffff
    jg .goaway_flow_control          ; 6.9.1 allows ending the connection for
                                     ; this, so long as the code says why
    mov [rax + linnea_h2_stream.swnd], rdx
    jmp .f_ignore
.f_rst:
    ; RFC 9113 6.4: "A RST_STREAM frame with a length other than 4 octets MUST
    ; be treated as a connection error of type FRAME_SIZE_ERROR." Unchecked, so
    ; a short one had its error code read from whatever followed it in the
    ; buffer — the next frame's header, or a stale tail.
    cmp r11, 13                      ; 9-byte header + 4-byte error code
    jne .goaway_frame_size
    ; RST_STREAM: drop the stream's slot. Rate-based rapid-reset guard
    ; (CVE-2023-44487): resets get a budget of LIMIT plus one token per eight
    ; streams that completed. A reset flood (few/no completions) still trips
    ; at ~LIMIT, but a busy, legitimate connection earns proportional headroom.
    inc qword [rbx + linnea_connection.h2_rst_count]
    mov rax, [rbx + linnea_connection.h2_done_count]
    shr rax, 3                       ; done_count / 8
    add rax, LINNEA_H2_RST_LIMIT
    cmp [rbx + linnea_connection.h2_rst_count], rax
    ja .goaway_calm                  ; RFC 9113 7: ENHANCE_YOUR_CALM is exactly
                                     ; "you are generating excessive load"
    movzx edx, byte [rsi + 5]
    and edx, 0x7f
    shl edx, 8
    movzx ecx, byte [rsi + 6]
    or edx, ecx
    shl edx, 8
    movzx ecx, byte [rsi + 7]
    or edx, ecx
    shl edx, 8
    movzx ecx, byte [rsi + 8]
    or edx, ecx
    ; RST_STREAM on stream 0 is a connection error (RFC 9113 6.4). It must not
    ; reach h2_slot_find: id 0 is the free-slot marker, so a lookup for 0 would
    ; return a freed slot and munmap its stale file_base a second time.
    test edx, edx
    jz .goaway_close
    ; RST_STREAM on an idle stream (even id, or above the highest opened) is a
    ; connection error (RFC 9113 5.1, Finding 5); a late RST on a closed stream
    ; is handled below (its slot lookup simply misses).
    test dl, 1
    jz .goaway_close
    cmp rdx, [rbx + linnea_connection.h2_last_stream]
    ja .goaway_close
    add r12, r11                     ; consume the frame (munmap clobbers r11)
    mov rdi, rbx
    mov esi, edx
    push rdx
    call h2_slot_find
    test rax, rax
    jz .rst_kill
    mov rdi, [rax + linnea_h2_stream.file_base]
    test rdi, rdi
    jz .rst_freed
    push rax
    mov rsi, [rax + linnea_h2_stream.file_size]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    pop rax
.rst_freed:
    mov qword [rax + linnea_h2_stream.id], 0
    mov qword [rax + linnea_h2_stream.file_base], 0   ; no stale mapping to re-free
.rst_kill:
    pop rdx                          ; the reset stream's id
    mov rdi, rbx
    mov esi, edx
    call h2p_kill                    ; drop any proxied exchange with it
    jmp .frames
.f_headers:
    ; Append the response HEADERS at the out cursor; a streaming body (if
    ; any) is registered in a pool slot and interleaved by the scheduler.
    ; Ensure room for a HEADERS (+ small inline error DATA) first.
    lea rax, [rbx + linnea_connection.out_buf + LINNEA_CONN_OUT_BUF]
    sub rax, r13
    cmp rax, LINNEA_H2_RESP_ROOM
    jb .flush                        ; not enough room now; flush and resume
    mov rdi, rbx                     ; conn
    ; rsi already = this frame's header pointer
    mov rdx, r14
    sub rdx, r12                     ; bytes available from the HEADERS frame
    mov rcx, r13                     ; out cursor
    call h2_build_request
    cmp rax, LINNEA_H2_REQ_MORE
    je .flush                        ; block not fully buffered: return MORE
    cmp rax, LINNEA_H2_REQ_ERR
    je .goaway_emit                  ; h2_build_request left the code in
                                     ; h2_goaway_code: do not overwrite it
    add r12, rax                     ; consume the whole HEADERS(+CONT) run
    add r13, rdx                     ; response bytes appended at the cursor
    jmp .frames
.f_data:
    ; A request body. The whole DATA payload, padding included, counts
    ; against flow control. Bytes we drop, or collect whole, are credited
    ; back at once (13 bytes; the frame loop reserved 32). A body being
    ; streamed upstream is credited only once those bytes have actually been
    ; sent — that is what stops a client outrunning the backend, and what
    ; keeps the FIFO within the window we advertised.
    mov [h2_fd_len], eax             ; the payload's flow-control cost
    mov dword [h2_fd_credit], 1
    mov dword [h2_fd_sid], 0         ; set only where the bytes are consumed
    movzx edx, byte [rsi + 5]        ; stream id
    and edx, 0x7f
    shl edx, 8
    movzx ecx, byte [rsi + 6]
    or edx, ecx
    shl edx, 8
    movzx ecx, byte [rsi + 7]
    or edx, ecx
    shl edx, 8
    movzx ecx, byte [rsi + 8]
    or edx, ecx
    test edx, edx
    jz .goaway_close                 ; DATA on stream 0 (RFC 9113 6.1): there is
                                     ; no stream to carry a body, and id 0 is
                                     ; also our free-slot marker
    ; DATA on an idle stream -- an even id, or one above the highest we have
    ; opened -- is a connection error (RFC 9113 5.1/5.1.1, Finding 5). A closed
    ; stream (id already opened, no live slot) is dropped below with its credit.
    test dl, 1
    jz .goaway_close
    cmp rdx, [rbx + linnea_connection.h2_last_stream]
    ja .goaway_close
    lea rcx, [rsi + 9]               ; payload, minus any padding
    test r10b, LINNEA_H2_FLAG_PADDED
    jz .fd_nopad
    test eax, eax
    jz .goaway_frame_size            ; PADDED but no room for the pad length:
                                     ; RFC 9113 4.2, too small for mandatory data
    movzx r8d, byte [rcx]
    inc rcx
    dec eax
    sub eax, r8d
    js .goaway_close                 ; padding exceeds the payload
.fd_nopad:
    push rax                         ; payload length
    push rcx                         ; payload ptr
    push r10                         ; flags
    push r11                         ; frame size
    mov rdi, rbx
    mov esi, edx
    call h2p_find_collect            ; -> rax = collecting slot* or 0
    mov rdi, rax
    pop r11
    pop r10
    pop rcx
    pop rax
    test rdi, rdi
    jz .fd_done                      ; nobody is collecting: dropped
    jmp .fd_collect                  ; over .fd_short, which only jumps reach
.fd_short:
    ; RFC 9113 8.1.1: content-length that does not equal the sum of the DATA
    ; payloads is malformed. END_STREAM was not looked at here at all, so a body
    ; that stopped short simply never completed — the request waited, holding an
    ; upstream slot, until the body clock timed it out at 408. Failing it now
    ; says what actually happened, and frees the slot at once.
    mov qword [rdi + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [rdi + linnea_h2p.status], 400
    jmp .fd_done
.fd_collect:
    mov r8, [rdi + linnea_h2p.len]
    ; max_body is the cap, and now the ONLY one. A body with no Content-Length
    ; is collected and measured here, so this is the only place its size is
    ; ever judged. Subtraction-before-addition (Finding 2): compare the incoming
    ; length against the headroom rather than adding first and comparing the sum,
    ; so a length near 2^64 cannot wrap the counter past a max_body of 2^64-1.
    ; r8 (current) <= max_body holds, so max_body - r8 does not underflow.
    push rcx
    lea rcx, [linnea_config_instance]
    mov rcx, [rcx + linnea_config.max_body]
    sub rcx, r8                        ; headroom = max_body - current
    cmp rax, rcx                       ; incoming > headroom?
    pop rcx
    ja .fd_toobig
    lea r9, [r8 + rax]                 ; now safe from wrap: the running total
    ; Past the slot buffer the body goes to a capture file, the way h1 and h3
    ; already do, instead of being refused. It used to stop at
    ; LINNEA_H2P_BODY_MAX whatever max_body said — 8 KiB — which caught every
    ; h2 upload that arrived without a usable Content-Length, and every second
    ; CONCURRENT upload on one connection, since the streaming buffer is
    ; per-connection and the loser falls back to here.
    cmp r9, LINNEA_H2P_BODY_MAX
    ja .fd_spill
    cmp dword [rdi + linnea_h2p.rq_fd], -1
    jne .fd_spill                    ; already spilling: everything goes to it
    ; append at buf[BODY_OFF + len)
    mov rsi, rcx
    lea rdx, [rdi + linnea_h2p.buf + LINNEA_H2P_BODY_OFF]
    add rdx, r8
    mov [rdi + linnea_h2p.len], r9
    push rdi
    push r10
    push r11
    mov rcx, rax
    mov rdi, rdx
    rep movsb
    pop r11
    pop r10
    pop rdi
.fd_end_check:
    ; Pay the body clock forward for these bytes. h2p_service ages a collecting
    ; slot against rq_start and fails it 408 once it falls further behind than
    ; the head deadline, so a client trickling a declared body cannot hold a
    ; slot for ever. The streaming path did this and the collect path did not,
    ; because collecting used to be the bounded 8 KiB fallback where no clock
    ; was worth keeping; it is now the only path, and carries the whole of
    ; max_body. h2_fd_len, not rax: the spill arm returns h2p_capture's status
    ; in rax, and the wire cost is what the deadline is denominated in anyway.
    ; No clock READ here — rcx and r11 hold live frame state (see .fd_done).
    ; r8 and r9 are dead here: .fd_collect's copies of len and the new total are
    ; finished with, and everything below reloads what it needs.
    mov r9d, [h2_fd_len]             ; this frame's wire cost, kept for credit
    mov r8, r9
    imul r8, r8, LINNEA_BODY_NS_PER_BYTE
    add [rdi + linnea_h2p.rq_start], r8
    ; The payload is consumed — buffered in the slot or written to the capture
    ; file — so the STREAM window can be given back, not only the connection
    ; window. Crediting stream 0 alone was enough while a collected body could
    ; not exceed 8 KiB; with the cap lifted to max_body the client ran out of
    ; stream window at exactly SETTINGS_INITIAL_WINDOW_SIZE and waited for
    ; ever. Measured before the fix: 4 MiB sent, 0 bytes of stream credit
    ; returned, 8.4 MB of connection credit returned.
    ;
    ; BATCHED, at LINNEA_H2P_GRANT_MIN, which is the whole reason that constant
    ; exists. Crediting every frame is what a path carrying only 8 KiB could
    ; afford; once every upload came through here it meant two WINDOW_UPDATE
    ; frames per DATA frame, and each batch of them is a send, a TLS record and
    ; a packet on a worker that also owns other connections. Measured on one
    ; 20 MB upload: 2443 frames in 1224 sends, against 157 in 81 for the
    ; streaming path this replaced — 15x the chatter, charged to every
    ; connection that worker holds, which is how an h2 upload came to slow down
    ; h3 requests and a WebSocket that had nothing to do with it.
    ;
    ; Withholding cannot stall the client: GRANT_MIN is smaller than the window
    ; it tops up (asserted where they are defined), so there is always room left
    ; to send into, and END_STREAM below flushes whatever is left over.
    add [rdi + linnea_h2p.rq_credit], r9
    mov r8, [rdi + linnea_h2p.rq_credit]
    cmp r8, LINNEA_H2P_GRANT_MIN
    jae .fd_credit_now
    test r10b, LINNEA_H2_FLAG_END_STREAM
    jnz .fd_credit_now               ; last frame: nothing more will trip it
    mov dword [h2_fd_credit], 0      ; held back, and owed on the slot
    jmp .fd_end_stream_check
.fd_credit_now:
    mov [h2_fd_len], r8d             ; the batch, not this frame
    mov qword [rdi + linnea_h2p.rq_credit], 0
.fd_end_stream_check:
    mov eax, [rdi + linnea_h2p.sid]
    mov [h2_fd_sid], eax
    test r10b, LINNEA_H2_FLAG_END_STREAM
    jz .fd_done                      ; more body to come
    ; ...and what arrived must be what was declared, when a length was given.
    ; This path measures the body and forwards its own count, so a mismatch used
    ; to be silently rewritten rather than refused.
    test qword [rdi + linnea_h2p.flags], LINNEA_H2P_F_HAS_CL
    jz .fd_finalize                  ; no content-length: nothing to reconcile
    mov r8, [rdi + linnea_h2p.rq_declared]
    cmp r8, [rdi + linnea_h2p.len]
    jne .fd_short
.fd_finalize:
    push r11
    call h2p_finalize                ; body complete: terminate and connect
    pop r11
    jmp .fd_done
.fd_spill:
    ; rdi = slot, rax = payload length, rcx = payload, r9 = the new total.
    ; h2p_capture takes the write offset from slot.len and moves the buffered
    ; prefix in on its first call, so len is updated only AFTER it returns.
    push rdi
    push r10
    push r11
    push r9
    mov rsi, rcx
    mov rdx, rax
    call h2p_capture
    pop r9
    pop r11
    pop r10
    pop rdi
    test eax, eax
    js .fd_capture_failed
    mov [rdi + linnea_h2p.len], r9
    jmp .fd_end_check
.fd_capture_failed:
    ; the upload was fine and it was we who could not hold it: 500, not the
    ; 413 that would blame the client for our full filesystem
    mov qword [rdi + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [rdi + linnea_h2p.status], 500
    jmp .fd_done
.fd_toobig:
    ; more than we will forward without a length to declare: the exchange
    ; fails with a 413, which the service emits
    mov qword [rdi + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [rdi + linnea_h2p.status], 413
.fd_done:
    cmp dword [h2_fd_credit], 0
    je .f_ignore
    mov eax, [h2_fd_len]
    test eax, eax
    jz .f_ignore
    mov byte [r13], 0
    mov byte [r13 + 1], 0
    mov byte [r13 + 2], 4
    mov byte [r13 + 3], LINNEA_H2_FT_WINDOW_UPDATE
    mov byte [r13 + 4], 0
    mov dword [r13 + 5], 0           ; stream 0: the connection window
    mov ecx, eax
    bswap ecx
    mov [r13 + 9], ecx
    add r13, 13
    ; ...and the same amount on the stream itself, when a slot consumed the
    ; payload. Two frames is 26 bytes of the 32 the frame loop reserves.
    cmp dword [h2_fd_sid], 0
    je .f_ignore
    mov byte [r13], 0
    mov byte [r13 + 1], 0
    mov byte [r13 + 2], 4
    mov byte [r13 + 3], LINNEA_H2_FT_WINDOW_UPDATE
    mov byte [r13 + 4], 0
    mov ecx, [h2_fd_sid]
    bswap ecx                        ; the reserved bit is clear: sid < 2^31
    mov [r13 + 5], ecx
    mov ecx, eax
    bswap ecx
    mov [r13 + 9], ecx
    add r13, 13
.f_ignore:
    add r12, r11
    jmp .frames
.f_priority:
    ; RFC 9113 6.3: a PRIORITY frame is exactly 5 octets and never on stream 0.
    ; We do not act on it (RFC 9218 carries priority instead), but a malformed
    ; one is still rejected: a wrong length is a FRAME_SIZE_ERROR (4.2 permits a
    ; connection error for it) and stream 0 is a PROTOCOL_ERROR.
    cmp r11, 14                      ; 9-byte header + 5-byte payload
    jne .goaway_frame_size
    mov eax, [rsi + 5]
    bswap eax
    and eax, 0x7fffffff
    test eax, eax
    jz .goaway_close                 ; stream 0
    jmp .f_ignore
.f_settings:
    ; RFC 9113 6.5: "If an endpoint receives a SETTINGS frame whose Stream
    ; Identifier field is anything other than 0x00, the endpoint MUST respond
    ; with a connection error of type PROTOCOL_ERROR." The field was read for
    ; DATA, HEADERS and RST_STREAM but ignored here and on PING, so a frame that
    ; belongs to the connection was accepted while claiming a stream.
    mov eax, [rsi + 5]
    bswap eax
    and eax, 0x7fffffff
    jnz .goaway_close
    test r10b, LINNEA_H2_FLAG_ACK
    jnz .f_settings_ack
    ; parse the settings entries [rsi+9 .. rsi+r11) — honour
    ; SETTINGS_INITIAL_WINDOW_SIZE; the length must be a multiple of 6.
    lea rax, [rsi + 9]               ; entry cursor
    lea rcx, [rsi + r11]             ; frame end
.set_loop:
    mov rdx, rcx
    sub rdx, rax
    jz .set_done
    cmp rdx, 6
    jb .goaway_frame_size            ; RFC 9113 6.5: not a multiple of 6
    movzx edx, byte [rax]            ; setting id (16-bit)
    shl edx, 8
    movzx r8d, byte [rax + 1]
    or edx, r8d
    mov r9d, edx                     ; the setting id, across the value decode
    movzx r8d, byte [rax + 2]        ; value (32-bit, big-endian), decoded for
    shl r8d, 8                       ; every setting now: 6.5.2 bounds three
    movzx edx, byte [rax + 3]
    or r8d, edx
    shl r8d, 8
    movzx edx, byte [rax + 4]
    or r8d, edx
    shl r8d, 8
    movzx edx, byte [rax + 5]
    or r8d, edx
    ; RFC 9113 6.5.2 gives three settings a legal range, and only one of them
    ; was checked. A value outside the other two was accepted in silence, which
    ; is the peer being told its configuration was understood when it was not.
    cmp r9d, LINNEA_H2_SETTINGS_ENABLE_PUSH
    je .set_push
    cmp r9d, LINNEA_H2_SETTINGS_MAX_FRAME_SIZE
    je .set_maxframe
    cmp r9d, LINNEA_H2_SETTINGS_INITIAL_WINDOW_SIZE
    jne .set_next
    cmp r8d, 0x7fffffff
    ja .goaway_flow_control          ; RFC 9113 6.5.2: above 2^31-1
    push rax
    push rcx
    mov rdi, rbx
    mov esi, r8d
    call h2_apply_init_window        ; adjust init window + open streams
    pop rcx
    pop rax
    jmp .set_next
.set_push:
    cmp r8d, 1                       ; 6.5.2: "any value other than 0 or 1"
    ja .goaway_close
    jmp .set_next
.set_maxframe:
    cmp r8d, 16384                   ; 6.5.2: 2^14 .. 2^24-1 inclusive
    jb .goaway_close
    cmp r8d, 16777215
    ja .goaway_close
.set_next:
    add rax, 6
    jmp .set_loop
.set_done:
    mov dword [r13], 0x04000000      ; SETTINGS ACK, length 0
    mov byte [r13 + 4], LINNEA_H2_FLAG_ACK
    mov dword [r13 + 5], 0
    add r13, 9
    add r12, r11
    jmp .frames
.f_settings_ack:
    cmp r11, 9                       ; a SETTINGS ACK must carry no payload
    jne .goaway_frame_size           ; RFC 9113 6.5
    add r12, r11
    jmp .frames
.f_ping:
    cmp r11, 17                      ; PING carries exactly 8 bytes (RFC 9113 6.7);
    jne .goaway_frame_size           ; else the echo below reads past the frame and
                                     ; returns 8 stale in_buf bytes to the peer
    mov eax, [rsi + 5]               ; 6.7: a PING naming a stream is a
    bswap eax                        ; connection error, as for SETTINGS
    and eax, 0x7fffffff
    jnz .goaway_close
    test r10b, LINNEA_H2_FLAG_ACK
    jnz .f_ignore
    mov byte [r13], 0                ; PING ACK: length 8
    mov byte [r13 + 1], 0
    mov byte [r13 + 2], 8
    mov byte [r13 + 3], LINNEA_H2_FT_PING
    mov byte [r13 + 4], LINNEA_H2_FLAG_ACK
    mov dword [r13 + 5], 0
    mov rax, [rsi + 9]               ; echo the 8-byte opaque payload
    mov [r13 + 9], rax
    add r13, 17
    add r12, r11
    jmp .frames
.f_goaway:
    ; RFC 9113 6.8: GOAWAY is only ever on stream 0 and carries at least the
    ; 8-byte last-stream-id + error-code. A nonzero stream is a PROTOCOL_ERROR,
    ; a short one a FRAME_SIZE_ERROR -- otherwise a truncated or misdirected
    ; GOAWAY silently put the connection into a graceful drain.
    mov eax, [rsi + 5]
    bswap eax
    and eax, 0x7fffffff
    test eax, eax
    jnz .goaway_close                ; GOAWAY on a nonzero stream
    cmp r11, 17                      ; 9-byte header + 8 mandatory payload bytes
    jb .goaway_frame_size
    ; GOAWAY says the peer will open no NEW streams — it does not
    ; abandon the ones already running, and "allows an endpoint to gracefully
    ; stop accepting new streams while still finishing processing of previously
    ; established streams". Closing the connection here threw away a response
    ; that was already in flight (h2-14). Put the connection in the same
    ; DRAINING state the worker-drain path uses: new streams are refused there
    ; already, and linnea_h2_after_send closes once the stream pool empties.
    ; Keep walking the buffer — frames for the open streams may follow this one.
    add r12, r11
    mov qword [rbx + linnea_connection.h2_state], LINNEA_H2_DRAINING
    jmp .frames
; Typed entries to the GOAWAY below. RFC 9113 names a specific code for most of
; these faults, and every one of them used to arrive here as PROTOCOL_ERROR
; because the reason was not threaded through. It matters on the wire: a peer
; that reads FRAME_SIZE_ERROR knows its framing is wrong, where PROTOCOL_ERROR
; sends it looking at its request semantics.
.goaway_frame_size:
    mov dword [h2_goaway_code], LINNEA_H2_FRAME_SIZE_ERROR
    jmp .goaway_emit
.goaway_flow_control:
    mov dword [h2_goaway_code], LINNEA_H2_FLOW_CONTROL_ERR
    jmp .goaway_emit
.goaway_compression:
    mov dword [h2_goaway_code], LINNEA_H2_COMPRESSION_ERR
    jmp .goaway_emit
.goaway_calm:
    mov dword [h2_goaway_code], LINNEA_H2_ENHANCE_CALM
    jmp .goaway_emit
.goaway_close:
    ; Queue GOAWAY and close once it is sent. Every jump here is a protocol
    ; fault, so the code must not be NO_ERROR: a conforming peer reads that as
    ; a graceful shutdown, retries the offending request on a fresh connection
    ; and — since the fault is deterministic — never stops. It also left real
    ; faults indistinguishable from an orderly close in a capture.
    ; This is the PROTOCOL_ERROR entry; the typed ones are above.
    mov dword [h2_goaway_code], LINNEA_H2_PROTOCOL_ERROR
.goaway_emit:
    mov byte [r13], 0
    mov byte [r13 + 1], 0
    mov byte [r13 + 2], 8
    mov byte [r13 + 3], LINNEA_H2_FT_GOAWAY
    mov byte [r13 + 4], 0
    mov dword [r13 + 5], 0
    ; The last stream id must be the highest we might have acted on (RFC 9113
    ; 6.8). This said 0, which claims we processed nothing — so a client is
    ; entitled to retry every request in flight, including a proxied POST the
    ; upstream has already executed. Reporting the highest id we have seen is
    ; also the safe direction to be wrong in: too high merely costs a request a
    ; retry it could have had, while too low duplicates non-idempotent work.
    ; h2_last_stream is stamped before the malformed-request checks, so a stream
    ; whose own fault caused this is included, which is what we want.
    mov rcx, [rbx + linnea_connection.h2_last_stream]
    mov rdx, rcx
    shr rcx, 24
    mov [r13 + 9], cl
    mov rcx, rdx
    shr rcx, 16
    mov [r13 + 10], cl
    mov rcx, rdx
    shr rcx, 8
    mov [r13 + 11], cl
    mov [r13 + 12], dl
    mov ecx, [h2_goaway_code]
    bswap ecx
    mov [r13 + 13], ecx              ; error code, big-endian
    add r13, 17
    mov qword [rbx + linnea_connection.h2_state], LINNEA_H2_CLOSING

.flush:
    mov rax, r14                     ; compact in_buf to the unconsumed tail
    sub rax, r12
    mov [rbx + linnea_connection.in_len], rax
    test r12, r12
    jz .no_compact
    test rax, rax
    jz .no_compact
    lea rsi, [r15 + r12]
    mov rdi, r15
    mov rcx, rax
    rep movsb
.no_compact:
    lea rax, [rbx + linnea_connection.out_buf]
    mov rcx, r13
    sub rcx, rax                     ; out length
    test rcx, rcx
    jz .no_out
    mov [rbx + linnea_connection.out_ptr], rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov qword [rbx + linnea_connection.file_rem], 0
    mov qword [rbx + linnea_connection.h2_tx_busy], 1
    mov eax, LINNEA_H2_SEND
    jmp .ret
.no_out:
    ; nothing queued this round: the shared idle decision streams the next
    ; ready DATA frame (a WINDOW_UPDATE may have unblocked one) or, while
    ; draining, drives the GOAWAY / finish-then-close sequence.
    mov rdi, rbx
    call linnea_h2_after_send        ; -> SEND (out set) / MORE / CLOSE
    jmp .ret
.more:
    mov eax, LINNEA_H2_MORE
    jmp .ret
.close:
    mov eax, LINNEA_H2_CLOSE
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; --- HTTP/2 request assembly (M16) ---------------------------------------
; h2_build_request(rdi=conn, rsi=first frame header (HEADERS), rdx=avail)
;   -> rax = bytes consumed (whole HEADERS + CONTINUATION run)
;          | LINNEA_H2_REQ_MORE  (-1): header block not fully buffered yet
;          | LINNEA_H2_REQ_ERR   (-2): malformed -> connection error
;   on success, rdx = response length written at conn.out_buf.
;
; Reassembles the header block (stripping HEADERS padding/priority and any
; CONTINUATION frames) into the connection's h2_hb_pool area, HPACK-decodes
; it, and writes a minimal
; 200 response — HEADERS(:status 200) + DATA echoing the decoded method and
; path — into out_buf. The echo proves the decode end to end; M17 replaces
; it with the real static/proxy response path and HPACK encoder.
;
; Stack locals: the req struct occupies [rsp+REQ, rsp+REQ+linnea_h2_req_size), the
; rest follow it. Deriving the offsets from linnea_h2_req_size (rather than hard-
; coding them) keeps a later field added to the struct from silently overwriting a
; local — e.g. the RFC 9218 `priority` fields once clobbered L_SID (the stream id),
; so a `priority` header from a browser broke every h2 request.
%define REQ      0
%define L_START  linnea_h2_req_size
%define L_SID    linnea_h2_req_size + 8
%define L_CONT   linnea_h2_req_size + 16
%define L_OUT    linnea_h2_req_size + 24
%define L_BIG    linnea_h2_req_size + 32
%define L_ASM    linnea_h2_req_size + 40
%if L_ASM + 8 > 600
  %error "h2_build_request stack frame (sub rsp,600) too small for req + locals"
%endif
h2_build_request:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    ; 600, not a round 592: six pushes leave rsp 8 past a 16-byte boundary, so an
    ; even frame would hand every callee a misaligned stack. Nothing under here
    ; uses an aligned SSE load today, so this was a trap rather than a crash — but
    ; it is one movaps away from being a crash, and the AES paths are close by.
    ; It grew from 392 when the request struct took a .cl_val; the %error above
    ; is what says so, rather than a local being silently overwritten.
    sub rsp, 600
    mov rbx, rdi                     ; conn
    mov [rsp + L_OUT], rcx           ; out cursor (where the response goes)
    mov [rsp + L_START], rsi
    lea r13, [rsi + rdx]             ; avail end
    mov r12, rsi                     ; current frame header
    mov r14, [rbx + linnea_connection.index]
    imul r14, r14, LINNEA_H2_HB_AREA
    add r14, [h2_hb_pool]                            ; this connection's area
    mov [rsp + L_ASM], r14
    lea r15, [r14 + LINNEA_H2_HB_ASM]                ; assembly limit
    mov qword [rsp + L_CONT], 0
    mov qword [rsp + L_BIG], 0

.frame_loop:
    mov rax, r13
    sub rax, r12
    cmp rax, 9
    jb .more                         ; a whole frame header not present yet
    movzx ecx, byte [r12]            ; payload length L
    shl ecx, 16
    movzx edx, byte [r12 + 1]
    shl edx, 8
    or ecx, edx
    movzx edx, byte [r12 + 2]
    or ecx, edx
    lea rdx, [rcx + 9]               ; whole frame size
    mov rax, r13
    sub rax, r12
    cmp rax, rdx
    jb .more                         ; wait for the rest of the frame
    cmp ecx, LINNEA_H2_MAX_FRAME
    ja .err_size                     ; RFC 9113 4.2: over the frame size limit we
                                     ; advertise (was the input buffer, ~1 KiB
                                     ; larger, so an oversized CONTINUATION that
                                     ; the outer loop never sees slipped through)
    movzx r9d, byte [r12 + 3]        ; type
    movzx r10d, byte [r12 + 4]       ; flags
    cmp qword [rsp + L_CONT], 0
    jne .cont_frame

    ; --- first frame: the HEADERS frame --------------------------------
    movzx r8d, byte [r12 + 5]        ; stream id (31-bit, big-endian)
    and r8d, 0x7f
    shl r8d, 8
    movzx eax, byte [r12 + 6]
    or r8d, eax
    shl r8d, 8
    movzx eax, byte [r12 + 7]
    or r8d, eax
    shl r8d, 8
    movzx eax, byte [r12 + 8]
    or r8d, eax
    test r8d, r8d
    jz .err                          ; HEADERS on stream 0 is illegal
    mov [rsp + L_SID], r8
    mov eax, r10d                    ; the HEADERS frame's END_STREAM flag:
    and eax, LINNEA_H2_FLAG_END_STREAM   ; a request with no body to come
    mov [h2_req_es], eax
    lea rsi, [r12 + 9]               ; payload start
    mov r11d, ecx                    ; fragment length (= L, trimmed below)
    test r10b, LINNEA_H2_FLAG_PADDED
    jz .no_pad
    test r11d, r11d
    jz .err_size                     ; PADDED with no room for the pad length:
                                     ; RFC 9113 4.2, too small for mandatory data
    movzx edx, byte [rsi]            ; pad length
    inc rsi
    dec r11d
    sub r11d, edx
    js .err                          ; padding exceeds the payload
.no_pad:
    test r10b, LINNEA_H2_FLAG_PRIORITY
    jz .append
    cmp r11d, 5
    jb .err_size                     ; PRIORITY set but no room for its 5 bytes
    add rsi, 5                       ; skip the priority fields
    sub r11d, 5
    jmp .append

.cont_frame:
    cmp r9d, LINNEA_H2_FT_CONTINUATION
    jne .err                         ; only CONTINUATION may follow HEADERS
    movzx r8d, byte [r12 + 5]        ; must be the same stream
    and r8d, 0x7f
    shl r8d, 8
    movzx eax, byte [r12 + 6]
    or r8d, eax
    shl r8d, 8
    movzx eax, byte [r12 + 7]
    or r8d, eax
    shl r8d, 8
    movzx eax, byte [r12 + 8]
    or r8d, eax
    cmp r8, [rsp + L_SID]
    jne .err
    lea rsi, [r12 + 9]
    mov r11d, ecx                    ; whole payload is fragment

.append:
    ; advance past this frame before the copy (rep movsb eats rcx = L)
    lea rax, [rcx + 9]
    add r12, rax
    inc qword [rsp + L_CONT]
    test r11d, r11d
    jz .after_append
    mov rax, r15
    sub rax, r14
    cmp r11, rax
    ja .block_big                    ; over the cap: consume the run, then 431
    mov rdi, r14
    mov rcx, r11
    rep movsb                        ; rsi -> rdi
    mov r14, rdi
.after_append:
    test r10b, LINNEA_H2_FLAG_END_HEADERS
    jnz .assembled
    cmp qword [rsp + L_CONT], LINNEA_H2_MAX_CONT
    ja .err_calm                     ; CONTINUATION flood — RFC 9113 7:
                                     ; ENHANCE_YOUR_CALM is the load signal
    jmp .frame_loop

.block_big:
    ; A block too large to hold. The frames are still consumed (nothing is
    ; copied) until END_HEADERS, and the stream is answered 431 at .too_big,
    ; which also decides whether the connection can live on: the block goes
    ; UNDECODED, so any insert it carried entered the peer's dynamic table and
    ; not ours.
    mov qword [rsp + L_BIG], 1
    jmp .after_append

.assembled:
    ; Stream-id rules first (RFC 9113 5.1.1): a client's stream is odd, and
    ; numerically above every stream it has already opened. An id breaking
    ; either says the peer's stream numbering is broken, which is a CONNECTION
    ; error — no per-stream answer can repair it, and the next id is not to be
    ; trusted either. This used to run AFTER the malformed-request checks, so a
    ; malformed request on an EVEN id was answered with a stream reset, and
    ; stamped h2_last_stream with an even number on its way out.
    ; Still checked once the block is whole, so a partial-block retry cannot
    ; double-count the floor; now also before the decode, so a bad id costs
    ; nothing. Every path below is past this, so the floor is stamped once here
    ; rather than again on each of them.
    mov r8, [rsp + L_SID]
    test r8, 1
    jz .err                          ; even id: connection error
    mov qword [h2_req_trail], 0
    ; A HEADERS arriving on a stream that is still taking body bytes is a
    ; TRAILER section (RFC 9113 8.1), not a new request. Its id is one we have
    ; already seen, so the strictly-increasing test below called it broken
    ; numbering and took the WHOLE CONNECTION down — every concurrent stream
    ; with it — for something the RFC explicitly allows. Any client that sends
    ; trailers met that: gRPC-web, a chunked upload declaring its length after
    ; the fact. HTTP/3 has handled trailers since Q134; HTTP/2 did not.
    mov rdi, rbx
    mov esi, r8d
    call h2p_find_collect            ; -> the slot still taking this stream's body
    test rax, rax
    jz .req_new_stream
    mov qword [h2_req_trail], 1
    jmp .req_id_ok
.req_new_stream:
    mov r8, [rsp + L_SID]            ; reload: the probe above owns the registers
    cmp r8, [rbx + linnea_connection.h2_last_stream]
    jbe .err                         ; not strictly increasing
    mov [rbx + linnea_connection.h2_last_stream], r8
.req_id_ok:
    cmp qword [rsp + L_BIG], 0
    jne .too_big
    ; zero the whole req struct — a count derived from the struct size, so a
    ; field added later (like the conditional-request pointers) cannot be left
    ; holding stale stack bytes
    lea rdi, [rsp + REQ]
    xor eax, eax
    mov ecx, linnea_h2_req_size / 8
    rep stosq
    mov rax, [rsp + L_ASM]
    add rax, LINNEA_H2_HB_ASM                        ; scratch follows the block
    mov [rsp + REQ + linnea_h2_req.scratch], rax
    lea rcx, [rax + LINNEA_H2_HB_SCRATCH]
    mov [rsp + REQ + linnea_h2_req.scratch_end], rcx
    mov rdi, rbx                     ; the connection's HPACK dynamic table
    call h2_dyn_for
    mov [rsp + REQ + linnea_h2_req.dyn], rax
    lea rax, [h2_hdrs_buf]           ; proxy header rebuild region
    mov [rsp + REQ + linnea_h2_req.hb_start], rax
    mov [rsp + REQ + linnea_h2_req.hb_cur], rax
    lea rax, [h2_hdrs_buf + 8192]
    mov [rsp + REQ + linnea_h2_req.hb_end], rax
    lea rax, [h2_cookie_buf]         ; split cookie fields join here (Finding 32)
    mov [rsp + REQ + linnea_h2_req.ck_buf], rax
    mov rdi, [rsp + L_ASM]           ; the reassembled block
    mov rsi, r14
    sub rsi, rdi                     ; block length
    lea rdx, [rsp + REQ]
    call linnea_hpack_decode
    test rax, rax
    js .decode_err
    cmp qword [h2_req_trail], 0
    jne .trailer_block
    ; CONNECT is a method we do not implement. Hand it straight to h2_serve, which
    ; declines it with 405 (h2-15); do NOT run req_check first, which would reject
    ; a CONNECT as malformed for omitting :scheme/:path (which it omits by design,
    ; RFC 9113 8.5) and reset the stream. h2-only — the shared req_check and the
    ; h3 path are untouched.
    mov rdi, [rsp + REQ + linnea_h2_req.method_ptr]
    test rdi, rdi
    jz .req_validate
    mov rsi, [rsp + REQ + linnea_h2_req.method_len]
    lea rdx, [method_connect_h2]
    mov ecx, 7
    call linnea_string_equal
    test rax, rax
    jz .req_validate
    ; CONNECT is unsupported (answered 405 at .serve), but RFC 9113 8.5 still
    ; requires it to carry :authority and to omit :scheme and :path; a Host, if
    ; present, must agree with :authority. A nonconforming CONNECT is malformed
    ; -- a stream error -- not an application method choice (Finding 28).
    cmp qword [rsp + REQ + linnea_h2_req.auth_ptr], 0
    je .malformed_stream             ; no :authority
    cmp qword [rsp + REQ + linnea_h2_req.auth_len], 0
    je .malformed_stream             ; empty :authority
    cmp qword [rsp + REQ + linnea_h2_req.scheme_ptr], 0
    jne .malformed_stream            ; :scheme is forbidden with CONNECT
    cmp qword [rsp + REQ + linnea_h2_req.path_ptr], 0
    jne .malformed_stream            ; :path is forbidden with CONNECT
    cmp qword [rsp + REQ + linnea_h2_req.host_count], 1
    ja .malformed_stream             ; more than one Host
    cmp qword [rsp + REQ + linnea_h2_req.host_count], 0
    je .serve                        ; no Host: :authority stands alone
    mov rcx, [rsp + REQ + linnea_h2_req.auth_len]
    cmp rcx, [rsp + REQ + linnea_h2_req.host_len]
    jne .malformed_stream            ; a Host that contradicts :authority
    test rcx, rcx
    jz .serve
    mov rsi, [rsp + REQ + linnea_h2_req.auth_ptr]
    mov rdi, [rsp + REQ + linnea_h2_req.host_ptr]
    repe cmpsb
    jne .malformed_stream
    jmp .serve
.req_validate:
    ; the rules the field-by-field pass cannot see: an authority from one
    ; source or the other, agreeing and plausible
    lea rdi, [rsp + REQ]
    call linnea_hpack_req_check
    test rax, rax
    js .malformed_stream
    cmp qword [rsp + REQ + linnea_h2_req.method_ptr], 0
    je .malformed_stream
    cmp qword [rsp + REQ + linnea_h2_req.path_ptr], 0
    je .malformed_stream
.serve:
    ; One decoded request is one request, which is what rate_limit meters. On a
    ; multiplexed protocol that is very far from what max_per_ip counts: 100
    ; streams may share one connection, so a per-connection cap barely bounds
    ; the request rate at all.
    cmp qword [linnea_ratelimit_on], 0
    je .rl_ok
    call linnea_uring_now            ; clock first: it takes rdi/rsi for the
    mov rdx, rax                     ; syscall and would eat the address
    lea rdi, [rbx + linnea_connection.peer_ip]
    mov rsi, [rbx + linnea_connection.peer_ip_len]
    call linnea_ratelimit_take
    test eax, eax
    jz .rl_ok
    mov rdi, rbx
    mov rsi, [rsp + L_SID]
    mov rdx, [rsp + L_OUT]
    call h2_429_stream               ; -> rax = response length
    mov rdx, rax
    mov rax, r12
    sub rax, [rsp + L_START]         ; bytes consumed
    jmp .ret
.rl_ok:
    ; --- serve the request: write the response at the out cursor --------
    mov rdi, rbx                     ; conn
    lea rsi, [rsp + REQ]             ; decoded request
    mov r8, [rsp + L_SID]            ; stream id
    mov r9, [rsp + L_OUT]            ; out cursor
    call h2_serve                    ; -> rax = bytes written at the cursor
    mov rdx, rax                     ; response length
    mov rax, r12
    sub rax, [rsp + L_START]         ; bytes consumed
    jmp .ret

.trailer_block:
    ; The trailer's fields were decoded for one reason only: HPACK is stateful,
    ; and a block we do not use must still be walked to its end or the dynamic
    ; table desynchronises and every later request on the connection decodes to
    ; nonsense. That is what Q152 settled. Nothing here reaches the request.
    ;
    ; "Pseudo-header fields MUST NOT appear in a trailer section" (8.1), and a
    ; message that breaks that is malformed — a stream error, not a connection
    ; one.
    cmp qword [rsp + REQ + linnea_h2_req.method_ptr], 0
    jne .malformed_stream
    cmp qword [rsp + REQ + linnea_h2_req.path_ptr], 0
    jne .malformed_stream
    cmp qword [rsp + REQ + linnea_h2_req.scheme_ptr], 0
    jne .malformed_stream
    cmp qword [rsp + REQ + linnea_h2_req.auth_ptr], 0
    jne .malformed_stream
    ; The collecting slot for this stream, needed whether the trailer completes
    ; the body or (below) is rejected for lacking END_STREAM.
    mov rdi, rbx
    mov esi, [rsp + L_SID]
    call h2p_find_collect
    test rax, rax
    jz .trailer_ret                  ; no body slot: nothing to end
    ; RFC 9113 8.1 requires END_STREAM on a trailer section, so it is where the
    ; body ends. Without it the body is NOT ended (Finding 4): the old code fell
    ; to .trailer_ret leaving the slot COLLECTING, so a later DATA frame still
    ; appended to it and the request hung to its 408 timeout — and the malformed
    ; trailer earned no error at all. Fail the stream instead: h2p_find_collect
    ; skips a FAILED slot, so no further DATA collects, and 400 is the answer. The
    ; block was already HPACK-decoded above, so compression state stays in sync.
    cmp dword [h2_req_es], 0
    jne .trailer_es
    mov qword [rax + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [rax + linnea_h2p.status], 400
    jmp .trailer_ret
.trailer_es:
    ; A trailer section ends the body, so a declared length is reconciled here
    ; too — the same RFC 9113 8.1.1 check the last DATA frame makes. This path
    ; never had to do it before: a body carrying a Content-Length always
    ; STREAMED, and a streamed upload left through its own completion rather
    ; than through here, so the only bodies that arrived were the ones with
    ; nothing to reconcile. Every body collects now, and without this a short
    ; body followed by trailers would be forwarded with our own measured count
    ; quietly substituted for the count the client declared.
    test qword [rax + linnea_h2p.flags], LINNEA_H2P_F_HAS_CL
    jz .trailer_fin                  ; no content-length: nothing to reconcile
    mov rdx, [rax + linnea_h2p.rq_declared]
    cmp rdx, [rax + linnea_h2p.len]
    je .trailer_fin
    mov qword [rax + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [rax + linnea_h2p.status], 400
    jmp .trailer_ret
.trailer_fin:
    mov rdi, rax
    call h2p_finalize
.trailer_ret:
    xor edx, edx                     ; nothing to write: a trailer has no reply
    mov rax, r12
    sub rax, [rsp + L_START]         ; but the frames are consumed
    jmp .ret

.decode_err:
    ; A request that broke a semantic rule (a repeated or misplaced
    ; pseudo-header) decoded perfectly well — the compression state is intact,
    ; so RFC 9113 8.1.1 wants the STREAM to fail, not the connection.
    cmp qword [rsp + REQ + linnea_h2_req.malformed], 0
    jne .malformed_stream
    ; The decoder's list bound (LINNEA_HPACK_MAX_LISTSIZE — exactly what we
    ; advertise as SETTINGS_MAX_HEADER_LIST_SIZE) is OUR limit, hit by a
    ; conforming block that is simply too big: answer the stream. Everything
    ; else is real HPACK rot and stays a connection error.
    cmp rax, -LINNEA_HPACK_ERR_LIMIT
    jne .err_comp                    ; real HPACK rot: RFC 9113 4.3 names
                                     ; COMPRESSION_ERROR for a decoding failure
.malformed_stream:
    ; RFC 9113 8.1.1: a malformed request is a stream error. The connection
    ; and its HPACK state are fine, so every other stream carries on. The id
    ; was validated and stamped at .assembled, so there is nothing to do here.
    mov rdi, [rsp + L_OUT]
    mov rsi, [rsp + L_SID]
    mov edx, LINNEA_H2_PROTOCOL_ERROR
    call h2p_emit_rst                ; -> rax = bytes written
    mov rdx, rax
    mov rax, r12
    sub rax, [rsp + L_START]         ; bytes consumed
    jmp .ret

.too_big:
    ; Skipping the block is survivable only while OUR table is empty. Empty, a
    ; dynamic reference from the peer can only land out of range, and that is
    ; already a connection error — a loud, safe failure. With entries in the
    ; table the same reference could instead resolve to the WRONG entry and be
    ; served as a request the client never sent, silently. So an unread block
    ; on a connection whose table holds anything ends the connection instead.
    ; This used to note that the table is "in practice always empty", because
    ; we advertised HEADER_TABLE_SIZE 0 and a conforming encoder inserted
    ; nothing. Advertising 4096 (Q153) inverted that: a browser populates the
    ; table on its first request, so from then on a block too big to hold ends
    ; the CONNECTION rather than answering 431 on the stream. That is still the
    ; only safe answer — an unread block leaves our table behind the peer's —
    ; but it is now the common case, not the unreachable one. Reaching it takes
    ; a client that ignores the MAX_HEADER_LIST_SIZE we advertise: a block
    ; within it always fits here, since list size counts 32 more per field than
    ; the wire does.
    mov rdi, rbx
    call h2_dyn_for                  ; -> rax = this connection's table
    cmp qword [rax + linnea_hpack_dyn.count], 0
    jne .err
    mov rdi, rbx
    mov rsi, [rsp + L_SID]
    mov rdx, [rsp + L_OUT]
    call h2_431_stream               ; -> rax = response length
    mov rdx, rax
    mov rax, r12
    sub rax, [rsp + L_START]         ; bytes consumed
    jmp .ret
.more:
    mov rax, LINNEA_H2_REQ_MORE
    jmp .ret
; The reason travels in h2_goaway_code rather than in rax: the caller has one
; error return to check, and each site here names the code RFC 9113 gives it.
.err:
    mov dword [h2_goaway_code], LINNEA_H2_PROTOCOL_ERROR
    mov rax, LINNEA_H2_REQ_ERR
    jmp .ret
.err_size:
    mov dword [h2_goaway_code], LINNEA_H2_FRAME_SIZE_ERROR
    mov rax, LINNEA_H2_REQ_ERR
    jmp .ret
.err_calm:
    mov dword [h2_goaway_code], LINNEA_H2_ENHANCE_CALM
    mov rax, LINNEA_H2_REQ_ERR
    jmp .ret
.err_comp:
    mov dword [h2_goaway_code], LINNEA_H2_COMPRESSION_ERR
    mov rax, LINNEA_H2_REQ_ERR
.ret:
    add rsp, 600
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; =========================================================================
; HTTP/2 response path (M17): serve a static file over h2 with a real HPACK
; encoder and connection/stream flow control. The proven HTTP/1.1 handler is
; left untouched; this is a parallel static path that reuses only the mmap
; syscall pattern. Responses carry the validators (ETag/Last-Modified, via
; the shared linnea_static helpers) plus Date, Server and any configured
; Cache-Control; a conditional request revalidates to a bodiless 304 (Q83);
; a single bytes= range gets a 206 slice, gated by If-Range, with the 416
; fallback (Q84); a pre-compressed .br/.gz beside the file is served when
; Accept-Encoding allows it, with Content-Encoding and Vary (Q85). The h1
; static feature set is fully mirrored; :authority selects the vhost.
; =========================================================================

; h2_serve(rdi=conn, rsi=req, r8=stream_id, r9=out cursor)
;   -> rax = bytes written at the out cursor.
; Writes the response HEADERS (and, for errors, an inline DATA) at the cursor.
; A 200 with a body allocates a pool slot recording the body-send state, which
; the round-robin scheduler (h2_schedule) then streams as interleaved DATA; the
; return value is only the HEADERS bytes. If the pool is full, the stream is
; refused with RST_STREAM instead.
%define S_SID   0
%define S_HEAD  8
%define S_DIR   16
%define S_LOC   24
%define S_JOIN  32
%define S_BASE  40
%define S_SIZE  48
%define S_MIME  56
%define S_MLEN  64
%define S_CLEN  72
%define S_STAT  80
%define S_OUT   88
%define S_ROFF  96              ; range offset into the file (0 when unranged)
%define S_RLEN  104             ; bytes to send (the range's, or the whole file's)
%define S_CRLEN 112             ; content-range value length (0 = not a 206)
%define S_ENC   120             ; coding served (0 plain, 1 gzip, 2 br)
%define S_LSTAT 128             ; access log: numeric status (0 = do not log)
%define S_LBYTES 136            ; access log: body bytes
%define S_COND  144             ; cursor over the If-Match/If-None-Match spans
; h2_data_window_take(rdi = conn, rsi = body length) -> rax = 1 when the body may
; go out now, 0 when it must be withheld. Debits the connection window on success.
;
; RFC 9113 6.9.1 MUST NOT: a sender must not send a flow-controlled frame carrying
; more than the receiver has advertised room for. The inline bodies — the 4xx and
; 5xx pages, the 431, the proxy's own errors — wrote their DATA straight at the
; out cursor and were charged against nothing at all. Two things followed. A peer
; advertising a zero window was sent one anyway, which is the standard h2spec
; 6.9.1 failure. And on a long-lived connection the server's idea of the
; connection window drifted above the peer's real one by the sum of every error
; body it had ever sent, until the peer — counting honestly — closed with
; FLOW_CONTROL_ERROR.
;
; These streams never take a pool slot, so nothing has gone out on them and their
; stream window is still exactly the peer's advertised initial value. Both windows
; are checked signed: h2_cwnd legitimately goes negative when the peer shrinks
; SETTINGS_INITIAL_WINDOW_SIZE under data already in flight.
h2_data_window_take:
    test rsi, rsi
    jz .dw_yes                        ; an empty body consumes no window at all
    mov rax, [rdi + linnea_connection.h2_cwnd]
    cmp rax, rsi
    jl .dw_no
    mov rax, [rdi + linnea_connection.h2_init_swnd]
    cmp rax, rsi
    jl .dw_no
    sub [rdi + linnea_connection.h2_cwnd], rsi
.dw_yes:
    mov eax, 1
    ret
.dw_no:
    xor eax, eax
    ret

h2_serve:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 152
    mov rbx, rdi                     ; conn
    mov qword [rsp + S_LSTAT], 0     ; paths that answer set these; a stream
    mov qword [rsp + S_LBYTES], 0    ; refused with RST logs nothing
    mov r12, rsi                     ; req
    mov [rsp + S_SID], r8
    mov [rsp + S_OUT], r9            ; where the response is written
    ; draining: GOAWAY already went out, refuse this new stream
    cmp qword [rbx + linnea_connection.h2_state], LINNEA_H2_DRAINING
    je .drain_refuse
    ; more If-Match/If-None-Match lines than can be combined: answered before
    ; anything is routed or opened, so a proxy location cannot forward a list
    ; with a member missing either (audit-report-31)
    cmp qword [r12 + linnea_h2_req.list_over], 0
    jne .list_over_431
    ; CONNECT: a registered method we do not implement (no tunnels). Decline with
    ; 405 before any :path handling — a CONNECT carries no :path. h2-15.
    mov rdi, [r12 + linnea_h2_req.method_ptr]
    mov rsi, [r12 + linnea_h2_req.method_len]
    lea rdx, [method_connect_h2]
    mov ecx, 7
    call linnea_string_equal
    test rax, rax
    jnz .connect_405
    ; is_head = method == "HEAD". The GET/HEAD gate applies to static files
    ; alone and moves past the location match: a proxy location forwards any
    ; method to its upstream.
    ; Compared case-SENSITIVELY: a method is case-sensitive (RFC 9110 9.1), and
    ; iequal is for header names. h1 and h3 both match exactly, so a lowercase
    ; "get" was a 405 there and a 200 here — h2 was the lenient odd one out.
    mov rdi, [r12 + linnea_h2_req.method_ptr]
    mov rsi, [r12 + linnea_h2_req.method_len]
    lea rdx, [method_head_h2]
    mov ecx, 4
    call linnea_string_equal
    mov [rsp + S_HEAD], rax
    mov rdi, rbx
    mov rsi, r12
    call h2_select_vhost             ; -> rax = server*
    mov r13, rax
    ; Is this connection allowed to answer for that name? It presented one
    ; certificate; a vhost covered by a DIFFERENT one is not ours to serve
    ; here, and RFC 9110 7.4 says so with 421 — the client then opens a
    ; connection where the right certificate is presented. A name we do not
    ; host at all selects the connection's own vhost above, so it never
    ; reaches this test.
    mov rdi, rbx
    call h2_conn_vhost
    ; the response is built from a vhost either way — for a 421 it is this
    ; connection's own, since that is the site whose certificate we presented
    ; (and h2_cur_srv is dereferenced while building ANY response, so it must
    ; be set before every path that can answer)
    mov [h2_cur_srv], rax
    cmp rax, r13
    je .vhost_ok
    mov rdi, r13
    mov rsi, rax
    call h2_same_cert
    test eax, eax
    jz .resp_421
.vhost_ok:
    mov [h2_cur_srv], r13            ; its security headers ride the response
    lea rdi, [h2_path_buf + LINNEA_HTTP2_PATH_ROOT]
    mov rsi, [r12 + linnea_h2_req.path_ptr]
    mov rdx, [r12 + linnea_h2_req.path_len]
    call linnea_static_normalize                ; -> rax=end (0=bad), r9=dir flag
    test rax, rax
    jz .resp_400
    mov r14, rax                     ; path end
    mov [rsp + S_DIR], r9
    lea r15, [h2_path_buf + LINNEA_HTTP2_PATH_ROOT]   ; path start
    mov rdi, r13
    mov rsi, r15
    mov rdx, r14
    sub rdx, r15
    call h2_match_location           ; -> rax = location* or 0
    test rax, rax
    jz .resp_404
    mov [rsp + S_LOC], rax
    ; TRACE reflects the received request to whoever sent it; through a proxy
    ; that hands the caller its own credentials and anything an intermediary
    ; added. Refused before the kinds diverge, so the answer does not depend on
    ; which location matched (audit-report-33 follow-up).
    mov rdi, [r12 + linnea_h2_req.method_ptr]
    mov rsi, [r12 + linnea_h2_req.method_len]
    lea rdx, [method_trace_h2]
    mov ecx, 5
    call linnea_string_equal
    test eax, eax
    jnz .resp_405
    mov rax, [rsp + S_LOC]           ; the compare returned into rax
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY
    jne .h2_not_proxy
    ; RFC 9110 7.6.2: an OPTIONS carrying Max-Forwards: 0 has reached its final
    ; recipient and MUST NOT be forwarded; we answer for ourselves.
    cmp qword [r12 + linnea_h2_req.mf_seen], 0
    je .serve_proxy
    cmp qword [r12 + linnea_h2_req.mf_val], 0
    jne .serve_proxy
    mov rdi, [r12 + linnea_h2_req.method_ptr]
    mov rsi, [r12 + linnea_h2_req.method_len]
    lea rdx, [method_options_h2]
    mov ecx, 7
    call linnea_string_equal
    test eax, eax
    jnz .h2_options_final
    jmp .serve_proxy
.h2_not_proxy:
    mov rax, [rsp + S_LOC]
    ; Past the proxy branch every answer is ours to make, so an expectation we
    ; cannot meet is refused rather than ignored: serving the resource would
    ; tell the client by omission that it had been honoured. A proxy location
    ; has already branched away and forwards it (audit-report-33).
    cmp qword [r12 + linnea_h2_req.expect_bad], 0
    jne .resp_417
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_REDIRECT
    je .serve_redirect
    ; static files answer GET and HEAD only
    cmp qword [rsp + S_HEAD], 0
    jne .static_go
    mov rdi, [r12 + linnea_h2_req.method_ptr]
    mov rsi, [r12 + linnea_h2_req.method_len]
    lea rdx, [method_get_h2]
    mov ecx, 3
    call linnea_string_equal         ; case-sensitive: see the HEAD test above
    test rax, rax
    jz .resp_405
.static_go:
    ; A static location serves a file: it has no use for request content, and
    ; content on GET or HEAD has no defined semantics anyway (RFC 9110 9.3.1).
    ; h2 does not read it -- a DATA frame on a stream no proxy slot is
    ; collecting is credited and DROPPED -- so serving the file regardless means
    ; silently discarding bytes the client announced, the request-smuggling
    ; shape 9.3.1 names. It also left h2 the one protocol here that never
    ; noticed a content-length disagreeing with its body: h3 reconciles the two
    ; before routing and h1 waits for the whole declared body, but h2 answers at
    ; the HEADERS frame and never counts what follows.
    ;
    ; So the test is on the DECLARATION and the framing, both known here:
    ; a nonzero content-length, or a HEADERS frame that does not end the message
    ; (content -- or a trailer section, which implies content -- is still to
    ; come). Testing only the content-length would be trivially bypassed by
    ; sending DATA without declaring one.
    ;
    ; After the method gate, not before it: a POST to a static path is a method
    ; fault (405), and answering 400 for it would be reporting the wrong thing.
    cmp qword [r12 + linnea_h2_req.cl_val], 0
    jne .resp_400
    cmp dword [h2_req_es], 0
    je .resp_400
    mov rax, [rsp + S_LOC]
    ; join: copy the root just ahead of the path start, in place
    mov rcx, [rax + linnea_config_location.root_len]
    mov rdi, r15
    sub rdi, rcx
    mov [rsp + S_JOIN], rdi
    lea rsi, [rax + linnea_config_location.root]
    push rdi
    rep movsb
    pop rdi
    ; a directory maps to its index.html
    cmp qword [rsp + S_DIR], 0
    je .named
    mov rdi, r14
    cmp byte [rdi - 1], '/'          ; normalize consumed the trailing slash on
    je .append_index_h2              ; every directory but "/", so put it back
    mov byte [rdi], '/'
    inc rdi
.append_index_h2:
    lea rsi, [index_html_h2]
    mov ecx, 10
    rep movsb
    mov r14, rdi
.named:
    ; open the file — negotiating a pre-compressed variant when the client's
    ; Accept-Encoding allows one (open_enc writes the suffix and NUL at r14;
    ; the MIME lookup below keeps using the name before it)
    mov rdi, [rsp + S_JOIN]
    mov rsi, r14
    lea rdx, [r12 + linnea_h2_req.ae_ptr]   ; one span per field line
    mov rcx, [r12 + linnea_h2_req.ae_n]
    call linnea_static_open_enc            ; -> rax = base, rdx = size, r8 = coding
    mov [rsp + S_ENC], r8
    test rax, rax
    jnz .h2_opened
    cmp r9d, 1
    je .resp_406                     ; the client refused every form we have
    jmp .resp_404
.h2_opened:
    mov [rsp + S_BASE], rax
    mov [rsp + S_SIZE], rdx
    mov qword [rsp + S_ROFF], 0      ; whole file until a range narrows it
    mov [rsp + S_RLEN], rdx
    mov qword [rsp + S_CRLEN], 0
    ; validators for this file, then the request's conditionals: If-None-Match
    ; wins over If-Modified-Since, and an INM mismatch answers 200 whatever
    ; If-Modified-Since says (RFC 9110 13.2.2)
    mov rdi, [linnea_static_mtime]
    mov rsi, rdx
    call linnea_static_validators
    ; If-Match first, then If-Unmodified-Since when it is absent (13.2.2). A
    ; failure is 412 and ends the evaluation — in particular it beats an
    ; If-None-Match that would otherwise have produced a 304. h1 got this in
    ; Q187; without it here the same request gets a different answer depending
    ; on which protocol carried it.
    ; Each If-Match line is its own span and any of them may carry the matching
    ; tag -- the field is a list, and repeated lines are the comma-joined value
    ; (RFC 9110 5.3). One span meant the LAST line decided here while the FIRST
    ; decided on h1, so the same request was 412 on one protocol and 200 on the
    ; other, and swapping the client's two lines swapped which was right
    ; (audit-report-30).
    cmp qword [r12 + linnea_h2_req.ifm_n], 0
    je .chk_ius
    mov qword [rsp + S_COND], 0
.ifm_span:
    mov rax, [rsp + S_COND]
    cmp rax, [r12 + linnea_h2_req.ifm_n]
    jae .h2_412                      ; no line matched
    shl rax, 4
    lea rdx, [r12 + linnea_h2_req.ifm_ptr]
    mov rdi, [rdx + rax]
    mov rsi, [rdx + rax + 8]
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    mov r8d, 1                       ; If-Match compares strongly (13.1.1)
    call linnea_http_etag_match
    inc qword [rsp + S_COND]
    test eax, eax
    jz .ifm_span
    jmp .chk_inm
.chk_ius:
    mov rdi, [r12 + linnea_h2_req.ius_ptr]
    test rdi, rdi
    jz .chk_inm
    mov rsi, [r12 + linnea_h2_req.ius_len]
    call linnea_time_parse_http_date
    cmp rax, -1
    je .chk_inm                      ; unparseable: ignored, as elsewhere
    cmp [linnea_static_mtime], rax
    ja .h2_412
.chk_inm:
    cmp qword [r12 + linnea_h2_req.inm_n], 0
    je .chk_ims
    mov qword [rsp + S_COND], 0
.inm_span:
    mov rax, [rsp + S_COND]
    cmp rax, [r12 + linnea_h2_req.inm_n]
    jae .cond_done                   ; no line matched, which beats If-Modified-Since
    shl rax, 4
    lea rdx, [r12 + linnea_h2_req.inm_ptr]
    mov rdi, [rdx + rax]
    mov rsi, [rdx + rax + 8]
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    call linnea_http_inm_match
    inc qword [rsp + S_COND]
    test eax, eax
    jz .inm_span
    jmp .h2_304
.chk_ims:
    mov rdi, [r12 + linnea_h2_req.ims_ptr]
    test rdi, rdi
    jz .cond_done
    mov rsi, [r12 + linnea_h2_req.ims_len]
    call linnea_time_parse_http_date
    cmp rax, -1
    je .cond_done              ; unparseable: the RFC says ignore it
    cmp [linnea_static_mtime], rax
    jbe .h2_304                ; not modified since the client's copy
.cond_done:
    ; --- Range: a single bytes= range on a GET, evaluated after the
    ; conditionals as RFC 9110 orders and gated by If-Range (strong match
    ; only). Anything not understood serves the full 200, which is always
    ; safe; a valid but unsatisfiable range earns the 416.
    cmp qword [rsp + S_HEAD], 0
    jne .range_done_h2               ; ranges apply to GET alone
    mov rdi, [r12 + linnea_h2_req.rng_ptr]
    test rdi, rdi
    jz .range_done_h2
    mov rdi, [r12 + linnea_h2_req.ifr_ptr]
    test rdi, rdi
    jz .range_eval_h2
    mov rsi, [r12 + linnea_h2_req.ifr_len]
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    mov r8, [linnea_static_mtime]
    call linnea_http_ifrange_match
    test eax, eax
    jz .range_done_h2                ; stale validator: the whole file
.range_eval_h2:
    mov rdi, [r12 + linnea_h2_req.rng_ptr]
    mov rsi, [r12 + linnea_h2_req.rng_len]
    mov rdx, [rsp + S_SIZE]
    call linnea_http_range_parse     ; rax = offset, rdx = count | -1 | -2
    cmp rax, -1
    je .range_done_h2
    cmp rax, -2
    je .h2_416
    mov [rsp + S_ROFF], rax
    mov [rsp + S_RLEN], rdx
    ; content-range value: "bytes first-last/size"
    lea rcx, [h2_crbuf]
    mov dword [rcx], 'byte'
    mov word [rcx + 4], 's '
    mov rdi, rax                     ; first
    lea rsi, [h2_crbuf + 6]
    call linnea_string_from_u64
    lea rcx, [h2_crbuf + 6]
    add rcx, rax
    mov byte [rcx], '-'
    inc rcx
    mov [rsp + S_STAT], rcx          ; write cursor, across the formatters
    mov rdi, [rsp + S_ROFF]
    add rdi, [rsp + S_RLEN]
    dec rdi                          ; last = first + count - 1
    mov rsi, rcx
    call linnea_string_from_u64
    mov rcx, [rsp + S_STAT]
    add rcx, rax
    mov byte [rcx], '/'
    inc rcx
    mov [rsp + S_STAT], rcx
    mov rdi, [rsp + S_SIZE]
    mov rsi, rcx
    call linnea_string_from_u64
    mov rcx, [rsp + S_STAT]
    add rcx, rax
    lea rax, [h2_crbuf]
    sub rcx, rax
    mov [rsp + S_CRLEN], rcx         ; nonzero: this response is a 206
.range_done_h2:
    mov rdi, [rsp + S_JOIN]
    mov rsi, r14
    sub rsi, [rsp + S_JOIN]          ; joined path length
    call linnea_static_mime                     ; -> rax = mime ptr, rdx = mime len
    mov [rsp + S_MIME], rax
    mov [rsp + S_MLEN], rdx
    ; content-length string: the range's length, or the whole file's
    mov rdi, [rsp + S_RLEN]
    lea rsi, [h2_numbuf]
    call linnea_string_from_u64      ; -> rax = length
    mov [rsp + S_CLEN], rax
    ; --- encode the 200/206 HEADERS payload (after a 9-byte frame header) ---
    mov rdi, [rsp + S_OUT]
    add rdi, 9
    mov r15, rdi                     ; payload start
    mov esi, 8                       ; :status
    lea rdx, [status_200_h2]
    mov qword [rsp + S_LSTAT], 200
    mov rax, [rsp + S_RLEN]
    mov [rsp + S_LBYTES], rax
    cmp qword [rsp + S_CRLEN], 0
    je .st_sel
    lea rdx, [status_206_h2]
    mov qword [rsp + S_LSTAT], 206
.st_sel:
    mov ecx, 3
    call h2_enc_hdr
    mov esi, 31                      ; content-type
    mov rdx, [rsp + S_MIME]
    mov rcx, [rsp + S_MLEN]
    call h2_enc_hdr
    mov esi, 28                      ; content-length
    lea rdx, [h2_numbuf]
    mov rcx, [rsp + S_CLEN]
    call h2_enc_hdr
    cmp qword [rsp + S_CRLEN], 0
    je .no_crange_h2
    mov esi, 30                      ; content-range: bytes first-last/size
    lea rdx, [h2_crbuf]
    mov rcx, [rsp + S_CRLEN]
    call h2_enc_hdr
.no_crange_h2:
    mov esi, 18                      ; accept-ranges: bytes
    lea rdx, [h2_bytes]
    mov ecx, h2_bytes_len
    call h2_enc_hdr
    cmp qword [rsp + S_ENC], 0
    je .no_cenc_h2
    mov esi, 26                      ; content-encoding: the coding served
    lea rdx, [enc_gzip_h2]
    mov ecx, enc_gzip_h2_len
    cmp qword [rsp + S_ENC], 2
    jne .cenc_emit
    lea rdx, [enc_br_h2]
    mov ecx, enc_br_h2_len
.cenc_emit:
    call h2_enc_hdr
.no_cenc_h2:
    mov esi, 59                      ; vary: accept-encoding — serving depends
    lea rdx, [h2_ae_name]            ; on it whether or not a variant was found
    mov ecx, h2_ae_name_len
    call h2_enc_hdr
    mov esi, 34                      ; etag
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    call h2_enc_hdr
    mov esi, 44                      ; last-modified
    lea rdx, [linnea_static_lastmod]
    mov ecx, LINNEA_HTTP_DATE_LEN
    call h2_enc_hdr
    call h2_enc_date_server
    mov rax, [rsp + S_LOC]           ; the location's Cache-Control, if set
    mov rcx, [rax + linnea_config_location.cache_control_len]
    test rcx, rcx
    jz .no_cc_h2
    mov esi, 24                      ; cache-control
    lea rdx, [rax + linnea_config_location.cache_control]
    call h2_enc_hdr
.no_cc_h2:
    ; Alt-Svc, when a QUIC listener is up (name is not in the static table)
    cmp qword [linnea_h3_altsvc_len], 0
    je .no_altsvc_h2
    mov eax, [rbx + linnea_connection.server]
    cmp byte [linnea_h3_advert + rax], 0
    je .no_altsvc_h2              ; this origin has no h3 vhost: nothing to advertise
    lea rsi, [hdr_altsvc_name]
    mov rdx, hdr_altsvc_name_len
    lea rcx, [linnea_h3_altsvc]
    mov r8, [linnea_h3_altsvc_len]
    call h2_enc_hdr_lit
.no_altsvc_h2:
    mov rbp, rdi
    sub rbp, r15                     ; payload length
    ; flags: END_HEADERS, plus END_STREAM when there is no body
    mov r8b, LINNEA_H2_FLAG_END_HEADERS
    cmp qword [rsp + S_HEAD], 0
    jne .no_body
    cmp qword [rsp + S_RLEN], 0
    jne .with_body
.no_body:
    or r8b, LINNEA_H2_FLAG_END_STREAM
    cmp qword [rsp + S_SIZE], 0      ; empty file uses a sentinel base, no map
    je .flags
    mov rdi, [rsp + S_BASE]
    mov rsi, [rsp + S_SIZE]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    jmp .flags
.with_body:
    ; register the body in a pool slot; the scheduler streams it as DATA
    mov rdi, rbx
    mov esi, [rsp + S_SID]
    mov rdx, r12                     ; req, for its priority field
    call h2_slot_alloc               ; -> rax = slot* or 0 (pool full)
    test rax, rax
    jz .refused
    mov rcx, [rbx + linnea_connection.h2_init_swnd]   ; peer's initial window
    mov [rax + linnea_h2_stream.swnd], rcx
    mov rcx, [rsp + S_BASE]
    mov [rax + linnea_h2_stream.file_base], rcx
    add rcx, [rsp + S_ROFF]          ; the requested slice, or the whole file
    mov [rax + linnea_h2_stream.body_ptr], rcx
    mov rcx, [rsp + S_SIZE]          ; munmap needs the whole mapping
    mov [rax + linnea_h2_stream.file_size], rcx
    mov rcx, [rsp + S_RLEN]
    mov [rax + linnea_h2_stream.body_rem], rcx
    mov qword [rax + linnea_h2_stream.flags], LINNEA_H2_STREAM_END
    ; a static body streams from the mapping, not from an upstream. The free
    ; paths clear only .id, so a slot that once served a proxied stream still
    ; carries its .up — which would send the scheduler to the upstream branch
    ; and stream this file from that exchange's buffer instead.
    mov qword [rax + linnea_h2_stream.up], 0
    mov r8b, LINNEA_H2_FLAG_END_HEADERS   ; DATA follows; no END_STREAM here
.flags:
    mov rdi, [rsp + S_OUT]
    mov rax, rbp
    shr rax, 16
    mov [rdi], al
    mov rax, rbp
    shr rax, 8
    mov [rdi + 1], al
    mov [rdi + 2], bpl
    mov byte [rdi + 3], LINNEA_H2_FT_HEADERS
    mov [rdi + 4], r8b               ; END_HEADERS [| END_STREAM]
    mov rax, [rsp + S_SID]
    mov rdx, rax
    shr rax, 24
    mov [rdi + 5], al
    mov rax, rdx
    shr rax, 16
    mov [rdi + 6], al
    mov rax, rdx
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], dl
    ; the access line: every stream answered via .flags — static, conditional,
    ; redirect — logs here. A stream that got no response (refused with
    ; RST_STREAM, or claimed by the proxy path, which logs at its own finish)
    ; left S_LSTAT zero and is skipped; the error path logs at its own exit.
    cmp qword [rsp + S_LSTAT], 0
    je .flags_unlogged
    mov rdx, [rsp + S_LSTAT]
    mov rcx, [rsp + S_LBYTES]
    call .acc_line
.flags_unlogged:
    lea rax, [rbp + 9]               ; HEADERS flight length
    jmp .out

.refused:
    ; pool full: drop the mapping and refuse the stream with RST_STREAM
    mov rdi, [rsp + S_BASE]
    mov rsi, [rsp + S_SIZE]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    mov rdi, [rsp + S_OUT]
    mov byte [rdi], 0
    mov byte [rdi + 1], 0
    mov byte [rdi + 2], 4
    mov byte [rdi + 3], LINNEA_H2_FT_RST_STREAM
    mov byte [rdi + 4], 0
    mov rax, [rsp + S_SID]
    mov rdx, rax
    shr rax, 24
    mov [rdi + 5], al
    mov rax, rdx
    shr rax, 16
    mov [rdi + 6], al
    mov rax, rdx
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], dl
    mov dword [rdi + 9], 0x07000000  ; error code REFUSED_STREAM (7), big-endian
    mov eax, 13
    jmp .out

.list_over_431:
    mov qword [rsp + S_LSTAT], 431
    mov qword [rsp + S_LBYTES], 0
    mov rdi, rbx
    mov rsi, [rsp + S_SID]
    mov rdx, [rsp + S_OUT]
    call h2_431_stream               ; -> rax = response length
    jmp .out
.drain_refuse:
    ; the worker is draining: refuse the new stream (nothing was opened)
    mov rdi, [rsp + S_OUT]
    mov byte [rdi], 0
    mov byte [rdi + 1], 0
    mov byte [rdi + 2], 4
    mov byte [rdi + 3], LINNEA_H2_FT_RST_STREAM
    mov byte [rdi + 4], 0
    mov rax, [rsp + S_SID]
    mov rdx, rax
    shr rax, 24
    mov [rdi + 5], al
    mov rax, rdx
    shr rax, 16
    mov [rdi + 6], al
    mov rax, rdx
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], dl
    mov dword [rdi + 9], 0x07000000  ; REFUSED_STREAM
    mov eax, 13
    jmp .out

.serve_redirect:
    ; 301 whose Location is the configured URL prefix plus the raw :path,
    ; encoding untouched — the h1 recipe, as an h2 HEADERS frame
    mov rax, [rsp + S_LOC]
    mov rcx, [rax + linnea_config_location.redirect_len]
    add rcx, [r12 + linnea_h2_req.path_len]
    cmp rcx, 2048
    ja .resp_400                     ; target too long for the value buffer
    lea rdi, [h2_locbuf]
    lea rsi, [rax + linnea_config_location.redirect]
    mov rcx, [rax + linnea_config_location.redirect_len]
    rep movsb
    mov rsi, [r12 + linnea_h2_req.path_ptr]
    mov rcx, [r12 + linnea_h2_req.path_len]
    rep movsb
    lea rax, [h2_locbuf]
    sub rdi, rax
    mov [rsp + S_CLEN], rdi          ; the Location value's length
    mov rdi, [rsp + S_OUT]
    add rdi, 9
    mov r15, rdi                     ; payload start
    mov esi, 8                       ; :status
    lea rdx, [status_301_h2]
    mov qword [rsp + S_LSTAT], 301
    mov ecx, 3
    call h2_enc_hdr
    mov esi, 46                      ; location
    lea rdx, [h2_locbuf]
    mov rcx, [rsp + S_CLEN]
    call h2_enc_hdr
    mov esi, 28                      ; content-length: 0
    lea rdx, [zero_h2]
    mov ecx, 1
    call h2_enc_hdr
    call h2_enc_date_server
    mov rbp, rdi
    sub rbp, r15                     ; payload length
    mov r8b, LINNEA_H2_FLAG_END_HEADERS | LINNEA_H2_FLAG_END_STREAM
    jmp .flags

.serve_proxy:
    ; forward the request to the location's upstream: an h1 exchange on its
    ; own connection, driven by the io_uring loop through an upstream slot.
    ; Here the request is rewritten into the slot; the loop connects, sends,
    ; reads the response head back and the pending-frame service translates
    ; it for the client (see the Q86 section below).
    ; First, coalesce any split cookie fields into one h1 Cookie line: RFC 9113
    ; 8.2.3 lets an h2 client split Cookie for compression but an intermediary
    ; must join them with "; " before a non-h2 hop (Finding 32). The values were
    ; accumulated during decode; append one line now, and let the bound check
    ; below answer 431 if it (or the block) did not fit.
    mov rcx, [r12 + linnea_h2_req.ck_len]
    test rcx, rcx
    jz .sp_cookies_done              ; no cookie field: nothing to emit
    cmp rcx, -1
    je .sp_cookie_over               ; the join overflowed its buffer
    mov rdi, [r12 + linnea_h2_req.hb_cur]
    lea rax, [rdi + rcx]
    add rax, ck_hdr_name_len + 2     ; "cookie: " + value + CRLF
    cmp rax, [r12 + linnea_h2_req.hb_end]
    ja .sp_cookie_over
    mov r8, rcx                      ; hold the value length across the copies
    lea rsi, [ck_hdr_name]
    mov rcx, ck_hdr_name_len
    rep movsb
    mov rsi, [r12 + linnea_h2_req.ck_buf]
    mov rcx, r8
    rep movsb
    mov word [rdi], 0x0a0d           ; CRLF
    add rdi, 2
    mov [r12 + linnea_h2_req.hb_cur], rdi
    jmp .sp_cookies_done
.sp_cookie_over:
    mov rax, [r12 + linnea_h2_req.hb_end]
    inc rax                          ; overflow sentinel: the check below fails it
    mov [r12 + linnea_h2_req.hb_cur], rax
.sp_cookies_done:
    ; ...and Max-Forwards, kept out of the rebuild so it could be re-emitted
    ; here: one hop fewer for an OPTIONS (RFC 9110 7.6.2), untouched for any
    ; other method, which 7.6.2 leaves free to ignore it. The zero case never
    ; reaches here -- it was answered before the upstream was chosen -- so the
    ; subtraction cannot wrap.
    cmp qword [r12 + linnea_h2_req.mf_seen], 0
    je .sp_mf_done
    ; the value first, while nothing else is held: is this an OPTIONS?
    mov rdi, [r12 + linnea_h2_req.method_ptr]
    mov rsi, [r12 + linnea_h2_req.method_len]
    lea rdx, [method_options_h2]
    mov ecx, 7
    call linnea_string_equal
    mov rdi, [r12 + linnea_h2_req.mf_val]
    test eax, eax
    jz .sp_mf_render
    dec rdi                          ; one hop taken
.sp_mf_render:
    lea rsi, [mf_num_buf]
    call linnea_string_from_u64      ; -> rax = digits written
    mov rdx, rax                     ; hold the digit count across the bound
    mov rdi, [r12 + linnea_h2_req.hb_cur]
    lea rax, [rdi + rdx]
    add rax, mf_hdr_name_len + 2
    cmp rax, [r12 + linnea_h2_req.hb_end]
    ja .resp_431
    lea rsi, [mf_hdr_name]
    mov rcx, mf_hdr_name_len
    rep movsb
    lea rsi, [mf_num_buf]
    mov rcx, rdx
    rep movsb
    mov word [rdi], 0x0a0d           ; CRLF
    add rdi, 2
    mov [r12 + linnea_h2_req.hb_cur], rdi
.sp_mf_done:
    mov rax, [r12 + linnea_h2_req.hb_cur]
    cmp rax, [r12 + linnea_h2_req.hb_end]
    ja .resp_431                     ; rebuilt header block overflowed
    mov rdi, rbx
    call h2p_alloc                   ; -> rax = free slot*, rdx = its index
    test rax, rax
    jz .drain_refuse                 ; no slot: refuse, the client may retry
    mov r13, rax                     ; upstream slot*
    mov r14, rdx                     ; its index
    mov rdi, rbx
    mov rsi, [rsp + S_SID]
    mov rdx, r12                     ; req, for its priority field
    call h2_slot_alloc               ; the stream slot (windows + scheduling)
    test rax, rax
    jz .drain_refuse                 ; stream pool full (the h2p slot was
                                     ; never claimed: still FREE)
    mov rcx, [rbx + linnea_connection.h2_init_swnd]
    mov [rax + linnea_h2_stream.swnd], rcx
    mov qword [rax + linnea_h2_stream.file_base], 0
    mov qword [rax + linnea_h2_stream.file_size], 0
    mov qword [rax + linnea_h2_stream.body_ptr], 0
    mov qword [rax + linnea_h2_stream.body_rem], 0
    mov qword [rax + linnea_h2_stream.flags], 0
    lea rcx, [r14 + 1]
    mov [rax + linnea_h2_stream.up], rcx
    ; claim and fill the upstream slot
    mov qword [r13 + linnea_h2p.state], LINNEA_H2P_COLLECT
    mov dword [r13 + linnea_h2p.fd], -1
    ; The body clock starts with the slot, not with the Content-Length, and it
    ; is written HERE because a slot is reused: the release path never scrubbed
    ; rq_start, which was harmless only while the field was read exclusively by
    ; the streaming path that had just set it. Reading it for every COLLECT slot
    ; made the leftover live, and an upload landing in a slot some earlier
    ; request had used was aged against THAT request's start — instantly past
    ; the deadline, answered 408 with nothing wrong with it. Setting it at the
    ; claim also covers a body with no Content-Length, which the streaming path
    ; could never bound at all.
    call linnea_uring_now            ; eats rdi/rsi; r13 and rbx survive
    mov [r13 + linnea_h2p.rq_start], rax
    mov rcx, [rsp + S_SID]
    mov [r13 + linnea_h2p.sid], rcx
    mov rcx, [rbx + linnea_connection.gen]
    mov [r13 + linnea_h2p.gen], rcx
    mov rcx, [rsp + S_LOC]
    mov [r13 + linnea_h2p.location], rcx
    mov rcx, [h2_cur_srv]            ; for the response's security headers,
    mov [r13 + linnea_h2p.srv], rcx  ; built long after this request returns
    mov qword [r13 + linnea_h2p.sent], 0
    mov qword [r13 + linnea_h2p.len], 0
    mov qword [r13 + linnea_h2p.rd], 0
    mov qword [r13 + linnea_h2p.wr], 0
    mov qword [r13 + linnea_h2p.off], 0
    mov qword [r13 + linnea_h2p.body_rem], 0
    mov qword [r13 + linnea_h2p.chunked], 0
    mov qword [r13 + linnea_h2p.chunk_rem], 0
    mov qword [r13 + linnea_h2p.status], 0
    mov qword [r13 + linnea_h2p.rq_rd], 0
    mov qword [r13 + linnea_h2p.rq_wr], 0
    mov qword [r13 + linnea_h2p.rq_rem], 0
    mov qword [r13 + linnea_h2p.rq_credit], 0
    mov qword [r13 + linnea_h2p.rq_buf], 0
    mov qword [r13 + linnea_h2p.rq_declared], -1
    mov dword [r13 + linnea_h2p.rq_fd], -1      ; NOT 0: fd 0 is a real one, and
    mov qword [r13 + linnea_h2p.rq_map], 0      ; a zeroed slot once closed it
    mov qword [r13 + linnea_h2p.rq_maplen], 0
    mov qword [r13 + linnea_h2p.lg_bytes], 0
    mov rcx, [rsp + S_HEAD]
    imul rcx, rcx, LINNEA_H2P_F_IS_HEAD
    mov [r13 + linnea_h2p.flags], rcx
    ; park the method and target for the access line (h2p_finish_stream):
    ; buf holds the rewritten head only until the response overwrites it
    mov rcx, [r12 + linnea_h2_req.method_len]
    cmp rcx, 15
    jbe .lg_m_fits
    mov ecx, 15
.lg_m_fits:
    mov [r13 + linnea_h2p.lg_meth], cl
    lea rdi, [r13 + linnea_h2p.lg_meth + 1]
    mov rsi, [r12 + linnea_h2_req.method_ptr]
    rep movsb
    mov rcx, [r12 + linnea_h2_req.path_len]
    cmp rcx, 103
    jbe .lg_t_fits
    mov ecx, 103
.lg_t_fits:
    mov [r13 + linnea_h2p.lg_tgt], cl
    lea rdi, [r13 + linnea_h2p.lg_tgt + 1]
    mov rsi, [r12 + linnea_h2_req.path_ptr]
    rep movsb
    ; --- rewrite the request head: request line, Host, rebuilt headers.
    ; Content-Length and the terminating empty line follow in h2p_finalize
    ; once the body (if any) is collected. Bound it first.
    mov rcx, [r12 + linnea_h2_req.method_len]
    add rcx, [r12 + linnea_h2_req.path_len]
    add rcx, [r12 + linnea_h2_req.auth_len]
    mov rax, [r12 + linnea_h2_req.hb_cur]
    sub rax, [r12 + linnea_h2_req.hb_start]
    add rcx, rax
    ; The literals this builder adds around the request's own bytes:
    ;   " " x2 + "HTTP/1.1" CRLF        10 + 2
    ;   "Host: " CRLF                    8   (the value is auth_len, above)
    ;   "Content-Length: " + 20 digits + CRLF   38
    ;   "Via: 2 linnea" CRLF            15
    ;   "Connection: keep-alive" CRLF CRLF   26  (the longer of the two)
    ; = 99. The old allowance of 64 did not cover them and never could: it was
    ; short before keep-alive added five bytes to the longest Connection line.
    ; Nothing overflowed, because HEAD_MAX is 8192 against a 16384-byte buf --
    ; 8 KB of slack absorbed the difference. Corrected rather than left to be
    ; rediscovered by whoever adds the next field.
    add rcx, 128                     ; literals + the Content-Length line
    cmp rcx, LINNEA_H2P_HEAD_MAX
    ja .proxy_toobig
    lea rdi, [r13 + linnea_h2p.buf]
    mov rsi, [r12 + linnea_h2_req.method_ptr]
    mov rcx, [r12 + linnea_h2_req.method_len]
    rep movsb
    mov byte [rdi], ' '
    inc rdi
    mov rsi, [r12 + linnea_h2_req.path_ptr]
    mov rcx, [r12 + linnea_h2_req.path_len]
    rep movsb
    lea rsi, [h2p_http11]            ; " HTTP/1.1" CRLF "Host: "
    mov ecx, h2p_http11_len
    rep movsb
    mov rsi, [r12 + linnea_h2_req.auth_ptr]
    test rsi, rsi
    jz .proxy_nohost
    mov rcx, [r12 + linnea_h2_req.auth_len]
    rep movsb
.proxy_nohost:
    mov word [rdi], 0x0a0d
    add rdi, 2
    mov rsi, [r12 + linnea_h2_req.hb_start]
    mov rcx, [r12 + linnea_h2_req.hb_cur]
    sub rcx, rsi
    rep movsb
    lea rax, [r13 + linnea_h2p.buf]
    sub rdi, rax
    mov [r13 + linnea_h2p.req_len], rdi   ; the head so far (no terminator)
    cmp dword [h2_req_es], 0
    je .proxy_has_body               ; not END_STREAM: a body follows
    ; END_STREAM on HEADERS: the body is empty, so a declared content-length must
    ; be zero (RFC 9113 8.1.1, Finding 24) or the message is malformed -- a body
    ; announced with no DATA. The old code forwarded it bodiless, replacing the
    ; client's contradiction with our own framing so the backend heard a request
    ; the client never sent. Fail the stream 400 instead, like .proxy_toolarge:
    ; the slot opens no socket, so the backend hears nothing of it.
    cmp qword [r12 + linnea_h2_req.cl_ptr], 0
    je .proxy_nobody                 ; no content-length: an ordinary bodiless request
    ; .cl_val was parsed and range-checked while the field section decoded
    ; (audit-report-5 Finding 1). Re-parsing it here is what let 2^64 through:
    ; the old parser guarded the multiply by asking whether the product had got
    ; SMALLER and never looked at the digit's carry, so the last digit of
    ; 18446744073709551616 wrapped the value to zero -- and zero is what this
    ; very test accepts as "no body announced".
    cmp qword [r12 + linnea_h2_req.cl_val], 0
    je .proxy_zerolen                ; content-length: 0 -- consistent with no body
    mov qword [r13 + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [r13 + linnea_h2p.status], 400
    jmp .proxy_done
.proxy_has_body:
    ; A body with a declared length streams: the length is forwarded as the
    ; client gave it and the bytes follow as they arrive, so an upload is
    ; bounded by the flow-control window rather than by our buffer. Without
    ; a length there is nothing to declare upstream, so those (rare) bodies
    ; are still collected and measured first.
    cmp qword [r12 + linnea_h2_req.cl_ptr], 0
    je .proxy_expect_100             ; no length: collect (100-continue below)
    mov rax, [r12 + linnea_h2_req.cl_val]     ; checked at decode: see above
    mov [r13 + linnea_h2p.rq_declared], rax   ; judged at END_STREAM (8.1.1)
    or qword [r13 + linnea_h2p.flags], LINNEA_H2P_F_HAS_CL
    ; rq_declared's -1 means "none was declared", which 18446744073709551615
    ; also is -- and a client may legally declare it. The old parser reported
    ; its own faults as -1 too, so a body declaring UINT64_MAX took the
    ; "unparseable, collect and re-derive" branch and was forwarded with OUR
    ; measured count in place of the client's: the exact rewrite the
    ; reconciliation exists to stop. The flag says which of the two it is.
    ; ...and refused here if it is larger than we accept. max_body bounds a
    ; request body on h1, which refuses on the DECLARED length for the same
    ; reason: the point of the cap is that the bytes never land. h2 never
    ; consulted it at all — the collect path below is bounded by its own buffer,
    ; but a body with a Content-Length streams straight through to the backend,
    ; so whatever the client declared is what the backend got. Lowering
    ; max_body to bound uploads did nothing on the one protocol browsers use.
    push rax
    lea rcx, [linnea_config_instance]
    mov rcx, [rcx + linnea_config.max_body]
    cmp rax, rcx
    pop rax
    ja .proxy_toolarge
    test rax, rax
    jz .proxy_nobody
    ; A body is COLLECTED, never streamed: the upstream socket is not opened
    ; until the last DATA frame is in, which is what h1 and h3 have always
    ; done. Streaming connected here, before a single body byte had arrived,
    ; and then fed the backend at the CLIENT's pace — so one 40 MB upload over
    ; a 4 MB/s uplink held a backend connection for nine seconds, and every
    ; other request to that backend queued behind it. h3 did not, purely
    ; because it forwards a body it already has, which is how the asymmetry
    ; was found. Capturing costs a late discovery that the backend is down;
    ; it buys back the ability to retry at all, which streaming gives up the
    ; moment the first body byte goes out (nginx documents exactly this
    ; trade under proxy_request_buffering, and defaults to buffering).
    ;
    ; Nothing to do here but let the DATA path have it: the body clock was
    ; started with the slot, and END_STREAM is what connects.
    jmp .proxy_expect_100
.proxy_nobody:
    mov rdi, r13
    call h2p_finalize                ; terminate the head and connect
.proxy_done:
    xor eax, eax                     ; no response bytes at the out cursor
    jmp .out
.proxy_expect_100:
    ; The body is buffered here before the upstream is contacted, so a client
    ; that sent "expect: 100-continue" and is waiting would stall (Finding 33).
    ; Answer the expectation locally: one interim 100 HEADERS (no END_STREAM),
    ; then leave the slot COLLECTing for the DATA frames it releases.
    cmp qword [r12 + linnea_h2_req.expect_100], 0
    je .proxy_done                   ; no expectation: collect silently
    mov rdi, [rsp + S_OUT]
    add rdi, 9                        ; payload after the 9-byte frame header
    mov r15, rdi
    mov esi, 8                        ; :status (indexed name, literal value)
    lea rdx, [status_100_h2]
    mov ecx, 3
    call h2_enc_hdr
    mov rbp, rdi
    sub rbp, r15                      ; payload length
    mov r8b, LINNEA_H2_FLAG_END_HEADERS   ; interim response: no END_STREAM
    jmp .flags
.proxy_zerolen:
    ; "content-length: 0" is a DECLARATION, not the absence of one, and the
    ; upstream head has to carry it forward. Falling into .proxy_nobody
    ; unmarked sent the backend a POST with no framing at all, and a backend
    ; entitled to require a length answered 411 -- which is what an empty file
    ; upload did over h2 and h3, while h1 forwards "Content-Length: 0" and
    ; worked. The flag is the one the reconciliation already uses, so
    ; h2p_finalize can tell "no body" from "a body of no bytes".
    ; Placed out of line here for the same reason .proxy_toolarge is: the
    ; fall-through into .proxy_done below is load-bearing.
    or qword [r13 + linnea_h2p.flags], LINNEA_H2P_F_HAS_CL
    jmp .proxy_nobody
.proxy_toolarge:
    ; NB: below .proxy_done's jmp, not above it — .proxy_nobody falls THROUGH
    ; into .proxy_done, so a label placed between them marks every bodiless
    ; proxied request (which is every GET) as failed.
    ; The slot never opens a socket, so the backend hears nothing of this. The
    ; body still arrives — the client was told nothing to make it hold back —
    ; and is dropped: h2p_find_collect skips a FAILED slot, so the DATA frames
    ; are credited and discarded, exactly as they are for .fd_toobig.
    mov qword [r13 + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [r13 + linnea_h2p.status], 413
    jmp .proxy_done
.proxy_toobig:
    mov qword [r13 + linnea_h2p.state], LINNEA_H2P_FREE
    mov rdi, rbx                     ; free the stream slot allocated above
    mov rsi, [rsp + S_SID]
    call h2_slot_find
    test rax, rax
    jz .resp_431
    mov qword [rax + linnea_h2_stream.id], 0
    jmp .resp_431

.resp_431:
    lea rax, [status_431_h2]
    lea r14, [body_431]
    mov r15d, body_431_len
    jmp .error
.h2_options_final:
    ; the final recipient of an OPTIONS describes ITSELF (RFC 9110 9.3.7)
    lea rax, [status_200_h2]
    lea r14, [body_options_h2]
    mov r15d, body_options_h2_len
    jmp .error
.resp_406:
    lea rax, [status_406_h2]
    lea r14, [body_406]
    mov r15d, body_406_len
    jmp .error
.resp_417:
    lea rax, [status_417_h2]
    lea r14, [body_417]
    mov r15d, body_417_len
    jmp .error

.h2_304:
    ; the client's copy is current: unmap the file and answer a bodiless 304
    ; carrying the validators it will compare next time
    cmp qword [rsp + S_SIZE], 0
    je .h2_304_nomap                 ; empty file: sentinel base, nothing mapped
    mov rdi, [rsp + S_BASE]
    mov rsi, [rsp + S_SIZE]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.h2_304_nomap:
    mov rdi, [rsp + S_OUT]
    add rdi, 9
    mov r15, rdi                     ; payload start
    mov esi, 8                       ; :status
    lea rdx, [status_304_h2]
    mov qword [rsp + S_LSTAT], 304
    mov ecx, 3
    call h2_enc_hdr
    mov esi, 34                      ; etag
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    call h2_enc_hdr
    mov esi, 44                      ; last-modified
    lea rdx, [linnea_static_lastmod]
    mov ecx, LINNEA_HTTP_DATE_LEN
    call h2_enc_hdr
    call h2_enc_date_server
    mov rax, [rsp + S_LOC]           ; a 304 carries the 200's Cache-Control:
    mov rcx, [rax + linnea_config_location.cache_control_len]
    test rcx, rcx                    ; it is metadata the client's cache must
    jz .no_cc_304                    ; refresh on revalidation
    mov esi, 24                      ; cache-control
    lea rdx, [rax + linnea_config_location.cache_control]
    call h2_enc_hdr
.no_cc_304:
    mov esi, 59                      ; a 304 must carry the Vary of its 200
    lea rdx, [h2_ae_name]
    mov ecx, h2_ae_name_len
    call h2_enc_hdr
    mov rbp, rdi
    sub rbp, r15                     ; payload length
    mov r8b, LINNEA_H2_FLAG_END_HEADERS | LINNEA_H2_FLAG_END_STREAM
    jmp .flags

.h2_412:
    ; a precondition the client set is not met: unmap and answer a bodiless
    ; 412 carrying the current validators, so a client that guessed wrong can
    ; see what the representation actually is (RFC 9110 15.5.13)
    cmp qword [rsp + S_SIZE], 0
    je .h2_412_nomap                 ; empty file: sentinel base, nothing mapped
    mov rdi, [rsp + S_BASE]
    mov rsi, [rsp + S_SIZE]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.h2_412_nomap:
    mov rdi, [rsp + S_OUT]
    add rdi, 9
    mov r15, rdi                     ; payload start
    mov esi, 8                       ; :status
    lea rdx, [status_412_h2]
    mov qword [rsp + S_LSTAT], 412
    mov ecx, 3
    call h2_enc_hdr
    mov esi, 34                      ; etag
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    call h2_enc_hdr
    mov esi, 44                      ; last-modified
    lea rdx, [linnea_static_lastmod]
    mov ecx, LINNEA_HTTP_DATE_LEN
    call h2_enc_hdr
    call h2_enc_date_server
    mov rbp, rdi
    sub rbp, r15                     ; payload length
    mov r8b, LINNEA_H2_FLAG_END_HEADERS | LINNEA_H2_FLAG_END_STREAM
    jmp .flags

.h2_416:
    ; the single range is valid but unsatisfiable: unmap the file and answer
    ; a bodiless 416 whose Content-Range names the actual length ("bytes
    ; */size") so the client can retry sensibly
    cmp qword [rsp + S_SIZE], 0
    je .h2_416_nomap                 ; empty file: sentinel base, nothing mapped
    mov rdi, [rsp + S_BASE]
    mov rsi, [rsp + S_SIZE]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.h2_416_nomap:
    lea rcx, [h2_crbuf]              ; content-range value: "bytes */size"
    mov dword [rcx], 'byte'
    mov dword [rcx + 4], 's */'
    mov rdi, [rsp + S_SIZE]
    lea rsi, [h2_crbuf + 8]
    call linnea_string_from_u64
    lea rcx, [rax + 8]               ; value length
    mov [rsp + S_CRLEN], rcx
    mov rdi, [rsp + S_OUT]
    add rdi, 9
    mov r15, rdi                     ; payload start
    mov esi, 8                       ; :status
    lea rdx, [status_416_h2]
    mov qword [rsp + S_LSTAT], 416
    mov ecx, 3
    call h2_enc_hdr
    mov esi, 30                      ; content-range
    lea rdx, [h2_crbuf]
    mov rcx, [rsp + S_CRLEN]
    call h2_enc_hdr
    mov esi, 28                      ; content-length: 0
    lea rdx, [zero_h2]
    mov ecx, 1
    call h2_enc_hdr
    call h2_enc_date_server
    mov rbp, rdi
    sub rbp, r15                     ; payload length
    mov r8b, LINNEA_H2_FLAG_END_HEADERS | LINNEA_H2_FLAG_END_STREAM
    jmp .flags

.connect_405:
    ; a 405 is built from a vhost; use this connection's own (the cert we
    ; presented), since CONNECT carries no :authority routing we honour.
    mov rdi, rbx
    call h2_conn_vhost
    mov [h2_cur_srv], rax
    mov qword [rsp + S_HEAD], 0      ; emit the small body (CONNECT is not HEAD)
    ; fall through to .resp_405
.resp_405:
    lea rax, [status_405_h2]
    lea r14, [body_405]
    mov r15d, body_405_len
    jmp .error
.resp_404:
    lea rax, [status_404_h2]
    lea r14, [body_404]
    mov r15d, body_404_len
    jmp .error
.resp_421:
    lea rax, [status_421_h2]
    lea r14, [body_421_h2]
    mov r15d, body_421_h2_len
    mov qword [rsp + S_LSTAT], 421
    jmp .error
.resp_400:
    lea rax, [status_400_h2]
    lea r14, [body_400]
    mov r15d, body_400_len
.error:
    mov [rsp + S_STAT], rax          ; status string (3 chars)
    ; the numeric status for the access line, from those three digits
    movzx ecx, byte [rax]
    lea ecx, [rcx + rcx * 4]
    imul ecx, ecx, 20                ; c0 * 100
    movzx edx, byte [rax + 1]
    lea edx, [rdx + rdx * 4]
    add edx, edx                     ; + c1 * 10
    add ecx, edx
    movzx edx, byte [rax + 2]        ; + c2
    add ecx, edx
    sub ecx, '0' * 111               ; the three digits' ASCII bias
    mov [rsp + S_LSTAT], rcx
    ; The body is flow-controlled. If the peer has no room for it, answer with an
    ; empty one rather than sending it regardless: the status is what an error
    ; response is for, content-length then agrees at 0, and a zero-length DATA
    ; frame consumes no window, so END_STREAM still arrives.
    mov rdi, rbx
    mov rsi, r15
    call h2_data_window_take
    test eax, eax
    jnz .body_fits
    xor r15d, r15d
.body_fits:
    mov [rsp + S_LBYTES], r15
    mov rdi, r15
    lea rsi, [h2_numbuf]
    call linnea_string_from_u64
    mov [rsp + S_CLEN], rax
    mov rdi, [rsp + S_OUT]
    add rdi, 9
    mov r13, rdi                     ; payload start
    mov esi, 8                       ; :status
    mov rdx, [rsp + S_STAT]
    mov ecx, 3
    call h2_enc_hdr
    mov esi, 31                      ; content-type: text/plain
    lea rdx, [mime_txt_h2]
    mov ecx, mime_txt_h2_len
    call h2_enc_hdr
    mov esi, 28                      ; content-length
    lea rdx, [h2_numbuf]
    mov rcx, [rsp + S_CLEN]
    call h2_enc_hdr
    ; a 405 names the methods the resource does take (RFC 9110 15.5.6); "allow"
    ; is HPACK static index 22, so only the value is a literal
    cmp qword [rsp + S_LSTAT], 405
    jne .no_allow_h2
    mov esi, 22                      ; allow
    lea rdx, [allow_val_h2]
    mov ecx, allow_val_h2_len
    call h2_enc_hdr
.no_allow_h2:
    ; a static path is content-negotiated even when it misses: a ".br" with no
    ; plain file beside it is served to whoever takes the encoding and 404s
    ; everyone else, so without Vary a shared cache stores this 404 under the
    ; bare URL and hands it to the very clients the variant was for (h1-15's
    ; sibling on h2). The negotiated 200 emits the same header at index 59.
    cmp qword [rsp + S_LSTAT], 404
    je .emit_vary_h2
    ; ...and the 406, which unlike the 404 depends on Accept-Encoding by
    ; definition rather than only on a static path (audit-report-37).
    cmp qword [rsp + S_LSTAT], 406
    jne .no_vary_h2
.emit_vary_h2:
    mov esi, 59                      ; vary: accept-encoding
    lea rdx, [h2_ae_name]
    mov ecx, h2_ae_name_len
    call h2_enc_hdr
.no_vary_h2:
    call h2_enc_date_server
    mov rbp, rdi
    sub rbp, r13                     ; payload length
    ; HEADERS frame header (END_HEADERS; a DATA frame follows)
    mov rdi, [rsp + S_OUT]
    mov rax, rbp
    shr rax, 16
    mov [rdi], al
    mov rax, rbp
    shr rax, 8
    mov [rdi + 1], al
    mov [rdi + 2], bpl
    mov byte [rdi + 3], LINNEA_H2_FT_HEADERS
    mov byte [rdi + 4], LINNEA_H2_FLAG_END_HEADERS
    mov rax, [rsp + S_SID]
    mov rdx, rax
    shr rax, 24
    mov [rdi + 5], al
    mov rax, rdx
    shr rax, 16
    mov [rdi + 6], al
    mov rax, rdx
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], dl
    ; DATA frame (the error body), END_STREAM
    mov rdi, [rsp + S_OUT]
    add rdi, 9
    add rdi, rbp
    mov rax, r15
    shr rax, 16
    mov [rdi], al
    mov rax, r15
    shr rax, 8
    mov [rdi + 1], al
    mov [rdi + 2], r15b
    mov byte [rdi + 3], LINNEA_H2_FT_DATA
    mov byte [rdi + 4], LINNEA_H2_FLAG_END_STREAM
    mov rax, [rsp + S_SID]
    mov rdx, rax
    shr rax, 24
    mov [rdi + 5], al
    mov rax, rdx
    shr rax, 16
    mov [rdi + 6], al
    mov rax, rdx
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], dl
    add rdi, 9
    mov rsi, r14
    mov rcx, r15
    rep movsb
    mov rax, rdi
    sub rax, [rsp + S_OUT]            ; total bytes written
    mov r13, rax                      ; keep it across the access line
    mov rdx, [rsp + S_LSTAT]
    mov rcx, [rsp + S_LBYTES]
    call .acc_line
    mov rax, r13
.out:
    add rsp, 152
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
; .acc_line(rdx=status, rcx=body bytes) — the access line for this stream,
; from rbx (conn), r12 (req) and h2_cur_srv. Register arguments only: the
; error path calls this with the stack as .flags sees it plus a return
; address, so rsp-relative slots would be off by eight.
.acc_line:
    mov [linnea_log_acc_status], rdx
    mov [linnea_log_acc_bytes], rcx
    lea rax, [proto_h2]
    mov [linnea_log_acc_proto], rax
    mov qword [linnea_log_acc_proto_len], proto_h2_len
    mov rax, [h2_cur_srv]
    lea rcx, [rax + linnea_config_server.hostname]
    mov [linnea_log_acc_host], rcx
    mov rcx, [rax + linnea_config_server.hostname_len]
    mov [linnea_log_acc_host_len], rcx
    lea rcx, [rbx + linnea_connection.peer]
    mov [linnea_log_acc_peer], rcx
    mov rcx, [rbx + linnea_connection.peer_len]
    mov [linnea_log_acc_peer_len], rcx
    mov rcx, [r12 + linnea_h2_req.method_ptr]
    mov [linnea_log_acc_meth], rcx
    mov rcx, [r12 + linnea_h2_req.method_len]
    mov [linnea_log_acc_meth_len], rcx
    mov rcx, [r12 + linnea_h2_req.path_ptr]
    mov [linnea_log_acc_tgt], rcx
    mov rcx, [r12 + linnea_h2_req.path_len]
    mov [linnea_log_acc_tgt_len], rcx
    jmp linnea_log_access

; =========================================================================
; proxy-over-h2 (Q86): a stream routed to a proxy location runs an HTTP/1.1
; exchange on its own upstream connection — the backend only ever speaks h1.
;
; Ownership: the request rewrite and the response bytes live in an upstream
; slot (linnea_h2p, one global array indexed by connection pool index so an
; io_uring completion can reach it from indices alone). The client-facing
; side keeps using the existing machinery: the response HEADERS are built
; into out_buf by h2p_service, and the body streams as DATA through
; h2_schedule's flow control, read straight out of the slot buffer.
;
; The one-op-per-connection invariant becomes one client op plus one op per
; upstream slot. conn.h2_tx_busy marks that a client send owns out_buf, so an
; upstream completion never builds frames underneath it; when the send drains,
; linnea_h2_after_send services whatever became ready meanwhile.
; =========================================================================

; linnea_h2p_init(rdi = connection pool size) — map the slot array.
linnea_h2p_init:
    push rbx
    mov rbx, rdi
    imul rdi, rdi, LINNEA_H2P_SLOTS * linnea_h2p_size
    call linnea_memory_map
    mov [h2p_pool], rax
    ; the HPACK decoder's per-connection dynamic table lives in the same
    ; shape: one lazily-mapped array indexed by connection pool index
    mov rdi, rbx
    imul rdi, rdi, linnea_hpack_dyn_size
    call linnea_memory_map
    mov [h2_dyn_pool], rax
    ; and the header-block assembly + decode scratch, one area per connection
    mov rdi, rbx
    imul rdi, rdi, LINNEA_H2_HB_AREA
    call linnea_memory_map
    mov [h2_hb_pool], rax
    pop rbx
    ret

; h2_dyn_for(rdi = conn) -> rax = its dynamic table, reset if it belongs to an
; earlier incarnation of this connection slot.
h2_dyn_for:
    mov rax, [rdi + linnea_connection.index]
    imul rax, rax, linnea_hpack_dyn_size
    add rax, [h2_dyn_pool]
    mov rcx, [rdi + linnea_connection.gen]
    cmp [rax + linnea_hpack_dyn.gen], rcx
    je .df_ret
    mov [rax + linnea_hpack_dyn.gen], rcx
    push rax
    mov rdi, rax
    call hpack_dyn_reset
    pop rax
.df_ret:
    ret

; linnea_h2p_at(rdi = conn index, rsi = slot index) -> rax = slot*.
linnea_h2p_at:
    mov rax, rdi
    imul rax, rax, LINNEA_H2P_SLOTS
    add rax, rsi
    imul rax, rax, linnea_h2p_size
    add rax, [h2p_pool]
    ret

; h2p_alloc(rdi = conn) -> rax = free slot* (0 = none), rdx = its index.
h2p_alloc:
    mov rdx, [rdi + linnea_connection.index]
    imul rdx, rdx, LINNEA_H2P_SLOTS
    imul rax, rdx, linnea_h2p_size
    add rax, [h2p_pool]
    xor edx, edx
.al_scan:
    cmp qword [rax + linnea_h2p.state], LINNEA_H2P_FREE
    je .al_hit
    add rax, linnea_h2p_size
    inc edx
    cmp edx, LINNEA_H2P_SLOTS
    jb .al_scan
    xor eax, eax
.al_hit:
    ret

; h2p_find_collect(rdi = conn, esi = stream id) -> rax = slot* still taking
; that stream's request body, or 0. COLLECT is now the whole answer: a slot
; taking a body has not connected yet, and one that has connected is no longer
; taking one. It used to have to admit a second, overlapping case — a STREAMING
; slot, which had already moved on to connecting and sending and went on
; accepting DATA behind that — and with it the FREE and ZOMBIE exclusions that
; only mattered because a stale flag could otherwise answer for a dead slot.
h2p_find_collect:
    mov rax, [rdi + linnea_connection.index]
    imul rax, rax, LINNEA_H2P_SLOTS
    imul rax, rax, linnea_h2p_size
    add rax, [h2p_pool]
    mov ecx, LINNEA_H2P_SLOTS
.fc_scan:
    cmp [rax + linnea_h2p.sid], rsi
    jne .fc_next
    cmp qword [rax + linnea_h2p.state], LINNEA_H2P_COLLECT
    je .fc_hit
.fc_next:
    add rax, linnea_h2p_size
    dec ecx
    jnz .fc_scan
    xor eax, eax
.fc_hit:
    ret

; h2p_kill(rdi = conn, esi = stream id) — abandon any upstream exchange for
; this stream (the client reset it, or the stream is gone). A slot with an op
; in flight becomes a ZOMBIE: its completion does the freeing, since the
; kernel still owns the buffer.
h2p_kill:
    push rbx
    push r12
    mov rax, [rdi + linnea_connection.index]
    imul rax, rax, LINNEA_H2P_SLOTS
    imul rax, rax, linnea_h2p_size
    add rax, [h2p_pool]
    ; the counter must be callee-saved: h2p_release issues a syscall, which
    ; clobbers rcx (and r11). A count kept in ecx would become a text address
    ; after the first release and the scan would run off the pool.
    mov r12d, LINNEA_H2P_SLOTS
.k_scan:
    cmp qword [rax + linnea_h2p.state], LINNEA_H2P_FREE
    je .k_next
    cmp qword [rax + linnea_h2p.state], LINNEA_H2P_ZOMBIE
    je .k_next
    cmp [rax + linnea_h2p.sid], rsi
    jne .k_next
    mov rbx, rax
    call h2p_release
    mov rax, rbx
.k_next:
    add rax, linnea_h2p_size
    dec r12d
    jnz .k_scan
    pop r12
    pop rbx
    ret

; h2p_release(rax = slot*) — close the upstream fd and free the slot, or park
; it as a ZOMBIE when an op is still in flight. Preserves rax.
h2p_release:
    test qword [rax + linnea_h2p.flags], LINNEA_H2P_F_INFLIGHT
    jnz .rel_zombie
    ; A complete response says this backend is working. BODY_DONE is exactly
    ; that claim -- h2 refuses to set it for a truncated body (Finding 31).
    test qword [rax + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jz .rel_not_ok
    push rax
    mov rdi, [rax + linnea_h2p.location]
    mov rsi, [rax + linnea_h2p.backend]
    call linnea_upstream_mark_ok
    pop rax
.rel_not_ok:
    ; Keep the connection on the same terms h1 and h3 use. BODY_DONE is what
    ; says the response ended where its framing promised -- h2 refuses to set it
    ; for a truncated body (Finding 31). F_EOF excludes the close-delimited
    ; case, which reaches BODY_DONE legitimately but does so because the peer
    ; hung up: that socket is already gone.
    cmp dword [rax + linnea_h2p.fd], -1
    je .rel_close
    cmp qword [rax + linnea_h2p.reusable], 0
    je .rel_close
    cmp qword [rax + linnea_h2p.no_reuse], 0
    jne .rel_close
    test qword [rax + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jz .rel_close
    test qword [rax + linnea_h2p.flags], LINNEA_H2P_F_EOF
    jnz .rel_close
    push rax
    mov rdi, [rax + linnea_h2p.location]
    mov rsi, [rax + linnea_h2p.backend]
    mov edx, [rax + linnea_h2p.fd]
    call linnea_upstream_park
    pop rcx                          ; the slot; this function preserves it
    test eax, eax
    jz .rel_kept
    mov dword [rcx + linnea_h2p.fd], -1   ; the pool owns it; nothing to close
.rel_kept:
    mov rax, rcx
.rel_close:
    push rax
    mov edi, [rax + linnea_h2p.fd]
    cmp edi, -1
    je .rel_nofd
    mov eax, LINNEA_SYS_CLOSE
    syscall
    call linnea_upstream_closed
.rel_nofd:
    pop rax
    mov dword [rax + linnea_h2p.fd], -1
    push rax
    mov rdi, rax
    call h2p_capture_release         ; unmap and close: the close IS the delete
    pop rax
    ; scrub what the walkers act on: a stale WANT_* would arm an op on the
    ; closed fd, a stale HEAD_RDY would emit a HEADERS frame for a stream
    ; that no longer exists, and a stale credit a WINDOW_UPDATE on an idle
    ; stream — which is a connection error to the peer
    mov rsi, [rax + linnea_h2p.flags]            ; read BEFORE the scrub
    mov qword [rax + linnea_h2p.flags], 0
    ; the connection still owes the peer for every request-body byte it sent:
    ; what went upstream uncredited, plus whatever is still sitting in the FIFO.
    ; A CAPTURED body owes nothing — its bytes were credited as they were
    ; written to the file, so counting the unsent remainder here would credit
    ; the same bytes twice and overflow the peer's connection window.
    test rsi, LINNEA_H2P_F_REQ_FILE
    jnz .rel_owed_done
    mov rcx, [rax + linnea_h2p.rq_credit]
    mov rdx, [rax + linnea_h2p.rq_wr]
    sub rdx, [rax + linnea_h2p.rq_rd]
    add rcx, rdx
    add [rax + linnea_h2p.rq_owed], rcx
.rel_owed_done:
    mov qword [rax + linnea_h2p.rq_rd], 0
    mov qword [rax + linnea_h2p.rq_wr], 0
    mov qword [rax + linnea_h2p.rq_credit], 0
    mov qword [rax + linnea_h2p.rq_buf], 0
    mov qword [rax + linnea_h2p.sid], 0
    mov qword [rax + linnea_h2p.state], LINNEA_H2P_FREE
    ret
.rel_zombie:
    ; the kernel may still write into the buffer: shut the socket down so the
    ; op completes promptly, and let that completion close and free
    push rax
    mov edi, [rax + linnea_h2p.fd]
    cmp edi, -1
    je .rel_z_nofd
    mov esi, 2                       ; SHUT_RDWR
    mov eax, LINNEA_SYS_SHUTDOWN
    syscall
.rel_z_nofd:
    pop rax
    mov qword [rax + linnea_h2p.state], LINNEA_H2P_ZOMBIE
    ret

; linnea_h2p_conn_close(rdi = conn) — release every slot of a dying
; connection. Called from the io_uring teardown beside linnea_h2_conn_free.
linnea_h2p_conn_close:
    push rbx
    push r12
    mov rax, [rdi + linnea_connection.index]
    imul rax, rax, LINNEA_H2P_SLOTS
    imul rax, rax, linnea_h2p_size
    add rax, [h2p_pool]
    mov r12d, LINNEA_H2P_SLOTS
.cc_scan:
    mov qword [rax + linnea_h2p.rq_owed], 0   ; the connection it was owed to
    cmp qword [rax + linnea_h2p.state], LINNEA_H2P_FREE
    je .cc_next
    cmp qword [rax + linnea_h2p.state], LINNEA_H2P_ZOMBIE
    je .cc_next
    mov rbx, rax
    call h2p_release
    mov rax, rbx
.cc_next:
    add rax, linnea_h2p_size
    dec r12d
    jnz .cc_scan
    pop r12
    pop rbx
    ret

; h2p_capture(rdi = slot*, rsi = payload, rdx = len) -> rax = 0 ok, -1 failed.
; Append request-body bytes to the slot's capture file, opening it on first
; use — and, on that first use, moving the bytes already buffered in the slot
; into the file ahead of them, so the file always holds the body from byte 0.
; slot.len is the body length so far and doubles as the write offset.
h2p_capture:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    cmp dword [rbx + linnea_h2p.rq_fd], -1
    jne .cap_write
    call linnea_spill_open_fd
    test eax, eax
    js .cap_fail
    mov [rbx + linnea_h2p.rq_fd], eax
    ; the prefix that fitted in the slot goes first, at offset 0
    mov r14, [rbx + linnea_h2p.len]
    test r14, r14
    jz .cap_write
    lea rsi, [rbx + linnea_h2p.buf + LINNEA_H2P_BODY_OFF]
    xor edx, edx
    mov rdi, rbx
    mov rcx, r14
    call h2p_pwrite
    test eax, eax
    js .cap_fail
.cap_write:
    mov rsi, r12
    mov rdx, [rbx + linnea_h2p.len]
    mov rdi, rbx
    mov rcx, r13
    call h2p_pwrite
    test eax, eax
    js .cap_fail
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.cap_fail:
    mov eax, -1
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2p_pwrite(rdi = slot*, rsi = buf, rdx = file offset, rcx = len)
;   -> rax = 0 ok, -1 failed.
; A regular file writes short only on a full filesystem or a signal, so the
; loop is for correctness rather than the common case — the same reasoning as
; linnea_spill_write, which cannot be reused here because it is keyed on the
; connection and an h2 capture belongs to one stream of several.
h2p_pwrite:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
.pw_loop:
    test r14, r14
    jz .pw_done
    mov eax, LINNEA_SYS_PWRITE64
    mov edi, [rbx + linnea_h2p.rq_fd]
    mov rsi, r12
    mov rdx, r14
    mov r10, r13
    syscall
    cmp rax, -4095
    jae .pw_retry
    test rax, rax
    jz .pw_fail                      ; no progress: a full filesystem
    add r12, rax
    add r13, rax
    sub r14, rax
    jmp .pw_loop
.pw_retry:
    cmp rax, -LINNEA_EINTR
    je .pw_loop
    cmp rax, -LINNEA_EAGAIN
    je .pw_loop
.pw_fail:
    mov eax, -1
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.pw_done:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2p_capture_map(rdi = slot*) -> rax = 0 ok, -1 failed.
; The body is complete in the file: map it and point the send at it. rq_buf
; and rq_rd/rq_wr are the streaming path's cursors, so the send needs no new
; case beyond not sliding a mapping it cannot make room in.
h2p_capture_map:
    push rbx
    mov rbx, rdi
    mov rdx, [rbx + linnea_h2p.len]
    test rdx, rdx
    jz .cm_empty                     ; captured nothing: nothing to map
    mov eax, LINNEA_SYS_MMAP
    xor edi, edi
    mov rsi, rdx
    mov edx, LINNEA_PROT_READ
    mov r10d, LINNEA_MAP_PRIVATE
    mov r8d, [rbx + linnea_h2p.rq_fd]
    xor r9d, r9d
    syscall
    cmp rax, -4095
    jae .cm_fail
    mov [rbx + linnea_h2p.rq_map], rax
    mov [rbx + linnea_h2p.rq_buf], rax
    mov rdx, [rbx + linnea_h2p.len]
    mov [rbx + linnea_h2p.rq_maplen], rdx
    mov [rbx + linnea_h2p.rq_wr], rdx
    mov qword [rbx + linnea_h2p.rq_rd], 0
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_REQ_FILE
.cm_empty:
    xor eax, eax
    pop rbx
    ret
.cm_fail:
    mov eax, -1
    pop rbx
    ret

; h2p_capture_release(rdi = slot*) — unmap and close, whichever exist. The
; close IS the delete (O_TMPFILE), so this is the whole cleanup. Called from
; every path that gives a slot up.
h2p_capture_release:
    push rbx
    mov rbx, rdi
    mov rax, [rbx + linnea_h2p.rq_map]
    test rax, rax
    jz .cr_nomap
    push rax
    mov eax, LINNEA_SYS_MUNMAP
    pop rdi
    mov rsi, [rbx + linnea_h2p.rq_maplen]
    syscall
    mov qword [rbx + linnea_h2p.rq_map], 0
    mov qword [rbx + linnea_h2p.rq_maplen], 0
.cr_nomap:
    mov edi, [rbx + linnea_h2p.rq_fd]
    cmp edi, -1
    je .cr_nofd
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov dword [rbx + linnea_h2p.rq_fd], -1
.cr_nofd:
    pop rbx
    ret

; h2p_finalize(rdi = slot*) — the request is complete: append Content-Length
; (when a body was collected) and the empty line, open the upstream socket
; and ask the loop to connect.
h2p_finalize:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, [rbx + linnea_h2p.len]        ; collected body length
    lea rdi, [rbx + linnea_h2p.buf]
    add rdi, [rbx + linnea_h2p.req_len]
    test r12, r12
    jnz .fin_clen
    ; No bytes -- but "no body" and "a body of no bytes" are different requests
    ; upstream, and only the second one declares a length. h1 forwards
    ; "Content-Length: 0" for it; h2 sent nothing at all, so a backend that
    ; requires a length answered 411 to an empty upload.
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_HAS_CL
    jz .fin_nobody
.fin_clen:
    push rdi
    lea rsi, [h2p_clen]                    ; "Content-Length: "
    mov ecx, h2p_clen_len
    pop rdi
    push rdi
    rep movsb
    mov [rbx + linnea_h2p.rd], rdi         ; scratch: the write cursor
    mov rdi, r12
    lea rsi, [h2p_numbuf]
    call linnea_string_from_u64
    mov rdi, [rbx + linnea_h2p.rd]
    lea rsi, [h2p_numbuf]
    mov rcx, rax
    rep movsb
    mov word [rdi], 0x0a0d
    add rdi, 2
    pop rax                                ; (balance the pushed cursor)
.fin_nobody:
    lea rsi, [h2p_via]                     ; RFC 9110 7.6.3: name this hop
    mov ecx, h2p_via_len
    rep movsb
    ; Keep the connection when this location opted in and the method may be
    ; sent again -- the same rule and reasons as h1 and h3. The method is the
    ; first token of the head this function is finishing, which is the only
    ; place h2p has it: the leg carries no request struct.
    push rdi                               ; the write cursor rep movsb needs
    mov qword [rbx + linnea_h2p.reusable], 0
    mov rcx, [rbx + linnea_h2p.location]
    test rcx, rcx
    jz .fin_conn_close
    cmp qword [rcx + linnea_config_location.proxy_keepalive], 0
    je .fin_conn_close
    ; A TLS backend leg is never parked, the same rule the h1 leg has carried
    ; since backend TLS landed: a parked kTLS socket carries kernel crypto state
    ; the pool does not track, and the taker sends its head with none of it set
    ; up. Until then the only thing keeping such a leg out of the pool was the
    ; "connection: close" the h2 driver stamps on every synthesized response —
    ; incidental, and nothing at all for a plain proxy_tls leg (audit-report-41).
    cmp qword [rcx + linnea_config_location.proxy_tls], 0
    jne .fin_conn_close
    lea rdi, [rbx + linnea_h2p.buf]
    xor ecx, ecx
.fin_meth_scan:
    cmp ecx, 8
    jae .fin_conn_close                    ; no space in 8: not GET or HEAD
    cmp byte [rdi + rcx], ' '
    je .fin_meth_found
    inc ecx
    jmp .fin_meth_scan
.fin_meth_found:
    mov rsi, rcx
    call linnea_upstream_method_safe
    test eax, eax
    jz .fin_conn_close
    mov qword [rbx + linnea_h2p.reusable], 1
    pop rdi
    lea rsi, [h2p_conn_keep]
    mov ecx, h2p_conn_keep_len
    rep movsb
    jmp .fin_conn_done
.fin_conn_close:
    pop rdi
    lea rsi, [h2p_conn_close]              ; "Connection: close" CRLF CRLF
    mov ecx, h2p_conn_close_len
    rep movsb
.fin_conn_done:
    ; the collected body follows the head — unless it outgrew the slot and was
    ; captured to a file, in which case it is sent from a mapping instead and
    ; the head must stay head-only
    test r12, r12
    jz .fin_head_only
    cmp dword [rbx + linnea_h2p.rq_fd], -1
    jne .fin_head_only
    lea rsi, [rbx + linnea_h2p.buf + LINNEA_H2P_BODY_OFF]
    mov rcx, r12
    rep movsb
.fin_head_only:
    lea rax, [rbx + linnea_h2p.buf]
    sub rdi, rax
    mov [rbx + linnea_h2p.req_len], rdi
    mov qword [rbx + linnea_h2p.rd], 0
    ; a captured body is mapped BEFORE len is cleared — the map takes its size
    ; from it, and buf becomes the response buffer straight after
    cmp dword [rbx + linnea_h2p.rq_fd], -1
    je .fin_nofile
    mov rdi, rbx
    call h2p_capture_map
    test eax, eax
    js .fin_capture_failed
.fin_nofile:
    mov qword [rbx + linnea_h2p.len], 0    ; buf is the response buffer now
    mov rdi, rbx
    call h2p_open_upstream
    pop r12
    pop rbx
    ret
.fin_capture_failed:
    ; the body is on disk but unreadable: 500, because the client's upload was
    ; fine and it was us that could not carry it — 413 would blame the request
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [rbx + linnea_h2p.status], 500
    pop r12
    pop rbx
    ret

; h2p_open_upstream(rdi = slot*) — open the socket and ask the loop to
; connect; a socket we cannot even open fails the exchange with a 502.
h2p_open_upstream:
    push rbx
    mov rbx, rdi
    ; the backend first: a parked connection belongs to exactly one of them
    mov qword [rbx + linnea_h2p.no_reuse], 0
    mov qword [rbx + linnea_h2p.pooled], 0
    mov rdi, [rbx + linnea_h2p.location]
    call linnea_upstream_pick
    mov [rbx + linnea_h2p.backend], rax
    mov qword [rbx + linnea_h2p.tries], 1
    cmp qword [rbx + linnea_h2p.reusable], 0
    je .ou_fresh
    mov rdi, [rbx + linnea_h2p.location]
    mov rsi, [rbx + linnea_h2p.backend]
    call linnea_upstream_take
    cmp eax, -1
    je .ou_fresh
    mov [rbx + linnea_h2p.fd], eax
    mov qword [rbx + linnea_h2p.pooled], 1
    ; already connected: this leg starts at the send
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_SENDING
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND
    pop rbx
    ret
.ou_fresh:
    ; The ceiling is consulted HERE, and only here, because only this branch
    ; opens a descriptor. A parked connection is already counted against
    ; max_upstream -- it is a live backend connection -- so refusing to look in
    ; the pool because the count is full is the ceiling refusing its own
    ; inventory. Worse than a wasted reuse: `take` is the only thing that reaps
    ; an expired pool entry, so an early refusal never reclaims the descriptor
    ; either, and the location stays 503 rather than recovering after the idle
    ; expiry (audit-report-39). h1 has had this ordering since the pool landed;
    ; h2 and h3 kept the old one.
.ou_ceiling:
    call linnea_upstream_count
    cmp rax, [linnea_upstream_limit]
    jb .ou_room
    call linnea_upstream_reap_one     ; an idle parked socket yields to a request
    test eax, eax
    jnz .ou_ceiling                    ; freed one: re-check the ceiling
    jmp .ou_busy                       ; genuinely at capacity with live requests
.ou_room:
    mov rdi, [rbx + linnea_h2p.location]
    mov rsi, [rbx + linnea_h2p.backend]
    call linnea_upstream_socket
    cmp rax, -4095
    jae .ou_nosock
    mov [rbx + linnea_h2p.fd], eax
    call linnea_upstream_open
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_CONNECTING
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_CONN
    pop rbx
    ret
.ou_nosock:
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [rbx + linnea_h2p.status], 502
    pop rbx
    ret
.ou_busy:
    ; at the ceiling: 503, which says "try again", rather than 502, which says
    ; the backend answered badly — it was never asked
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [rbx + linnea_h2p.status], 503
    pop rbx
    ret

; h2p_reconnect(rdi = h2p slot) -> eax = 0 armed, -1 could not
; The failed socket goes first: it cannot be reused and holding it would leak a
; descriptor for the life of the exchange.
h2p_reconnect:
    push rbx
    mov rbx, rdi
    mov edi, [rbx + linnea_h2p.fd]
    cmp edi, -1
    je .rc_nofd
    mov eax, LINNEA_SYS_CLOSE
    syscall
    call linnea_upstream_closed
    mov dword [rbx + linnea_h2p.fd], -1
.rc_nofd:
    ; the backend BEFORE the socket, as in linnea_uring_up_reconnect
    mov rdi, [rbx + linnea_h2p.location]
    call linnea_upstream_pick
    mov [rbx + linnea_h2p.backend], rax
    mov rdi, [rbx + linnea_h2p.location]
    mov rsi, rax
    call linnea_upstream_socket
    cmp rax, -4095
    jae .rc_fail
    mov [rbx + linnea_h2p.fd], eax
    call linnea_upstream_open
    inc qword [rbx + linnea_h2p.tries]
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_CONNECTING
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_CONN
    xor eax, eax
    pop rbx
    ret
.rc_fail:
    mov eax, -1
    pop rbx
    ret

; h2p_retry_pooled(rdi = h2p slot) -> eax = 0 armed, -1 could not
; A connection taken from the idle pool died at send or before its first
; response byte -- the idle-timeout race the GET/HEAD-only reuse rule exists to
; absorb. Resend on a FRESH connection to the SAME backend (unlike h2p_reconnect,
; which moves to the next one on a connect failure). It is not a backend failure:
; no health is counted and the attempt count is untouched, and it can happen only
; once because the leg is no longer pooled afterwards. The request buffer is
; intact -- callers gate on len == 0 -- so only the send cursor is rewound.
h2p_retry_pooled:
    push rbx
    mov rbx, rdi
    mov edi, [rbx + linnea_h2p.fd]
    cmp edi, -1
    je .rt_nofd
    mov eax, LINNEA_SYS_CLOSE
    syscall
    call linnea_upstream_closed
    mov dword [rbx + linnea_h2p.fd], -1
.rt_nofd:
    mov rdi, [rbx + linnea_h2p.location]
    mov rsi, [rbx + linnea_h2p.backend]     ; the SAME backend
    call linnea_upstream_socket
    cmp rax, -4095
    jae .rt_fail
    mov [rbx + linnea_h2p.fd], eax
    call linnea_upstream_open
    mov qword [rbx + linnea_h2p.pooled], 0     ; a fresh leg now: no second retry
    mov qword [rbx + linnea_h2p.sent], 0       ; replay the request from the top
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_CONNECTING
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_CONN
    xor eax, eax
    pop rbx
    ret
.rt_fail:
    mov eax, -1
    pop rbx
    ret

; --- proxy_h2 leg helpers: the slot's fixed position in h2p_pool encodes its
; linear index (conn.index*SLOTS + slot), which keys its TLS + h2c arenas. This
; avoids threading the (conn,slot) pair through the event handler. rbx = slot*.
h2p_leg_linear:
    mov rax, rbx
    sub rax, [h2p_pool]
    xor edx, edx
    mov rcx, linnea_h2p_size
    div rcx
    ret
h2p_slot_hs:                          ; -> rax = linnea_tls_client_hs
    mov rdi, [rbx + linnea_h2p.leg_lin]
    jmp linnea_h2p_tls_hs_for
h2p_slot_ctx:                         ; -> rax = linnea_h2c driver context
    mov rdi, [rbx + linnea_h2p.leg_lin]
    jmp linnea_h2p_h2c_for

; linnea_h2p_event(rdi = conn, rsi = slot index, edx = op tag, ecx = result)
;   -> rax = 1 when the connection has frames to flush (out_ptr/out_rem set),
;      else 0. The io_uring loop's upstream-completion hook: advance the
;      exchange, then service whatever became ready.
linnea_h2p_event:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi                     ; conn
    mov r14d, ecx                    ; result
    mov r13d, edx                    ; tag
    mov rdi, [rdi + linnea_connection.index]
    call linnea_h2p_at
    mov rbx, rax                     ; slot*
    and qword [rbx + linnea_h2p.flags], ~LINNEA_H2P_F_INFLIGHT
    ; the connection this exchange belonged to may have closed — and its pool
    ; slot may already serve a different client. Anything but an exact
    ; generation match means the completion is stale: free the slot and tell
    ; the caller to leave the connection alone.
    mov rax, [rbx + linnea_h2p.gen]
    cmp rax, [r12 + linnea_connection.gen]
    jne .ev_stale
    cmp dword [r12 + linnea_connection.fd], -1
    je .ev_stale                     ; the connection closed under this op
    cmp qword [rbx + linnea_h2p.state], LINNEA_H2P_ZOMBIE
    je .ev_zombie
    cmp r13d, LINNEA_UD_H2UP_CONNECT
    je .ev_connect
    cmp r13d, LINNEA_UD_H2UP_SEND
    je .ev_send
    ; --- recv completion: route the proxy_h2 sub-states first ---
    cmp qword [rbx + linnea_h2p.state], LINNEA_H2P_TLS
    je .ev_tls_recv
    cmp qword [rbx + linnea_h2p.state], LINNEA_H2P_H2
    je .ev_h2_recv
    ; --- recv: response bytes (or EOF / error) ---
    test r14d, r14d
    js .ev_recv_err
    jz .ev_eof
    ; A kTLS leg (a plain proxy_tls backend) gets one TLS RECORD per read, with
    ; its type in a cmsg. A backend's NewSessionTicket is a control record, not
    ; response bytes: counting it into .len would feed ticket bytes to the head
    ; parser. Skip it and read again; an alert is the close it announces.
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_KTLS
    jz .ev_recv_data
    mov rdi, rbx                     ; slot
    call h2p_krx_rectype             ; eax: 0 data, 1 skip-control, 2 eof(alert)
    cmp eax, 1
    je .ev_want_more
    cmp eax, 2
    je .ev_eof
.ev_recv_data:
    add [rbx + linnea_h2p.len], r14d
    cmp qword [rbx + linnea_h2p.state], LINNEA_H2P_HEAD
    jne .ev_relay_data
    mov rdi, rbx
    call h2p_parse_head              ; -> rax = 1 parsed, 0 need more, -1 bad, 2 interim
    test rax, rax
    js .ev_bad_gateway
    jz .ev_want_more                 ; the head is not complete yet
    cmp rax, 2
    je .ev_interim                   ; a 1xx head: relay it, keep reading (Finding 30)
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_RELAY
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_HEAD_RDY
.ev_relay_data:
    mov rdi, rbx
    call h2p_decode                  ; advance the de-chunk / length decode
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_DEC_ERR
    jnz .ev_bad_gateway              ; malformed chunk framing (Finding 31)
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jnz .ev_service
    jmp .ev_want_more
.ev_eof:
    ; the upstream closed. Before the head, that is a bad gateway; during a
    ; close-delimited body it is the legitimate end.
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_EOF
    cmp qword [rbx + linnea_h2p.state], LINNEA_H2P_RELAY
    jne .ev_eof_nohead
    mov rdi, rbx
    call h2p_decode
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jnz .ev_service                  ; the decode reached the true end
    ; Not complete at EOF (Finding 31): the old code set BODY_DONE unconditionally,
    ; so a fixed-length body cut short or a chunked body missing its 0-size chunk
    ; was ended with a clean END_STREAM -- the client saw a complete-but-truncated
    ; response. Only a CLOSE-DELIMITED body (no Content-Length, not chunked:
    ; body_rem == -1 with chunked clear) legitimately ends at EOF. A truncated body
    ; is a bad gateway, which .ev_fail turns into a 502 before the head or an
    ; RST_STREAM after it -- the same routing a mid-stream upstream error takes.
    cmp qword [rbx + linnea_h2p.chunked], 0
    jne .ev_bad_gateway              ; chunked without its terminating 0-chunk
    cmp qword [rbx + linnea_h2p.body_rem], -1
    jne .ev_bad_gateway              ; fixed-length, still owed bytes
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jmp .ev_service
.ev_eof_nohead:
    cmp qword [rbx + linnea_h2p.pooled], 0
    jne .ev_pooled_retry       ; a parked socket that closed before answering
    jmp .ev_bad_gateway
.ev_recv_err:
    cmp qword [rbx + linnea_h2p.pooled], 0
    jne .ev_pooled_retry       ; a dead parked socket: resend, do not blame it
    cmp r14d, -LINNEA_ECANCELED
    je .ev_timeout
    jmp .ev_bad_gateway
; A leg from the idle pool failed at send or before its first response byte --
; the idle-timeout race the GET/HEAD-only reuse rule exists to absorb. Resend
; once on a fresh connection rather than answering, and rather than charging the
; backend for a socket it parked and closed. Only while nothing has arrived: past
; that the request buffer holds response bytes and the backend has answered.
.ev_pooled_retry:
    cmp qword [rbx + linnea_h2p.len], 0
    jne .ev_bad_gateway        ; a response already began: not retriable
    mov rdi, rbx
    call h2p_retry_pooled
    test eax, eax
    js .ev_bad_gateway_counted ; could not resend: fail without a health strike
    jmp .ev_service
.ev_connect:
    test r14d, r14d
    js .ev_conn_failed
    ; Health is cleared at COMPLETION, in h2p_release. Accepting a connection is
    ; not evidence a backend works: one that accepts and then times out every
    ; time would have its counter zeroed here on each attempt and could never
    ; reach the threshold.
    ; A proxy_tls backend runs the TLS 1.3 handshake (SPKI pin) on this slot's fd
    ; before any request. What follows the handshake is what ALPN asked for: an
    ; h2 driver for a proxy_h2 backend, the ordinary HTTP/1.1 send for a plain
    ; one. The h1 and h3 legs have keyed this off proxy_tls since the backend
    ; client landed; the h2p leg keyed it off proxy_h2, so an h2 CLIENT reaching
    ; a plain proxy_tls location sent its request head in cleartext to a backend
    ; expecting records — an unfailable 502 for a documented configuration.
    mov rax, [rbx + linnea_h2p.location]
    cmp qword [rax + linnea_config_location.proxy_tls], 0
    jne .ev_connect_tls
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_SENDING
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND
    jmp .ev_service
.ev_connect_tls:
    call h2p_leg_linear               ; rbx = slot -> rax = linear slot index
    mov [rbx + linnea_h2p.leg_lin], rax
    mov rdi, rax
    call linnea_h2p_tls_hs_for        ; rax = this leg's TLS handshake arena
    mov rdi, rax
    mov r8, [rbx + linnea_h2p.location]
    ; ALPN offer: h2 when this is a proxy_h2 backend, else http/1.1. The arena is
    ; reused, so set it every connect (stale otherwise) — the same rule the h1/h3
    ; leg follows in linnea_uring.asm .connect_tls.
    mov rcx, [r8 + linnea_config_location.proxy_h2]
    mov [rdi + linnea_tls_client_hs.alpn_sel], rcx
    lea rsi, [r8 + linnea_config_location.proxy_pin]
    lea rdx, [r8 + linnea_config_location.proxy_sni]
    mov rcx, [r8 + linnea_config_location.proxy_sni_len]
    call linnea_tls_client_start      ; ClientHello into hs.out
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_TLS
    mov qword [rbx + linnea_h2p.leg_sent], 0
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND
    mov rax, [rbx + linnea_h2p.location]
    cmp qword [rax + linnea_config_location.proxy_h2], 0
    je .ev_service                    ; a plain TLS leg: no h2 driver to mark
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_PROXY_H2
    jmp .ev_service
.ev_conn_failed:
    ; the h2 twin of the h1/h3 failover in linnea_uring.asm: count the failure,
    ; then move to the next backend while nothing of the request has been sent.
    ; r14d holds the result and must survive the calls.
    push r14
    mov rdi, [rbx + linnea_h2p.location]
    mov rsi, [rbx + linnea_h2p.backend]
    mov edx, r14d                     ; the cause, while we still have it
    call linnea_upstream_mark_fail
    pop r14
    mov rax, [rbx + linnea_h2p.location]
    mov rax, [rax + linnea_config_location.proxy_count]
    cmp [rbx + linnea_h2p.tries], rax
    jae .ev_conn_giveup
    mov rdi, rbx
    call h2p_reconnect
    test eax, eax
    js .ev_conn_giveup
    jmp .ev_service
.ev_conn_giveup:
    ; each attempt was counted in .ev_conn_failed; enter past the counter
    cmp r14d, -LINNEA_ECANCELED
    je .ev_timeout_counted
    jmp .ev_bad_gateway_counted

.ev_send:
    cmp qword [rbx + linnea_h2p.state], LINNEA_H2P_TLS
    je .ev_tls_send
    cmp qword [rbx + linnea_h2p.state], LINNEA_H2P_H2
    je .ev_h2_send
    test r14d, r14d
    js .ev_send_err
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_REQ_FILE
    jnz .ev_send_file
    add [rbx + linnea_h2p.sent], r14d
    mov rax, [rbx + linnea_h2p.sent]
    cmp rax, [rbx + linnea_h2p.req_len]
    jb .ev_send_more
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_HEAD
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV
    jmp .ev_service
.ev_send_file:
    ; a captured request: head first, then straight out of the mapping. No
    ; slide — a mapping has no window to make room in — and no credit, because
    ; these bytes were credited back to the client as they were captured.
    mov rax, [rbx + linnea_h2p.sent]
    cmp rax, [rbx + linnea_h2p.req_len]
    jae .ev_file_body
    add [rbx + linnea_h2p.sent], r14d          ; still the head
    jmp .ev_file_next
.ev_file_body:
    mov eax, r14d
    add [rbx + linnea_h2p.rq_rd], rax
.ev_file_next:
    mov rax, [rbx + linnea_h2p.sent]
    cmp rax, [rbx + linnea_h2p.req_len]
    jb .ev_send_more                           ; head not fully out
    mov rax, [rbx + linnea_h2p.rq_rd]
    cmp rax, [rbx + linnea_h2p.rq_wr]
    jb .ev_send_more                           ; mapping has bytes left
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_REQ_DONE
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_HEAD
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV
    jmp .ev_service

.ev_send_more:
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND
    jmp .ev_service
.ev_send_err:
    cmp qword [rbx + linnea_h2p.pooled], 0
    jne .ev_pooled_retry       ; a dead parked socket: resend, do not blame it
    cmp r14d, -LINNEA_ECANCELED
    je .ev_timeout
    jmp .ev_bad_gateway
.ev_want_more:
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV
    jmp .ev_service
.ev_interim:
    ; a 1xx informational head (Finding 30). Mark it for the scheduler, which
    ; relays it without END_STREAM and resumes parsing the next head from the
    ; buffer. RELAY is the "head parsed" state; F_HEAD_INTERIM tells .sv_head to
    ; take the interim path rather than finalise the stream.
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_RELAY
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_HEAD_RDY | LINNEA_H2P_F_HEAD_INTERIM
    jmp .ev_service
.ev_timeout:
    ; the backend accepted and then did not answer in time: counted against
    ; SELECTION, never retried -- the head is already out (see .proxy_fail in
    ; linnea_uring.asm for the full reasoning; the two must agree)
    mov rdi, [rbx + linnea_h2p.location]
    mov rsi, [rbx + linnea_h2p.backend]
    call linnea_upstream_mark_unanswered
.ev_timeout_counted:
    mov qword [rbx + linnea_h2p.status], 504
    jmp .ev_fail
.ev_bad_gateway:
    ; likewise: a closed connection, a send error, framing we will not relay.
    ; NOT a 5xx from the application, which never reaches here.
    ; ...and NOT a response head past HDRBLK_CAP either: the backend delivered
    ; that correctly and only our buffer objected, so it is logged as ours and
    ; kept out of the health counters (see linnea_upstream_log_oversize).
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_HDR_BIG
    jnz .ev_bg_oursize               ; a buffer of ours said no, whatever the leg
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_PROXY_H2
    jz .ev_bg_count
    call h2p_slot_ctx
    cmp qword [rax + linnea_h2c.hdr_big], 0
    je .ev_bg_count
.ev_bg_oursize:
    mov rdi, [rbx + linnea_h2p.location]
    mov rsi, [rbx + linnea_h2p.backend]
    call linnea_upstream_log_oversize
    jmp .ev_bad_gateway_counted
.ev_bg_count:
    mov rdi, [rbx + linnea_h2p.location]
    mov rsi, [rbx + linnea_h2p.backend]
    call linnea_upstream_mark_unanswered
.ev_bad_gateway_counted:
    mov qword [rbx + linnea_h2p.status], 502
.ev_fail:
    ; close the upstream now; the client still needs an answer, so the slot
    ; lives until the service emits the error (or a RST mid-response)
    mov edi, [rbx + linnea_h2p.fd]
    cmp edi, -1
    je .ev_fail_nofd
    mov eax, LINNEA_SYS_CLOSE
    syscall
    call linnea_upstream_closed   ; release the ceiling slot here: setting fd
                                  ; to -1 makes the later free skip its decrement
    mov dword [rbx + linnea_h2p.fd], -1
.ev_fail_nofd:
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_FAILED
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_HEAD_SENT
    jz .ev_service
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_RST
    jmp .ev_service                   ; RST the stream via the service pass. This
                                      ; jmp was a fall-through into .ev_service
                                      ; until the proxy_h2 leg handlers below were
                                      ; inserted between the two; without it a
                                      ; head-sent failure with an errored op falls
                                      ; into .ev_tls_send -> .ev_bad_gateway ->
                                      ; back here, an infinite mark_unanswered loop.
; ============================================================================
; proxy_h2 leg sub-state handlers: TLS handshake, then the h2 driver, over .fd.
; The recv landing for both is the leg's h2c out_buf (free during these phases);
; the arming (.ao_send/.ao_recv in linnea_uring.asm) picks the buffer by state.
; r12=conn, rbx=slot; tls_client_* and drv_* preserve rbx and r12.
; ============================================================================
.ev_tls_send:
    test r14d, r14d
    js .ev_bad_gateway
    add [rbx + linnea_h2p.leg_sent], r14
    call h2p_slot_hs                  ; rax = hs
    mov rcx, [rbx + linnea_h2p.leg_sent]
    cmp rcx, [rax + linnea_tls_client_hs.out_len]
    jb .ev_tls_want_send
    cmp qword [rax + linnea_tls_client_hs.state], LINNEA_CLIENT_HS_DONE
    je .ev_tls_handoff                ; the client Finished just went out
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV   ; read the flight
    jmp .ev_service
.ev_tls_want_send:
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND
    jmp .ev_service
.ev_tls_recv:
    test r14d, r14d
    jle .ev_bad_gateway               ; eof/err during the handshake -> 502
    call h2p_slot_ctx                 ; rax = ctx (the recv landed in ctx.out_buf)
    lea rsi, [rax + linnea_h2c.out_buf]
    mov edx, r14d
    call h2p_slot_hs                  ; rax = hs
    mov rdi, rax
    call linnea_tls_client_input      ; -> MORE(0) / DONE(1) / FAIL(-1)
    cmp rax, LINNEA_CLIENT_FAIL
    je .ev_bad_gateway
    cmp rax, LINNEA_CLIENT_DONE
    je .ev_tls_recv_fin
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV    ; MORE
    jmp .ev_service
.ev_tls_recv_fin:
    mov qword [rbx + linnea_h2p.leg_sent], 0
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND    ; send Finished
    jmp .ev_service
.ev_tls_handoff:
    ; hand .fd to kTLS (client orientation: TX=c_ap, RX=s_ap, app seqs 0), then
    ; start the h2 driver with the request head h2p_claim built in .buf.
    call h2p_slot_hs                  ; rax = hs
    mov edi, [rbx + linnea_h2p.fd]
    lea rsi, [rax + linnea_tls_client_hs.c_ap]
    lea rdx, [rax + linnea_tls_client_hs.s_ap]
    xor ecx, ecx
    xor r8d, r8d
    call linnea_ktls_enable
    test rax, rax
    js .ev_bad_gateway
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_KTLS
    ; A plain proxy_tls backend speaks HTTP/1.1 over the socket kTLS now owns, so
    ; the leg rejoins the ordinary SENDING/HEAD/RELAY path from here: the request
    ; head is already in .buf and the send needs no change (kTLS encrypts what we
    ; write). F_KTLS is what turns the reads into record-type-aware RECVMSGs.
    mov rax, [rbx + linnea_h2p.location]
    cmp qword [rax + linnea_config_location.proxy_h2], 0
    jne .ev_tls_handoff_h2
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_SENDING
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND
    jmp .ev_service
.ev_tls_handoff_h2:
    call h2p_slot_ctx                 ; rax = ctx
    mov rdi, rax
    lea rsi, [rbx + linnea_h2p.buf]   ; the rewritten h1 request head
    mov rdx, [rbx + linnea_h2p.req_len]
    mov rcx, [rbx + linnea_h2p.rq_buf]    ; request body mapping (0 = none)
    mov r8, [rbx + linnea_h2p.rq_wr]      ; its length (rq_rd is 0 at the start)
    test rcx, rcx
    jnz .ev_h2_start_go
    xor r8, r8
.ev_h2_start_go:
    mov r9, LINNEA_H2C_SCHEME_HTTPS
    call linnea_h2c_drv_start         ; -> verdict
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_H2
    jmp .ev_h2_verdict
.ev_h2_send:
    test r14d, r14d
    js .ev_bad_gateway
    call h2p_slot_ctx
    mov rdi, rax
    mov esi, r14d
    call linnea_h2c_drv_on_sent       ; -> verdict
    jmp .ev_h2_verdict
.ev_h2_recv:
    test r14d, r14d
    jle .ev_bad_gateway               ; eof/err mid-exchange -> 502
    ; a kTLS read delivers one TLS record; a control record (a backend's
    ; NewSessionTicket) is not part of the h2 stream. Skip it and re-read rather
    ; than feed it to the driver -- otherwise a ticket-sending backend (nginx and
    ; most real h2 servers) faults the leg and 502s a response it did answer.
    mov rdi, rbx                      ; slot
    call h2p_krx_rectype              ; eax: 0 data, 1 skip-control, 2 eof(alert)
    cmp eax, 1
    je .ev_h2_recv_skip
    cmp eax, 2
    je .ev_bad_gateway
.ev_h2_recv_ok:
    call h2p_slot_ctx
    mov rdi, rax
    lea rsi, [rax + linnea_h2c.out_buf]  ; the recv landed here
    mov edx, r14d
    call linnea_h2c_drv_on_recv       ; -> verdict
    jmp .ev_h2_verdict
.ev_h2_recv_skip:
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV   ; re-read the next record
    jmp .ev_service
.ev_h2_verdict:
    cmp rax, LINNEA_H2C_WANT_SEND
    je .ev_h2_want_send
    cmp rax, LINNEA_H2C_WANT_RECV
    je .ev_h2_want_recv
    cmp rax, LINNEA_H2C_DRV_DONE
    je .ev_h2_done
    jmp .ev_bad_gateway               ; FAIL / RST / GOAWAY -> 502
.ev_h2_want_send:
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND
    jmp .ev_service
.ev_h2_want_recv:
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV
    jmp .ev_service
.ev_h2_done:
    ; the whole response is buffered in the leg ctx. Present it to the existing
    ; HEAD/RELAY path: compose the h1 head into .buf and parse it; the body is
    ; then fed chunk by chunk from ctx as the relay drains (.ao_recv feed).
    mov rdi, rbx
    call h2p_resp_begin               ; -> rax = 0 ok, -1 malformed synthesized head
    test rax, rax
    js .ev_bad_gateway
    jmp .ev_service

.ev_service:
    mov rdi, r12
    call linnea_h2p_service          ; -> rax = 1 if frames are queued
    jmp .ev_ret
.ev_stale:
    ; a completion for a previous incarnation of this connection slot
    call h2p_free_slot
    mov rax, -1                      ; the caller must not touch the connection
    jmp .ev_ret
.ev_zombie:
    ; the stream died (a RST) while this op was in flight, but the connection
    ; is still live: the kernel is done with the buffer, so close and free,
    ; then service the connection's remaining slots as usual
    call h2p_free_slot
    xor eax, eax
.ev_ret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2p_free_slot(rbx = slot*) — close the upstream fd and mark the slot free.
h2p_free_slot:
    mov edi, [rbx + linnea_h2p.fd]
    cmp edi, -1
    je .fsl_nofd
    mov eax, LINNEA_SYS_CLOSE
    syscall
    call linnea_upstream_closed
.fsl_nofd:
    mov dword [rbx + linnea_h2p.fd], -1
    mov rdi, rbx
    call h2p_capture_release
    mov rsi, [rbx + linnea_h2p.flags]            ; read BEFORE the scrub
    mov qword [rbx + linnea_h2p.flags], 0        ; see h2p_release
    ; Whatever credit was held back short of a full GRANT_MIN step goes back on
    ; stream 0: the stream is gone, so that is the only window left to put it
    ; on, and left unreturned it is gone for good — a connection doing upload
    ; after upload would starve its own window a remainder at a time.
    ;
    ; rq_credit ALONE. This used to add the unsent FIFO remainder (rq_wr minus
    ; rq_rd) with it, and skip captured bodies entirely to avoid double-crediting
    ; bytes the capture had already paid for. Both halves are wrong now: nothing
    ; streams, so those cursors index a MAPPING rather than a FIFO and their
    ; difference is body still to go upstream, which was credited when it was
    ; captured; and a captured body can now owe, because credit is batched.
    ; Skipping F_REQ_FILE would leak up to GRANT_MIN of connection window per
    ; aborted upload.
    mov rcx, [rbx + linnea_h2p.rq_credit]
    add [rbx + linnea_h2p.rq_owed], rcx
    mov qword [rbx + linnea_h2p.rq_rd], 0
    mov qword [rbx + linnea_h2p.rq_wr], 0
    mov qword [rbx + linnea_h2p.rq_credit], 0
    mov qword [rbx + linnea_h2p.rq_buf], 0
    mov qword [rbx + linnea_h2p.sid], 0
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_FREE
    ret

; ============================================================================
; proxy_h2 response feed: present the driver's buffered h1 response (head in the
; leg ctx, body in ctx.body_buf) to the existing HEAD/RELAY path via .buf.
; ============================================================================
; h2p_resp_begin(rdi = slot*) -> rax = 0 ok, -1 malformed synthesized head.
; Compose the h1 head into .buf, parse it, then feed the first body chunk.
h2p_resp_begin:
    push rbx
    push r12
    mov rbx, rdi
    mov rdi, [rbx + linnea_h2p.leg_lin]
    call linnea_h2p_h2c_for
    mov r12, rax                      ; ctx
    mov rdi, r12
    lea rsi, [rbx + linnea_h2p.buf]
    mov rdx, LINNEA_H2P_BUF
    call linnea_h2c_drv_head          ; rax = head length in .buf
    test rax, rax
    js .rb_bad                        ; will not fit: ctx.hdr_big says whose
    mov [rbx + linnea_h2p.len], rax
    mov qword [rbx + linnea_h2p.resp_off], 0
    mov rdi, rbx
    call h2p_parse_head               ; -> 1 parsed, 0 need-more, -1 bad
    cmp rax, 1
    jne .rb_bad                       ; a synthesized head must parse whole
    ; The backend leg is DONE: the whole response is buffered in the leg ctx, so
    ; no further backend send/recv is owed. Drop the driver's leftover WANT_SEND
    ; (and WANT_RECV, which h2p_resp_feed re-sets iff more body remains) before
    ; entering the client-facing RELAY phase — otherwise arm_h2p_ops, seeing a
    ; non-TLS/H2 state, would arm a *normal* h1 backend send (SENDING/HEAD) and
    ; corrupt the exchange.
    and qword [rbx + linnea_h2p.flags], ~(LINNEA_H2P_F_WANT_SEND | LINNEA_H2P_F_WANT_RECV)
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_RELAY
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_HEAD_RDY
    mov rdi, rbx
    call h2p_resp_feed                 ; first body chunk (also handles no body)
    xor eax, eax
    jmp .rb_ret
.rb_bad:
    mov rax, -1
.rb_ret:
    pop r12
    pop rbx
    ret

; h2p_resp_feed(rdi = slot*) — append the next response-body chunk from the leg
; ctx into .buf (.ao_recv has already compacted, freeing room), decode it, and
; ask for more if the body is not exhausted. Called instead of a socket recv for
; a RELAY-state proxy_h2 leg. Clobbers only caller-saved + the flags.
h2p_resp_feed:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov rdi, [rbx + linnea_h2p.leg_lin]
    call linnea_h2p_h2c_for
    mov r12, rax                      ; ctx
    mov r13, [r12 + linnea_h2c.body_len]
    sub r13, [rbx + linnea_h2p.resp_off]     ; remaining body
    jz .rf_decode                     ; nothing to append; let decode finish
    mov rcx, LINNEA_H2P_BUF
    sub rcx, [rbx + linnea_h2p.len]           ; room in .buf
    jz .rf_more                       ; no room yet; the relay must drain first
    cmp r13, rcx
    jbe .rf_n
    mov r13, rcx                      ; n = min(remaining, room)
.rf_n:
    lea rdi, [rbx + linnea_h2p.buf]
    add rdi, [rbx + linnea_h2p.len]
    lea rsi, [r12 + linnea_h2c.body_buf]
    add rsi, [rbx + linnea_h2p.resp_off]
    mov rcx, r13
    rep movsb
    add [rbx + linnea_h2p.len], r13
    add [rbx + linnea_h2p.resp_off], r13
.rf_decode:
    mov rdi, rbx
    call h2p_decode                   ; counted body: advances .wr, sets BODY_DONE
    ; more body still to feed?
    mov rax, [r12 + linnea_h2c.body_len]
    cmp rax, [rbx + linnea_h2p.resp_off]
    ja .rf_more
    jmp .rf_ret
.rf_more:
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV
.rf_ret:
    pop r13
    pop r12
    pop rbx
    ret

; linnea_h2p_service(rdi = conn) -> rax = 1 when out_ptr/out_rem now hold
; frames to send, else 0. Emits whatever the slots have made ready: a
; translated response HEADERS, an error response, or a RST_STREAM. Body DATA
; is left to h2_schedule, which reads it from the slot buffer.
; Never runs while a client send owns out_buf (h2_tx_busy).
linnea_h2p_service:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi                     ; conn
    ; The body clock, read ONCE for the whole pass and aged per slot in the
    ; walk below. It used to hang off the single streaming upload the
    ; connection could have; every request now collects its body, so there is
    ; no one slot to hang it on and up to LINNEA_H2P_SLOTS of them can be
    ; taking a body at the same time. Reading the clock once rather than per
    ; slot also keeps every slot in a pass judged against the same instant.
    call linnea_uring_now             ; eats rdi/rsi; rbx is already the conn
    mov [h2_sv_now], rax
.sv_claim_ok:
    cmp qword [rbx + linnea_connection.h2_tx_busy], 0
    jne .sv_none                     ; out_buf is in flight; retry on drain
    lea r15, [rbx + linnea_connection.out_buf]   ; write cursor
    mov rax, [rbx + linnea_connection.index]
    imul rax, rax, LINNEA_H2P_SLOTS
    imul rax, rax, linnea_h2p_size
    add rax, [h2p_pool]
    mov r12, rax                     ; slot cursor
    mov r13d, LINNEA_H2P_SLOTS
.sv_scan:
    ; a translated HEADERS frame has to fit whole (see LINNEA_H2P_HEAD_ROOM);
    ; if it cannot, stop and let the next pass emit it
    lea rax, [rbx + linnea_connection.out_buf + LINNEA_CONN_OUT_BUF]
    sub rax, r15
    cmp rax, LINNEA_H2P_HEAD_ROOM
    jb .sv_done
    ; credit a dead stream's request body back on the connection window. This
    ; outlives the slot, so it runs before the free-slot skip below: the stream
    ; is gone, so stream 0 is the only place it can go, and without it one
    ; aborted upload leaves the connection window short for good.
    mov r14, [r12 + linnea_h2p.rq_owed]
    test r14, r14
    jz .sv_no_owed
    mov qword [r12 + linnea_h2p.rq_owed], 0
    mov rdi, r15
    xor esi, esi                     ; stream 0 only
    mov edx, r14d
    call h2p_emit_window
    add r15, rax
.sv_no_owed:
    ; a free slot keeps no flags worth acting on: skip it before the credit
    ; and readiness tests below, so a stale bit cannot resurrect it
    cmp qword [r12 + linnea_h2p.state], LINNEA_H2P_FREE
    je .sv_next
    ; a zombie belongs to a connection that is already gone — it is parked only
    ; until its in-flight op completes. Its sid names a stream this connection
    ; never opened, so acting on its readiness flags or its stream-level credit
    ; would emit frames for a stranger's stream once the slot's index is reused
    cmp qword [r12 + linnea_h2p.state], LINNEA_H2P_ZOMBIE
    je .sv_next
    ; The body clock. A slot still COLLECTing has to keep up with the pace every
    ; received byte paid forward (LINNEA_BODY_NS_PER_BYTE, in the DATA path); a
    ; client trickling — or gone silent, with the recv timeout driving this pass
    ; — falls further behind than the head deadline and the exchange fails 408.
    ; Nothing upstream is held any more (the socket is not opened until the body
    ; is in), but the slot and its capture file are, and there are only
    ; LINNEA_H2P_SLOTS of them per connection.
    cmp qword [r12 + linnea_h2p.state], LINNEA_H2P_COLLECT
    jne .sv_no_clock
    mov rcx, [r12 + linnea_h2p.rq_start]
    test rcx, rcx
    jz .sv_no_clock                  ; unstarted clock: never age against zero
    mov rax, [h2_sv_now]
    cmp rcx, rax
    jbe .sv_body_age
    mov [r12 + linnea_h2p.rq_start], rax   ; no credit banked ahead of now
    jmp .sv_no_clock
.sv_body_age:
    sub rax, rcx
    cmp rax, [head_timeout_ns]
    jbe .sv_no_clock
    mov qword [r12 + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [r12 + linnea_h2p.status], 408
.sv_no_clock:
    ; Request-body credit is emitted where the bytes are CONSUMED, in the DATA
    ; handler, batched at LINNEA_H2P_GRANT_MIN. It used to be emitted here
    ; instead, because the streaming path owed it only once the bytes had gone
    ; upstream and this pass was the first place that was known. Nothing streams
    ; now, and a slot's rq_credit is both accumulated and flushed in one place —
    ; so a second emitter reading the same field would hand the client the same
    ; window twice and overflow it, which is a connection error to the peer.
    ; What still belongs to this pass is rq_owed above: credit that outlived its
    ; STREAM and can only go back on stream 0.
.sv_no_credit:
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_REAP
    jnz .sv_reap
    cmp qword [r12 + linnea_h2p.state], LINNEA_H2P_FAILED
    je .sv_failed
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_HEAD_RDY
    jnz .sv_head
.sv_next:
    add r12, linnea_h2p_size
    dec r13d
    jnz .sv_scan
.sv_done:
    lea rax, [rbx + linnea_connection.out_buf]
    mov rcx, r15
    sub rcx, rax
    test rcx, rcx
    jz .sv_none
    mov [rbx + linnea_connection.out_ptr], rax
    mov [rbx + linnea_connection.out_rem], rcx
    mov qword [rbx + linnea_connection.file_rem], 0
    mov qword [rbx + linnea_connection.h2_tx_busy], 1
    mov eax, 1
    jmp .sv_ret
.sv_none:
    xor eax, eax
.sv_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.sv_reap:
    ; its last DATA frame has drained: the buffer is nobody's now. The
    ; scheduler already freed the stream slot at END_STREAM, so finish here
    ; only emits the exchange's access line (slot_find misses, harmlessly).
    mov rdi, rbx
    mov rsi, r12
    call h2p_finish_stream
    mov rax, r12
    call h2p_release
    jmp .sv_next

.sv_head:
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_HEAD_INTERIM
    jnz .sv_head_interim
    ; emit the translated response HEADERS for this slot
    and qword [r12 + linnea_h2p.flags], ~LINNEA_H2P_F_HEAD_RDY
    or qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_HEAD_SENT
    mov rdi, r15
    mov rsi, r12
    mov rdx, rbx
    call h2p_emit_headers            ; -> rax = bytes written
    add r15, rax
    ; a bodiless response ends the stream here: no DATA will follow, so the
    ; scheduler never sees this slot and it is freed now
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_NO_BODY
    jz .sv_next
    mov rdi, rbx
    mov rsi, r12
    call h2p_finish_stream
    mov rax, r12
    call h2p_release
    jmp .sv_next

.sv_head_interim:
    ; A 1xx informational head (Finding 30). Relay it without END_STREAM
    ; (NO_BODY is clear, so h2p_emit_headers adds none) and leave F_HEAD_SENT
    ; clear -- the final response head is still to come, and a later upstream
    ; failure can still answer with a final 502 HEADERS rather than a reset.
    ; Then drop the interim head from the buffer and parse the next head, which
    ; may already be buffered (a backend that wrote the interim and the final
    ; response in one go).
    and qword [r12 + linnea_h2p.flags], ~(LINNEA_H2P_F_HEAD_RDY | LINNEA_H2P_F_HEAD_INTERIM)
    mov rdi, r15
    mov rsi, r12
    mov rdx, rbx
    call h2p_emit_headers
    add r15, rax
    ; slide buf[rd..len] down over the interim head just relayed
    mov rcx, [r12 + linnea_h2p.rd]   ; interim head length
    mov r14, [r12 + linnea_h2p.len]
    sub r14, rcx                     ; bytes of the next head already buffered
    push rsi
    push rdi
    lea rsi, [r12 + linnea_h2p.buf]
    add rsi, rcx
    lea rdi, [r12 + linnea_h2p.buf]
    mov rcx, r14
    rep movsb
    pop rdi
    pop rsi
    mov [r12 + linnea_h2p.len], r14
    mov qword [r12 + linnea_h2p.rd], 0
    mov qword [r12 + linnea_h2p.wr], 0
    mov qword [r12 + linnea_h2p.off], 0
    ; parse the next head from what remains
    mov rdi, r12
    call h2p_parse_head              ; 1 final, 0 need-more, -1 bad, 2 interim
    test rax, rax
    js .sv_interim_bad
    jz .sv_interim_more
    cmp rax, 2
    je .sv_interim_again
    ; a final head is buffered. Decode any body already present (same
    ; parse->decode->emit order as the normal recv path), then emit the head.
    mov qword [r12 + linnea_h2p.state], LINNEA_H2P_RELAY
    mov rdi, r12
    call h2p_decode
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_DEC_ERR
    jnz .sv_interim_bad
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jnz .sv_interim_final
    or qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV   ; more body to read
.sv_interim_final:
    ; room for the final HEADERS in this pass? If not, re-arm HEAD_RDY (INTERIM
    ; is clear now) and let the next pass emit it; the decoded body is retained.
    lea rax, [rbx + linnea_connection.out_buf + LINNEA_CONN_OUT_BUF]
    sub rax, r15
    cmp rax, LINNEA_H2P_HEAD_ROOM
    jb .sv_interim_defer
    or qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_HEAD_RDY
    jmp .sv_head                     ; emit the final head (INTERIM cleared)
.sv_interim_defer:
    or qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_HEAD_RDY
    jmp .sv_done
.sv_interim_again:
    ; another interim head is buffered. Emit it too if the out buffer has room,
    ; else defer this slot's remaining heads to the next pass.
    lea rax, [rbx + linnea_connection.out_buf + LINNEA_CONN_OUT_BUF]
    sub rax, r15
    cmp rax, LINNEA_H2P_HEAD_ROOM
    jb .sv_interim_again_defer
    jmp .sv_head_interim
.sv_interim_again_defer:
    or qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_HEAD_RDY | LINNEA_H2P_F_HEAD_INTERIM
    jmp .sv_done
.sv_interim_more:
    ; the next head is not fully buffered: read more upstream bytes, then the
    ; recv path parses it (state HEAD)
    mov qword [r12 + linnea_h2p.state], LINNEA_H2P_HEAD
    or qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV
    jmp .sv_next
.sv_interim_bad:
    ; the next head is malformed, or its body decode failed. No final head has
    ; reached the client (F_HEAD_SENT is clear after an interim), so 502 stands.
    mov qword [r12 + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [r12 + linnea_h2p.status], 502
    jmp .sv_failed

.sv_failed:
    test qword [r12 + linnea_h2p.flags], LINNEA_H2P_F_RST
    jnz .sv_rst
    ; nothing sent yet: a synthetic error response (502/504/413)
    mov rdi, r15
    mov rsi, r12
    mov rdx, rbx
    call h2p_emit_error              ; -> rax = bytes written
    add r15, rax
    mov rdi, rbx
    mov rsi, r12
    call h2p_finish_stream
    mov rax, r12
    call h2p_release
    jmp .sv_next
.sv_rst:
    ; the response was already under way: RST_STREAM(INTERNAL_ERROR) is the
    ; only honest signal left
    mov rdi, r15
    mov rsi, [r12 + linnea_h2p.sid]
    mov edx, LINNEA_H2_INTERNAL_ERROR
    call h2p_emit_rst
    add r15, rax
    mov rdi, rbx
    mov rsi, r12
    call h2p_finish_stream
    mov rax, r12
    call h2p_release
    jmp .sv_next

; h2p_finish_stream(rdi = conn, rsi = slot*) — the stream needs no more DATA
; from this slot: free its stream-pool slot (nothing is mapped) so the
; scheduler stops considering it and the reset budget is credited.
; h2_431_stream(rdi=conn, rsi=stream id, rdx=out) -> rax = bytes written.
; A whole 431 response — HEADERS + DATA(END_STREAM) — for a stream whose
; header block overran our limits before it ever parsed: there is no req and
; no :authority, so the accepting server stands in as the vhost (its security
; headers ride the response, and its name goes in the access line, where the
; method and target print "-").
; h2_429_stream / h2_431_stream(rdi=conn, rsi=stream id, rdx=out) -> rax.
; One builder, two statuses. It was written for 431 alone and every byte of it
; except the status text and the body is the same for any bodied stream error,
; so the second caller parameterises rather than copies -- eighty lines of
; near-identical assembly is how a fix comes to land on one of them.
h2_429_stream:
    lea rax, [status_429_h2]
    mov [h2_err_status], rax
    lea rax, [body_429]
    mov [h2_err_body], rax
    mov qword [h2_err_bodylen], body_429_len
    mov qword [h2_err_code], 429
    jmp h2_err_stream
h2_431_stream:
    lea rax, [status_431_h2]
    mov [h2_err_status], rax
    lea rax, [body_431]
    mov [h2_err_body], rax
    mov qword [h2_err_bodylen], body_431_len
    mov qword [h2_err_code], 431
h2_err_stream:
    push rbx
    push r12
    push r13
    push r14
    push rbp
    mov rbx, rdi                     ; conn
    mov r12, rsi                     ; stream id
    mov r14, rdx                     ; out start
    mov eax, [rbx + linnea_connection.server]
    imul rax, rax, linnea_config_server_size
    lea rax, [rax + linnea_config_instance + linnea_config.servers]
    mov [h2_cur_srv], rax
    ; the body is flow-controlled (RFC 9113 6.9.1): withhold it if the peer has
    ; advertised no room, and let content-length agree at 0
    mov rax, [h2_err_bodylen]
    mov [h2_err_blen], rax
    mov rdi, rbx
    mov rsi, [h2_err_bodylen]
    call h2_data_window_take
    test eax, eax
    jnz .b431_fits
    mov qword [h2_err_blen], 0
.b431_fits:
    ; content-length text
    mov rdi, [h2_err_blen]
    lea rsi, [h2_numbuf]
    call linnea_string_from_u64
    mov r13, rax                     ; its length
    ; HEADERS payload
    lea rdi, [r14 + 9]
    mov rbp, rdi                     ; payload start
    mov esi, 8                       ; :status
    mov rdx, [h2_err_status]
    mov ecx, 3
    call h2_enc_hdr
    mov esi, 31                      ; content-type: text/plain
    lea rdx, [mime_txt_h2]
    mov ecx, mime_txt_h2_len
    call h2_enc_hdr
    mov esi, 28                      ; content-length
    lea rdx, [h2_numbuf]
    mov rcx, r13
    call h2_enc_hdr
    call h2_enc_date_server
    mov rcx, rdi
    sub rcx, rbp                     ; payload length
    ; HEADERS frame header (END_HEADERS; the DATA carries END_STREAM)
    mov rdi, r14
    mov rax, rcx
    shr rax, 16
    mov [rdi], al
    mov rax, rcx
    shr rax, 8
    mov [rdi + 1], al
    mov [rdi + 2], cl
    mov byte [rdi + 3], LINNEA_H2_FT_HEADERS
    mov byte [rdi + 4], LINNEA_H2_FLAG_END_HEADERS
    mov rax, r12
    shr rax, 24
    mov [rdi + 5], al
    mov rax, r12
    shr rax, 16
    mov [rdi + 6], al
    mov rax, r12
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], r12b
    ; DATA frame: the 431 body, END_STREAM
    lea rdi, [rdi + rcx + 9]
    mov byte [rdi], 0
    mov byte [rdi + 1], 0
    mov rax, [h2_err_blen]
    mov [rdi + 2], al
    mov byte [rdi + 3], LINNEA_H2_FT_DATA
    mov byte [rdi + 4], LINNEA_H2_FLAG_END_STREAM
    mov rax, r12
    shr rax, 24
    mov [rdi + 5], al
    mov rax, r12
    shr rax, 16
    mov [rdi + 6], al
    mov rax, r12
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], r12b
    add rdi, 9
    mov rsi, [h2_err_body]
    mov rcx, [h2_err_blen]
    rep movsb
    mov r13, rdi
    sub r13, r14                     ; total bytes written
    ; the access line: the request never parsed, so method and target are "-"
    mov rax, [h2_cur_srv]
    lea rcx, [rax + linnea_config_server.hostname]
    mov [linnea_log_acc_host], rcx
    mov rcx, [rax + linnea_config_server.hostname_len]
    mov [linnea_log_acc_host_len], rcx
    lea rcx, [rbx + linnea_connection.peer]
    mov [linnea_log_acc_peer], rcx
    mov rcx, [rbx + linnea_connection.peer_len]
    mov [linnea_log_acc_peer_len], rcx
    xor ecx, ecx
    mov [linnea_log_acc_meth], rcx
    mov [linnea_log_acc_tgt], rcx
    ; the status the client actually received, not the one this builder was
    ; written for: parameterising the wire response and leaving the ACCESS LINE
    ; hardcoded logged 156 rate-limited requests as 431 on the live server
    mov rax, [h2_err_code]
    mov [linnea_log_acc_status], rax
    mov rax, [h2_err_bodylen]
    mov [linnea_log_acc_bytes], rax
    lea rcx, [proto_h2]
    mov [linnea_log_acc_proto], rcx
    mov qword [linnea_log_acc_proto_len], proto_h2_len
    call linnea_log_access
    mov rax, r13
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

h2p_finish_stream:
    push rbx
    push r12
    sub rsp, 8                        ; keep the calls 16-aligned
    mov rbx, rsi                      ; slot
    mov r12, rdi                      ; conn
    ; the access line for the proxied exchange — method and target were parked
    ; at the claim, status and body bytes are the outcome (a synthetic
    ; 502/504/408 included). Once per exchange: the length byte is cleared.
    cmp byte [rbx + linnea_h2p.lg_meth], 0
    je .fs_scan
    mov rax, [rbx + linnea_h2p.srv]
    lea rcx, [rax + linnea_config_server.hostname]
    mov [linnea_log_acc_host], rcx
    mov rcx, [rax + linnea_config_server.hostname_len]
    mov [linnea_log_acc_host_len], rcx
    lea rcx, [r12 + linnea_connection.peer]
    mov [linnea_log_acc_peer], rcx
    mov rcx, [r12 + linnea_connection.peer_len]
    mov [linnea_log_acc_peer_len], rcx
    movzx ecx, byte [rbx + linnea_h2p.lg_meth]
    mov [linnea_log_acc_meth_len], rcx
    lea rcx, [rbx + linnea_h2p.lg_meth + 1]
    mov [linnea_log_acc_meth], rcx
    movzx ecx, byte [rbx + linnea_h2p.lg_tgt]
    mov [linnea_log_acc_tgt_len], rcx
    lea rcx, [rbx + linnea_h2p.lg_tgt + 1]
    mov [linnea_log_acc_tgt], rcx
    mov rcx, [rbx + linnea_h2p.status]
    mov [linnea_log_acc_status], rcx
    mov rcx, [rbx + linnea_h2p.lg_bytes]
    mov [linnea_log_acc_bytes], rcx
    lea rcx, [proto_h2]
    mov [linnea_log_acc_proto], rcx
    mov qword [linnea_log_acc_proto_len], proto_h2_len
    mov byte [rbx + linnea_h2p.lg_meth], 0
    call linnea_log_access
.fs_scan:
    mov rdi, r12
    mov rsi, [rbx + linnea_h2p.sid]
    call h2_slot_find
    test rax, rax
    jz .fs_ret
    mov qword [rax + linnea_h2_stream.id], 0
    inc qword [r12 + linnea_connection.h2_done_count]
.fs_ret:
    add rsp, 8
    pop r12
    pop rbx
    ret

; h2p_emit_window(rdi = out, rsi = stream id (0 = connection), edx =
; increment) -> rax = 13. A WINDOW_UPDATE frame.
h2p_emit_window:
    mov byte [rdi], 0
    mov byte [rdi + 1], 0
    mov byte [rdi + 2], 4
    mov byte [rdi + 3], LINNEA_H2_FT_WINDOW_UPDATE
    mov byte [rdi + 4], 0
    mov rax, rsi
    mov rcx, rax
    shr rax, 24
    mov [rdi + 5], al
    mov rax, rcx
    shr rax, 16
    mov [rdi + 6], al
    mov rax, rcx
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], cl
    bswap edx
    mov [rdi + 9], edx
    mov eax, 13
    ret

; h2p_emit_rst(rdi = out, rsi = stream id, edx = error code) -> rax = 13.
h2p_emit_rst:
    mov byte [rdi], 0
    mov byte [rdi + 1], 0
    mov byte [rdi + 2], 4
    mov byte [rdi + 3], LINNEA_H2_FT_RST_STREAM
    mov byte [rdi + 4], 0
    mov rax, rsi
    mov rcx, rax
    shr rax, 24
    mov [rdi + 5], al
    mov rax, rcx
    shr rax, 16
    mov [rdi + 6], al
    mov rax, rcx
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], cl
    bswap edx
    mov [rdi + 9], edx
    mov eax, 13
    ret

; h2p_compact(rdi = slot*) — recycle the slot buffer: bytes already framed to
; the client (everything below .off — the response head plus the body sent so
; far) are dropped and the remainder moved down, so a body larger than the
; buffer streams through it. Only safe once the head has been emitted (it is
; read from the buffer to build the HEADERS frame) and while no client send is
; reading the body bytes, which the caller checks (h2_tx_busy).
h2p_compact:
    push rbx
    mov rbx, rdi
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_HEAD_SENT
    jz .cp_ret                       ; the head is still needed in place
    mov rcx, [rbx + linnea_h2p.off]
    test rcx, rcx
    jz .cp_ret
    mov rdx, [rbx + linnea_h2p.len]
    sub rdx, rcx                     ; bytes to keep
    push rsi
    push rdi
    lea rsi, [rbx + linnea_h2p.buf]
    add rsi, rcx
    lea rdi, [rbx + linnea_h2p.buf]
    mov rcx, rdx
    rep movsb
    pop rdi
    pop rsi
    mov rcx, [rbx + linnea_h2p.off]
    sub [rbx + linnea_h2p.len], rcx
    sub [rbx + linnea_h2p.rd], rcx
    sub [rbx + linnea_h2p.wr], rcx
    mov qword [rbx + linnea_h2p.off], 0
.cp_ret:
    pop rbx
    ret


; h2p_parse_head(rdi = slot*) -> rax = 1 parsed, 0 need more bytes, -1 bad.
; Finds the CRLF CRLF, reads the status line and the framing headers
; (Content-Length, Transfer-Encoding: chunked), and leaves .rd at the first
; body byte. The head itself stays in the buffer: h2p_emit_headers walks it
; again to translate the fields.
h2p_parse_head:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    lea r12, [rbx + linnea_h2p.buf]
    mov r13, [rbx + linnea_h2p.len]
    cmp r13, 12
    jb .ph_more                      ; not even a status line yet
    ; "HTTP/1.x SSS"
    mov eax, [r12]
    cmp eax, 'HTTP'
    jne .ph_bad
    cmp byte [r12 + 4], '/'
    jne .ph_bad
    cmp byte [r12 + 8], ' '
    jne .ph_bad
    xor eax, eax
    movzx ecx, byte [r12 + 9]
    sub ecx, '0'
    cmp ecx, 9
    ja .ph_bad
    imul eax, ecx, 100
    movzx ecx, byte [r12 + 10]
    sub ecx, '0'
    cmp ecx, 9
    ja .ph_bad
    imul ecx, ecx, 10
    add eax, ecx
    movzx ecx, byte [r12 + 11]
    sub ecx, '0'
    cmp ecx, 9
    ja .ph_bad
    add eax, ecx
    mov [rbx + linnea_h2p.status], rax
    ; find the empty line
    xor ecx, ecx                     ; scan cursor
.ph_scan:
    lea rax, [rcx + 4]
    cmp rax, r13
    ja .ph_more
    cmp byte [r12 + rcx], 13
    jne .ph_scan_next
    cmp byte [r12 + rcx + 1], 10
    jne .ph_scan_next
    cmp byte [r12 + rcx + 2], 13
    jne .ph_scan_next
    cmp byte [r12 + rcx + 3], 10
    je .ph_found
.ph_scan_next:
    inc rcx
    jmp .ph_scan
.ph_found:
    add rcx, 4
    cmp rcx, LINNEA_H2P_RHEAD_MAX
    ja .ph_toobig                    ; a head this large is not worth relaying
    ; reject a malformed upstream head before any of it is translated into an
    ; HTTP/2 field block the client would then have to reject (Finding 34)
    push rcx
    mov rdi, r12
    mov rsi, rcx
    call linnea_http_upstream_head_valid
    pop rcx
    test eax, eax
    jz .ph_bad
    mov [rbx + linnea_h2p.rd], rcx   ; first body byte
    mov [rbx + linnea_h2p.wr], rcx   ; decoded body starts here too
    mov [rbx + linnea_h2p.off], rcx
    ; A backend that says "close" is about to go; parking that socket would
    ; hand the next request a race with its FIN. rcx is the head length and
    ; h2p_head_find takes the NAME length in the same register, so it is saved
    ; across both calls and every path below reaches the pop.
    push rcx
    mov rdi, r12
    mov rsi, rcx
    lea rdx, [h2p_hn_conn]
    mov ecx, 10
    call h2p_head_find
    test rdx, rdx
    jz .ph_conn_done
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [h2p_val_close]
    mov ecx, 5
    call h2p_val_has
    test eax, eax
    jz .ph_conn_done
    mov qword [rbx + linnea_h2p.no_reuse], 1
.ph_conn_done:
    pop rcx
    ; framing: Transfer-Encoding: chunked wins over Content-Length
    mov rdi, r12
    mov rsi, rcx
    lea rdx, [h2p_hn_te]
    mov ecx, h2p_hn_te_len
    call h2p_head_find               ; -> rax = value ptr, rdx = len (0 = none)
    test rdx, rdx
    jz .ph_clen
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [h2p_chunked]
    mov ecx, h2p_chunked_len
    call h2p_val_has
    test eax, eax
    jz .ph_clen
    mov qword [rbx + linnea_h2p.chunked], 1     ; phase 1: reading a size line
    mov qword [rbx + linnea_h2p.body_rem], -1
    ; ...but a response carrying BOTH is contradictory and must not be relayed
    ; (RFC 9112 6.3). h1 refuses it with a 502 and says why: forwarding both
    ; lets a compromised backend split the next keep-alive response. h2 picked
    ; a side instead, and picked badly — it de-chunked the body while
    ; forwarding the upstream's content-length verbatim, so the message it
    ; emitted declared 5 bytes and carried 7, and the client rejected the
    ; stream with PROTOCOL_ERROR. Refuse it here, where h1 does.
    mov rdi, r12
    mov rsi, [rbx + linnea_h2p.rd]
    lea rdx, [h2p_hn_cl]
    mov ecx, h2p_hn_cl_len
    call h2p_head_find
    test rdx, rdx
    jnz .ph_bad
    jmp .ph_bodyflag
.ph_clen:
    mov rdi, r12
    mov rsi, [rbx + linnea_h2p.rd]
    lea rdx, [h2p_hn_cl]
    mov ecx, h2p_hn_cl_len
    call h2p_head_find
    test rdx, rdx
    jz .ph_close_delim
    mov rdi, rax
    mov rsi, rdx
    call linnea_string_to_u64        ; -> rax = value, edx = 0 ok / 1 / 2
    test edx, edx
    jnz .ph_bad
    cmp rax, -1
    je .ph_bad                       ; body_rem's -1 means "until the upstream
                                     ; closes"; a backend declaring exactly
                                     ; 2^64-1 bytes would turn a counted body
                                     ; into a close-delimited one
    mov [rbx + linnea_h2p.body_rem], rax
    jmp .ph_bodyflag
.ph_close_delim:
    mov qword [rbx + linnea_h2p.body_rem], -1   ; until the upstream closes
.ph_bodyflag:
    mov rax, [rbx + linnea_h2p.status]
    cmp rax, 200
    jae .ph_final_status
    ; a 1xx informational response (RFC 9113 8.8.5, Finding 30): the caller
    ; relays it as an interim HEADERS block without END_STREAM and reads the
    ; next head. 101 has no meaning over an h2 proxy, and a status below 100 is
    ; not a valid response line -- both are a bad gateway.
    cmp rax, 100
    jb .ph_bad
    cmp rax, 101
    je .ph_bad
    mov eax, 2
    jmp .ph_ret
.ph_final_status:
    ; responses that never carry a body, whatever the headers say
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_IS_HEAD
    jnz .ph_nobody
    ; 1xx, 204, 205 and 304 carry no content, whatever the head says. 205 was
    ; missing from all three of these lists (audit-report-10 Finding 1); the
    ; rule is one predicate now so they cannot disagree again.
    mov edi, eax
    call linnea_http_status_no_content
    test eax, eax
    jnz .ph_nobody
    cmp qword [rbx + linnea_h2p.body_rem], 0
    jne .ph_ok
.ph_nobody:
    mov qword [rbx + linnea_h2p.body_rem], 0
    mov qword [rbx + linnea_h2p.chunked], 0
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_NO_BODY | LINNEA_H2P_F_BODY_DONE
.ph_ok:
    mov eax, 1
    jmp .ph_ret
.ph_more:
    cmp r13, LINNEA_H2P_RHEAD_MAX
    ja .ph_bad                       ; head keeps growing without terminating
    xor eax, eax
    jmp .ph_ret
.ph_toobig:
    ; ours, not the backend's -- the same distinction the leg makes for an
    ; oversized block, made here for the h2-client path's own head cap. rbx is
    ; the slot throughout this function.
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_HDR_BIG
.ph_bad:
    mov rax, -1
.ph_ret:
    pop r13
    pop r12
    pop rbx
    ret

; h2p_decode(rdi = slot*) — advance the body decode: for a chunked upstream,
; move chunk data down over the size lines (in place, wr <= rd, so the
; decoded body is contiguous from the head's end); otherwise the raw bytes
; already are the body and wr just follows len. Sets F_BODY_DONE at the end.
h2p_decode:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    lea r12, [rbx + linnea_h2p.buf]
    cmp qword [rbx + linnea_h2p.state], LINNEA_H2P_RELAY
    jne .dec_ret                     ; the head is not parsed yet
    cmp qword [rbx + linnea_h2p.chunked], 0
    jne .dec_chunked
    ; identity: everything received past the head is body
    mov rax, [rbx + linnea_h2p.len]
    mov [rbx + linnea_h2p.wr], rax
    mov rcx, [rbx + linnea_h2p.body_rem]
    cmp rcx, -1
    je .dec_ret                      ; close-delimited: EOF ends it
    mov rdx, [rbx + linnea_h2p.wr]
    sub rdx, [rbx + linnea_h2p.rd]   ; body bytes received
    cmp rdx, rcx
    jb .dec_ret
    ; the whole declared body is in
    add rcx, [rbx + linnea_h2p.rd]
    mov [rbx + linnea_h2p.wr], rcx   ; ignore anything past it
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jmp .dec_ret
.dec_chunked:
    ; phase 1 = expecting a size line, 2 = copying chunk data, 3 = the CRLF
    ; after a chunk, then the TRAILER section: 4 = at the start of a trailer
    ; line, 5 = inside one, 6 = the LF after it, 7 = the LF that ends the whole
    ; body, 8 = done. Phase 4 used to mean "done", which collapsed two different
    ; boundaries: "0\r\n" is the zero-size chunk LINE and it OPENS the trailer
    ; section -- the empty line after it is what ends the message. Stopping at
    ; the first meant an upstream could close after "0\r\n" and h2 emitted a
    ; clean completed response while h3 refused the same bytes
    ; (audit-report-18). These states mirror linnea_spill_chunked's, which is
    ; the decoder h3 uses and the one that was right.
    mov r13, [rbx + linnea_h2p.rd]   ; raw cursor
    mov r14, [rbx + linnea_h2p.wr]   ; decoded write cursor
.dec_loop:
    mov rax, [rbx + linnea_h2p.chunked]
    cmp rax, 1
    je .dec_size
    cmp rax, 2
    je .dec_data
    cmp rax, 3
    je .dec_crlf
    cmp rax, 4
    je .dec_trail
    cmp rax, 5
    je .dec_trail_line
    cmp rax, 6
    je .dec_trail_lf
    cmp rax, 7
    je .dec_end_lf
    cmp rax, 9
    je .dec_trail_value
    jmp .dec_save                    ; phase 8: done
.dec_size:
    ; a size line ends at the first CRLF; hex digits up to ';' or CR
    mov rcx, r13
    xor edx, edx                     ; value
    xor r8d, r8d                     ; digits seen
.dec_size_scan:
    cmp rcx, [rbx + linnea_h2p.len]
    jae .dec_save                    ; incomplete: wait for more bytes
    movzx eax, byte [r12 + rcx]
    ; chunk-size is 1*HEXDIG (RFC 9112 7.1) -- there is no leading whitespace in
    ; that grammar, and this decoder alone used to skip a space before the first
    ; digit. The other two chunk decoders in this tree, linnea_spill_chunked and
    ; the HTTP/1 request side, both refuse it (audit-report-17). Anything that
    ; is not a digit ends the size and opens the chunk-ext, whose grammar --
    ; including whether a CR may stand there at all -- belongs to
    ; linnea_chunk_ext_step and not to a test spelled out again here.
    call h2p_hexval                  ; al -> eax, -1 if not hex
    test eax, eax
    js .dec_size_ext_start
    ; ...and bound the accumulator BEFORE the shift, as they also do. Without
    ; it a 17-digit size shifted the value one nybble too far and wrapped rdx to
    ; ZERO -- which .dec_size_eol then reads as the terminal chunk, so a nonzero
    ; size line silently became end-of-message and the response completed,
    ; truncated and successful.
    mov r9, 0x0fffffffffffffff
    cmp rdx, r9
    ja .dec_bad                      ; a size no body could ever have
    shl rdx, 4
    or rdx, rax
    cmp rdx, r9
                                     ; ...and after it: the pre-shift test only
                                     ; stops the shift OVERFLOWING, so a 16-digit
                                     ; value up to 0xffff... still slipped past a
                                     ; bound documented as "a size no body could
                                     ; ever have". chunkbig passed only because
                                     ; h2p_hexval was rejecting 'f' (sweep after
                                     ; report 21).
    ja .dec_bad
    inc r8d
.dec_size_next:
    inc rcx
    jmp .dec_size_scan
.dec_size_ext_start:
    ; A chunk extension is ignored as metadata, but its LINE FRAMING is not
    ; optional and neither is its SYNTAX. This scan took every byte that was
    ; not CR (so an embedded LF became extension data, audit-report-19), then
    ; every byte that was not a control (so "4;=bad" and an unterminated
    ; quoted-string were well-formed chunk headers, audit-report-23). Both
    ; rules now come from linnea_chunk_ext_step, which is also what the two
    ; HTTP/1 request decoders ask -- the point being that three decoders cannot
    ; hold one grammar by each spelling it out.
    ;
    ; The state is a register because this decoder re-scans the size line from
    ; its start whenever more bytes arrive: r13 is not advanced until the whole
    ; line is in hand, so there is nothing to carry between calls.
    mov r10d, LINNEA_CHUNK_EXT_START
.dec_size_ext:
    cmp rcx, [rbx + linnea_h2p.len]
    jae .dec_save
    push rsi
    push rdi                         ; live across h2p_decode, as at .dec_move
    movzx esi, byte [r12 + rcx]
    mov rdi, r10
    call linnea_chunk_ext_step
    pop rdi
    pop rsi
    cmp rax, -2
    je .dec_size_eol                 ; the CR that ends the size line
    cmp rax, -1
    je .dec_bad
    mov r10, rax
    inc rcx
    jmp .dec_size_ext
.dec_size_eol:
    lea rax, [rcx + 2]
    cmp rax, [rbx + linnea_h2p.len]
    ja .dec_save                     ; the LF has not arrived
    cmp byte [r12 + rcx + 1], 10
    jne .dec_bad
    test r8d, r8d
    jz .dec_bad                      ; a size line with no digits
    mov r13, rax                     ; past the size line
    mov [rbx + linnea_h2p.chunk_rem], rdx
    test rdx, rdx
    jz .dec_last                     ; the terminating 0-size chunk
    mov qword [rbx + linnea_h2p.chunked], 2
    jmp .dec_loop
.dec_last:
    ; the zero-size line OPENS the trailer section; it does not end the message
    mov qword [rbx + linnea_h2p.chunked], 4
    mov r13, rax
    jmp .dec_loop

    ; --- the trailer section ---------------------------------------------
    ; An empty line here ends the whole body. Anything else is a trailer field
    ; line, dropped: h2 carries trailers as their own field section and this
    ; proxy does not translate them, which is the behaviour that was already in
    ; place -- what was missing is CONSUMING them before declaring the message
    ; complete. EOF in any unfinished state below leaves `chunked` non-zero, and
    ; the EOF path turns that into a bad gateway rather than a clean end.
.dec_trail:
    cmp r13, [rbx + linnea_h2p.len]
    jae .dec_save                    ; wait for more
    ; a field line needs at least one name byte, so one OPENING with a colon
    ; has an empty name -- checked here rather than with a counter in the name
    ; state below
    cmp byte [r12 + r13], ':'
    je .dec_bad
    cmp byte [r12 + r13], 13
    je .dec_trail_end
    mov qword [rbx + linnea_h2p.chunked], 5
    jmp .dec_loop
.dec_trail_end:
    inc r13
    mov qword [rbx + linnea_h2p.chunked], 7
    jmp .dec_loop
.dec_trail_line:
    ; A trailer section is a section of HTTP FIELD LINES, so a line here needs a
    ; token name and a colon -- rejecting a bare LF made the DELIMITERS right
    ; without making the line a field (audit-report-21). Judged byte by byte
    ; because this decoder has nowhere to buffer the line; the same grammar the
    ; head validator applies, from the same tchar bitmap.
    cmp r13, [rbx + linnea_h2p.len]
    jae .dec_save
    movzx eax, byte [r12 + r13]
    cmp al, ':'
    je .dec_trail_colon
    cmp al, 13
    je .dec_bad                      ; no colon: not a field line
    cmp al, 10
    je .dec_bad
    mov edi, eax
    call linnea_string_is_tchar
    test eax, eax
    jz .dec_bad
    inc r13
    jmp .dec_trail_line
.dec_trail_colon:
    inc r13
    mov qword [rbx + linnea_h2p.chunked], 9
    jmp .dec_loop
.dec_trail_value:
    cmp r13, [rbx + linnea_h2p.len]
    jae .dec_save
    movzx eax, byte [r12 + r13]
    cmp al, 13
    je .dec_trail_cr
    cmp al, 9
    je .dec_trail_value_next         ; HTAB is legal in a value
    cmp al, 0x20
    jb .dec_bad                      ; any other control byte is not
    cmp al, 0x7f
    je .dec_bad                      ; DEL
.dec_trail_value_next:
    inc r13
    jmp .dec_trail_value
.dec_trail_cr:
    inc r13
    mov qword [rbx + linnea_h2p.chunked], 6
    jmp .dec_loop
.dec_trail_lf:
    cmp r13, [rbx + linnea_h2p.len]
    jae .dec_save
    cmp byte [r12 + r13], 10
    jne .dec_bad                     ; a bare CR is not a line ending
    inc r13
    mov qword [rbx + linnea_h2p.chunked], 4   ; another trailer line, or the end
    jmp .dec_loop
.dec_end_lf:
    cmp r13, [rbx + linnea_h2p.len]
    jae .dec_save
    cmp byte [r12 + r13], 10
    jne .dec_bad
    inc r13
    mov qword [rbx + linnea_h2p.chunked], 8
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jmp .dec_save
.dec_data:
    mov rcx, [rbx + linnea_h2p.len]
    sub rcx, r13                     ; raw bytes available
    jbe .dec_save
    mov rax, [rbx + linnea_h2p.chunk_rem]
    cmp rcx, rax
    jbe .dec_have
    mov rcx, rax
.dec_have:
    ; move the chunk's data down over the consumed size line
    push rsi
    push rdi
    lea rsi, [r12 + r13]
    lea rdi, [r12 + r14]
    add r13, rcx
    add r14, rcx
    sub [rbx + linnea_h2p.chunk_rem], rcx
    rep movsb
    pop rdi
    pop rsi
    cmp qword [rbx + linnea_h2p.chunk_rem], 0
    jne .dec_save                    ; more data for this chunk to come
    mov qword [rbx + linnea_h2p.chunked], 3
    jmp .dec_loop
.dec_crlf:
    lea rax, [r13 + 2]
    cmp rax, [rbx + linnea_h2p.len]
    ja .dec_save
    cmp byte [r12 + r13], 13
    jne .dec_bad
    cmp byte [r12 + r13 + 1], 10
    jne .dec_bad
    mov r13, rax
    mov qword [rbx + linnea_h2p.chunked], 1
    jmp .dec_loop
.dec_bad:
    ; malformed chunk framing (Finding 31): the old code set BODY_DONE and let
    ; the caller finish with a clean END_STREAM, calling a corrupt de-chunked
    ; response complete. Flag it as a decode error too, so the caller fails the
    ; exchange (502 before the head, RST_STREAM after) instead. BODY_DONE still
    ; stops the loop.
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE | LINNEA_H2P_F_DEC_ERR
.dec_save:
    mov [rbx + linnea_h2p.rd], r13
    mov [rbx + linnea_h2p.wr], r14
.dec_ret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2p_hexval(al = char) -> eax = 0-15, or -1.
h2p_hexval:
    ; `sub eax, '0'` writes AL -- it is the low byte of EAX -- so the letter
    ; path below re-read a byte that had already been decremented: 'a' (0x61)
    ; arrived there as 0x31 and was rejected as not-hex. h2 therefore refused
    ; EVERY chunked response whose size contained a hex letter, which is any
    ; chunk of 10-15 bytes and most real ones, with a 502 -- while h1 and h3
    ; served it. Long-standing; found by sweeping the chunk grammar
    ; differentially rather than by reading, because every chunk fixture in the
    ; tree happened to use sizes 0-9. r11 is scratch here and unused by
    ; h2p_decode.
    movzx eax, al
    mov r11d, eax                    ; the byte, before the subtraction eats it
    sub eax, '0'
    cmp eax, 9
    jbe .hv_ret
    mov eax, r11d
    or eax, 0x20                     ; fold A-F to a-f
    sub eax, 'a'
    cmp eax, 5
    ja .hv_bad
    add eax, 10
.hv_ret:
    ret
.hv_bad:
    mov eax, -1
    ret

; h2p_head_find(rdi = head ptr, rsi = head len, rdx = name, ecx = name len)
;   -> rax = value ptr, rdx = value length (0 = absent). Case-insensitive on
; the name; the value is trimmed of surrounding spaces.
h2p_head_find:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14d, ecx
    xor r15d, r15d                   ; line start
.hf_line:
    ; advance to the next line
    mov rbp, r15
.hf_eol:
    cmp rbp, r12
    jae .hf_none
    cmp byte [rbx + rbp], 13
    je .hf_have_eol
    inc rbp
    jmp .hf_eol
.hf_have_eol:
    mov rcx, rbp
    sub rcx, r15                     ; line length
    test rcx, rcx
    jz .hf_none                      ; the empty line: end of the head
    ; the line must be longer than the name plus its colon
    lea rax, [r14 + 1]
    cmp rcx, rax
    jbe .hf_next
    lea rax, [r15 + r14]             ; the colon's offset in the head
    cmp byte [rbx + rax], ':'
    jne .hf_next
    push rbp
    lea rdi, [rbx + r15]
    mov rsi, r14
    mov rdx, r13
    mov ecx, r14d
    call linnea_string_iequal
    pop rbp
    test eax, eax
    jz .hf_next
    ; value: past the colon, spaces trimmed
    lea rax, [r15 + r14 + 1]
.hf_lead:
    cmp rax, rbp
    jae .hf_valdone
    cmp byte [rbx + rax], ' '
    je .hf_lead_skip
    cmp byte [rbx + rax], 9          ; HTAB is OWS too (RFC 9110 5.6.3), and
    jne .hf_valdone                  ; skipping only SP made "Content-Length:
.hf_lead_skip:                       ; <TAB>5" a 502 on h2 while h1 served it
    inc rax
    jmp .hf_lead
.hf_valdone:
    mov rdx, rbp
    sub rdx, rax                     ; value length
.hf_trail:
    test rdx, rdx
    jz .hf_val_ret
    mov rcx, rax
    add rcx, rdx
    cmp byte [rbx + rcx - 1], ' '
    je .hf_trail_cut
    cmp byte [rbx + rcx - 1], 9      ; ...and the trailing half, likewise
    jne .hf_val_ret
.hf_trail_cut:
    dec rdx
    jmp .hf_trail
.hf_val_ret:
    add rax, rbx
    jmp .hf_ret
.hf_next:
    lea r15, [rbp + 2]               ; past CRLF
    cmp r15, r12
    jb .hf_line
.hf_none:
    xor eax, eax
    xor edx, edx
.hf_ret:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2p_val_has(rdi = value, rsi = len, rdx = token, ecx = token len) -> eax
; 1 when a comma-separated value contains the token (case-insensitive).
h2p_val_has:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14d, ecx
    xor r15d, r15d
.vh_tok:
    cmp r15, r12
    jae .vh_no
    movzx eax, byte [rbx + r15]
    cmp al, ' '
    je .vh_skip
    cmp al, 9
    je .vh_skip
    cmp al, ','
    jne .vh_start
.vh_skip:
    inc r15
    jmp .vh_tok
.vh_start:
    mov rcx, r15
.vh_end:
    cmp rcx, r12
    jae .vh_have
    movzx eax, byte [rbx + rcx]
    cmp al, ','
    je .vh_have
    cmp al, ' '
    je .vh_have
    inc rcx
    jmp .vh_end
.vh_have:
    push rcx
    mov rax, rcx
    sub rax, r15
    lea rdi, [rbx + r15]
    mov rsi, rax
    mov rdx, r13
    mov ecx, r14d
    call linnea_string_iequal
    pop rcx
    test eax, eax
    jnz .vh_yes
    mov r15, rcx
    inc r15
    jmp .vh_tok
.vh_yes:
    mov eax, 1
    jmp .vh_ret
.vh_no:
    xor eax, eax
.vh_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2p_emit_headers(rdi = out, rsi = slot*, rdx = conn) -> rax = bytes written.
; Translate the upstream's h1 response head into an h2 HEADERS frame: the
; status as :status, then every field except the hop-by-hop ones and the
; framing we re-derive (Transfer-Encoding, Connection, Content-Length for a
; chunked body). Names are lowercased into the HPACK literal, as h2 requires.
h2p_emit_headers:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 56                      ; +[rsp+40] tracks a forwarded content-length
                                     ; and [rsp+48] which policy fields SURVIVE
    mov [rsp], rdi                   ; frame start
    mov rbx, rsi                     ; slot
    mov [rsp + 8], rdx               ; conn
    mov rax, [rbx + linnea_h2p.srv]  ; the vhost this request selected
    mov [h2_cur_srv], rax
    lea r15, [rdi + 9]               ; payload cursor
    ; [rsp+40] is "a content-length must not go out from here". It starts set
    ; when the status is one HTTP forbids a Content-Length on -- 1xx and 204,
    ; RFC 9110 8.6 -- and is set again by the first one that does go out, since
    ; a repeat would hand the client two (Finding 34). Both are the same
    ; question, so they share the one flag (audit-report-9 Finding 2). rdi is
    ; the frame start until r15 is taken off it, so the call waits until here.
    mov edi, [rbx + linnea_h2p.status]
    call linnea_http_status_no_clen
    mov [rsp + 40], rax
    mov qword [rsp + 48], 0          ; no surviving policy field seen yet
    ; :status — literal with the static name index (8), value as 3 digits
    mov rax, [rbx + linnea_h2p.status]
    lea rdi, [h2p_stbuf]
    xor edx, edx
    mov ecx, 100
    div ecx
    add al, '0'
    mov [rdi], al
    mov eax, edx
    xor edx, edx
    mov ecx, 10
    div ecx
    add al, '0'
    mov [rdi + 1], al
    add dl, '0'
    mov [rdi + 2], dl
    mov rdi, r15
    mov esi, 8
    lea rdx, [h2p_stbuf]
    mov ecx, 3
    call h2_enc_hdr
    mov r15, rdi
    ; the upstream's fields
    lea r12, [rbx + linnea_h2p.buf]  ; head start
    mov r13, [rbx + linnea_h2p.rd]   ; head length (rd = first body byte)
    xor r14d, r14d                   ; line start
    ; skip the status line
.eh_status_eol:
    cmp r14, r13
    jae .eh_done
    cmp byte [r12 + r14], 13
    je .eh_status_done
    inc r14
    jmp .eh_status_eol
.eh_status_done:
    add r14, 2
.eh_line:
    cmp r14, r13
    jae .eh_done
    mov rbp, r14
.eh_eol:
    cmp rbp, r13
    jae .eh_done
    cmp byte [r12 + rbp], 13
    je .eh_have
    inc rbp
    jmp .eh_eol
.eh_have:
    mov rcx, rbp
    sub rcx, r14                     ; line length
    test rcx, rcx
    jz .eh_done                      ; the empty line ends the head
    ; split at the colon
    mov rdx, r14
.eh_colon:
    cmp rdx, rbp
    jae .eh_next                     ; no colon: not a header line, skip it
    cmp byte [r12 + rdx], ':'
    je .eh_colon_found
    inc rdx
    jmp .eh_colon
.eh_colon_found:
    mov [rsp + 16], rdx              ; colon offset
    mov rax, rdx
    sub rax, r14                     ; name length
    test rax, rax
    jz .eh_next
    cmp rax, LINNEA_HTTP_MAX_FIELD_NAME
    ja .eh_next                      ; a backstop on this buffer, not a
                                     ; policy: the shared validator has
                                     ; already refused a longer name, so
                                     ; reaching here would be a bug. It
                                     ; WAS the policy, at 64 bytes and
                                     ; enforced only here, which erased
                                     ; valid fields h1 forwarded
                                     ; (audit-report-12 Finding 2).
    mov [rsp + 24], rax              ; the name's length, across the calls
    ; lowercase the name into the scratch (h2 forbids uppercase)
    lea rdi, [h2p_nmbuf]
    lea rsi, [r12 + r14]
    mov rcx, rax
.eh_lower:
    movzx edx, byte [rsi]
    cmp dl, 'A'
    jb .eh_lower_put
    cmp dl, 'Z'
    ja .eh_lower_put
    or dl, 0x20
.eh_lower_put:
    mov [rdi], dl
    inc rsi
    inc rdi
    dec rcx
    jnz .eh_lower
    ; drop the fields we re-derive or must not forward
    lea rdi, [h2p_nmbuf]
    mov rsi, [rsp + 24]
    call h2p_name_dropped            ; -> eax = 1 when it must not be forwarded
    test eax, eax
    jnz .eh_next
    ; ...and the fields this head's own Connection value names (RFC 9110 7.6.1).
    ; h2 must strip these regardless: RFC 9113 8.2.2 forbids connection-specific
    ; fields in an h2 message at all (audit-report-10 Finding 2).
    mov rdi, r12                     ; the head being translated...
    mov rsi, r13                     ; ...and its length
    lea rdx, [h2p_nmbuf]
    mov rcx, [rsp + 24]
    call linnea_http_head_conn_named
    test eax, eax
    jnz .eh_next
    ; It survives, so it will reach the client -- and only now does it count as
    ; the backend having set a policy. Asking the RAW head afterwards, which is
    ; what this used to do, meant an upstream could name its own
    ; Strict-Transport-Security in Connection and have the field correctly
    ; dropped AND suppress ours, so the client got neither (audit-report-15
    ; Finding 2).
    mov rax, [rsp + 24]              ; name length
    cmp rax, h2p_hn_hsts_len
    jne .eh_sec_sniff
    lea rdi, [h2p_nmbuf]
    mov rsi, rax
    lea rdx, [h2p_hn_hsts]
    mov ecx, h2p_hn_hsts_len
    call linnea_string_iequal
    test eax, eax
    jz .eh_sec_done
    or qword [rsp + 48], 1
    jmp .eh_sec_done
.eh_sec_sniff:
    cmp rax, h2_nosniff_name_len
    jne .eh_sec_done
    lea rdi, [h2p_nmbuf]
    mov rsi, rax
    lea rdx, [h2_nosniff_name]
    mov ecx, h2_nosniff_name_len
    call linnea_string_iequal
    test eax, eax
    jz .eh_sec_done
    or qword [rsp + 48], 2
.eh_sec_done:
    ; forward only the FIRST content-length (RFC 9110 8.6, Finding 34), and none
    ; at all on a status that forbids the field. A repeated one was validated to
    ; name the same length; emitting both would hand the client two
    ; content-length fields, which it may reject.
    cmp qword [rsp + 24], h2p_hn_cl_len
    jne .eh_forward
    lea rdi, [h2p_nmbuf]             ; already lowercased
    mov rsi, h2p_hn_cl_len
    lea rdx, [h2p_hn_cl]
    mov rcx, h2p_hn_cl_len
    call linnea_string_iequal
    test eax, eax
    jz .eh_forward                   ; a different 14-char name
    cmp qword [rsp + 40], 0
    jne .eh_next                     ; forbidden here, or one already went out
    mov qword [rsp + 40], 1
.eh_forward:
    ; The VALUE, not the field line: OWS at either end belongs to the line, and
    ; RFC 9113 8.2.1 forbids an h2 field value that starts or ends with SP or
    ; HTAB. This stripped a leading SP and nothing else, so a legal upstream
    ; "X-Note:\tvalue\t" was HPACK-encoded with its delimiters attached
    ; (audit-report-14 Finding 2). Report 7 asked for exactly this and only the
    ; framing lookups were changed, which is why Content-Length with HTAB worked
    ; while every other field still carried its whitespace through.
    mov rdx, [rsp + 16]
    inc rdx                          ; past the colon
    mov [rsp + 32], rbp              ; the line's CR offset, across the calls
    lea rdi, [r12 + rdx]
    mov rsi, rbp
    sub rsi, rdx                     ; the raw span between colon and CR
    call linnea_string_trim_ows      ; -> rax = value, rdx = its length
    mov rcx, rdx                     ; value length
    mov rdx, rax                     ; value pointer
.eh_vdone:
    ; emit: literal without indexing, literal name (index 0)
    mov rdi, r15
    lea rsi, [h2p_nmbuf]
    mov r8, rcx                      ; value length
    mov rcx, rdx                     ; value ptr (already trimmed)
    mov rdx, [rsp + 24]              ; name length
    call h2_enc_hdr_lit
    mov r15, rdi
    mov rbp, [rsp + 32]
.eh_next:
    lea r14, [rbp + 2]
    jmp .eh_line
.eh_done:
    ; the hop this response crossed (RFC 9110 7.6.3), naming the version the
    ; upstream answered on. `via` is static-table 60, so the name costs a byte.
    mov rdi, r15
    mov esi, 60
    lea rdx, [h2p_via_val]
    mov ecx, h2p_via_val_len
    call h2_enc_hdr
    mov r15, rdi
    ; our own security headers ride a proxied response too — they describe
    ; the origin, not the backend — but only when the backend did not set
    ; them itself, so an app that sends its own policy still wins
    mov r14, [h2_cur_srv]
    test r14, r14
    jz .eh_frame
    cmp qword [r14 + linnea_config_server.hsts_len], 0
    je .eh_nosniff
    test qword [rsp + 48], 1         ; did one actually SURVIVE to the client?
    jnz .eh_nosniff
    mov rdi, r15
    mov esi, 56                      ; strict-transport-security
    lea rdx, [r14 + linnea_config_server.hsts]
    mov rcx, [r14 + linnea_config_server.hsts_len]
    call h2_enc_hdr
    mov r15, rdi
.eh_nosniff:
    cmp qword [r14 + linnea_config_server.nosniff], 0
    je .eh_frame
    test qword [rsp + 48], 2
    jnz .eh_frame
    mov rdi, r15
    lea rsi, [h2_nosniff_name]
    mov rdx, h2_nosniff_name_len
    lea rcx, [h2_nosniff_val]
    mov r8, h2_nosniff_val_len
    call h2_enc_hdr_lit
    mov r15, rdi
.eh_frame:
    ; the frame header: END_HEADERS, plus END_STREAM when no body follows
    mov rdi, [rsp]
    mov rbp, r15
    sub rbp, rdi
    sub rbp, 9                       ; payload length
    mov rax, rbp
    shr rax, 16
    mov [rdi], al
    mov rax, rbp
    shr rax, 8
    mov [rdi + 1], al
    mov [rdi + 2], bpl
    mov byte [rdi + 3], LINNEA_H2_FT_HEADERS
    mov r8b, LINNEA_H2_FLAG_END_HEADERS
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_NO_BODY
    jz .eh_flags
    or r8b, LINNEA_H2_FLAG_END_STREAM
.eh_flags:
    mov [rdi + 4], r8b
    mov rax, [rbx + linnea_h2p.sid]
    mov rdx, rax
    shr rax, 24
    mov [rdi + 5], al
    mov rax, rdx
    shr rax, 16
    mov [rdi + 6], al
    mov rax, rdx
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], dl
    lea rax, [rbp + 9]
    add rsp, 56
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2p_name_dropped(rdi = lowercased name, rsi = len) -> eax = 1 when the
; field must not be forwarded to the client: hop-by-hop (RFC 9110 7.6.1) and
; the framing h2 carries itself.
h2p_name_dropped:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    lea rdx, [h2p_dropped_tab]
.nd_loop:
    mov rcx, [rdx]                   ; name ptr (0 = end)
    test rcx, rcx
    jz .nd_no
    cmp qword [rdx + 8], r12
    jne .nd_next
    push rdx
    mov rdi, rbx
    mov rsi, r12
    mov rdx, rcx
    mov rcx, r12
    call linnea_string_iequal
    pop rdx
    test eax, eax
    jnz .nd_yes
.nd_next:
    add rdx, 16
    jmp .nd_loop
.nd_yes:
    mov eax, 1
    jmp .nd_ret
.nd_no:
    xor eax, eax
.nd_ret:
    pop r12
    pop rbx
    ret

; h2p_emit_error(rdi = out, rsi = slot*, rdx = conn) -> rax = bytes written.
; The synthetic response for an exchange that failed before any bytes reached
; the client: HEADERS(:status, content-type, content-length) + DATA, both
; ending the stream.
h2p_emit_error:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [h2_err_conn], rdx           ; kept: rdx is reused before the body is sized
    mov rbx, rsi                     ; slot
    mov rax, [rbx + linnea_h2p.srv]
    mov [h2_cur_srv], rax
    mov r14, rdi                     ; frame start
    mov rax, [rbx + linnea_h2p.status]
    lea r12, [body_502]              ; the message body
    mov r13d, body_502_len
    cmp rax, 504
    jne .ee_pick_413
    lea r12, [body_504]
    mov r13d, body_504_len
    jmp .ee_status
.ee_pick_413:
    cmp rax, 413
    jne .ee_pick_408
    lea r12, [body_413]
    mov r13d, body_413_len
    jmp .ee_status
.ee_pick_408:
    cmp rax, 408
    jne .ee_status
    lea r12, [body_408]
    mov r13d, body_408_len
.ee_status:
    lea rdi, [h2p_stbuf]             ; the status as three digits
    xor edx, edx
    mov ecx, 100
    div ecx
    add al, '0'
    mov [rdi], al
    mov eax, edx
    xor edx, edx
    mov ecx, 10
    div ecx
    add al, '0'
    mov [rdi + 1], al
    add dl, '0'
    mov [rdi + 2], dl
    ; Flow control, now that the status is safely in h2p_stbuf: rax carried it
    ; into the division above, so this could not go any earlier. Sized before
    ; content-length and the access line, so both describe what actually goes out
    ; (RFC 9113 6.9.1).
    mov rdi, [h2_err_conn]
    mov rsi, r13
    call h2_data_window_take
    test eax, eax
    jnz .ee_body_fits
    xor r13d, r13d
.ee_body_fits:
    mov [rbx + linnea_h2p.lg_bytes], r13   ; the synthetic body, for the access line
    mov rdi, r13                     ; content-length text
    lea rsi, [h2p_numbuf]
    call linnea_string_from_u64
    mov r15, rax                     ; its length
    lea rdi, [r14 + 9]
    mov esi, 8                       ; :status
    lea rdx, [h2p_stbuf]
    mov ecx, 3
    call h2_enc_hdr
    mov esi, 31                      ; content-type: text/plain
    lea rdx, [mime_txt_h2]
    mov ecx, mime_txt_h2_len
    call h2_enc_hdr
    mov esi, 28                      ; content-length
    lea rdx, [h2p_numbuf]
    mov rcx, r15
    call h2_enc_hdr
    call h2_enc_date_server
    mov rbp, rdi
    sub rbp, r14
    sub rbp, 9                       ; payload length
    mov rdi, r14
    mov rax, rbp
    shr rax, 16
    mov [rdi], al
    mov rax, rbp
    shr rax, 8
    mov [rdi + 1], al
    mov [rdi + 2], bpl
    mov byte [rdi + 3], LINNEA_H2_FT_HEADERS
    mov byte [rdi + 4], LINNEA_H2_FLAG_END_HEADERS
    mov rax, [rbx + linnea_h2p.sid]
    mov rdx, rax
    shr rax, 24
    mov [rdi + 5], al
    mov rax, rdx
    shr rax, 16
    mov [rdi + 6], al
    mov rax, rdx
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], dl
    ; DATA (END_STREAM) carrying the message
    lea rdi, [r14 + rbp + 9]
    mov rax, r13
    shr rax, 16
    mov [rdi], al
    mov rax, r13
    shr rax, 8
    mov [rdi + 1], al
    mov [rdi + 2], r13b
    mov byte [rdi + 3], LINNEA_H2_FT_DATA
    mov byte [rdi + 4], LINNEA_H2_FLAG_END_STREAM
    mov rax, [rbx + linnea_h2p.sid]
    mov rdx, rax
    shr rax, 24
    mov [rdi + 5], al
    mov rax, rdx
    shr rax, 16
    mov [rdi + 6], al
    mov rax, rdx
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], dl
    add rdi, 9
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov rax, rdi
    sub rax, r14                     ; total bytes written
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2_slot_find(rdi=conn, esi=stream id) -> rax = slot* or 0. Caller-saved only
; besides reading the pool; preserves the frame-loop's rbx/r12-r15.
h2_slot_find:
    lea rax, [rdi + linnea_connection.up_buf + LINNEA_H2_POOL_OFF]
    mov ecx, LINNEA_H2_MAX_STREAMS
.sf_loop:
    cmp [rax + linnea_h2_stream.id], rsi
    je .sf_hit
    add rax, linnea_h2_stream_size
    dec ecx
    jnz .sf_loop
    xor eax, eax
.sf_hit:
    ret

; h2_slot_alloc(rdi=conn, esi=stream id) -> rax = slot* or 0 (pool full).
; h2_slot_alloc(rdi=conn, rsi=stream id, rdx=req) -> rax = slot* or 0 (pool
; full). Also records the request's RFC 9218 priority on the slot, so the two
; call sites cannot drift apart on how a response gets scheduled.
h2_slot_alloc:
    lea rax, [rdi + linnea_connection.up_buf + LINNEA_H2_POOL_OFF]
    mov ecx, LINNEA_H2_MAX_STREAMS
.sa_loop:
    cmp qword [rax + linnea_h2_stream.id], 0
    je .sa_free
    add rax, linnea_h2_stream_size
    dec ecx
    jnz .sa_loop
    xor eax, eax
    ret
.sa_free:
    mov [rax + linnea_h2_stream.id], rsi
    mov qword [rax + linnea_h2_stream.urgency], 3      ; RFC 9218 defaults
    mov qword [rax + linnea_h2_stream.incremental], 0
    test rdx, rdx
    jz .sa_ret                       ; no request (never happens today)
    mov rdi, [rdx + linnea_h2_req.prio_ptr]
    test rdi, rdi
    jz .sa_ret                       ; no `priority` field: keep the defaults
    push rax                         ; (also what leaves the call 16-aligned)
    mov rsi, [rdx + linnea_h2_req.prio_len]
    call linnea_quic_parse_priority  ; rax = urgency, rdx = incremental
    mov rcx, rax
    pop rax
    mov [rax + linnea_h2_stream.urgency], rcx
    mov [rax + linnea_h2_stream.incremental], rdx
.sa_ret:
    ret

; h2_schedule(rdi=conn) -> rax = 1 if a DATA frame was queued (out_ptr /
; out_rem / file_ptr / file_rem set), else 0. Reaps finished slots (munmap +
; free), then round-robins from h2_rr_cursor to the next slot with body bytes
; and window, emitting one DATA frame capped at 16 KB and the send windows.
h2_schedule:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32                      ; [0]=best key, [8]=best slot, [16]=its cursor
    mov qword [rsp], -1              ; no candidate yet (every real key is lower)
    mov qword [rsp + 8], 0
    mov rbx, rdi
    lea r12, [rdi + linnea_connection.up_buf + LINNEA_H2_POOL_OFF]  ; pool base
    ; reap slots whose body is fully framed (their last DATA has drained)
    xor ecx, ecx
.reap:
    cmp ecx, LINNEA_H2_MAX_STREAMS
    jae .reaped
    mov eax, ecx
    imul rax, rax, linnea_h2_stream_size
    lea rax, [r12 + rax]
    cmp qword [rax + linnea_h2_stream.id], 0
    je .reap_next
    cmp qword [rax + linnea_h2_stream.up], 0
    jne .reap_next                   ; proxied: h2p_finish_stream frees it
    cmp qword [rax + linnea_h2_stream.body_rem], 0
    jne .reap_next
    mov rdi, [rax + linnea_h2_stream.file_base]
    test rdi, rdi
    jz .reap_free
    push rax
    push rcx
    mov rsi, [rax + linnea_h2_stream.file_size]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    pop rcx
    pop rax
.reap_free:
    mov qword [rax + linnea_h2_stream.id], 0
    mov qword [rax + linnea_h2_stream.file_base], 0   ; no stale mapping to re-free
    inc qword [rbx + linnea_connection.h2_done_count]   ; refills the reset budget
.reap_next:
    inc ecx
    jmp .reap
.reaped:
    ; connection window closed -> nobody can send
    mov rax, [rbx + linnea_connection.h2_cwnd]
    test rax, rax
    jle .none
    ; round-robin scan for a slot with body bytes and a stream window
    mov r13, [rbx + linnea_connection.h2_rr_cursor]
    xor r14d, r14d                   ; slots examined
.scan:
    cmp r14d, LINNEA_H2_MAX_STREAMS
    jae .scan_done
    mov rax, r13                     ; the cursor is kept in [0, MAX_STREAMS)
    imul rax, rax, linnea_h2_stream_size
    lea r15, [r12 + rax]             ; slot ptr
    cmp qword [r15 + linnea_h2_stream.id], 0
    je .scan_next
    cmp qword [r15 + linnea_h2_stream.up], 0
    je .scan_static
    ; proxied: point body_ptr/body_rem at the slot's decoded, unframed bytes
    push rbx
    push r13
    push r14
    mov rdi, [rbx + linnea_connection.index]
    mov rsi, [r15 + linnea_h2_stream.up]
    dec rsi
    call linnea_h2p_at
    pop r14
    pop r13
    pop rbx
    mov rcx, [rax + linnea_h2p.wr]
    sub rcx, [rax + linnea_h2p.off]  ; decoded bytes not yet framed
    mov [r15 + linnea_h2_stream.body_rem], rcx
    lea rdx, [rax + linnea_h2p.buf]
    add rdx, [rax + linnea_h2p.off]
    mov [r15 + linnea_h2_stream.body_ptr], rdx
    ; END_STREAM rides the last DATA frame once the body is complete
    mov rdx, [rax + linnea_h2p.flags]
    and rdx, LINNEA_H2P_F_BODY_DONE
    jz .scan_up_flags
    mov qword [r15 + linnea_h2_stream.flags], LINNEA_H2_STREAM_END
.scan_up_flags:
    test rcx, rcx
    jnz .scan_win
    ; nothing decoded to send: finish the stream when the body is complete
    test qword [rax + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jz .scan_next
    test qword [rax + linnea_h2p.flags], LINNEA_H2P_F_NO_BODY
    jnz .scan_next                   ; HEADERS already carried END_STREAM
    jmp .scan_cand                   ; an empty final DATA carries END_STREAM
.scan_static:
    cmp qword [r15 + linnea_h2_stream.body_rem], 0
    je .scan_next
    jmp .scan_win
.scan_win:
    cmp qword [r15 + linnea_h2_stream.swnd], 0
    jle .scan_next
.scan_cand:
    ; This slot can send. Score it: priority key = urgency<<40 |
    ; incremental<<39 | tiebreak, lowest wins — the same key h3's pump uses.
    ; The tiebreak keeps order within one urgency: a non-incremental stream is
    ; ranked by its stream id, so the earliest arrival runs to completion first,
    ; while an incremental one is ranked by its distance past the round-robin
    ; cursor, so equal peers take turns.
    mov rax, [r15 + linnea_h2_stream.urgency]
    shl rax, 40
    mov rcx, [r15 + linnea_h2_stream.incremental]
    shl rcx, 39
    or rax, rcx
    cmp qword [r15 + linnea_h2_stream.incremental], 0
    jne .scan_key_incr
    mov rcx, [r15 + linnea_h2_stream.id]
    jmp .scan_key
.scan_key_incr:
    mov rcx, r14                     ; slots examined = distance past the cursor
.scan_key:
    mov rdx, 0x7FFFFFFFFF            ; keep the tiebreak inside its 39-bit field
    and rcx, rdx
    or rax, rcx
    cmp rax, [rsp]
    jae .scan_next                   ; no better than the best so far
    mov [rsp], rax
    mov [rsp + 8], r15
    mov [rsp + 16], r13
.scan_next:
    inc r13
    cmp r13, LINNEA_H2_MAX_STREAMS
    jb .scan_wrapped
    xor r13d, r13d
.scan_wrapped:
    inc r14d
    jmp .scan
.scan_done:
    cmp qword [rsp + 8], 0
    je .none                         ; nothing servable
    mov r15, [rsp + 8]
    mov r13, [rsp + 16]
.emit:
    ; chunk = min(cwnd, swnd, body_rem, MAX_FRAME)
    mov rax, [rbx + linnea_connection.h2_cwnd]
    mov rdx, [r15 + linnea_h2_stream.swnd]
    cmp rdx, rax
    jge .m1
    mov rax, rdx
.m1:
    mov rdx, [r15 + linnea_h2_stream.body_rem]
    cmp rax, rdx
    jbe .m2
    mov rax, rdx
.m2:
    cmp rax, LINNEA_H2_MAX_FRAME
    jbe .m3
    mov eax, LINNEA_H2_MAX_FRAME
.m3:
    mov r14, rax                     ; chunk
    lea rdi, [rbx + linnea_connection.out_buf]
    mov rax, r14
    shr rax, 16
    mov [rdi], al
    mov rax, r14
    shr rax, 8
    mov [rdi + 1], al
    mov [rdi + 2], r14b
    mov byte [rdi + 3], LINNEA_H2_FT_DATA
    ; END_STREAM if this chunk finishes the body and END was requested
    xor r8d, r8d
    mov rax, [r15 + linnea_h2_stream.body_rem]
    cmp rax, r14
    jne .e_flags
    test qword [r15 + linnea_h2_stream.flags], LINNEA_H2_STREAM_END
    jz .e_flags
    mov r8b, LINNEA_H2_FLAG_END_STREAM
.e_flags:
    mov [rdi + 4], r8b
    mov r9, [r15 + linnea_h2_stream.id]
    mov rax, r9
    shr rax, 24
    mov [rdi + 5], al
    mov rax, r9
    shr rax, 16
    mov [rdi + 6], al
    mov rax, r9
    shr rax, 8
    mov [rdi + 7], al
    mov [rdi + 8], r9b
    mov [rbx + linnea_connection.out_ptr], rdi
    mov qword [rbx + linnea_connection.out_rem], 9
    mov qword [rbx + linnea_connection.h2_tx_busy], 1
    mov rax, [r15 + linnea_h2_stream.body_ptr]
    mov [rbx + linnea_connection.file_ptr], rax
    mov [rbx + linnea_connection.file_rem], r14
    add [r15 + linnea_h2_stream.body_ptr], r14
    sub [r15 + linnea_h2_stream.body_rem], r14
    sub [r15 + linnea_h2_stream.swnd], r14
    sub [rbx + linnea_connection.h2_cwnd], r14
    ; a proxied stream: charge the bytes to its upstream slot, and once the
    ; decoded body is fully framed, release the slot (it holds no mapping)
    cmp qword [r15 + linnea_h2_stream.up], 0
    je .emit_static
    push rbx
    push r13
    push r14
    mov rdi, [rbx + linnea_connection.index]
    mov rsi, [r15 + linnea_h2_stream.up]
    dec rsi
    call linnea_h2p_at
    pop r14
    pop r13
    pop rbx
    add [rax + linnea_h2p.off], r14
    add [rax + linnea_h2p.lg_bytes], r14   ; body bytes framed, for the access line
    test qword [rax + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jz .emit_static
    mov rcx, [rax + linnea_h2p.wr]
    cmp [rax + linnea_h2p.off], rcx
    jb .emit_static                  ; more decoded bytes still to frame
    mov qword [r15 + linnea_h2_stream.id], 0      ; the stream is complete
    inc qword [rbx + linnea_connection.h2_done_count]
    ; the DATA frame just queued sends straight out of this slot's buffer, so
    ; the slot cannot be freed (and reused) until that send has drained: mark
    ; it, and the next service pass — which only runs with no send in flight —
    ; releases it
    or qword [rax + linnea_h2p.flags], LINNEA_H2P_F_REAP
.emit_static:
    ; Rotate the cursor past this slot only if it is incremental, so its
    ; equal-urgency peers get the next turn. A non-incremental stream leaves the
    ; cursor alone and keeps winning its urgency until it is done (RFC 9218 4.1
    ; — the client asked for one response in full before the others).
    cmp qword [r15 + linnea_h2_stream.incremental], 0
    je .emit_done
    inc r13
    cmp r13, LINNEA_H2_MAX_STREAMS
    jb .emit_store
    xor r13d, r13d
.emit_store:
    mov [rbx + linnea_connection.h2_rr_cursor], r13
.emit_done:
    mov eax, 1
    jmp .sched_ret
.none:
    xor eax, eax
.sched_ret:
    add rsp, 32                      ; the best-candidate frame
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; h2_conn_vhost(rdi=conn) -> rax = server* whose certificate this connection
; presented: the SNI-selected vhost, or the accepting server when the client
; named nothing we host (the RFC 6066 fallback hs_init starts from).
h2_conn_vhost:
    mov rax, [rdi + linnea_connection.sni_vhost]
    test rax, rax
    jnz .cv_ret
    mov eax, [rdi + linnea_connection.server]
    imul rax, rax, linnea_config_server_size
    lea rcx, [linnea_config_instance]
    lea rax, [rcx + rax + linnea_config.servers]
.cv_ret:
    ret

; h2_same_cert(rdi=server* a, rsi=server* b) -> eax = 1 when both are served
; under the same certificate. The certificate BYTES are compared, not the
; vhost: one multi-SAN certificate shared by several vhosts is exactly what a
; browser coalesces onto one connection, and those names are all ours to
; answer. (The HTTP/3 side does the same in vhost_same_cert.)
h2_same_cert:
    mov rax, [rdi + linnea_config_server.cert_list_len]
    cmp rax, [rsi + linnea_config_server.cert_list_len]
    jne .sc_no
    push rsi
    push rdi
    mov rdi, [rdi + linnea_config_server.cert_list]
    mov rsi, [rsi + linnea_config_server.cert_list]
    cmp rdi, rsi
    je .sc_yes_pop
    mov rcx, rax
    repe cmpsb
    jne .sc_no_pop
.sc_yes_pop:
    pop rdi
    pop rsi
    mov eax, 1
    ret
.sc_no_pop:
    pop rdi
    pop rsi
.sc_no:
    xor eax, eax
    ret

; h2_select_vhost(rdi=conn, rsi=req) -> rax = server* (by :authority, else the
; accepting server). Authority host is compared without any :port suffix.
h2_select_vhost:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    ; the default is the vhost whose certificate this connection presented,
    ; not the listener owner: a name we do not host (an address, an alias) is
    ; answered by the site the client actually negotiated, which is also what
    ; keeps it clear of the 421 test in the caller
    push rsi
    call h2_conn_vhost
    pop rsi
    mov r15, rax                                     ; default / result
    lea rbx, [linnea_config_instance]
    mov r12, [rsi + linnea_h2_req.auth_ptr]
    test r12, r12
    jz .vdone
    mov r13, [rsi + linnea_h2_req.auth_len]
    ; the host to match is the parser's slice (bracket-aware, port stripped),
    ; not everything before the first ':'. rsp is 8-aligned here, so square it
    ; for the call. r12/r13 survive it (the parser saves only rbx).
    mov rdi, r12
    mov rsi, r13
    sub rsp, 8
    call linnea_http_authority_host        ; rax = host len, rdx = host offset
    add rsp, 8
    cmp rax, -1
    je .vdone                              ; malformed (already rejected): default
    add r12, rdx
    mov r13, rax
.vscan:
    test r13, r13
    jz .vdone
    test r15, r15
    jz .vdone                              ; no connection vhost to scope the scan to
    mov r14, [rbx + linnea_config.server_count]
    xor ebp, ebp
.vloop:
    cmp rbp, r14
    jae .vdone
    mov rax, rbp
    imul rax, rax, linnea_config_server_size
    lea rax, [rbx + rax + linnea_config.servers]
    ; Only the vhosts on THIS connection's listener are candidates. The scan
    ; matched on hostname across every server, so two TLS servers sharing a
    ; hostname on different ports both resolved to the first one: a request to
    ; the second port was served from the first server's locations and root.
    ; h1 has always filtered here; h2 never did, and h3 cannot reach the case
    ; because its vhost table is built per port.
    ;
    ; r15 is the connection's own vhost throughout the loop -- it is only
    ; replaced by a match, and that jumps straight to .vdone.
    mov ecx, [rax + linnea_config_server.listen_fd]
    cmp ecx, [r15 + linnea_config_server.listen_fd]
    jne .vnext
    mov rcx, [rax + linnea_config_server.hostname_len]
    test rcx, rcx
    jz .vnext
    push rax
    mov rdi, r12
    mov rsi, r13
    lea rdx, [rax + linnea_config_server.hostname]
    call linnea_string_iequal
    pop rdx
    test rax, rax
    jz .vnext
    mov r15, rdx
    jmp .vdone
.vnext:
    inc rbp
    jmp .vloop
.vdone:
    mov rax, r15
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; h2_match_location(rdi=server*, rsi=path, rdx=path len) -> rax = location* or 0
; Longest matching prefix wins; prefixes are matched byte for byte.
h2_match_location:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r11, [rdi + linnea_config_server.location_count]
    xor r10d, r10d
    xor ebx, ebx                     ; best location
    xor ebp, ebp                     ; best prefix length
.qloop:
    cmp r10, r11
    jae .qdone
    mov rcx, r10
    imul rcx, rcx, linnea_config_location_size
    lea rcx, [r12 + rcx + linnea_config_server.locations]
    mov rdx, [rcx + linnea_config_location.prefix_len]
    cmp rdx, r14
    ja .qnext
    cmp rdx, rbp
    jbe .qnext
    lea rsi, [rcx + linnea_config_location.prefix]
    xor r8d, r8d
.qcmp:
    cmp r8, rdx
    jae .qbest
    mov al, [r13 + r8]
    cmp al, [rsi + r8]
    jne .qnext
    inc r8
    jmp .qcmp
.qbest:
    mov rbx, rcx
    mov rbp, rdx
.qnext:
    inc r10
    jmp .qloop
.qdone:
    mov rax, rbx
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret



; h2_enc_int(rdi=dst, rsi=value, cl=N prefix bits, r8b=flags) -> rdi advanced.
; HPACK integer (RFC 7541 5.1); the high bits of the first byte come from r8b.
h2_enc_int:
    mov eax, 1
    shl eax, cl
    dec eax                          ; max = (1<<N) - 1
    cmp rsi, rax
    jb .ismall
    mov r9d, eax                     ; keep max
    or eax, r8d
    mov [rdi], al
    inc rdi
    sub rsi, r9
.icont:
    cmp rsi, 0x80
    jb .ilast
    mov rax, rsi
    and eax, 0x7f
    or eax, 0x80
    mov [rdi], al
    inc rdi
    shr rsi, 7
    jmp .icont
.ilast:
    mov [rdi], sil
    inc rdi
    ret
.ismall:
    mov eax, esi
    or eax, r8d
    mov [rdi], al
    inc rdi
    ret

; h2_enc_hdr_lit(rdi=dst, rsi=name ptr, rdx=name len, rcx=value ptr, r8=value
; len) -> rdi advanced. Literal header field without indexing whose name is
; also a literal (name index 0), for headers outside the static table.
h2_enc_hdr_lit:
    push rbx
    push rbp
    push r12
    push r13
    mov rbx, rsi                     ; name ptr
    mov rbp, rdx                     ; name len
    mov r12, rcx                     ; value ptr
    mov r13, r8                      ; value len
    mov byte [rdi], 0                ; literal, name index 0 -> name follows
    inc rdi
    mov rsi, rbp                     ; name length: 7-bit prefix, H = 0
    mov cl, 7
    xor r8d, r8d
    call h2_enc_int
    mov rsi, rbx
    mov rcx, rbp
    rep movsb
    mov rsi, r13                     ; value length: 7-bit prefix, H = 0
    mov cl, 7
    xor r8d, r8d
    call h2_enc_int
    mov rsi, r12
    mov rcx, r13
    rep movsb
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; h2_enc_date_server(rdi=dst) -> rdi advanced. The date and server response
; fields every response carries (static-table names 33 and 54), then the
; serving vhost's security headers. The vhost comes from h2_cur_srv, set by
; whichever path is building this response — every caller runs synchronously
; inside one response build, so a global is enough and keeps this off the
; register-starved encode paths.
h2_enc_date_server:
    push rbx
    push r12
    mov rbx, rdi
    call linnea_time_http_now        ; rax = current IMF-fixdate text
    mov rdi, rbx
    mov esi, 33                      ; date
    mov rdx, rax
    mov ecx, LINNEA_HTTP_DATE_LEN
    call h2_enc_hdr
    mov esi, 54                      ; server
    lea rdx, [srv_linnea]
    mov ecx, srv_linnea_len
    call h2_enc_hdr
    mov r12, [h2_cur_srv]
    test r12, r12
    jz .eds_done
    cmp qword [r12 + linnea_config_server.hsts_len], 0
    je .eds_nosniff
    mov esi, 56                      ; strict-transport-security
    lea rdx, [r12 + linnea_config_server.hsts]
    mov rcx, [r12 + linnea_config_server.hsts_len]
    call h2_enc_hdr
.eds_nosniff:
    cmp qword [r12 + linnea_config_server.nosniff], 0
    je .eds_done
    lea rsi, [h2_nosniff_name]       ; not in the HPACK static table: both
    mov rdx, h2_nosniff_name_len     ; the name and the value are literals
    lea rcx, [h2_nosniff_val]
    mov r8, h2_nosniff_val_len
    call h2_enc_hdr_lit
.eds_done:
    pop r12
    pop rbx
    ret

; h2_enc_hdr(rdi=dst, esi=name index, rdx=value ptr, rcx=value len) -> rdi adv.
; Literal header field without indexing (RFC 7541 6.2.2), name by static
; index, value as a raw (non-Huffman) string.
h2_enc_hdr:
    push rbx
    push rbp
    mov rbx, rdx                     ; value ptr
    mov rbp, rcx                     ; value len
    mov cl, 4                        ; name index: 4-bit prefix, flags 0
    xor r8d, r8d
    call h2_enc_int
    mov rsi, rbp                     ; value length: 7-bit prefix, H = 0
    mov cl, 7
    xor r8d, r8d
    call h2_enc_int
    mov rsi, rbx
    mov rcx, rbp
    rep movsb                        ; copy the value bytes
    pop rbp
    pop rbx
    ret

; linnea_h2_conn_free(rdi=conn) — munmap every active stream slot's body
; mapping. Called from the io_uring teardown so a connection that closes with
; responses still in flight does not leak its file mappings. Preserves the
; teardown path's r12 (conn) and r13 (server*).
linnea_h2_conn_free:
    push r12
    push r13
    lea r12, [rdi + linnea_connection.up_buf + LINNEA_H2_POOL_OFF]
    mov r13d, LINNEA_H2_MAX_STREAMS
.cf_loop:
    cmp qword [r12 + linnea_h2_stream.id], 0
    je .cf_next
    mov rdi, [r12 + linnea_h2_stream.file_base]
    test rdi, rdi
    jz .cf_clear
    mov rsi, [r12 + linnea_h2_stream.file_size]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.cf_clear:
    mov qword [r12 + linnea_h2_stream.id], 0
.cf_next:
    add r12, linnea_h2_stream_size
    dec r13d
    jnz .cf_loop
    pop r13
    pop r12
    ret

; linnea_h2_after_send(rdi=conn) -> rax = LINNEA_H2_SEND / _MORE / _CLOSE.
; The idle decision shared by the io_uring send-drain hook and h2_handle's
; .no_out: continue streaming response bodies (interleaved), and fold in the
; drain path — on the worker's SIGTERM/upgrade drain an h2 connection sends
; GOAWAY(last-stream), finishes its open streams, then closes.
linnea_h2_after_send:
    push rbx
    mov rbx, rdi
    cmp dword [drain_flag], 0
    je .live
    cmp qword [rbx + linnea_connection.h2_state], LINNEA_H2_DRAINING
    je .drain_sched
    ; first notice of drain on this connection: announce GOAWAY once
    mov rdi, rbx
    call h2_queue_goaway
    mov eax, LINNEA_H2_SEND
    jmp .aret
.drain_sched:
    ; GOAWAY already sent: keep streaming open bodies; close once drained
    mov rdi, rbx
    call linnea_h2p_service
    test eax, eax
    jnz .send
    mov rdi, rbx
    call h2_schedule
    test eax, eax
    jnz .send
    mov rdi, rbx
    call h2_pool_active
    test rax, rax
    jnz .more                        ; streams remain: recv (WINDOW_UPDATE / idle)
    jmp .close
.live:
    mov rdi, rbx                      ; a proxied exchange may have a response
    call linnea_h2p_service           ; head / error / RST ready to go out
    test eax, eax
    jnz .send
    mov rdi, rbx
    call h2_schedule
    test eax, eax
    jnz .send
    cmp qword [rbx + linnea_connection.h2_state], LINNEA_H2_CLOSING
    je .close
    ; A peer that sent us GOAWAY is draining without the worker being: finish
    ; what is open, then close, rather than waiting for the idle timeout (h2-14).
    cmp qword [rbx + linnea_connection.h2_state], LINNEA_H2_DRAINING
    jne .more
    mov rdi, rbx
    call h2_pool_active
    test rax, rax
    jz .close                        ; nothing left in flight: done
.more:
    mov eax, LINNEA_H2_MORE
    jmp .aret
.send:
    mov eax, LINNEA_H2_SEND
    jmp .aret
.close:
    mov eax, LINNEA_H2_CLOSE
.aret:
    pop rbx
    ret

; The loop queues a GOAWAY when it closes an idle connection during a stop.
h2_queue_goaway_pub:
    jmp h2_queue_goaway

; h2_queue_goaway(rdi=conn) — write GOAWAY(last-stream-id, NO_ERROR) into
; out_buf, arm it as the pending send, and move to the DRAINING state.
h2_queue_goaway:
    lea rax, [rdi + linnea_connection.out_buf]
    mov byte [rax], 0
    mov byte [rax + 1], 0
    mov byte [rax + 2], 8            ; payload: last-stream(4) + error(4)
    mov byte [rax + 3], LINNEA_H2_FT_GOAWAY
    mov byte [rax + 4], 0
    mov dword [rax + 5], 0           ; stream 0
    mov rcx, [rdi + linnea_connection.h2_last_stream]
    mov rdx, rcx
    shr rcx, 24
    mov [rax + 9], cl
    mov rcx, rdx
    shr rcx, 16
    mov [rax + 10], cl
    mov rcx, rdx
    shr rcx, 8
    mov [rax + 11], cl
    mov [rax + 12], dl
    mov dword [rax + 13], 0          ; error code NO_ERROR
    mov [rdi + linnea_connection.out_ptr], rax
    mov qword [rdi + linnea_connection.out_rem], 17
    mov qword [rdi + linnea_connection.file_rem], 0
    mov qword [rdi + linnea_connection.h2_tx_busy], 1
    mov qword [rdi + linnea_connection.h2_state], LINNEA_H2_DRAINING
    ret

; h2_pool_active(rdi=conn) -> rax = number of active (non-free) stream slots.
linnea_h2_pool_active:
; linnea_h2_busy(rdi = conn) -> rax = 1 if this connection has work of its own
; in progress: an open response stream, or an upstream exchange still running.
;
; The client's idle timeout is armed per receive and refreshed only by bytes
; FROM the client, so a connection where the server is the one making progress
; looks idle. That is tolerable for a static body — a send is almost always in
; flight and the timeout path defers on h2_tx_busy — but a proxied response
; sits with nothing in flight in the gaps between upstream chunks, and the
; timeout would tear the connection down mid-response, taking every other
; stream on it with it.
linnea_h2_busy:
    push rdi
    call h2_pool_active
    pop rdi
    test eax, eax
    jnz .busy_yes
    mov rax, [rdi + linnea_connection.index]      ; any upstream slot still live
    imul rax, rax, LINNEA_H2P_SLOTS
    imul rax, rax, linnea_h2p_size
    add rax, [h2p_pool]
    mov ecx, LINNEA_H2P_SLOTS
.busy_scan:
    cmp qword [rax + linnea_h2p.state], LINNEA_H2P_FREE
    jne .busy_yes
    add rax, linnea_h2p_size
    dec ecx
    jnz .busy_scan
    xor eax, eax
    ret
.busy_yes:
    mov eax, 1
    ret

h2_pool_active:
    lea rdx, [rdi + linnea_connection.up_buf + LINNEA_H2_POOL_OFF]
    xor eax, eax
    mov ecx, LINNEA_H2_MAX_STREAMS
.pa_loop:
    cmp qword [rdx + linnea_h2_stream.id], 0
    je .pa_next
    inc eax
.pa_next:
    add rdx, linnea_h2_stream_size
    dec ecx
    jnz .pa_loop
    ret

; h2_apply_init_window(rdi=conn, esi=new SETTINGS_INITIAL_WINDOW_SIZE) — record
; the peer's initial stream send window (used for new streams) and shift every
; open stream's window by the delta (RFC 9113 6.9.2). A window may go negative;
; the scheduler simply will not send on it until a WINDOW_UPDATE lifts it > 0.
h2_apply_init_window:
    mov r8d, esi
    sub r8, [rdi + linnea_connection.h2_init_swnd]   ; delta = new - old
    mov [rdi + linnea_connection.h2_init_swnd], rsi
    lea rdx, [rdi + linnea_connection.up_buf + LINNEA_H2_POOL_OFF]
    mov ecx, LINNEA_H2_MAX_STREAMS
.aiw_loop:
    cmp qword [rdx + linnea_h2_stream.id], 0
    je .aiw_next
    add [rdx + linnea_h2_stream.swnd], r8
.aiw_next:
    add rdx, linnea_h2_stream_size
    dec ecx
    jnz .aiw_loop
    ret

section .rodata
method_get_h2:   db "GET"
method_head_h2:  db "HEAD"
method_connect_h2: db "CONNECT"
index_html_h2:   db "index.html"
status_100_h2:   db "100"
status_200_h2:   db "200"
status_206_h2:   db "206"
status_304_h2:   db "304"
status_412_h2:   db "412"
status_400_h2:   db "400"
status_404_h2:   db "404"
status_405_h2:   db "405"
status_416_h2:   db "416"
zero_h2:         db "0"
srv_linnea:      db "linnea"
srv_linnea_len   equ $ - srv_linnea
h2_bytes:        db "bytes"
h2_bytes_len     equ $ - h2_bytes
enc_br_h2:       db "br"
enc_br_h2_len    equ $ - enc_br_h2
enc_gzip_h2:     db "gzip"
enc_gzip_h2_len  equ $ - enc_gzip_h2
h2_ae_name:      db "Accept-Encoding"
h2_ae_name_len   equ $ - h2_ae_name
h2_nosniff_name: db "x-content-type-options"
h2_nosniff_name_len equ $ - h2_nosniff_name
h2_nosniff_val:  db "nosniff"
h2_nosniff_val_len equ $ - h2_nosniff_val
status_301_h2:   db "301"
status_421_h2:   db "421"
status_429_h2:   db "429"
method_options_h2: db "OPTIONS"
method_trace_h2:   db "TRACE"
body_options_h2:   db "Allow: GET, HEAD, OPTIONS", 10
body_options_h2_len equ $ - body_options_h2
mf_hdr_name:     db "Max-Forwards: "
mf_hdr_name_len  equ $ - mf_hdr_name
status_406_h2:   db "406"
status_417_h2:   db "417"
status_431_h2:   db "431"
body_429: db "429 Too Many Requests", 10
body_429_len equ $ - body_429
body_431: db "431 Request Header Fields Too Large", 10
body_431_len equ $ - body_431
body_502: db "502 Bad Gateway", 10
body_502_len equ $ - body_502
body_504: db "504 Gateway Timeout", 10
body_504_len equ $ - body_504
proto_h2: db "HTTP/2"
proto_h2_len equ $ - proto_h2
body_408: db "408 Request Timeout", 10
body_408_len equ $ - body_408
body_421_h2: db "421 Misdirected Request", 10
body_421_h2_len equ $ - body_421_h2
body_413: db "413 Content Too Large", 10
body_413_len equ $ - body_413
body_406: db "406 Not Acceptable", 10
body_406_len equ $ - body_406
body_417: db "417 Expectation Failed", 10
body_417_len equ $ - body_417
; --- proxy-over-h2 literals ---
h2p_http11:      db " HTTP/1.1", 13, 10, "Host: "
h2p_http11_len   equ $ - h2p_http11
ck_hdr_name:     db "cookie: "         ; the coalesced h1 Cookie line's name (Finding 32)
ck_hdr_name_len  equ $ - ck_hdr_name
h2p_clen:        db "Content-Length: "
h2p_clen_len     equ $ - h2p_clen
; The request reached us over HTTP/2, so that is what our Via entry names
; (RFC 9110 7.6.3). The response side uses the static-table "via" instead, and
; says 1.1 — the version the upstream answered on.
h2p_via:         db "Via: 2 linnea", 13, 10
h2p_via_len      equ $ - h2p_via
h2p_via_val:     db "1.1 linnea"
h2p_via_val_len  equ $ - h2p_via_val
h2p_conn_keep:   db "Connection: keep-alive", 13, 10, 13, 10
h2p_conn_keep_len equ $ - h2p_conn_keep
h2p_hn_conn:     db "connection"
h2p_val_close:   db "close"
h2p_conn_close:  db "Connection: close", 13, 10, 13, 10
h2p_conn_close_len equ $ - h2p_conn_close
h2p_hn_te:       db "transfer-encoding"
h2p_hn_te_len    equ $ - h2p_hn_te
h2p_hn_cl:       db "content-length"
h2p_hn_cl_len    equ $ - h2p_hn_cl
h2p_chunked:     db "chunked"
h2p_chunked_len  equ $ - h2p_chunked
h2p_hn_hsts:     db "strict-transport-security"
h2p_hn_hsts_len  equ $ - h2p_hn_hsts
; response fields never forwarded to the client: hop-by-hop (RFC 9110 7.6.1)
; plus the framing h2 carries itself
h2p_d_conn:      db "connection"
h2p_d_ka:        db "keep-alive"
h2p_d_tenc:      db "transfer-encoding"
h2p_d_upg:       db "upgrade"
h2p_d_trailer:   db "trailer"
h2p_d_pauth:     db "proxy-authenticate"
h2p_d_pconn:     db "proxy-connection"
; TE is hop-by-hop like the rest, and on HTTP/2 it is more than that: RFC 9113
; 8.2.2 makes a message carrying a connection-specific field malformed, TE
; included unless its value is exactly "trailers". It was missing here while
; every other name on the list was present, so a backend answering "TE: gzip"
; had it relayed to the client — us emitting a message the peer is entitled to
; reject. h1 has always dropped it and h3 does too; this is h2 catching up.
h2p_d_te:        db "te"
h2p_dropped_tab:
    dq h2p_d_conn, 10
    dq h2p_d_ka, 10
    dq h2p_d_tenc, 17
    dq h2p_d_upg, 7
    dq h2p_d_trailer, 7
    dq h2p_d_pauth, 18
    dq h2p_d_pconn, 16
    dq h2p_d_te, 2
    dq 0, 0
body_400: db "400 Bad Request", 10
body_400_len equ $ - body_400
body_404: db "404 Not Found", 10
body_404_len equ $ - body_404
; A 405 must say what the resource does allow (RFC 9110 15.5.6). Static files
; answer GET and HEAD; h3's POST echo is not a thing this resource supports, so
; it is deliberately not listed here either.
allow_val_h2:     db "GET, HEAD"
allow_val_h2_len  equ $ - allow_val_h2
body_405: db "405 Method Not Allowed", 10
body_405_len equ $ - body_405

section .bss
mf_num_buf: resb 24              ; the re-emitted Max-Forwards value
h2_path_buf:  resb LINNEA_HTTP2_PATH_BUF
h2_goaway_code: resd 1                ; the code the GOAWAY below reports
h2_err_conn:  resq 1                  ; the connection an inline error is answering
h2_err_blen:  resq 1                  ; its body length after the flow-control check
h2_err_status:  resq 1     ; which bodied stream error h2_err_stream is building
h2_err_code:    resq 1     ; ...as a number, for the access line
h2_err_body:    resq 1
h2_err_bodylen: resq 1
h2_numbuf:    resb 24
h2_crbuf:     resb 80                ; "bytes first-last/size" / "bytes */size"
h2_locbuf:    resb 2560              ; a redirect's Location value
h2_hdrs_buf:  resb 8192              ; proxy: the rebuilt h1 header lines
h2_cookie_buf: resb 8192             ; proxy: split cookie fields joined "; " (Finding 32)
h2_req_es:    resd 1                 ; END_STREAM was set on the HEADERS frame
h2_req_trail: resq 1                 ; ...and that HEADERS was a trailer section
h2p_pool:     resq 1                 ; the upstream slot array (one mmap)
h2_dyn_pool:  resq 1                 ; per-connection HPACK dynamic tables
h2_hb_pool:    resq 1                ; per-connection header-block assembly +
                                     ; HPACK decode scratch (LINNEA_H2_HB_AREA)
h2_cur_srv:   resq 1                 ; vhost whose response is being built
h2_fd_len:    resd 1                 ; a DATA frame's flow-control cost
h2_fd_credit: resd 1                 ; and whether it is owed back now
; The stream to credit alongside the connection, or 0. Only a slot that
; CONSUMED the payload outright sets it — a dropped frame must not, because a
; WINDOW_UPDATE on a stream that is idle or already reset is a connection error
; to the peer.
h2_fd_sid:    resd 1
; One clock read per h2p_service pass, so every slot in a pass is aged against
; the same instant. Per worker, like everything else here: the loop is
; single-threaded and the value does not outlive the pass that wrote it.
h2_sv_now:    resq 1
h2p_numbuf:   resb 24
h2p_stbuf:    resb 4                 ; a status as three ASCII digits
h2p_nmbuf:    resb LINNEA_HTTP_MAX_FIELD_NAME                ; a response field name, lowercased
