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

global linnea_h2_init
global linnea_h2_handle
global linnea_h2_after_send
global linnea_h2_conn_free
global linnea_h2_pool_active
global h2_queue_goaway_pub

extern linnea_hpack_decode
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
extern linnea_http_range_parse
extern linnea_http_ifrange_match
extern linnea_time_parse_http_date
extern linnea_time_http_now
extern linnea_config_instance
extern linnea_string_from_u64
extern linnea_string_iequal
extern linnea_memory_map
extern linnea_log_stamp
extern linnea_log_write
extern linnea_log_u64
extern drain_flag

; proxy-over-h2: slot pool init + lookup for the io_uring loop, the upstream
; event handler, and connection teardown (see the Q86 section below)
global linnea_h2p_init
global linnea_h2p_at
global linnea_h2p_event
global linnea_h2p_service
global linnea_h2p_conn_close
global h2p_compact

section .rodata

; PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
h2_preface: db "PRI * HTTP/2.0", 13, 10, 13, 10, "SM", 13, 10, 13, 10
h2_preface_len equ $ - h2_preface

hdr_altsvc_name: db "alt-svc"
hdr_altsvc_name_len equ $ - hdr_altsvc_name
mime_txt_h2:    db "text/plain"
mime_txt_h2_len equ $ - mime_txt_h2

dbgs:           db "DBG appends/bytes/sends/bodysends "
dbgs_len        equ $ - dbgs
dbgsp:          db " "
dbgc:           db "DBG credit "
dbgc_len        equ $ - dbgc
dbgnl:          db 10
dbgm:           db "DBG h2 goaway", 10
dbgm_len        equ $ - dbgm
msg_h2_pre:     db "linnea h2: "
msg_h2_pre_len  equ $ - msg_h2_pre

section .text

; linnea_h2_init(rdi=conn) — queue the server's initial SETTINGS frame
; (empty) into out_buf and mark the connection awaiting the client
; preface. The caller sends out_ptr/out_rem, then reads.
linnea_h2_init:
    mov qword [rdi + linnea_connection.h2_state], LINNEA_H2_PREFACE
    mov qword [rdi + linnea_connection.h2_cwnd], LINNEA_H2_INIT_WINDOW
    mov qword [rdi + linnea_connection.h2_rr_cursor], 0
    mov qword [rdi + linnea_connection.h2_last_stream], 0
    mov qword [rdi + linnea_connection.h2_rst_count], 0
    mov qword [rdi + linnea_connection.h2_done_count], 0
    mov qword [rdi + linnea_connection.h2_upload], 0
    mov qword [rdi + linnea_connection.h2_init_swnd], LINNEA_H2_INIT_WINDOW
    ; zero the stream pool: every slot free (id 0)
    push rdi
    lea rdi, [rdi + linnea_connection.up_buf + LINNEA_H2_POOL_OFF]
    xor eax, eax
    mov ecx, LINNEA_H2_POOL_BYTES / 8
    rep stosq
    pop rdi
    lea rax, [rdi + linnea_connection.out_buf]
    ; SETTINGS frame: length 12, type 4, flags 0, stream 0, two settings
    mov byte [rax], 0
    mov byte [rax + 1], 0
    mov byte [rax + 2], 12
    mov byte [rax + 3], LINNEA_H2_FT_SETTINGS
    mov byte [rax + 4], 0
    mov dword [rax + 5], 0          ; stream 0
    ; HEADER_TABLE_SIZE = 0: the peer's HPACK encoder gets no dynamic table,
    ; so our decoder never has to keep one (see linnea_hpack.inc).
    mov byte [rax + 9], 0
    mov byte [rax + 10], LINNEA_H2_SETTINGS_HEADER_TABLE_SIZE
    mov dword [rax + 11], 0         ; value 0
    ; MAX_CONCURRENT_STREAMS = LINNEA_H2_MAX_STREAMS (16): the size of our
    ; per-connection body-streaming pool.
    mov byte [rax + 15], 0
    mov byte [rax + 16], LINNEA_H2_SETTINGS_MAX_CONCURRENT_STREAMS
    mov dword [rax + 17], 0x10000000    ; value 16, big-endian
    mov [rdi + linnea_connection.out_ptr], rax
    mov qword [rdi + linnea_connection.out_rem], 21
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
    cmp eax, LINNEA_CONN_IN_BUF - 9  ; frame we could never buffer
    ja .goaway_close
    lea rcx, [rax + 9]               ; whole frame size
    mov rdx, r14
    sub rdx, r12
    cmp rdx, rcx
    jb .flush                        ; wait for the rest of the frame
    mov r11, rcx                     ; frame size
    movzx r9d, byte [rsi + 3]        ; type
    movzx r10d, byte [rsi + 4]       ; flags
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
    je .f_ignore
    cmp r9d, LINNEA_H2_FT_DATA
    je .f_data                       ; a request body (proxying) or dropped
    cmp r9d, LINNEA_H2_FT_HEADERS
    je .f_headers
    jmp .goaway_close                ; stray CONTINUATION / unknown
.f_window:
    ; WINDOW_UPDATE: grow the connection window (stream 0) or a streaming
    ; response's window. A zero increment is a protocol error.
    mov eax, [rsi + 9]
    bswap eax
    and eax, 0x7fffffff              ; 31-bit increment (top bit reserved)
    test eax, eax
    jz .goaway_close
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
    test edx, edx
    jnz .f_window_stream
    add [rbx + linnea_connection.h2_cwnd], rax
    jmp .f_ignore
.f_window_stream:
    push rax                         ; increment
    mov rdi, rbx
    mov esi, edx
    call h2_slot_find                ; -> rax = slot* or 0
    pop rcx                          ; increment
    test rax, rax
    jz .f_ignore                     ; unknown / closed stream: ignore
    add [rax + linnea_h2_stream.swnd], rcx
    jmp .f_ignore
.f_rst:
    ; RST_STREAM: drop the stream's slot. Rate-based rapid-reset guard
    ; (CVE-2023-44487): resets get a budget of LIMIT plus one token per eight
    ; streams that completed. A reset flood (few/no completions) still trips
    ; at ~LIMIT, but a busy, legitimate connection earns proportional headroom.
    inc qword [rbx + linnea_connection.h2_rst_count]
    mov rax, [rbx + linnea_connection.h2_done_count]
    shr rax, 3                       ; done_count / 8
    add rax, LINNEA_H2_RST_LIMIT
    cmp [rbx + linnea_connection.h2_rst_count], rax
    ja .goaway_close
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
    cmp rax, 600
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
    je .goaway_close
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
    lea rcx, [rsi + 9]               ; payload, minus any padding
    test r10b, LINNEA_H2_FLAG_PADDED
    jz .fd_nopad
    test eax, eax
    jz .goaway_close                 ; PADDED but empty payload
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
    test qword [rdi + linnea_h2p.flags], LINNEA_H2P_F_REQ_STREAM
    jz .fd_collect
    ; --- streaming: append to the FIFO; the loop sends it upstream ---
    mov r8, [rdi + linnea_h2p.rq_wr]
    lea r9, [r8 + rax]
    cmp r9, LINNEA_H2P_UPLOAD_BUF
    ja .fd_toobig                    ; past a full receive window: impossible
    cmp rax, [rdi + linnea_h2p.rq_rem]
    ja .fd_toobig                    ; more body than Content-Length declared
    mov dword [h2_fd_credit], 0      ; credited once it has gone upstream
    push rdi
    push r10
    push r11
    mov rdx, [rdi + linnea_h2p.rq_buf]
    add rdx, r8
    mov rsi, rcx
    mov rdi, rdx
    mov rcx, rax
    rep movsb
    pop r11
    pop r10
    pop rdi
    mov [rdi + linnea_h2p.rq_wr], r9
    sub [rdi + linnea_h2p.rq_rem], rax
    inc qword [dbg_appends]
    add [dbg_appended], rax
    or qword [rdi + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND
    jmp .fd_done
.fd_collect:
    mov r8, [rdi + linnea_h2p.len]
    lea r9, [r8 + rax]
    cmp r9, LINNEA_H2P_BODY_MAX
    ja .fd_toobig
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
    test r10b, LINNEA_H2_FLAG_END_STREAM
    jz .fd_done                      ; more body to come
    push r11
    call h2p_finalize                ; body complete: terminate and connect
    pop r11
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
.f_ignore:
    add r12, r11
    jmp .frames
.f_settings:
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
    jb .goaway_close                 ; FRAME_SIZE_ERROR: partial entry
    movzx edx, byte [rax]            ; setting id (16-bit)
    shl edx, 8
    movzx r8d, byte [rax + 1]
    or edx, r8d
    cmp edx, LINNEA_H2_SETTINGS_INITIAL_WINDOW_SIZE
    jne .set_next
    movzx r8d, byte [rax + 2]        ; value (32-bit, big-endian)
    shl r8d, 8
    movzx edx, byte [rax + 3]
    or r8d, edx
    shl r8d, 8
    movzx edx, byte [rax + 4]
    or r8d, edx
    shl r8d, 8
    movzx edx, byte [rax + 5]
    or r8d, edx
    cmp r8d, 0x7fffffff
    ja .goaway_close                 ; FLOW_CONTROL_ERROR: window too large
    push rax
    push rcx
    mov rdi, rbx
    mov esi, r8d
    call h2_apply_init_window        ; adjust init window + open streams
    pop rcx
    pop rax
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
    jne .goaway_close                ; FRAME_SIZE_ERROR
    add r12, r11
    jmp .frames
.f_ping:
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
    add r12, r11
    jmp .close                       ; peer is going away
.goaway_close:
    push rsi
    push r9
    push r10
    push r11
    call linnea_log_stamp
    lea rdi, [dbgm]
    mov esi, dbgm_len
    call linnea_log_write
    pop r11
    pop r10
    pop r9
    pop rsi
    ; queue GOAWAY(last_stream_id=0, NO_ERROR) and close once it's sent
    mov byte [r13], 0
    mov byte [r13 + 1], 0
    mov byte [r13 + 2], 8
    mov byte [r13 + 3], LINNEA_H2_FT_GOAWAY
    mov byte [r13 + 4], 0
    mov dword [r13 + 5], 0
    mov dword [r13 + 9], 0           ; last_stream_id 0
    mov dword [r13 + 13], 0          ; error code NO_ERROR
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
; CONTINUATION frames) into up_buf, HPACK-decodes it, and writes a minimal
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
%if L_OUT + 8 > 280
  %error "h2_build_request stack frame (sub rsp,280) too small for req + locals"
%endif
h2_build_request:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 280
    mov rbx, rdi                     ; conn
    mov [rsp + L_OUT], rcx           ; out cursor (where the response goes)
    mov [rsp + L_START], rsi
    lea r13, [rsi + rdx]             ; avail end
    mov r12, rsi                     ; current frame header
    lea r14, [rbx + linnea_connection.up_buf + LINNEA_H2_ASSEMBLY_OFF]
    lea r15, [r14 + LINNEA_H2_HBLOCK_MAX]            ; assembly limit
    mov qword [rsp + L_CONT], 0

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
    cmp ecx, LINNEA_CONN_IN_BUF - 9
    ja .err
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
    jz .err
    movzx edx, byte [rsi]            ; pad length
    inc rsi
    dec r11d
    sub r11d, edx
    js .err                          ; padding exceeds the payload
.no_pad:
    test r10b, LINNEA_H2_FLAG_PRIORITY
    jz .append
    cmp r11d, 5
    jb .err
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
    ja .err                          ; header block exceeds HBLOCK_MAX
    mov rdi, r14
    mov rcx, r11
    rep movsb                        ; rsi -> rdi
    mov r14, rdi
.after_append:
    test r10b, LINNEA_H2_FLAG_END_HEADERS
    jnz .assembled
    cmp qword [rsp + L_CONT], LINNEA_H2_MAX_CONT
    ja .err                          ; CONTINUATION flood
    jmp .frame_loop

.assembled:
    ; zero the whole req struct — a count derived from the struct size, so a
    ; field added later (like the conditional-request pointers) cannot be left
    ; holding stale stack bytes
    lea rdi, [rsp + REQ]
    xor eax, eax
    mov ecx, linnea_h2_req_size / 8
    rep stosq
    lea rax, [rbx + linnea_connection.up_buf + LINNEA_H2_SCRATCH_OFF]
    mov [rsp + REQ + linnea_h2_req.scratch], rax
    lea rcx, [rax + LINNEA_H2_HBLOCK_MAX]
    mov [rsp + REQ + linnea_h2_req.scratch_end], rcx
    mov rdi, rbx                     ; the connection's HPACK dynamic table
    call h2_dyn_for
    mov [rsp + REQ + linnea_h2_req.dyn], rax
    lea rax, [h2_hdrs_buf]           ; proxy header rebuild region
    mov [rsp + REQ + linnea_h2_req.hb_start], rax
    mov [rsp + REQ + linnea_h2_req.hb_cur], rax
    lea rax, [h2_hdrs_buf + 8192]
    mov [rsp + REQ + linnea_h2_req.hb_end], rax
    lea rdi, [rbx + linnea_connection.up_buf + LINNEA_H2_ASSEMBLY_OFF]  ; block
    mov rsi, r14
    sub rsi, rdi                     ; block length
    lea rdx, [rsp + REQ]
    call linnea_hpack_decode
    test rax, rax
    js .err                          ; any HPACK error -> connection error
    cmp qword [rsp + REQ + linnea_h2_req.method_ptr], 0
    je .err
    cmp qword [rsp + REQ + linnea_h2_req.path_ptr], 0
    je .err

    ; stream-id validation (RFC 9113 5.1.1): a client stream must be odd and
    ; numerically greater than every stream it has opened. Checked here (once
    ; the block is whole) so a partial-block retry does not double-count.
    mov r8, [rsp + L_SID]
    test r8, 1
    jz .err                          ; even id: connection error
    cmp r8, [rbx + linnea_connection.h2_last_stream]
    jbe .err                         ; not strictly increasing
    mov [rbx + linnea_connection.h2_last_stream], r8

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

.more:
    mov rax, LINNEA_H2_REQ_MORE
    jmp .ret
.err:
    mov rax, LINNEA_H2_REQ_ERR
.ret:
    add rsp, 280
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
h2_serve:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 136
    mov rbx, rdi                     ; conn
    mov r12, rsi                     ; req
    mov [rsp + S_SID], r8
    mov [rsp + S_OUT], r9            ; where the response is written
    ; draining: GOAWAY already went out, refuse this new stream
    cmp qword [rbx + linnea_connection.h2_state], LINNEA_H2_DRAINING
    je .drain_refuse
    ; is_head = method == "HEAD". The GET/HEAD gate applies to static files
    ; alone and moves past the location match: a proxy location forwards any
    ; method to its upstream.
    mov rdi, [r12 + linnea_h2_req.method_ptr]
    mov rsi, [r12 + linnea_h2_req.method_len]
    lea rdx, [method_head_h2]
    mov ecx, 4
    call linnea_string_iequal
    mov [rsp + S_HEAD], rax
    mov rdi, rbx
    mov rsi, r12
    call h2_select_vhost             ; -> rax = server*
    mov r13, rax
    mov [h2_cur_srv], rax            ; its security headers ride the response
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
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY
    je .serve_proxy
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_REDIRECT
    je .serve_redirect
    ; static files answer GET and HEAD only
    cmp qword [rsp + S_HEAD], 0
    jne .static_go
    mov rdi, [r12 + linnea_h2_req.method_ptr]
    mov rsi, [r12 + linnea_h2_req.method_len]
    lea rdx, [method_get_h2]
    mov ecx, 3
    call linnea_string_iequal
    test rax, rax
    jz .resp_405
.static_go:
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
    mov rdx, [r12 + linnea_h2_req.ae_ptr]
    mov rcx, [r12 + linnea_h2_req.ae_len]
    call linnea_static_open_enc            ; -> rax = base, rdx = size, r8 = coding
    mov [rsp + S_ENC], r8
    test rax, rax
    jz .resp_404
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
    mov rdi, [r12 + linnea_h2_req.inm_ptr]
    test rdi, rdi
    jz .chk_ims
    mov rsi, [r12 + linnea_h2_req.inm_len]
    lea rdx, [linnea_static_etag]
    mov rcx, [linnea_static_etag_len]
    call linnea_http_inm_match
    test eax, eax
    jnz .h2_304
    jmp .cond_done
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
    cmp qword [rsp + S_CRLEN], 0
    je .st_sel
    lea rdx, [status_206_h2]
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
    mov rcx, [rsp + S_HEAD]
    imul rcx, rcx, LINNEA_H2P_F_IS_HEAD
    mov [r13 + linnea_h2p.flags], rcx
    ; --- rewrite the request head: request line, Host, rebuilt headers.
    ; Content-Length and the terminating empty line follow in h2p_finalize
    ; once the body (if any) is collected. Bound it first.
    mov rcx, [r12 + linnea_h2_req.method_len]
    add rcx, [r12 + linnea_h2_req.path_len]
    add rcx, [r12 + linnea_h2_req.auth_len]
    mov rax, [r12 + linnea_h2_req.hb_cur]
    sub rax, [r12 + linnea_h2_req.hb_start]
    add rcx, rax
    add rcx, 64                      ; literals + the Content-Length line
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
    jne .proxy_nobody                ; END_STREAM on HEADERS: no body at all
    ; A body with a declared length streams: the length is forwarded as the
    ; client gave it and the bytes follow as they arrive, so an upload is
    ; bounded by the flow-control window rather than by our buffer. Without
    ; a length there is nothing to declare upstream, so those (rare) bodies
    ; are still collected and measured first.
    mov rdi, [r12 + linnea_h2_req.cl_ptr]
    test rdi, rdi
    jz .proxy_done
    mov rsi, [r12 + linnea_h2_req.cl_len]
    call h2p_dec_u64                 ; -> rax = the value, or -1
    cmp rax, -1
    je .proxy_done                   ; unparseable: collect and re-derive
    test rax, rax
    jz .proxy_nobody
    ; claim the connection's upload buffer; without it (a second concurrent
    ; upload) fall back to collecting a bounded body
    cmp qword [rbx + linnea_connection.h2_upload], 0
    jne .proxy_done
    lea rcx, [r14 + 1]
    mov [rbx + linnea_connection.h2_upload], rcx
    mov rcx, [rbx + linnea_connection.index]
    imul rcx, rcx, LINNEA_H2P_UPLOAD_BUF
    add rcx, [h2_upload_pool]
    mov [r13 + linnea_h2p.rq_buf], rcx
    mov [r13 + linnea_h2p.rq_rem], rax
    or qword [r13 + linnea_h2p.flags], LINNEA_H2P_F_REQ_STREAM
    mov rdi, r13
    mov rsi, [r12 + linnea_h2_req.cl_ptr]
    mov rdx, [r12 + linnea_h2_req.cl_len]
    call h2p_finalize_stream         ; head + Content-Length, then connect
    jmp .proxy_done
.proxy_nobody:
    mov rdi, r13
    call h2p_finalize                ; terminate the head and connect
.proxy_done:
    xor eax, eax                     ; no response bytes at the out cursor
    jmp .out
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
.resp_400:
    lea rax, [status_400_h2]
    lea r14, [body_400]
    mov r15d, body_400_len
.error:
    mov [rsp + S_STAT], rax          ; status string (3 chars)
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
.out:
    add rsp, 136
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

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
    ; and one streaming-upload buffer per connection
    mov rdi, rbx
    imul rdi, rdi, LINNEA_H2P_UPLOAD_BUF
    call linnea_memory_map
    mov [h2_upload_pool], rax
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
; that stream's request body, or 0. Either it is buffering the body whole
; (COLLECT), or it is streaming one — in which case it has already moved on
; to connecting and sending, and keeps taking DATA until the declared length
; is in.
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
    test qword [rax + linnea_h2p.flags], LINNEA_H2P_F_REQ_STREAM
    jz .fc_next
    cmp qword [rax + linnea_h2p.state], LINNEA_H2P_FREE
    je .fc_next
    cmp qword [rax + linnea_h2p.state], LINNEA_H2P_ZOMBIE
    je .fc_next
    cmp qword [rax + linnea_h2p.rq_rem], 0
    jne .fc_hit
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
    mov rax, [rdi + linnea_connection.index]
    imul rax, rax, LINNEA_H2P_SLOTS
    imul rax, rax, linnea_h2p_size
    add rax, [h2p_pool]
    mov ecx, LINNEA_H2P_SLOTS
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
    dec ecx
    jnz .k_scan
    pop rbx
    ret

; h2p_release(rax = slot*) — close the upstream fd and free the slot, or park
; it as a ZOMBIE when an op is still in flight. Preserves rax.
h2p_release:
    test qword [rax + linnea_h2p.flags], LINNEA_H2P_F_INFLIGHT
    jnz .rel_zombie
    push rax
    mov edi, [rax + linnea_h2p.fd]
    cmp edi, -1
    je .rel_nofd
    mov eax, LINNEA_SYS_CLOSE
    syscall
.rel_nofd:
    pop rax
    mov dword [rax + linnea_h2p.fd], -1
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
    mov qword [rdi + linnea_connection.h2_upload], 0
    push rdi
    call linnea_log_stamp
    lea rdi, [dbgs]
    mov esi, dbgs_len
    call linnea_log_write
    mov rdi, [dbg_appends]
    call linnea_log_u64
    lea rdi, [dbgsp]
    mov esi, 1
    call linnea_log_write
    mov rdi, [dbg_appended]
    call linnea_log_u64
    lea rdi, [dbgsp]
    mov esi, 1
    call linnea_log_write
    mov rdi, [dbg_sends]
    call linnea_log_u64
    lea rdi, [dbgsp]
    mov esi, 1
    call linnea_log_write
    mov rdi, [dbg_bodysends]
    call linnea_log_u64
    lea rdi, [dbgnl]
    mov esi, 1
    call linnea_log_write
    pop rdi
    mov rax, [rdi + linnea_connection.index]
    imul rax, rax, LINNEA_H2P_SLOTS
    imul rax, rax, linnea_h2p_size
    add rax, [h2p_pool]
    mov r12d, LINNEA_H2P_SLOTS
.cc_scan:
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
    jz .fin_nobody
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
    lea rsi, [h2p_conn_close]              ; "Connection: close" CRLF CRLF
    mov ecx, h2p_conn_close_len
    rep movsb
    ; the collected body follows the head
    test r12, r12
    jz .fin_head_only
    lea rsi, [rbx + linnea_h2p.buf + LINNEA_H2P_BODY_OFF]
    mov rcx, r12
    rep movsb
.fin_head_only:
    lea rax, [rbx + linnea_h2p.buf]
    sub rdi, rax
    mov [rbx + linnea_h2p.req_len], rdi
    mov qword [rbx + linnea_h2p.rd], 0
    mov qword [rbx + linnea_h2p.len], 0    ; buf is the response buffer now
    mov rdi, rbx
    call h2p_open_upstream
    pop r12
    pop rbx
    ret

; h2p_open_upstream(rdi = slot*) — open the socket and ask the loop to
; connect; a socket we cannot even open fails the exchange with a 502.
h2p_open_upstream:
    push rbx
    mov rbx, rdi
    mov edi, LINNEA_AF_INET
    mov esi, LINNEA_SOCK_STREAM
    xor edx, edx
    mov eax, LINNEA_SYS_SOCKET
    syscall
    test eax, eax
    js .ou_nosock
    mov [rbx + linnea_h2p.fd], eax
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_CONNECTING
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_CONN
    pop rbx
    ret
.ou_nosock:
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_FAILED
    mov qword [rbx + linnea_h2p.status], 502
    pop rbx
    ret

; h2p_finalize_stream(rdi = slot*, rsi = content-length text, rdx = its
; length) — the request head is complete and its body will follow through the
; FIFO: declare the length the client gave us (verbatim, so we forward what it
; promised), terminate the head, and open the upstream socket. The body is not
; part of req_len — it is sent from the FIFO as it arrives.
h2p_finalize_stream:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    lea rdi, [rbx + linnea_h2p.buf]
    add rdi, [rbx + linnea_h2p.req_len]
    lea rsi, [h2p_clen]              ; "Content-Length: "
    mov ecx, h2p_clen_len
    rep movsb
    mov rsi, r12                     ; the value as the client wrote it
    mov rcx, r13
    rep movsb
    mov word [rdi], 0x0a0d
    add rdi, 2
    lea rsi, [h2p_conn_close]        ; "Connection: close" CRLF CRLF
    mov ecx, h2p_conn_close_len
    rep movsb
    lea rax, [rbx + linnea_h2p.buf]
    sub rdi, rax
    mov [rbx + linnea_h2p.req_len], rdi
    mov qword [rbx + linnea_h2p.rd], 0
    mov qword [rbx + linnea_h2p.len], 0    ; buf doubles as the response buffer
    mov rdi, rbx
    call h2p_open_upstream
    pop r13
    pop r12
    pop rbx
    ret

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
    ; --- recv: response bytes (or EOF / error) ---
    test r14d, r14d
    js .ev_recv_err
    jz .ev_eof
    add [rbx + linnea_h2p.len], r14d
    cmp qword [rbx + linnea_h2p.state], LINNEA_H2P_HEAD
    jne .ev_relay_data
    mov rdi, rbx
    call h2p_parse_head              ; -> rax = 1 parsed, 0 need more, -1 bad
    test rax, rax
    js .ev_bad_gateway
    jz .ev_want_more                 ; the head is not complete yet
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_RELAY
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_HEAD_RDY
.ev_relay_data:
    mov rdi, rbx
    call h2p_decode                  ; advance the de-chunk / length decode
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jnz .ev_service
    jmp .ev_want_more
.ev_eof:
    ; the upstream closed. Before the head, that is a bad gateway; during a
    ; close-delimited body it is the legitimate end.
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_EOF
    cmp qword [rbx + linnea_h2p.state], LINNEA_H2P_RELAY
    jne .ev_bad_gateway
    mov rdi, rbx
    call h2p_decode
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
    jmp .ev_service
.ev_recv_err:
    cmp r14d, -LINNEA_ECANCELED
    je .ev_timeout
    jmp .ev_bad_gateway
.ev_connect:
    test r14d, r14d
    js .ev_conn_failed
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_SENDING
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND
    jmp .ev_service
.ev_conn_failed:
    cmp r14d, -LINNEA_ECANCELED
    je .ev_timeout
    jmp .ev_bad_gateway
.ev_send:
    test r14d, r14d
    js .ev_send_err
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_REQ_STREAM
    jnz .ev_send_stream
    add [rbx + linnea_h2p.sent], r14d
    mov rax, [rbx + linnea_h2p.sent]
    cmp rax, [rbx + linnea_h2p.req_len]
    jb .ev_send_more
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_HEAD
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV
    jmp .ev_service
.ev_send_stream:
    inc qword [dbg_sends]
    ; a streamed request: the head goes out first, then FIFO body bytes.
    ; Body bytes that have left are owed back to the client as flow-control
    ; credit, and the FIFO slides down so the next window can land in it.
    mov rax, [rbx + linnea_h2p.sent]
    cmp rax, [rbx + linnea_h2p.req_len]
    jae .ev_sent_body
    add [rbx + linnea_h2p.sent], r14d          ; still the head
    jmp .ev_stream_next
.ev_sent_body:
    inc qword [dbg_bodysends]
    mov eax, r14d
    add [rbx + linnea_h2p.rq_rd], rax
    add [rbx + linnea_h2p.rq_credit], rax      ; owed back as WINDOW_UPDATE
    ; Reclaim what has been sent. Fully drained, the FIFO simply restarts;
    ; partly drained, the remainder slides down — a body of any size then
    ; flows through a buffer the size of one receive window. This is the one
    ; safe moment to move those bytes: the send that was reading them has
    ; just completed and the next is armed after we return.
    mov rax, [rbx + linnea_h2p.rq_rd]
    cmp rax, [rbx + linnea_h2p.rq_wr]
    jb .ev_stream_slide
    mov qword [rbx + linnea_h2p.rq_rd], 0      ; FIFO drained: start over
    mov qword [rbx + linnea_h2p.rq_wr], 0
    jmp .ev_stream_next
.ev_stream_slide:
    push rsi
    push rdi
    mov rsi, [rbx + linnea_h2p.rq_buf]
    mov rdi, rsi
    add rsi, rax                               ; the unsent remainder
    mov rcx, [rbx + linnea_h2p.rq_wr]
    sub rcx, rax
    mov [rbx + linnea_h2p.rq_wr], rcx
    mov qword [rbx + linnea_h2p.rq_rd], 0
    rep movsb
    pop rdi
    pop rsi
.ev_stream_next:
    ; more to send? Otherwise, if the body is complete, read the response
    mov rax, [rbx + linnea_h2p.sent]
    cmp rax, [rbx + linnea_h2p.req_len]
    jb .ev_send_more                           ; head not fully out
    mov rax, [rbx + linnea_h2p.rq_rd]
    cmp rax, [rbx + linnea_h2p.rq_wr]
    jb .ev_send_more                           ; FIFO has bytes
    cmp qword [rbx + linnea_h2p.rq_rem], 0
    jne .ev_service                            ; waiting on more DATA
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_REQ_DONE
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_HEAD
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV
    jmp .ev_service
.ev_send_more:
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_SEND
    jmp .ev_service
.ev_send_err:
    cmp r14d, -LINNEA_ECANCELED
    je .ev_timeout
    jmp .ev_bad_gateway
.ev_want_more:
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_WANT_RECV
    jmp .ev_service
.ev_timeout:
    mov qword [rbx + linnea_h2p.status], 504
    jmp .ev_fail
.ev_bad_gateway:
    mov qword [rbx + linnea_h2p.status], 502
.ev_fail:
    ; close the upstream now; the client still needs an answer, so the slot
    ; lives until the service emits the error (or a RST mid-response)
    mov edi, [rbx + linnea_h2p.fd]
    cmp edi, -1
    je .ev_fail_nofd
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov dword [rbx + linnea_h2p.fd], -1
.ev_fail_nofd:
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_FAILED
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_HEAD_SENT
    jz .ev_service
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_RST
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
    mov qword [rbx + linnea_h2p.rq_buf], 0
    mov edi, [rbx + linnea_h2p.fd]
    cmp edi, -1
    je .fsl_nofd
    mov eax, LINNEA_SYS_CLOSE
    syscall
.fsl_nofd:
    mov dword [rbx + linnea_h2p.fd], -1
    mov qword [rbx + linnea_h2p.state], LINNEA_H2P_FREE
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
    ; the upload buffer belongs to one streaming request at a time: hand it
    ; back as soon as that slot is done, so the next upload can have it
    mov rcx, [rbx + linnea_connection.h2_upload]
    test rcx, rcx
    jz .sv_claim_ok
    dec rcx
    imul rax, rcx, linnea_h2p_size
    mov rdx, [rbx + linnea_connection.index]
    imul rdx, rdx, LINNEA_H2P_SLOTS
    imul rdx, rdx, linnea_h2p_size
    add rax, rdx
    add rax, [h2p_pool]
    test qword [rax + linnea_h2p.flags], LINNEA_H2P_F_REQ_STREAM
    jz .sv_unclaim
    cmp qword [rax + linnea_h2p.state], LINNEA_H2P_FREE
    jne .sv_claim_ok
.sv_unclaim:
    mov qword [rbx + linnea_connection.h2_upload], 0
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
    ; keep a frame's worth of headroom
    lea rax, [rbx + linnea_connection.out_buf + LINNEA_CONN_OUT_BUF]
    sub rax, r15
    cmp rax, 1024
    jb .sv_done
    ; request-body bytes that have gone upstream are owed back to the client
    ; as flow-control credit — on the stream and on the connection — or it
    ; stops sending after one window
    mov r14, [r12 + linnea_h2p.rq_credit]
    test r14, r14
    jz .sv_no_credit
    push r14
    call linnea_log_stamp
    lea rdi, [dbgc]
    mov esi, dbgc_len
    call linnea_log_write
    mov rdi, [rsp]
    call linnea_log_u64
    lea rdi, [dbgnl]
    mov esi, 1
    call linnea_log_write
    pop r14
    mov qword [r12 + linnea_h2p.rq_credit], 0
    mov rdi, r15
    mov rsi, [r12 + linnea_h2p.sid]
    mov edx, r14d
    call h2p_emit_window
    add r15, rax
    mov rdi, r15
    xor esi, esi                     ; stream 0: the connection window
    mov edx, r14d
    call h2p_emit_window
    add r15, rax
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
    ; its last DATA frame has drained: the buffer is nobody's now
    mov rax, r12
    call h2p_release
    jmp .sv_next

.sv_head:
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
h2p_finish_stream:
    push rbx
    mov rbx, rsi
    mov rsi, [rsi + linnea_h2p.sid]
    push rdi
    call h2_slot_find
    pop rdi
    test rax, rax
    jz .fs_ret
    mov qword [rax + linnea_h2_stream.id], 0
    inc qword [rdi + linnea_connection.h2_done_count]
.fs_ret:
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
    ja .ph_bad                       ; a head this large is not worth relaying
    mov [rbx + linnea_h2p.rd], rcx   ; first body byte
    mov [rbx + linnea_h2p.wr], rcx   ; decoded body starts here too
    mov [rbx + linnea_h2p.off], rcx
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
    call h2p_dec_u64                 ; -> rax = value, or -1
    cmp rax, -1
    je .ph_bad
    mov [rbx + linnea_h2p.body_rem], rax
    jmp .ph_bodyflag
.ph_close_delim:
    mov qword [rbx + linnea_h2p.body_rem], -1   ; until the upstream closes
.ph_bodyflag:
    ; responses that never carry a body, whatever the headers say
    test qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_IS_HEAD
    jnz .ph_nobody
    mov rax, [rbx + linnea_h2p.status]
    cmp rax, 204
    je .ph_nobody
    cmp rax, 304
    je .ph_nobody
    cmp rax, 200
    jb .ph_nobody                    ; 1xx: no body either
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
    ; after a chunk, 4 = trailers/end
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
    jmp .dec_save                    ; phase 4: done
.dec_size:
    ; a size line ends at the first CRLF; hex digits up to ';' or CR
    mov rcx, r13
    xor edx, edx                     ; value
    xor r8d, r8d                     ; digits seen
.dec_size_scan:
    cmp rcx, [rbx + linnea_h2p.len]
    jae .dec_save                    ; incomplete: wait for more bytes
    movzx eax, byte [r12 + rcx]
    cmp al, 13
    je .dec_size_eol
    cmp al, ';'
    je .dec_size_ext
    test r8d, r8d
    jnz .dec_size_digit
    cmp al, ' '                      ; tolerate leading space
    je .dec_size_next
.dec_size_digit:
    call h2p_hexval                  ; al -> eax, -1 if not hex
    test eax, eax
    js .dec_bad
    shl rdx, 4
    or rdx, rax
    inc r8d
.dec_size_next:
    inc rcx
    jmp .dec_size_scan
.dec_size_ext:
    ; chunk extension: skip to the CRLF
    cmp rcx, [rbx + linnea_h2p.len]
    jae .dec_save
    cmp byte [r12 + rcx], 13
    je .dec_size_eol
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
    mov qword [rbx + linnea_h2p.chunked], 4
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
    ; a malformed chunked body: stop here and let the caller finish the
    ; stream with what was decoded (the client sees a truncated body, which
    ; RST_STREAM would also convey)
    or qword [rbx + linnea_h2p.flags], LINNEA_H2P_F_BODY_DONE
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
    movzx eax, al
    sub eax, '0'
    cmp eax, 9
    jbe .hv_ret
    movzx eax, al
    or eax, 0x20
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
    jne .hf_valdone
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
    jne .hf_val_ret
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

; h2p_dec_u64(rdi = ptr, rsi = len) -> rax = value, or -1 when not all digits
; (or absurdly long: a Content-Length we cannot honour is a bad gateway).
h2p_dec_u64:
    xor eax, eax
    xor ecx, ecx
    test rsi, rsi
    jz .du_bad
.du_loop:
    cmp rcx, rsi
    jae .du_ret
    movzx edx, byte [rdi + rcx]
    sub edx, '0'
    cmp edx, 9
    ja .du_bad
    mov r8, rax
    imul rax, rax, 10
    cmp rax, r8                      ; overflow guard (cheap monotonicity)
    jb .du_bad
    add rax, rdx
    inc rcx
    jmp .du_loop
.du_ret:
    ret
.du_bad:
    mov rax, -1
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
    sub rsp, 40
    mov [rsp], rdi                   ; frame start
    mov rbx, rsi                     ; slot
    mov [rsp + 8], rdx               ; conn
    mov rax, [rbx + linnea_h2p.srv]  ; the vhost this request selected
    mov [h2_cur_srv], rax
    lea r15, [rdi + 9]               ; payload cursor
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
    cmp rax, 64
    ja .eh_next                      ; an implausible name: drop it
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
    ; the value, spaces trimmed
    mov rdx, [rsp + 16]
    inc rdx                          ; past the colon
.eh_vlead:
    cmp rdx, rbp
    jae .eh_vdone
    cmp byte [r12 + rdx], ' '
    jne .eh_vdone
    inc rdx
    jmp .eh_vlead
.eh_vdone:
    mov rcx, rbp
    sub rcx, rdx                     ; value length
    mov [rsp + 32], rbp              ; the line's CR offset, across the call
    ; emit: literal without indexing, literal name (index 0)
    mov rdi, r15
    lea rsi, [h2p_nmbuf]
    mov r8, rcx                      ; value length
    lea rcx, [r12 + rdx]             ; value ptr
    mov rdx, [rsp + 24]              ; name length
    call h2_enc_hdr_lit
    mov r15, rdi
    mov rbp, [rsp + 32]
.eh_next:
    lea r14, [rbp + 2]
    jmp .eh_line
.eh_done:
    ; our own security headers ride a proxied response too — they describe
    ; the origin, not the backend — but only when the backend did not set
    ; them itself, so an app that sends its own policy still wins
    mov r14, [h2_cur_srv]
    test r14, r14
    jz .eh_frame
    cmp qword [r14 + linnea_config_server.hsts_len], 0
    je .eh_nosniff
    lea rdi, [r12]                   ; the upstream head
    mov rsi, [rbx + linnea_h2p.rd]
    lea rdx, [h2p_hn_hsts]
    mov ecx, h2p_hn_hsts_len
    call h2p_head_find               ; -> rdx = length (0 = absent)
    test rdx, rdx
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
    lea rdi, [r12]
    mov rsi, [rbx + linnea_h2p.rd]
    lea rdx, [h2_nosniff_name]
    mov ecx, h2_nosniff_name_len
    call h2p_head_find
    test rdx, rdx
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
    add rsp, 40
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
    jne .ee_status
    lea r12, [body_413]
    mov r13d, body_413_len
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
    jae .none
    mov rax, r13
    and eax, LINNEA_H2_MAX_STREAMS - 1   ; MAX_STREAMS is a power of two (16)
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
    jmp .emit                        ; an empty final DATA carries END_STREAM
.scan_static:
    cmp qword [r15 + linnea_h2_stream.body_rem], 0
    je .scan_next
    jmp .scan_win
.scan_win:
    cmp qword [r15 + linnea_h2_stream.swnd], 0
    jle .scan_next
    jmp .emit
.scan_next:
    inc r13
    inc r14d
    jmp .scan
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
    ; advance the round-robin cursor past this slot
    inc r13
    mov [rbx + linnea_connection.h2_rr_cursor], r13
    mov eax, 1
    jmp .sched_ret
.none:
    xor eax, eax
.sched_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
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
    mov eax, [rdi + linnea_connection.server]
    imul rax, rax, linnea_config_server_size
    lea rbx, [linnea_config_instance]
    lea r15, [rbx + rax + linnea_config.servers]     ; default / result
    mov r12, [rsi + linnea_h2_req.auth_ptr]
    test r12, r12
    jz .vdone
    mov r13, [rsi + linnea_h2_req.auth_len]
    xor eax, eax
.vport:
    cmp rax, r13
    jae .vscan
    cmp byte [r12 + rax], ':'
    je .vcut
    inc rax
    jmp .vport
.vcut:
    mov r13, rax
.vscan:
    test r13, r13
    jz .vdone
    mov r14, [rbx + linnea_config.server_count]
    xor ebp, ebp
.vloop:
    cmp rbp, r14
    jae .vdone
    mov rax, rbp
    imul rax, rax, linnea_config_server_size
    lea rax, [rbx + rax + linnea_config.servers]
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
index_html_h2:   db "index.html"
status_200_h2:   db "200"
status_206_h2:   db "206"
status_304_h2:   db "304"
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
status_431_h2:   db "431"
body_431: db "431 Request Header Fields Too Large", 10
body_431_len equ $ - body_431
body_502: db "502 Bad Gateway", 10
body_502_len equ $ - body_502
body_504: db "504 Gateway Timeout", 10
body_504_len equ $ - body_504
body_413: db "413 Content Too Large", 10
body_413_len equ $ - body_413
; --- proxy-over-h2 literals ---
h2p_http11:      db " HTTP/1.1", 13, 10, "Host: "
h2p_http11_len   equ $ - h2p_http11
h2p_clen:        db "Content-Length: "
h2p_clen_len     equ $ - h2p_clen
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
h2p_d_te:        db "transfer-encoding"
h2p_d_upg:       db "upgrade"
h2p_d_trailer:   db "trailer"
h2p_d_pauth:     db "proxy-authenticate"
h2p_d_pconn:     db "proxy-connection"
h2p_dropped_tab:
    dq h2p_d_conn, 10
    dq h2p_d_ka, 10
    dq h2p_d_te, 17
    dq h2p_d_upg, 7
    dq h2p_d_trailer, 7
    dq h2p_d_pauth, 18
    dq h2p_d_pconn, 16
    dq 0, 0
body_400: db "400 Bad Request", 10
body_400_len equ $ - body_400
body_404: db "404 Not Found", 10
body_404_len equ $ - body_404
body_405: db "405 Method Not Allowed", 10
body_405_len equ $ - body_405

section .bss
h2_path_buf:  resb LINNEA_HTTP2_PATH_BUF
h2_numbuf:    resb 24
h2_crbuf:     resb 80                ; "bytes first-last/size" / "bytes */size"
h2_locbuf:    resb 2560              ; a redirect's Location value
h2_hdrs_buf:  resb 8192              ; proxy: the rebuilt h1 header lines
h2_req_es:    resd 1                 ; END_STREAM was set on the HEADERS frame
h2p_pool:     resq 1                 ; the upstream slot array (one mmap)
h2_dyn_pool:  resq 1                 ; per-connection HPACK dynamic tables
h2_upload_pool: resq 1               ; per-connection streaming-upload buffers
h2_cur_srv:   resq 1                 ; vhost whose response is being built
dbg_appends:  resq 1
dbg_appended: resq 1
dbg_sends:    resq 1
dbg_bodysends: resq 1
h2_fd_len:    resd 1                 ; a DATA frame's flow-control cost
h2_fd_credit: resd 1                 ; and whether it is owed back now
h2p_numbuf:   resb 24
h2p_stbuf:    resb 4                 ; a status as three ASCII digits
h2p_nmbuf:    resb 64                ; a response field name, lowercased
