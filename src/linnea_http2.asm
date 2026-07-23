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

global linnea_h2_init
global linnea_h2_handle
global linnea_h2_after_send
global linnea_h2_conn_free

extern linnea_hpack_decode
extern linnea_h3_altsvc
extern linnea_h3_altsvc_len
extern linnea_h3_server
; static-file resolution lives in linnea_static.asm (shared with HTTP/3)
extern linnea_static_normalize
extern linnea_static_open
extern linnea_static_mime
extern linnea_config_instance
extern linnea_string_from_u64
extern linnea_string_iequal
extern drain_flag

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
linnea_h2_init:
    mov qword [rdi + linnea_connection.h2_state], LINNEA_H2_PREFACE
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
    je .f_ignore                     ; request bodies are not served
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
    call h2_slot_find
    test rax, rax
    jz .frames
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
    jmp .frames
.f_headers:
    ; Append the response HEADERS at the out cursor; a streaming body (if
    ; any) is registered in a pool slot and interleaved by the scheduler.
    ; Ensure room for a HEADERS (+ small inline error DATA) first.
    lea rax, [rbx + linnea_connection.out_buf + LINNEA_CONN_OUT_BUF]
    sub rax, r13
    cmp rax, 300
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
%if L_OUT + 8 > 168
  %error "h2_build_request stack frame (sub rsp,168) too small for req + locals"
%endif
h2_build_request:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 168
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
    ; zero the req struct (12 qwords)
    lea rdi, [rsp + REQ]
    xor eax, eax
    mov ecx, 12
    rep stosq
    lea rax, [rbx + linnea_connection.up_buf + LINNEA_H2_SCRATCH_OFF]
    mov [rsp + REQ + linnea_h2_req.scratch], rax
    lea rcx, [rax + LINNEA_H2_HBLOCK_MAX]
    mov [rsp + REQ + linnea_h2_req.scratch_end], rcx
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
    add rsp, 168
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
; syscall pattern. Ranges, conditionals and content-encoding negotiation are
; HTTP/1.1 features deferred for h2; :authority selects the vhost.
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
h2_serve:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 104
    mov rbx, rdi                     ; conn
    mov r12, rsi                     ; req
    mov [rsp + S_SID], r8
    mov [rsp + S_OUT], r9            ; where the response is written
    ; draining: GOAWAY already went out, refuse this new stream
    cmp qword [rbx + linnea_connection.h2_state], LINNEA_H2_DRAINING
    je .drain_refuse
    ; is_head = method == "HEAD"
    mov rdi, [r12 + linnea_h2_req.method_ptr]
    mov rsi, [r12 + linnea_h2_req.method_len]
    lea rdx, [method_head_h2]
    mov ecx, 4
    call linnea_string_iequal
    mov [rsp + S_HEAD], rax
    test rax, rax
    jnz .method_ok
    mov rdi, [r12 + linnea_h2_req.method_ptr]
    mov rsi, [r12 + linnea_h2_req.method_len]
    lea rdx, [method_get_h2]
    mov ecx, 3
    call linnea_string_iequal
    test rax, rax
    jz .resp_405
.method_ok:
    mov rdi, rbx
    mov rsi, r12
    call h2_select_vhost             ; -> rax = server*
    mov r13, rax
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
    cmp qword [rax + linnea_config_location.kind], LINNEA_LOC_KIND_ROOT
    jne .resp_404                    ; proxy / redirect over h2: deferred
    mov [rsp + S_LOC], rax
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
    mov byte [r14], 0                ; NUL-terminate the joined path
    mov rdi, [rsp + S_JOIN]
    call linnea_static_open                ; -> rax = base (0 = miss), rdx = size
    test rax, rax
    jz .resp_404
    mov [rsp + S_BASE], rax
    mov [rsp + S_SIZE], rdx
    mov rdi, [rsp + S_JOIN]
    mov rsi, r14
    sub rsi, [rsp + S_JOIN]          ; joined path length
    call linnea_static_mime                     ; -> rax = mime ptr, rdx = mime len
    mov [rsp + S_MIME], rax
    mov [rsp + S_MLEN], rdx
    ; content-length string
    mov rdi, [rsp + S_SIZE]
    lea rsi, [h2_numbuf]
    call linnea_string_from_u64      ; -> rax = length
    mov [rsp + S_CLEN], rax
    ; --- encode the 200 HEADERS payload (after a 9-byte frame header) ---
    mov rdi, [rsp + S_OUT]
    add rdi, 9
    mov r15, rdi                     ; payload start
    mov esi, 8                       ; :status
    lea rdx, [status_200_h2]
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
    ; Alt-Svc, when a QUIC listener is up (name is not in the static table)
    cmp qword [linnea_h3_altsvc_len], 0
    je .no_altsvc_h2
    mov eax, [rbx + linnea_connection.server]
    cmp rax, [linnea_h3_server]
    jne .no_altsvc_h2              ; a different origin: not ours to advertise
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
    cmp qword [rsp + S_SIZE], 0
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
    mov [rax + linnea_h2_stream.body_ptr], rcx
    mov rcx, [rsp + S_SIZE]
    mov [rax + linnea_h2_stream.file_size], rcx
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
    add rsp, 104
    pop rbp
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
    cmp qword [r15 + linnea_h2_stream.body_rem], 0
    je .scan_next
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
    mov rax, [r15 + linnea_h2_stream.body_ptr]
    mov [rbx + linnea_connection.file_ptr], rax
    mov [rbx + linnea_connection.file_rem], r14
    add [r15 + linnea_h2_stream.body_ptr], r14
    sub [r15 + linnea_h2_stream.body_rem], r14
    sub [r15 + linnea_h2_stream.swnd], r14
    sub [rbx + linnea_connection.h2_cwnd], r14
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
    call h2_schedule
    test eax, eax
    jnz .send
    mov rdi, rbx
    call h2_pool_active
    test rax, rax
    jnz .more                        ; streams remain: recv (WINDOW_UPDATE / idle)
    jmp .close
.live:
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
    mov qword [rdi + linnea_connection.h2_state], LINNEA_H2_DRAINING
    ret

; h2_pool_active(rdi=conn) -> rax = number of active (non-free) stream slots.
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
status_400_h2:   db "400"
status_404_h2:   db "404"
status_405_h2:   db "405"
body_400: db "400 Bad Request", 10
body_400_len equ $ - body_400
body_404: db "404 Not Found", 10
body_404_len equ $ - body_404
body_405: db "405 Method Not Allowed", 10
body_405_len equ $ - body_405

section .bss
h2_path_buf:  resb LINNEA_HTTP2_PATH_BUF
h2_numbuf:    resb 24
