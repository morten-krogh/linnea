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

extern linnea_hpack_decode
extern linnea_config_instance
extern linnea_string_from_u64
extern linnea_string_iequal

section .rodata

; PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
h2_preface: db "PRI * HTTP/2.0", 13, 10, 13, 10, "SM", 13, 10, 13, 10
h2_preface_len equ $ - h2_preface

msg_h2_pre:     db "linnea h2: "
msg_h2_pre_len  equ $ - msg_h2_pre

section .text

; linnea_h2_init(rdi=conn) — queue the server's initial SETTINGS frame
; (empty) into out_buf and mark the connection awaiting the client
; preface. The caller sends out_ptr/out_rem, then reads.
linnea_h2_init:
    mov qword [rdi + linnea_connection.h2_state], LINNEA_H2_PREFACE
    mov qword [rdi + linnea_connection.h2_send_stream], 0
    mov qword [rdi + linnea_connection.h2_cwnd], LINNEA_H2_INIT_WINDOW
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
    ; MAX_CONCURRENT_STREAMS = 1: peers serialize streams, so M17 serves one
    ; request at a time (real multiplexing is M18).
    mov byte [rax + 15], 0
    mov byte [rax + 16], LINNEA_H2_SETTINGS_MAX_CONCURRENT_STREAMS
    mov dword [rax + 17], 0x01000000    ; value 1, big-endian
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
    cmp r9d, LINNEA_H2_FT_PRIORITY
    je .f_ignore
    cmp r9d, LINNEA_H2_FT_RST_STREAM
    je .f_ignore
    cmp r9d, LINNEA_H2_FT_HEADERS
    je .f_headers
    jmp .goaway_close                ; DATA / stray CONTINUATION / unknown
.f_window:
    ; WINDOW_UPDATE: grow the connection window (stream 0) or the active
    ; stream's window. A zero increment is a protocol error.
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
    cmp rdx, [rbx + linnea_connection.h2_send_stream]
    jne .f_ignore                    ; not the active stream: ignore for M17
    add [rbx + linnea_connection.h2_swnd], rax
    jmp .f_ignore
.f_headers:
    ; While a response body is streaming, defer a new stream (we advertise
    ; MAX_CONCURRENT_STREAMS=1, so peers serialize; this is the safety net).
    cmp qword [rbx + linnea_connection.h2_send_stream], 0
    jne .flush
    ; A request response uses the whole out_buf, so it must be empty first;
    ; if anything is queued this round, flush it and resume next round.
    lea rax, [rbx + linnea_connection.out_buf]
    cmp r13, rax
    jne .flush
    mov rdi, rbx                     ; conn
    ; rsi already = this frame's header pointer
    mov rdx, r14
    sub rdx, r12                     ; bytes available from the HEADERS frame
    call h2_build_request
    cmp rax, LINNEA_H2_REQ_MORE
    je .flush                        ; block not fully buffered: return MORE
    cmp rax, LINNEA_H2_REQ_ERR
    je .goaway_close
    add r12, rax                     ; consume the whole HEADERS(+CONT) run
    add r13, rdx                     ; response frames queued
    jmp .frames
.f_ignore:
    add r12, r11
    jmp .frames
.f_settings:
    test r10b, LINNEA_H2_FLAG_ACK
    jnz .f_ignore
    mov dword [r13], 0x04000000      ; SETTINGS, length 0
    mov byte [r13 + 4], LINNEA_H2_FLAG_ACK
    mov dword [r13 + 5], 0
    add r13, 9
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
    ; nothing queued this round: if a response body is in flight and the
    ; window now allows, stream the next DATA frame (a WINDOW_UPDATE just
    ; processed may have unblocked it).
    mov rdi, rbx
    call h2_try_send_data
    test eax, eax
    jnz .send_direct                 ; out_ptr/out_rem/file_* already set
    cmp qword [rbx + linnea_connection.h2_state], LINNEA_H2_CLOSING
    je .close
.more:
    mov eax, LINNEA_H2_MORE
    jmp .ret
.send_direct:
    mov eax, LINNEA_H2_SEND
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
; Stack locals (below the req struct):
%define REQ      0
%define L_START  96
%define L_SID    104
%define L_CONT   112
h2_build_request:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 168
    mov rbx, rdi                     ; conn
    mov [rsp + L_START], rsi
    lea r13, [rsi + rdx]             ; avail end
    mov r12, rsi                     ; current frame header
    lea r14, [rbx + linnea_connection.up_buf]        ; assembly cursor
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
    lea rdi, [rbx + linnea_connection.up_buf]        ; block ptr
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

    ; --- serve the request: build the response flight into out_buf ------
    mov rdi, rbx                     ; conn
    lea rsi, [rsp + REQ]             ; decoded request
    mov r8, [rsp + L_SID]            ; stream id
    call h2_serve                    ; -> rax = bytes written to out_buf
    mov rdx, rax                     ; response (HEADERS flight) length
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

; h2_serve(rdi=conn, rsi=req, r8=stream_id) -> rax = bytes written to out_buf
; Builds the response HEADERS (and, for errors, an inline DATA) into out_buf.
; For a 200 with a body it records the send state so the body streams as DATA
; frames via h2_try_send_data; the return value is only the HEADERS flight.
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
    call h2_normalize                ; -> rax=end (0=bad), r9=dir flag
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
    call h2_open_mmap                ; -> rax = base (0 = miss), rdx = size
    test rax, rax
    jz .resp_404
    mov [rsp + S_BASE], rax
    mov [rsp + S_SIZE], rdx
    mov rdi, [rsp + S_JOIN]
    mov rsi, r14
    sub rsi, [rsp + S_JOIN]          ; joined path length
    call h2_mime                     ; -> rax = mime ptr, rdx = mime len
    mov [rsp + S_MIME], rax
    mov [rsp + S_MLEN], rdx
    ; content-length string
    mov rdi, [rsp + S_SIZE]
    lea rsi, [h2_numbuf]
    call linnea_string_from_u64      ; -> rax = length
    mov [rsp + S_CLEN], rax
    ; --- encode the 200 HEADERS payload (after a 9-byte frame header) ---
    lea rdi, [rbx + linnea_connection.out_buf + 9]
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
    mov rbp, rdi
    sub rbp, r15                     ; payload length
    ; frame header flags: END_HEADERS, plus END_STREAM when there is no body
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
    mov rax, [rsp + S_SID]
    mov [rbx + linnea_connection.h2_send_stream], rax
    mov rax, [rsp + S_BASE]
    mov [rbx + linnea_connection.h2_body_ptr], rax
    mov [rbx + linnea_connection.file_base], rax     ; munmap on completion
    mov rax, [rsp + S_SIZE]
    mov [rbx + linnea_connection.h2_body_rem], rax
    mov [rbx + linnea_connection.file_size], rax
    mov qword [rbx + linnea_connection.h2_end_stream], 1
    mov qword [rbx + linnea_connection.h2_swnd], LINNEA_H2_INIT_WINDOW
.flags:
    lea rdi, [rbx + linnea_connection.out_buf]
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
    mov qword [rbx + linnea_connection.h2_send_stream], 0
    mov rdi, r15
    lea rsi, [h2_numbuf]
    call linnea_string_from_u64
    mov [rsp + S_CLEN], rax
    lea rdi, [rbx + linnea_connection.out_buf + 9]
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
    lea rdi, [rbx + linnea_connection.out_buf]
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
    lea rdi, [rbx + linnea_connection.out_buf + 9]
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
    lea rax, [rbx + linnea_connection.out_buf]
    sub rdi, rax                     ; total bytes written
    mov rax, rdi
.out:
    add rsp, 104
    pop rbp
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

; h2_normalize(rdi=dst, rsi=raw, rdx=raw len) -> rax = end ptr (0 = 400),
; r9 = directory flag. Percent-decodes then normalizes ".."/"."/"" in place,
; refusing traversal above the root. Ported from the HTTP/1.1 handler.
h2_normalize:
    push r13
    cmp rdx, LINNEA_HTTP2_MAX_PATH
    ja .zbad
    mov r13, rdi                     ; start of decoded target
    mov rcx, rdx                     ; raw length
    xor edx, edx                     ; raw index
.zdec:
    cmp rdx, rcx
    jae .zdecoded
    movzx eax, byte [rsi + rdx]
    cmp al, '%'
    je .zpct
    mov [rdi], al
    inc rdi
    inc rdx
    jmp .zdec
.zpct:
    lea rax, [rdx + 3]
    cmp rax, rcx
    ja .zbad
    movzx eax, byte [rsi + rdx + 1]
    call .zhex
    test eax, eax
    js .zbad
    mov r8d, eax
    movzx eax, byte [rsi + rdx + 2]
    call .zhex
    test eax, eax
    js .zbad
    shl r8d, 4
    or eax, r8d
    jz .zbad                         ; %00 truncates the path
    mov [rdi], al
    inc rdi
    add rdx, 3
    jmp .zdec
.zdecoded:
    cmp byte [r13], '/'
    jne .zbad
    mov rsi, r13                     ; read cursor
    mov rcx, rdi                     ; end of decoded input
    mov rdi, r13                     ; write cursor
    xor r9d, r9d                     ; directory flag
.znl:
    cmp rsi, rcx
    jae .znd
    inc rsi
    mov rdx, rsi
.zse:
    cmp rdx, rcx
    jae .zhs
    cmp byte [rdx], '/'
    je .zhs
    inc rdx
    jmp .zse
.zhs:
    mov rax, rdx
    sub rax, rsi                     ; segment length
    test rax, rax
    jz .zskip
    cmp rax, 1
    jne .znnd
    cmp byte [rsi], '.'
    je .zskip
    jmp .zcp
.znnd:
    cmp rax, 2
    jne .zcp
    cmp word [rsi], '..'
    jne .zcp
    cmp rdi, r13
    jbe .zbad                        ; ".." above the root
    dec rdi
.zpop:
    cmp rdi, r13
    jbe .zskip
    cmp byte [rdi], '/'
    je .zskip
    dec rdi
    jmp .zpop
.zskip:
    cmp rdx, rcx
    jb .znx
    mov r9d, 1
    jmp .znx
.zcp:
    mov byte [rdi], '/'
    inc rdi
.zcpl:
    cmp rsi, rdx
    jae .zcpd
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    jmp .zcpl
.zcpd:
    xor r9d, r9d
.znx:
    mov rsi, rdx
    jmp .znl
.znd:
    cmp rdi, r13
    jne .zok
    mov byte [rdi], '/'              ; the root itself
    inc rdi
    mov r9d, 1
.zok:
    mov rax, rdi
    pop r13
    ret
.zbad:
    xor eax, eax
    pop r13
    ret
.zhex:                               ; al -> eax (nibble), -1 if not hex
    cmp al, '0'
    jb .zhbad
    cmp al, '9'
    jbe .zhdig
    or al, 0x20
    cmp al, 'a'
    jb .zhbad
    cmp al, 'f'
    ja .zhbad
    movzx eax, al
    sub eax, 'a' - 10
    ret
.zhdig:
    movzx eax, al
    sub eax, '0'
    ret
.zhbad:
    mov eax, -1
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

; h2_open_mmap(rdi=path cstr) -> rax = base (0 = missing/irregular), rdx = size.
; A non-empty regular file is mapped read-only; an empty file returns the
; sentinel base 1 with size 0 (found, but nothing to map).
h2_open_mmap:
    push rbx
    push r12
    xor esi, esi                     ; O_RDONLY
    xor edx, edx
    mov eax, LINNEA_SYS_OPEN
    syscall
    cmp rax, -4095
    jae .omiss
    mov rbx, rax                     ; fd
    mov rdi, rax
    lea rsi, [h2_statbuf]
    mov eax, LINNEA_SYS_FSTAT
    syscall
    cmp rax, -4095
    jae .oreject
    mov eax, [h2_statbuf + LINNEA_STAT_ST_MODE]
    and eax, LINNEA_S_IFMT
    cmp eax, LINNEA_S_IFREG
    jne .oreject
    mov r12, [h2_statbuf + LINNEA_STAT_ST_SIZE]
    test r12, r12
    jz .oempty
    mov rsi, r12                     ; size
    xor edi, edi
    mov edx, LINNEA_PROT_READ
    mov r10d, LINNEA_MAP_PRIVATE
    mov r8d, ebx                     ; fd
    xor r9d, r9d
    mov eax, LINNEA_SYS_MMAP
    syscall
    cmp rax, -4095
    jae .oreject
    push rax
    mov rdi, rbx
    mov eax, LINNEA_SYS_CLOSE
    syscall
    pop rax
    mov rdx, r12
    pop r12
    pop rbx
    ret
.oempty:
    mov rdi, rbx
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov eax, 1
    xor edx, edx
    pop r12
    pop rbx
    ret
.oreject:
    mov rdi, rbx
    mov eax, LINNEA_SYS_CLOSE
    syscall
.omiss:
    xor eax, eax
    xor edx, edx
    pop r12
    pop rbx
    ret

; h2_mime(rdi=name ptr, rsi=name len) -> rax = mime ptr, rdx = mime len.
h2_mime:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    lea r13, [rdi + rsi]             ; name end
    mov rcx, r13
.uscan:
    cmp rcx, r12
    jbe .udefault
    movzx eax, byte [rcx - 1]
    cmp al, '/'
    je .udefault
    cmp al, '.'
    je .ufound
    dec rcx
    jmp .uscan
.ufound:
    mov r14, rcx                     ; extension bytes (after the '.')
    mov r15, r13
    sub r15, rcx                     ; extension length
    lea r12, [mime_table_h2]
.uloop:
    mov rdx, [r12]
    test rdx, rdx
    jz .udefault
    mov rdi, r14
    mov rsi, r15
    mov rcx, [r12 + 8]
    call linnea_string_iequal
    test eax, eax
    jnz .umatch
    add r12, 32
    jmp .uloop
.umatch:
    mov rax, [r12 + 16]
    mov rdx, [r12 + 24]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.udefault:
    lea rax, [mime_default_h2]
    mov edx, mime_default_h2_len
    pop r15
    pop r14
    pop r13
    pop r12
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

; h2_try_send_data(rdi=conn) -> rax = 1 if a DATA frame was queued (out_ptr /
; out_rem / file_ptr / file_rem set), else 0. When the body is fully framed it
; munmaps and clears the send state (the connection stays open).
h2_try_send_data:
    push rbx
    push r12
    mov rbx, rdi
    cmp qword [rbx + linnea_connection.h2_send_stream], 0
    je .tnone
    mov rax, [rbx + linnea_connection.h2_body_rem]
    test rax, rax
    jnz .thave
    mov rdi, [rbx + linnea_connection.file_base]
    test rdi, rdi
    jz .tcleared
    mov rsi, [rbx + linnea_connection.file_size]
    mov eax, LINNEA_SYS_MUNMAP
    syscall
.tcleared:
    mov qword [rbx + linnea_connection.file_base], 0
    mov qword [rbx + linnea_connection.file_size], 0
    mov qword [rbx + linnea_connection.h2_send_stream], 0
    xor eax, eax
    jmp .tout
.thave:
    mov rax, [rbx + linnea_connection.h2_swnd]
    mov rdx, [rbx + linnea_connection.h2_cwnd]
    cmp rdx, rax
    jge .twin
    mov rax, rdx                     ; window = min(swnd, cwnd)
.twin:
    test rax, rax
    jle .tnone                       ; window closed: wait for WINDOW_UPDATE
    mov rdx, [rbx + linnea_connection.h2_body_rem]
    cmp rax, rdx
    jbe .tcap
    mov rax, rdx
.tcap:
    cmp rax, LINNEA_H2_MAX_FRAME
    jbe .tchunk
    mov eax, LINNEA_H2_MAX_FRAME
.tchunk:
    mov r12, rax                     ; chunk size
    lea rdi, [rbx + linnea_connection.out_buf]
    mov rax, r12
    shr rax, 16
    mov [rdi], al
    mov rax, r12
    shr rax, 8
    mov [rdi + 1], al
    mov [rdi + 2], r12b
    mov byte [rdi + 3], LINNEA_H2_FT_DATA
    xor r8d, r8d
    mov rax, [rbx + linnea_connection.h2_body_rem]
    cmp rax, r12
    jne .tflags
    cmp qword [rbx + linnea_connection.h2_end_stream], 0
    je .tflags
    mov r8b, LINNEA_H2_FLAG_END_STREAM
.tflags:
    mov [rdi + 4], r8b
    mov r9, [rbx + linnea_connection.h2_send_stream]
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
    mov rax, [rbx + linnea_connection.h2_body_ptr]
    mov [rbx + linnea_connection.file_ptr], rax
    mov [rbx + linnea_connection.file_rem], r12
    add [rbx + linnea_connection.h2_body_ptr], r12
    sub [rbx + linnea_connection.h2_body_rem], r12
    sub [rbx + linnea_connection.h2_swnd], r12
    sub [rbx + linnea_connection.h2_cwnd], r12
    mov eax, 1
    jmp .tout
.tnone:
    xor eax, eax
.tout:
    pop r12
    pop rbx
    ret

; linnea_h2_after_send(rdi=conn) -> rax = LINNEA_H2_SEND / _MORE / _CLOSE.
; Called by the io_uring loop when an h2 send drains: continue streaming the
; response body if one is in flight, else report MORE so the loop processes
; buffered frames or reads.
linnea_h2_after_send:
    push rbx
    mov rbx, rdi
    call h2_try_send_data
    test eax, eax
    jnz .send
    cmp qword [rbx + linnea_connection.h2_state], LINNEA_H2_CLOSING
    je .close
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

ext_html_h2: db "html"
ext_css_h2:  db "css"
ext_js_h2:   db "js"
ext_json_h2: db "json"
ext_txt_h2:  db "txt"
ext_png_h2:  db "png"
ext_jpg_h2:  db "jpg"
ext_jpeg_h2: db "jpeg"
ext_gif_h2:  db "gif"
ext_svg_h2:  db "svg"
ext_ico_h2:  db "ico"
mime_html_h2: db "text/html"
mime_html_h2_len equ $ - mime_html_h2
mime_css_h2:  db "text/css"
mime_css_h2_len equ $ - mime_css_h2
mime_js_h2:   db "application/javascript"
mime_js_h2_len equ $ - mime_js_h2
mime_json_h2: db "application/json"
mime_json_h2_len equ $ - mime_json_h2
mime_txt_h2:  db "text/plain"
mime_txt_h2_len equ $ - mime_txt_h2
mime_png_h2:  db "image/png"
mime_png_h2_len equ $ - mime_png_h2
mime_jpeg_h2: db "image/jpeg"
mime_jpeg_h2_len equ $ - mime_jpeg_h2
mime_gif_h2:  db "image/gif"
mime_gif_h2_len equ $ - mime_gif_h2
mime_svg_h2:  db "image/svg+xml"
mime_svg_h2_len equ $ - mime_svg_h2
mime_ico_h2:  db "image/x-icon"
mime_ico_h2_len equ $ - mime_ico_h2
mime_default_h2: db "application/octet-stream"
mime_default_h2_len equ $ - mime_default_h2
mime_table_h2:
    dq ext_html_h2, 4, mime_html_h2, mime_html_h2_len
    dq ext_css_h2,  3, mime_css_h2,  mime_css_h2_len
    dq ext_js_h2,   2, mime_js_h2,   mime_js_h2_len
    dq ext_json_h2, 4, mime_json_h2, mime_json_h2_len
    dq ext_txt_h2,  3, mime_txt_h2,  mime_txt_h2_len
    dq ext_png_h2,  3, mime_png_h2,  mime_png_h2_len
    dq ext_jpg_h2,  3, mime_jpeg_h2, mime_jpeg_h2_len
    dq ext_jpeg_h2, 4, mime_jpeg_h2, mime_jpeg_h2_len
    dq ext_gif_h2,  3, mime_gif_h2,  mime_gif_h2_len
    dq ext_svg_h2,  3, mime_svg_h2,  mime_svg_h2_len
    dq ext_ico_h2,  3, mime_ico_h2,  mime_ico_h2_len
    dq 0

section .bss
h2_path_buf:  resb LINNEA_HTTP2_PATH_BUF
h2_statbuf:   resb LINNEA_STAT_SIZE
h2_numbuf:    resb 24
