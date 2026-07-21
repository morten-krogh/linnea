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

%include "linnea_connection.inc"
%include "linnea_http2.inc"
%include "linnea_hpack.inc"

global linnea_h2_init
global linnea_h2_handle

extern linnea_hpack_decode

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
    lea rax, [rdi + linnea_connection.out_buf]
    ; SETTINGS frame: length 6, type 4, flags 0, stream 0, one setting
    mov byte [rax], 0
    mov byte [rax + 1], 0
    mov byte [rax + 2], 6
    mov byte [rax + 3], LINNEA_H2_FT_SETTINGS
    mov byte [rax + 4], 0
    mov dword [rax + 5], 0          ; stream 0
    ; HEADER_TABLE_SIZE = 0: the peer's HPACK encoder gets no dynamic table,
    ; so our decoder never has to keep one (see linnea_hpack.inc).
    mov byte [rax + 9], 0
    mov byte [rax + 10], LINNEA_H2_SETTINGS_HEADER_TABLE_SIZE
    mov dword [rax + 11], 0         ; value 0
    mov [rdi + linnea_connection.out_ptr], rax
    mov qword [rdi + linnea_connection.out_rem], 15
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
    je .f_ignore
    cmp r9d, LINNEA_H2_FT_PRIORITY
    je .f_ignore
    cmp r9d, LINNEA_H2_FT_RST_STREAM
    je .f_ignore
    cmp r9d, LINNEA_H2_FT_HEADERS
    je .f_headers
    jmp .goaway_close                ; DATA / stray CONTINUATION / unknown
.f_headers:
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
    cmp qword [rbx + linnea_connection.h2_state], LINNEA_H2_CLOSING
    je .close
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

    ; --- response: HEADERS(:status 200) + DATA(echo) into out_buf -------
    lea r8, [rbx + linnea_connection.out_buf]        ; out start
    mov rdi, r8
    mov byte [rdi], 0                ; HEADERS: length 1
    mov byte [rdi + 1], 0
    mov byte [rdi + 2], 1
    mov byte [rdi + 3], LINNEA_H2_FT_HEADERS
    mov byte [rdi + 4], LINNEA_H2_FLAG_END_HEADERS
    mov r9, [rsp + L_SID]
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
    mov byte [rdi + 9], 0x88         ; :status: 200 (static index 8)
    add rdi, 10
    mov r11, rdi                     ; DATA frame header goes here
    add rdi, 9
    mov r10, rdi                     ; body start
    ; "linnea h2: "
    lea rsi, [msg_h2_pre]
    mov rcx, msg_h2_pre_len
    call .copy
    ; method (capped 16)
    mov rsi, [rsp + REQ + linnea_h2_req.method_ptr]
    mov rcx, [rsp + REQ + linnea_h2_req.method_len]
    cmp rcx, 16
    jbe .m_ok
    mov ecx, 16
.m_ok:
    call .copy
    mov byte [rdi], ' '
    inc rdi
    ; path (capped 300)
    mov rsi, [rsp + REQ + linnea_h2_req.path_ptr]
    mov rcx, [rsp + REQ + linnea_h2_req.path_len]
    cmp rcx, 300
    jbe .p_ok
    mov ecx, 300
.p_ok:
    call .copy
    mov byte [rdi], 10               ; newline
    inc rdi
    ; DATA frame header at r11: length = rdi - r10, type 0, END_STREAM, sid
    mov rdx, rdi
    sub rdx, r10                     ; body length
    mov rax, rdx
    shr rax, 16
    mov [r11], al
    mov rax, rdx
    shr rax, 8
    mov [r11 + 1], al
    mov [r11 + 2], dl
    mov byte [r11 + 3], LINNEA_H2_FT_DATA
    mov byte [r11 + 4], LINNEA_H2_FLAG_END_STREAM
    mov r9, [rsp + L_SID]
    mov rax, r9
    shr rax, 24
    mov [r11 + 5], al
    mov rax, r9
    shr rax, 16
    mov [r11 + 6], al
    mov rax, r9
    shr rax, 8
    mov [r11 + 7], al
    mov [r11 + 8], r9b
    ; return: rdx = response length, rax = bytes consumed
    mov rdx, rdi
    sub rdx, r8
    mov rax, r12
    sub rax, [rsp + L_START]
    jmp .ret

.copy:                               ; rsi -> rdi, rcx bytes; advances rdi
    rep movsb
    ret
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
