; linnea_h3test.asm — test-only: read HTTP/3 request-stream bytes on stdin,
; parse the frame layer with linnea_h3_read_headers (which QPACK-decodes the
; HEADERS frame), and print the recovered pseudo-headers followed by the request
; body. Exits non-zero on a parse/decode error. Driven by h3_test.py, which
; frames a HEADERS frame around a pylsqpack field section (plus a leading
; DATA/unknown frame to be skipped, or DATA frames whose bodies must join).

%include "linnea_syscall.inc"
%include "linnea_hpack.inc"
%include "linnea_config.inc"   ; LINNEA_MAX_ROOT, which linnea_http3.inc builds on
%include "linnea_http3.inc"

global _start
extern linnea_h3_read_headers
extern linnea_h3_walk_feed

section .bss
inbuf:    resb 8192
scratch:  resb 8192
req:      resb linnea_h2_req_size
walk:     resb linnea_h3_walk_size
nl:       resb 1
frag:     resq 1                     ; argv[1]: feed the walk this many bytes at
                                     ; a time (0 = one call with the lot)
usesink:  resq 1                     ; argv[2]: send the body to a sink instead
                                     ; of joining it in place
sinkbuf:  resb 8192                  ; what the sink was handed, in order
sinklen:  resq 1

section .text
_start:
    ; argv[1], when given, is a fragment size: the same stream is fed to the
    ; walk that many bytes at a time. Every fragmentation must reach the same
    ; verdict and the same body as one call with the lot -- that is the whole
    ; property the incremental path will rest on, and it cannot be tested
    ; through a socket because nothing makes the network split where you want.
    mov qword [frag], 0
    mov rax, [rsp]                   ; argc
    cmp rax, 2
    jb .no_frag
    mov rsi, [rsp + 16]              ; argv[1]
    xor eax, eax
.fd_digit:
    movzx ecx, byte [rsi]
    test cl, cl
    jz .fd_done
    sub ecx, '0'
    cmp ecx, 9
    ja .fd_done
    imul rax, rax, 10
    add rax, rcx
    inc rsi
    jmp .fd_digit
.fd_done:
    mov [frag], rax
    mov rax, [rsp]
    cmp rax, 3
    jb .no_frag
    mov qword [usesink], 1
.no_frag:
    xor eax, eax                     ; read stdin
    xor edi, edi
    lea rsi, [inbuf]
    mov edx, 8192
    syscall
    test rax, rax
    js .fail
    mov r12, rax
    lea rdi, [req]                   ; zero the req
    xor eax, eax
    mov ecx, linnea_h2_req_size
    rep stosb
    lea rax, [scratch]
    mov [req + linnea_h2_req.scratch], rax
    lea rax, [scratch + 8192]
    mov [req + linnea_h2_req.scratch_end], rax
    cmp qword [frag], 0
    jne .fragmented
    lea rdi, [inbuf]
    mov rsi, r12
    lea rdx, [req]
    call linnea_h3_read_headers
    test rax, rax
    jnz .fail
    jmp .parsed
.fragmented:
    ; drive the walk by hand, in slices of ONE buffer (the body join is in
    ; place, so the slices have to be of the same buffer -- which is exactly
    ; how the QUIC layer will feed it)
    lea rdi, [walk]
    xor eax, eax
    mov ecx, LINNEA_H3_WALK_RESET
    rep stosb
    cmp qword [usesink], 0
    je .no_sink
    lea rax, [mem_sink]
    mov [walk + linnea_h3_walk.sink], rax
.no_sink:
    xor r13d, r13d                   ; bytes fed so far
.frag_loop:
    mov r14, r12
    sub r14, r13                     ; bytes left
    cmp r14, [frag]
    jbe .frag_last
    mov r14, [frag]
.frag_last:
    lea rdi, [walk]
    lea rsi, [inbuf + r13]
    mov rdx, r14
    lea rcx, [req]
    xor r8d, r8d                     ; the FIN rides the last slice only
    mov rbp, r13
    add rbp, r14
    cmp rbp, r12
    jne .frag_call
    mov r8d, 1
.frag_call:
    call linnea_h3_walk_feed
    test rax, rax
    js .fail
    mov r13, rbp
    cmp rax, 1
    je .frag_ok
    cmp r13, r12
    jb .frag_loop
    jmp .fail                        ; ran out of input without a verdict
.frag_ok:
    mov r8, [walk + linnea_h3_walk.body_ptr]
    mov r9, [walk + linnea_h3_walk.body_len]
    cmp qword [usesink], 0
    je .parsed
    lea r8, [sinkbuf]                ; the sink's copy is the body here
    mov r9, [sinklen]
.parsed:
    mov r13, r8                      ; the request body, printed last
    mov r14, r9
    mov rdi, [req + linnea_h2_req.method_ptr]
    mov rsi, [req + linnea_h2_req.method_len]
    call .putline
    mov rdi, [req + linnea_h2_req.path_ptr]
    mov rsi, [req + linnea_h2_req.path_len]
    call .putline
    mov rdi, [req + linnea_h2_req.scheme_ptr]
    mov rsi, [req + linnea_h2_req.scheme_len]
    call .putline
    mov rdi, [req + linnea_h2_req.auth_ptr]
    mov rsi, [req + linnea_h2_req.auth_len]
    call .putline
    mov rdi, r13                     ; body bytes as one line (empty if none)
    mov rsi, r14
    call .putline
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
.putline:
    push rdi
    push rsi
    test rdi, rdi
    jz .nl
    mov rdx, rsi
    mov rsi, rdi
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    syscall
.nl:
    mov byte [nl], 10
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    lea rsi, [nl]
    mov edx, 1
    syscall
    pop rsi
    pop rdi
    ret
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall

; mem_sink(rdi = walk state, rsi = bytes, rdx = length) -> rax = 0.
; Appends each run to sinkbuf in the order the walk hands them over, which is
; the order the body has. Touches no callee-saved register: the walk keeps its
; whole position in them.
mem_sink:
    mov rax, [sinklen]
    lea rcx, [rax + rdx]
    cmp rcx, 8192
    ja .ms_full
    push rdi
    push rsi
    lea rdi, [sinkbuf]
    add rdi, rax
    mov rcx, rdx
    rep movsb
    pop rsi
    pop rdi
    add [sinklen], rdx
    xor eax, eax
    ret
.ms_full:
    mov rax, -1
    ret
