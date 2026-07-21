; linnea_h3test.asm — test-only: read HTTP/3 request-stream bytes on stdin,
; parse the frame layer with linnea_h3_read_headers (which QPACK-decodes the
; HEADERS frame), and print the recovered pseudo-headers. Exits non-zero on a
; parse/decode error. Driven by h3_test.py, which frames a HEADERS frame around
; a pylsqpack field section (plus a leading DATA/unknown frame to be skipped).

%include "linnea_syscall.inc"
%include "linnea_hpack.inc"

global _start
extern linnea_h3_read_headers

section .bss
inbuf:    resb 8192
scratch:  resb 8192
req:      resb linnea_h2_req_size

section .text
_start:
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
    lea rdi, [inbuf]
    mov rsi, r12
    lea rdx, [req]
    call linnea_h3_read_headers
    test rax, rax
    jnz .fail
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
    mov byte [inbuf + 8100], 10
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    lea rsi, [inbuf + 8100]
    mov edx, 1
    syscall
    pop rsi
    pop rdi
    ret
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall
