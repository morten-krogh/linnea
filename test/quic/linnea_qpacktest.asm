; linnea_qpacktest.asm — test-only: read a QPACK-encoded field section on stdin,
; decode it with linnea_qpack_decode, and print the recovered pseudo-headers
; (:method, :path, :scheme, :authority) each on their own line. Exits non-zero
; on a decode error. Driven by qpack_test.py, which encodes with pylsqpack.

%include "linnea_syscall.inc"
%include "linnea_hpack.inc"

global _start
extern linnea_qpack_decode

section .bss
inbuf:    resb 8192
scratch:  resb 8192
req:      resb linnea_h2_req_size

section .text
_start:
    ; read the encoded field section from stdin
    xor eax, eax                     ; read
    xor edi, edi                     ; fd 0
    lea rsi, [inbuf]
    mov edx, 8192
    syscall
    test rax, rax
    js .fail
    mov r12, rax                     ; block length
    ; zero the req struct
    lea rdi, [req]
    xor eax, eax
    mov ecx, linnea_h2_req_size
    rep stosb
    ; scratch region for Huffman-decoded literals
    lea rax, [scratch]
    mov [req + linnea_h2_req.scratch], rax
    lea rax, [scratch + 8192]
    mov [req + linnea_h2_req.scratch_end], rax
    ; decode
    lea rdi, [inbuf]
    mov rsi, r12
    lea rdx, [req]
    call linnea_qpack_decode
    test rax, rax
    jnz .fail
    ; print :method, :path, :scheme, :authority each on its own line
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

; .putline(rdi=ptr, rsi=len) — write the field (if present) then a newline.
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
