; linnea_h3resp.asm — test-only: build an HTTP/3 response (HEADERS + DATA) with
; linnea_h3_build_response and write it to stdout. h3resp_test.py parses the
; frames and QPACK-decodes the HEADERS with pylsqpack to check the result.

%include "linnea_syscall.inc"

global _start
extern linnea_h3_build_response

section .rodata
ctype:  db "text/plain"
ctype_len equ $ - ctype
body:   db "hello over http/3", 10
body_len equ $ - body

section .bss
out:    resb 4096

section .text
_start:
    lea rdi, [out]
    mov esi, 200                     ; status
    lea rdx, [ctype]
    mov ecx, ctype_len
    lea r8, [body]
    mov r9, body_len
    call linnea_h3_build_response    ; rax = total length
    mov rdx, rax
    mov eax, LINNEA_SYS_WRITE
    mov edi, 1
    lea rsi, [out]
    syscall
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
