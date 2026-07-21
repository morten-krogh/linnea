; linnea_quiccert.asm — test-only: frame the test certificate chain into a TLS
; Certificate handshake message and write it to stdout, so aioquic's TLS parser
; (cert_parse.py) confirms the message is well formed.

%include "linnea_syscall.inc"

global _start
extern linnea_pem_cert_list
extern linnea_quic_build_cert

section .rodata
cert_pem:     incbin "test/tls/server.crt"
cert_pem_len  equ $ - cert_pem

section .bss
cert_list_buf: resb 8192
cert_msg_buf:  resb 8192

section .text
_start:
    lea rdi, [cert_pem]              ; frame the PEM chain into a certificate_list
    mov esi, cert_pem_len
    lea rdx, [cert_list_buf]
    mov ecx, 8192
    call linnea_pem_cert_list        ; rax = certificate_list length
    test rax, rax
    js .fail
    lea rdi, [cert_msg_buf]          ; wrap it in a Certificate message
    lea rsi, [cert_list_buf]
    mov rdx, rax
    call linnea_quic_build_cert      ; rax = message length
    mov rdx, rax
    mov edi, 1
    lea rsi, [cert_msg_buf]
    mov eax, 1
    syscall
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall
