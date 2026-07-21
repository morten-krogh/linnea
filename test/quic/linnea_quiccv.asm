; linnea_quiccv.asm — test-only: sign a CertificateVerify over a fixed
; transcript hash with the test private key and write it to stdout, so
; cv_verify.py can verify the ECDSA signature against the test certificate.

%include "linnea_syscall.inc"

global _start
extern linnea_pem_p256_key
extern linnea_quic_build_cert_verify

section .rodata
key_pem:     incbin "test/tls/server.key"
key_pem_len  equ $ - key_pem
transcript:  db 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
             db 16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31

section .bss
cv_buf: resb 512

section .text
_start:
    lea rdi, [key_pem]
    mov esi, key_pem_len
    call linnea_pem_p256_key         ; rax = private-scalar pointer, <0 on error
    test rax, rax
    js .fail
    mov rdx, rax
    lea rdi, [cv_buf]
    lea rsi, [transcript]
    call linnea_quic_build_cert_verify   ; rax = message length
    mov rdx, rax
    mov edi, 1
    lea rsi, [cv_buf]
    mov eax, 1
    syscall
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
.fail:
    mov edi, 1
    mov eax, LINNEA_SYS_EXIT
    syscall
