; linnea_quicee.asm — test-only: build the QUIC EncryptedExtensions (h3 ALPN +
; transport parameters) with fixed connection IDs and write the raw message to
; stdout for aioquic's TLS parser (ee_parse.py).

%include "linnea_syscall.inc"

global _start
extern linnea_quic_build_ee

section .rodata
odcid: db 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7
scid:  db 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7

section .bss
ee_buf: resb 512

section .text
_start:
    lea rdi, [ee_buf]
    lea rsi, [odcid]
    mov edx, 8
    lea rcx, [scid]
    mov r8d, 8
    call linnea_quic_build_ee         ; rax = length
    mov rdx, rax
    mov edi, 1
    lea rsi, [ee_buf]
    mov eax, 1
    syscall
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
