; linnea_quictp.asm — test-only: build the server QUIC transport parameters
; with fixed connection IDs and write the raw bytes to stdout, so aioquic can
; parse them (tp_parse.py) and confirm the encoding interoperates.

%include "linnea_syscall.inc"

global _start
extern linnea_quic_build_transport_params

section .rodata
odcid: db 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7
scid:  db 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7

section .bss
tp_buf: resb 512

section .text
_start:
    lea rdi, [tp_buf]
    lea rsi, [odcid]
    mov edx, 8
    lea rcx, [scid]
    mov r8d, 8
    call linnea_quic_build_transport_params   ; rax = length
    mov rdx, rax                     ; write(1, tp_buf, len)
    mov edi, 1
    lea rsi, [tp_buf]
    mov eax, 1
    syscall
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
