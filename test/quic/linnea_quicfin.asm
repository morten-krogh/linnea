; linnea_quicfin.asm — test-only: build the Finished message from a fixed
; server handshake secret and transcript hash, and write it to stdout, so
; fin_verify.py recomputes the HMAC verify_data and compares.

%include "linnea_syscall.inc"

global _start
extern linnea_quic_build_finished

section .rodata
s_hs:  db 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
       db 16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
th:    db 32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47
       db 48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63

section .bss
fin_buf: resb 64

section .text
_start:
    lea rdi, [fin_buf]
    lea rsi, [s_hs]
    lea rdx, [th]
    call linnea_quic_build_finished   ; rax = 36
    mov rdx, rax
    mov edi, 1
    lea rsi, [fin_buf]
    mov eax, 1
    syscall
    xor edi, edi
    mov eax, LINNEA_SYS_EXIT
    syscall
