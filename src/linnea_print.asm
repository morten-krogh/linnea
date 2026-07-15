; linnea_print.asm — write(2) helpers for stdout and stderr.

default rel

%include "linnea_syscall.inc"

global linnea_print_stdout
global linnea_print_stderr

section .text

; linnea_print_stdout(rdi=ptr, rsi=len)
linnea_print_stdout:
    mov rdx, rsi
    mov rsi, rdi
    mov edi, LINNEA_STDOUT
    jmp linnea_print_fd

; linnea_print_stderr(rdi=ptr, rsi=len)
linnea_print_stderr:
    mov rdx, rsi
    mov rsi, rdi
    mov edi, LINNEA_STDERR
    ; fall through

; linnea_print_fd(rdi=fd, rsi=ptr, rdx=len) — loops over partial writes.
; Write errors are ignored: there is no channel left to report them on.
linnea_print_fd:
.loop:
    test rdx, rdx
    jz .done
    mov eax, LINNEA_SYS_WRITE
    syscall
    cmp rax, -4095
    jae .done
    add rsi, rax
    sub rdx, rax
    jmp .loop
.done:
    ret
