; linnea_log.asm — the server log. Opened from the config's "log" path;
; until then log writes fall back to stdout.

default rel

%include "linnea_syscall.inc"

global linnea_log_open
global linnea_log_write
global linnea_log_u64

extern linnea_print_fd
extern linnea_string_from_u64
extern linnea_error_open

section .rodata

msg_open:       db "cannot open log file: "
msg_open_len    equ $ - msg_open

section .data

linnea_log_fd:  dd LINNEA_STDOUT

section .bss

num_buf:        resb 20

section .text

; linnea_log_open(rdi=path cstr) — open for append, create with 0644.
linnea_log_open:
    push rbx
    mov rbx, rdi               ; kept for the error message
    mov eax, LINNEA_SYS_OPEN
    mov esi, LINNEA_O_WRONLY | LINNEA_O_CREAT | LINNEA_O_APPEND
    mov edx, LINNEA_MODE_0644
    syscall
    cmp rax, -4095
    jae .fail
    mov [linnea_log_fd], eax
    pop rbx
    ret
.fail:
    lea rdi, [msg_open]
    mov esi, msg_open_len
    mov rdx, rbx
    jmp linnea_error_open      ; never returns

; linnea_log_write(rdi=ptr, rsi=len)
linnea_log_write:
    mov rdx, rsi
    mov rsi, rdi
    mov edi, [linnea_log_fd]
    jmp linnea_print_fd

; linnea_log_u64(rdi=value)
linnea_log_u64:
    lea rsi, [num_buf]
    call linnea_string_from_u64
    lea rdi, [num_buf]
    mov rsi, rax
    jmp linnea_log_write
