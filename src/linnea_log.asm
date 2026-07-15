; linnea_log.asm — the server log. Opened from the config's "log" path;
; until then log writes fall back to stdout.

default rel

%include "linnea_syscall.inc"
%include "linnea_time.inc"

global linnea_log_open
global linnea_log_write
global linnea_log_u64
global linnea_log_stamp

extern linnea_print_fd
extern linnea_string_from_u64
extern linnea_time_civil
extern linnea_error_open

section .rodata

msg_open:       db "cannot open log file: "
msg_open_len    equ $ - msg_open

section .data

linnea_log_fd:  dd LINNEA_STDOUT

section .bss

num_buf:        resb 20
time_ts:        resq 2         ; struct timespec
stamp_buf:      resb 24        ; "[YYYY-MM-DD HH:MM:SS] "

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

; linnea_log_stamp() — write "[YYYY-MM-DD HH:MM:SS] " (UTC) to the log.
linnea_log_stamp:
    push rbx
    sub rsp, 64                ; linnea_tm, keeping calls 16-byte aligned
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    mov edi, LINNEA_CLOCK_REALTIME
    lea rsi, [time_ts]
    syscall
    mov rdi, [time_ts]         ; tv_sec
    mov rsi, rsp
    call linnea_time_civil
    mov byte [stamp_buf], '['
    mov rax, [rsp + linnea_tm.year]
    xor edx, edx
    mov ecx, 100
    div ecx                    ; rax = century, edx = year % 100
    mov rbx, rdx
    lea rdi, [stamp_buf + 1]
    call .put2
    mov rax, rbx
    lea rdi, [stamp_buf + 3]
    call .put2
    mov byte [stamp_buf + 5], '-'
    mov rax, [rsp + linnea_tm.month]
    lea rdi, [stamp_buf + 6]
    call .put2
    mov byte [stamp_buf + 8], '-'
    mov rax, [rsp + linnea_tm.day]
    lea rdi, [stamp_buf + 9]
    call .put2
    mov byte [stamp_buf + 11], ' '
    mov rax, [rsp + linnea_tm.hour]
    lea rdi, [stamp_buf + 12]
    call .put2
    mov byte [stamp_buf + 14], ':'
    mov rax, [rsp + linnea_tm.min]
    lea rdi, [stamp_buf + 15]
    call .put2
    mov byte [stamp_buf + 17], ':'
    mov rax, [rsp + linnea_tm.sec]
    lea rdi, [stamp_buf + 18]
    call .put2
    mov byte [stamp_buf + 20], ']'
    mov byte [stamp_buf + 21], ' '
    add rsp, 64
    pop rbx
    lea rdi, [stamp_buf]
    mov esi, 22
    jmp linnea_log_write

; .put2(rax=value 0-99, rdi=dest) — two zero-padded digits; clobbers rax,rcx,rdx
.put2:
    xor edx, edx
    mov ecx, 10
    div ecx
    add al, '0'
    mov [rdi], al
    add dl, '0'
    mov [rdi + 1], dl
    ret
