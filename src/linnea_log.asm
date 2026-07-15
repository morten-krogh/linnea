; linnea_log.asm — the server log. Opened from the config's "log" path;
; until then log writes fall back to stdout.

default rel

%include "linnea_syscall.inc"

global linnea_log_open
global linnea_log_write
global linnea_log_u64
global linnea_log_stamp

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
; Date from days-since-epoch via the civil-from-days algorithm.
linnea_log_stamp:
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    mov edi, LINNEA_CLOCK_REALTIME
    lea rsi, [time_ts]
    syscall
    mov rax, [time_ts]         ; tv_sec
    xor edx, edx
    mov rcx, 86400
    div rcx                    ; rax = days, rdx = seconds of day
    mov r8, rdx
    ; civil date: z = days + 719468
    add rax, 719468
    xor edx, edx
    mov rcx, 146097
    div rcx                    ; rax = era, rdx = doe
    mov r9, rax                ; era
    mov r10, rdx               ; doe
    ; yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365
    mov rax, r10
    xor edx, edx
    mov rcx, 1460
    div rcx
    mov r11, r10
    sub r11, rax
    mov rax, r10
    xor edx, edx
    mov rcx, 36524
    div rcx
    add r11, rax
    mov rax, r10
    xor edx, edx
    mov rcx, 146096
    div rcx
    sub r11, rax
    mov rax, r11
    xor edx, edx
    mov rcx, 365
    div rcx
    mov r11, rax               ; yoe
    ; y = yoe + era * 400
    imul r9, r9, 400
    add r9, r11
    ; doy = doe - (365*yoe + yoe/4 - yoe/100)
    imul rcx, r11, 365
    mov rax, r11
    shr rax, 2
    add rcx, rax
    mov rax, r11
    xor edx, edx
    mov rsi, 100
    div rsi
    sub rcx, rax
    sub r10, rcx               ; doy
    ; mp = (5*doy + 2) / 153
    imul rax, r10, 5
    add rax, 2
    xor edx, edx
    mov rcx, 153
    div rcx
    mov r11, rax               ; mp
    ; d = doy - (153*mp + 2)/5 + 1
    imul rax, r11, 153
    add rax, 2
    xor edx, edx
    mov rcx, 5
    div rcx
    sub r10, rax
    inc r10                    ; day
    ; m = mp + 3 if mp < 10 else mp - 9; January/February belong to y+1
    lea rcx, [r11 + 3]
    cmp r11, 10
    jb .month_ok
    lea rcx, [r11 - 9]
    inc r9
.month_ok:
    mov r11, rcx               ; month (rcx is clobbered by .put2)
    ; format the date
    mov byte [stamp_buf], '['
    mov rax, r9
    xor edx, edx
    mov ecx, 100
    div ecx                    ; rax = century, edx = year % 100
    mov r9, rdx
    lea rdi, [stamp_buf + 1]
    call .put2
    mov rax, r9
    lea rdi, [stamp_buf + 3]
    call .put2
    mov byte [stamp_buf + 5], '-'
    mov rax, r11
    lea rdi, [stamp_buf + 6]
    call .put2
    mov byte [stamp_buf + 8], '-'
    mov rax, r10
    lea rdi, [stamp_buf + 9]
    call .put2
    mov byte [stamp_buf + 11], ' '
    ; format the time from r8 = seconds of day
    mov rax, r8
    xor edx, edx
    mov ecx, 3600
    div ecx
    mov r8, rdx
    lea rdi, [stamp_buf + 12]
    call .put2
    mov byte [stamp_buf + 14], ':'
    mov rax, r8
    xor edx, edx
    mov ecx, 60
    div ecx
    mov r8, rdx
    lea rdi, [stamp_buf + 15]
    call .put2
    mov byte [stamp_buf + 17], ':'
    mov rax, r8
    lea rdi, [stamp_buf + 18]
    call .put2
    mov byte [stamp_buf + 20], ']'
    mov byte [stamp_buf + 21], ' '
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
