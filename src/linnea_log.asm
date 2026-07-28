; linnea_log.asm — the server log. Opened from the config's "log" path;
; until then log writes fall back to stdout.

default rel

%include "linnea_syscall.inc"
%include "linnea_time.inc"

global linnea_log_open
global linnea_log_reopen
global linnea_log_write
global linnea_log_u64
global linnea_log_stamp
global linnea_log_access
global linnea_log_acc_host
global linnea_log_acc_host_len
global linnea_log_acc_peer
global linnea_log_acc_peer_len
global linnea_log_acc_meth
global linnea_log_acc_meth_len
global linnea_log_acc_tgt
global linnea_log_acc_tgt_len
global linnea_log_acc_proto
global linnea_log_acc_proto_len
global linnea_log_acc_status
global linnea_log_acc_bytes

extern linnea_print_fd
extern linnea_string_from_u64
extern linnea_time_civil
extern linnea_error_open

section .rodata

msg_open:       db "cannot open log file: "
msg_open_len    equ $ - msg_open
; the access line's fixed pieces — the same format for every protocol:
; 'request <host> from <peer> "<METHOD> <TARGET>" <status> <bytes>'
acc_req:        db "request "
acc_req_len     equ $ - acc_req
acc_from:       db " from "
acc_from_len    equ $ - acc_from
acc_quote:      db ' "'
acc_endq:       db '" '
acc_dash:       db "-"
acc_sp:         db " "
acc_nl:         db 10

section .data

linnea_log_fd:  dd LINNEA_STDOUT

LOG_LINE_CAP equ 2048

section .bss

num_buf:        resb 20
time_ts:        resq 2         ; struct timespec
stamp_buf:      resb 24        ; "[YYYY-MM-DD HH:MM:SS] "
line_buf:       resb LOG_LINE_CAP
line_len:       resq 1
log_path:       resq 1     ; the configured path, for reopening after a rotate
; The access-line parameter block (see linnea_log_access): seven fields
; outgrow the argument registers, and the worker is single-threaded, so the
; caller fills these and calls. A zero text pointer prints as "-".
linnea_log_acc_host:     resq 1
linnea_log_acc_host_len: resq 1
linnea_log_acc_peer:     resq 1
linnea_log_acc_peer_len: resq 1
linnea_log_acc_meth:     resq 1
linnea_log_acc_meth_len: resq 1
linnea_log_acc_tgt:      resq 1
linnea_log_acc_tgt_len:  resq 1
linnea_log_acc_proto:    resq 1     ; "HTTP/1.1" / "HTTP/2" / "HTTP/3"
linnea_log_acc_proto_len: resq 1
linnea_log_acc_status:   resq 1
linnea_log_acc_bytes:    resq 1

section .text

; linnea_log_open(rdi=path cstr) — open for append, create with 0644.
; The path is kept so the file can be reopened later (see linnea_log_reopen).
; O_CLOEXEC, unlike the listeners, which are deliberately left inheritable so
; the hot upgrade's execve can adopt them: the new generation opens its own
; log, so an inherited one would leak an fd per reload and pin the rotated
; inode, keeping a rotated-away log's disk space from ever being reclaimed.
linnea_log_open:
    push rbx
    mov rbx, rdi               ; kept for the error message
    mov [log_path], rdi
    mov eax, LINNEA_SYS_OPEN
    mov esi, LINNEA_O_WRONLY | LINNEA_O_CREAT | LINNEA_O_APPEND | LINNEA_O_CLOEXEC
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

; linnea_log_reopen() — reopen the log file at its configured path, for
; SIGHUP after a rotation: without it every process keeps writing into the
; renamed (or deleted) inode, so the lines are lost and the disk is never
; reclaimed. Opening the new file before dropping the old fd means a failure
; leaves logging working — an unwritable path is a reason to keep the old
; file, not to lose the log. Anything buffered from a half-built line is
; dropped: it belongs to the old file's last write.
linnea_log_reopen:
    push rbx
    mov rdi, [log_path]
    test rdi, rdi
    jz .lr_ret                 ; never opened: nothing to reopen
    mov eax, LINNEA_SYS_OPEN
    mov esi, LINNEA_O_WRONLY | LINNEA_O_CREAT | LINNEA_O_APPEND | LINNEA_O_CLOEXEC
    mov edx, LINNEA_MODE_0644
    syscall
    cmp rax, -4095
    jae .lr_ret                ; keep the old fd
    mov ebx, eax               ; the new fd
    mov edi, [linnea_log_fd]
    cmp edi, ebx
    je .lr_store
    mov eax, LINNEA_SYS_CLOSE
    syscall
.lr_store:
    mov [linnea_log_fd], ebx
    mov qword [line_len], 0
.lr_ret:
    pop rbx
    ret

; linnea_log_write(rdi=ptr, rsi=len) — append to the pending line and
; emit it as ONE write once the chunk ends in a newline. A log line is
; assembled from several calls (stamp, text, numbers); buffering until
; the newline turns it into a single O_APPEND write, so lines from
; concurrent worker processes interleave whole, never torn.
linnea_log_write:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    test r12, r12
    jz .done
    cmp r12, LOG_LINE_CAP      ; a chunk the buffer can never hold is
    ja .direct                 ; written through on its own
    mov rax, [line_len]
    lea rcx, [rax + r12]
    cmp rcx, LOG_LINE_CAP
    jbe .append
    call log_flush             ; overlong line: emit what is held first
.append:
    lea rdi, [line_buf]
    add rdi, [line_len]
    mov rsi, rbx
    mov rcx, r12
    rep movsb
    add [line_len], r12
    cmp byte [rbx + r12 - 1], 10
    jne .done
    call log_flush
.done:
    pop r12
    pop rbx
    ret
.direct:
    call log_flush
    mov edi, [linnea_log_fd]
    mov rsi, rbx
    mov rdx, r12
    call linnea_print_fd
    jmp .done

; log_flush — write the buffered line bytes, if any, as one write.
log_flush:
    mov rdx, [line_len]
    test rdx, rdx
    jz .none
    mov qword [line_len], 0
    mov edi, [linnea_log_fd]
    lea rsi, [line_buf]
    jmp linnea_print_fd
.none:
    ret

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

; linnea_log_access — emit one access-log line from the linnea_log_acc_*
; parameter block, in the same format for every protocol:
;   '[stamp] request <host> from <peer> "<METHOD> <TARGET> <PROTO>" <status> <bytes>'
; The protocol goes inside the quotes, where the Common Log Format has always
; put it, so the request line reads as the client sent it (h2 and h3 have no
; request line of their own, but the shape is what log tools expect).
; A zero host/peer/method/target pointer prints as "-" (a request that never
; parsed far enough to have one). Clobbers no callee-saved registers.
linnea_log_access:
    push rbx
    call linnea_log_stamp
    lea rdi, [acc_req]
    mov esi, acc_req_len
    call linnea_log_write
    lea rbx, [linnea_log_acc_host]
    call .acc_field
    lea rdi, [acc_from]
    mov esi, acc_from_len
    call linnea_log_write
    lea rbx, [linnea_log_acc_peer]
    call .acc_field
    lea rdi, [acc_quote]
    mov esi, 2
    call linnea_log_write
    lea rbx, [linnea_log_acc_meth]
    call .acc_field
    lea rdi, [acc_sp]
    mov esi, 1
    call linnea_log_write
    lea rbx, [linnea_log_acc_tgt]
    call .acc_field
    lea rdi, [acc_sp]
    mov esi, 1
    call linnea_log_write
    lea rbx, [linnea_log_acc_proto]
    call .acc_field
    lea rdi, [acc_endq]
    mov esi, 2
    call linnea_log_write
    mov rdi, [linnea_log_acc_status]
    call linnea_log_u64
    lea rdi, [acc_sp]
    mov esi, 1
    call linnea_log_write
    mov rdi, [linnea_log_acc_bytes]
    call linnea_log_u64
    lea rdi, [acc_nl]
    mov esi, 1
    call linnea_log_write
    pop rbx
    ret
.acc_field:                    ; rbx = ptr slot (its length follows); "-" if 0
    mov rdi, [rbx]
    mov rsi, [rbx + 8]
    test rdi, rdi
    jnz linnea_log_write
    lea rdi, [acc_dash]
    mov esi, 1
    jmp linnea_log_write
