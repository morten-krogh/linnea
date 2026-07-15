; linnea_error.asm — error reporting. Every function here prints to stderr
; and exits with status 1; none of them return, so callers may jmp to them
; and error paths need no register preservation or cleanup.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global linnea_error_usage
global linnea_error_exit
global linnea_error_open
global linnea_error_parse
global linnea_error_server

extern linnea_print_stderr
extern linnea_print_u64_stderr
extern linnea_string_length
extern linnea_parser_state

section .rodata

usage_msg:      db "usage: linnea <config.json>", 10
usage_msg_len   equ $ - usage_msg
prefix_msg:     db "linnea: "
prefix_len      equ $ - prefix_msg
open_msg:       db "cannot open config file: "
open_msg_len    equ $ - open_msg
parse_msg:      db "parse error at line "
parse_msg_len   equ $ - parse_msg
column_msg:     db ", column "
column_msg_len  equ $ - column_msg
colon_msg:      db ": "
colon_msg_len   equ $ - colon_msg
space_msg:      db " "
colon_char:     db ":"
errno_open:     db " (errno "
errno_open_len  equ $ - errno_open
errno_close:    db ")"
newline_msg:    db 10

section .text

; linnea_error_usage()
linnea_error_usage:
    lea rdi, [usage_msg]
    mov esi, usage_msg_len
    call linnea_print_stderr
    jmp linnea_error_die

; linnea_error_exit(rdi=msg, rsi=len) — prints "linnea: <msg>\n", exit(1)
linnea_error_exit:
    mov r12, rdi
    mov r13, rsi
    lea rdi, [prefix_msg]
    mov esi, prefix_len
    call linnea_print_stderr
    mov rdi, r12
    mov rsi, r13
    call linnea_print_stderr
    lea rdi, [newline_msg]
    mov esi, 1
    call linnea_print_stderr
    jmp linnea_error_die

; linnea_error_open(rdi=path cstr) — prints "linnea: cannot open config file: <path>\n"
linnea_error_open:
    mov r12, rdi
    lea rdi, [prefix_msg]
    mov esi, prefix_len
    call linnea_print_stderr
    lea rdi, [open_msg]
    mov esi, open_msg_len
    call linnea_print_stderr
    mov rdi, r12
    call linnea_string_length
    mov rdi, r12
    mov rsi, rax
    call linnea_print_stderr
    lea rdi, [newline_msg]
    mov esi, 1
    call linnea_print_stderr
    jmp linnea_error_die

; linnea_error_parse(rdi=msg, rsi=len, rdx=offset)
; Prints "linnea: parse error at line L, column C: <msg>\n" where L and C
; are computed by scanning the parser buffer from the start to offset.
linnea_error_parse:
    mov r12, rdi               ; msg
    mov r13, rsi               ; len
    mov r14, rdx               ; offset
    mov r8, [linnea_parser_state + linnea_parser.base]
    xor ecx, ecx               ; index
    mov ebx, 1                 ; line, 1-based
    xor r10d, r10d             ; offset of current line start
.scan:
    cmp rcx, r14
    jae .scanned
    cmp byte [r8 + rcx], 10
    jne .next
    inc rbx
    lea r10, [rcx + 1]
.next:
    inc rcx
    jmp .scan
.scanned:
    mov r15, r14
    sub r15, r10
    inc r15                    ; column, 1-based
    lea rdi, [prefix_msg]
    mov esi, prefix_len
    call linnea_print_stderr
    lea rdi, [parse_msg]
    mov esi, parse_msg_len
    call linnea_print_stderr
    mov rdi, rbx
    call linnea_print_u64_stderr
    lea rdi, [column_msg]
    mov esi, column_msg_len
    call linnea_print_stderr
    mov rdi, r15
    call linnea_print_u64_stderr
    lea rdi, [colon_msg]
    mov esi, colon_msg_len
    call linnea_print_stderr
    mov rdi, r12
    mov rsi, r13
    call linnea_print_stderr
    lea rdi, [newline_msg]
    mov esi, 1
    call linnea_print_stderr
    jmp linnea_error_die

; linnea_error_server(rdi=msg, rsi=len, rdx=server*, rcx=errno)
; Prints "linnea: <msg> <host>:<port> (errno N)\n"; the errno part is
; omitted when rcx is 0.
linnea_error_server:
    mov r12, rdi               ; msg
    mov r13, rsi               ; len
    mov r14, rdx               ; server*
    mov r15, rcx               ; errno, 0 = none
    lea rdi, [prefix_msg]
    mov esi, prefix_len
    call linnea_print_stderr
    mov rdi, r12
    mov rsi, r13
    call linnea_print_stderr
    lea rdi, [space_msg]
    mov esi, 1
    call linnea_print_stderr
    lea rdi, [r14 + linnea_config_server.host]
    mov rsi, [r14 + linnea_config_server.host_len]
    call linnea_print_stderr
    lea rdi, [colon_char]
    mov esi, 1
    call linnea_print_stderr
    movzx edi, word [r14 + linnea_config_server.port]
    call linnea_print_u64_stderr
    test r15, r15
    jz .newline
    lea rdi, [errno_open]
    mov esi, errno_open_len
    call linnea_print_stderr
    mov rdi, r15
    call linnea_print_u64_stderr
    lea rdi, [errno_close]
    mov esi, 1
    call linnea_print_stderr
.newline:
    lea rdi, [newline_msg]
    mov esi, 1
    call linnea_print_stderr
    jmp linnea_error_die

; linnea_error_die() — file-local, exit(1)
linnea_error_die:
    mov eax, LINNEA_SYS_EXIT
    mov edi, 1
    syscall
