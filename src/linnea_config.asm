; linnea_config.asm — config storage, semantic validation, and dump.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global linnea_config_instance
global linnea_config_validate
global linnea_config_dump

extern linnea_print_stdout
extern linnea_print_u64_stdout
extern linnea_error_exit

section .rodata

dump_config:            db "config: "
dump_config_len         equ $ - dump_config
dump_servers:           db " servers timeout="
dump_servers_len        equ $ - dump_servers
dump_maxconn:           db " max_connections="
dump_maxconn_len        equ $ - dump_maxconn
dump_server:            db "server "
dump_server_len         equ $ - dump_server
dump_host:              db ": host="
dump_host_len           equ $ - dump_host
dump_port:              db " port="
dump_port_len           equ $ - dump_port
dump_hostname:          db " hostname="
dump_hostname_len       equ $ - dump_hostname
dump_root:              db " root="
dump_root_len           equ $ - dump_root
newline:                db 10

msg_no_servers:         db "config must define at least one server"
msg_no_servers_len      equ $ - msg_no_servers
msg_port_zero:          db "server port must be between 1 and 65535"
msg_port_zero_len       equ $ - msg_port_zero
msg_empty_host:         db "server host must not be empty"
msg_empty_host_len      equ $ - msg_empty_host
msg_empty_hostname:     db "server hostname must not be empty"
msg_empty_hostname_len  equ $ - msg_empty_hostname
msg_empty_root:         db "server root must not be empty"
msg_empty_root_len      equ $ - msg_empty_root
msg_empty_log:          db "config log must not be empty"
msg_empty_log_len       equ $ - msg_empty_log

section .bss

linnea_config_instance: resb linnea_config_size

section .text

; linnea_config_validate(rdi=config*) — semantic rules, checked after parse.
; Exits with an error message on the first violation.
linnea_config_validate:
    cmp qword [rdi + linnea_config.log_len], 0
    je .empty_log
    mov rax, [rdi + linnea_config.server_count]
    test rax, rax
    jz .no_servers
    xor r8d, r8d               ; server index
.loop:
    cmp r8, rax
    jae .ok
    imul r9, r8, linnea_config_server_size
    lea r9, [rdi + r9 + linnea_config.servers]
    cmp word [r9 + linnea_config_server.port], 0
    je .port_zero
    cmp qword [r9 + linnea_config_server.host_len], 0
    je .empty_host
    cmp qword [r9 + linnea_config_server.hostname_len], 0
    je .empty_hostname
    cmp qword [r9 + linnea_config_server.root_len], 0
    je .empty_root
    inc r8
    jmp .loop
.ok:
    ret
.no_servers:
    lea rdi, [msg_no_servers]
    mov esi, msg_no_servers_len
    jmp linnea_error_exit
.port_zero:
    lea rdi, [msg_port_zero]
    mov esi, msg_port_zero_len
    jmp linnea_error_exit
.empty_host:
    lea rdi, [msg_empty_host]
    mov esi, msg_empty_host_len
    jmp linnea_error_exit
.empty_hostname:
    lea rdi, [msg_empty_hostname]
    mov esi, msg_empty_hostname_len
    jmp linnea_error_exit
.empty_root:
    lea rdi, [msg_empty_root]
    mov esi, msg_empty_root_len
    jmp linnea_error_exit
.empty_log:
    lea rdi, [msg_empty_log]
    mov esi, msg_empty_log_len
    jmp linnea_error_exit

; linnea_config_dump(rdi=config*) — human-readable dump to stdout:
;   config: 2 servers
;   server 0: host=0.0.0.0 port=8080 hostname=example.com
linnea_config_dump:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    lea rdi, [dump_config]
    mov esi, dump_config_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.server_count]
    call linnea_print_u64_stdout
    lea rdi, [dump_servers]
    mov esi, dump_servers_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.timeout]
    call linnea_print_u64_stdout
    lea rdi, [dump_maxconn]
    mov esi, dump_maxconn_len
    call linnea_print_stdout
    mov rdi, [rbx + linnea_config.max_connections]
    call linnea_print_u64_stdout
    lea rdi, [newline]
    mov esi, 1
    call linnea_print_stdout
    xor r12d, r12d             ; server index
.loop:
    cmp r12, [rbx + linnea_config.server_count]
    jae .done
    imul r13, r12, linnea_config_server_size
    lea r13, [rbx + r13 + linnea_config.servers]
    lea rdi, [dump_server]
    mov esi, dump_server_len
    call linnea_print_stdout
    mov rdi, r12
    call linnea_print_u64_stdout
    lea rdi, [dump_host]
    mov esi, dump_host_len
    call linnea_print_stdout
    lea rdi, [r13 + linnea_config_server.host]
    mov rsi, [r13 + linnea_config_server.host_len]
    call linnea_print_stdout
    lea rdi, [dump_port]
    mov esi, dump_port_len
    call linnea_print_stdout
    movzx edi, word [r13 + linnea_config_server.port]
    call linnea_print_u64_stdout
    lea rdi, [dump_hostname]
    mov esi, dump_hostname_len
    call linnea_print_stdout
    lea rdi, [r13 + linnea_config_server.hostname]
    mov rsi, [r13 + linnea_config_server.hostname_len]
    call linnea_print_stdout
    lea rdi, [dump_root]
    mov esi, dump_root_len
    call linnea_print_stdout
    lea rdi, [r13 + linnea_config_server.root]
    mov rsi, [r13 + linnea_config_server.root_len]
    call linnea_print_stdout
    lea rdi, [newline]
    mov esi, 1
    call linnea_print_stdout
    inc r12
    jmp .loop
.done:
    pop r13
    pop r12
    pop rbx
    ret
