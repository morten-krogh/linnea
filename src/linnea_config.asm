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
dump_locations:         db " locations="
dump_locations_len      equ $ - dump_locations
dump_location:          db "location "
dump_location_len       equ $ - dump_location
dump_prefix:            db ": prefix="
dump_prefix_len         equ $ - dump_prefix
dump_root:              db " root="
dump_root_len           equ $ - dump_root
dump_proxy:             db " proxy="
dump_proxy_len          equ $ - dump_proxy
newline:                db 10

msg_no_servers:         db "config must define at least one server"
msg_no_servers_len      equ $ - msg_no_servers
msg_port_zero:          db "server port must be between 1 and 65535"
msg_port_zero_len       equ $ - msg_port_zero
msg_empty_host:         db "server host must not be empty"
msg_empty_host_len      equ $ - msg_empty_host
msg_empty_hostname:     db "server hostname must not be empty"
msg_empty_hostname_len  equ $ - msg_empty_hostname
msg_no_locations:       db "server requires at least one location"
msg_no_locations_len    equ $ - msg_no_locations
msg_bad_prefix:         db "location prefix must start with '/'"
msg_bad_prefix_len      equ $ - msg_bad_prefix
msg_empty_root:         db "location root must not be empty"
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
    mov r10, [r9 + linnea_config_server.location_count]
    test r10, r10
    jz .no_locations
    xor r11d, r11d             ; location index
.loc_loop:
    cmp r11, r10
    jae .loc_done
    imul rdx, r11, linnea_config_location_size
    lea rdx, [r9 + rdx + linnea_config_server.locations]
    cmp qword [rdx + linnea_config_location.prefix_len], 0
    je .bad_prefix
    cmp byte [rdx + linnea_config_location.prefix], '/'
    jne .bad_prefix
    cmp qword [rdx + linnea_config_location.kind], LINNEA_LOC_KIND_ROOT
    jne .loc_next
    cmp qword [rdx + linnea_config_location.root_len], 0
    je .empty_root
.loc_next:
    inc r11
    jmp .loc_loop
.loc_done:
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
.no_locations:
    lea rdi, [msg_no_locations]
    mov esi, msg_no_locations_len
    jmp linnea_error_exit
.bad_prefix:
    lea rdi, [msg_bad_prefix]
    mov esi, msg_bad_prefix_len
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
;   config: 2 servers timeout=5 max_connections=1024
;   server 0: host=0.0.0.0 port=8080 hostname=example.com locations=2
;   location 0: prefix=/ root=test/www
;   location 1: prefix=/api proxy=127.0.0.1:3000
linnea_config_dump:
    push rbx
    push r12
    push r13
    push r14
    push r15
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
    lea rdi, [dump_locations]
    mov esi, dump_locations_len
    call linnea_print_stdout
    mov rdi, [r13 + linnea_config_server.location_count]
    call linnea_print_u64_stdout
    lea rdi, [newline]
    mov esi, 1
    call linnea_print_stdout
    xor r14d, r14d             ; location index
.loc_loop:
    cmp r14, [r13 + linnea_config_server.location_count]
    jae .loc_done
    imul r15, r14, linnea_config_location_size
    lea r15, [r13 + r15 + linnea_config_server.locations]
    lea rdi, [dump_location]
    mov esi, dump_location_len
    call linnea_print_stdout
    mov rdi, r14
    call linnea_print_u64_stdout
    lea rdi, [dump_prefix]
    mov esi, dump_prefix_len
    call linnea_print_stdout
    lea rdi, [r15 + linnea_config_location.prefix]
    mov rsi, [r15 + linnea_config_location.prefix_len]
    call linnea_print_stdout
    cmp qword [r15 + linnea_config_location.kind], LINNEA_LOC_KIND_PROXY
    je .loc_proxy
    lea rdi, [dump_root]
    mov esi, dump_root_len
    call linnea_print_stdout
    lea rdi, [r15 + linnea_config_location.root]
    mov rsi, [r15 + linnea_config_location.root_len]
    jmp .loc_target
.loc_proxy:
    lea rdi, [dump_proxy]
    mov esi, dump_proxy_len
    call linnea_print_stdout
    lea rdi, [r15 + linnea_config_location.proxy_str]
    mov rsi, [r15 + linnea_config_location.proxy_str_len]
.loc_target:
    call linnea_print_stdout
    lea rdi, [newline]
    mov esi, 1
    call linnea_print_stdout
    inc r14
    jmp .loc_loop
.loc_done:
    inc r12
    jmp .loop
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
