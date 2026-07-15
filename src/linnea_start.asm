; linnea_start.asm — entry point and top-level orchestration:
; map config file -> parse -> unmap -> validate -> dump -> listen -> event loop.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global _start

extern linnea_file_map_readonly
extern linnea_file_unmap
extern linnea_config_parse
extern linnea_config_validate
extern linnea_config_dump
extern linnea_config_instance
extern linnea_network_listen_all
extern linnea_connections_init
extern linnea_uring_run
extern linnea_error_usage

section .text

_start:
    mov rax, [rsp]             ; argc
    cmp rax, 2
    jl .usage
    mov rdi, [rsp + 16]        ; argv[1] = config path
    call linnea_file_map_readonly
    mov r12, rax               ; ptr
    mov r13, rdx               ; size
    mov rdi, rax
    mov rsi, rdx
    lea rdx, [linnea_config_instance]
    call linnea_config_parse
    mov rdi, r12
    mov rsi, r13
    call linnea_file_unmap
    lea rdi, [linnea_config_instance]
    call linnea_config_validate
    lea rdi, [linnea_config_instance]
    call linnea_config_dump
    lea rdi, [linnea_config_instance]
    call linnea_network_listen_all
    call linnea_connections_init
    lea rdi, [linnea_config_instance]
    call linnea_uring_run      ; never returns
.usage:
    jmp linnea_error_usage
