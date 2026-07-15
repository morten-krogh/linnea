; linnea_connection.asm — fixed-size connection pool with a free list.
; The pool is one anonymous mmap allocated at startup; slots are linked
; through .next_free and handed out in O(1).

default rel

%include "linnea_connection.inc"

global linnea_connections_init
global linnea_connection_alloc
global linnea_connection_free
global linnea_connection_at

extern linnea_memory_map

section .bss

pool_base:      resq 1
free_head:      resq 1         ; pool index of first free slot, -1 = none

section .text

; linnea_connections_init() — allocate the pool and chain the free list.
linnea_connections_init:
    mov rdi, linnea_connection_size * LINNEA_MAX_CONNECTIONS
    call linnea_memory_map
    mov [pool_base], rax
    mov rdx, rax               ; slot cursor
    xor ecx, ecx               ; index
.chain:
    cmp rcx, LINNEA_MAX_CONNECTIONS
    jae .done
    mov [rdx + linnea_connection.index], rcx
    lea r8, [rcx + 1]
    cmp r8, LINNEA_MAX_CONNECTIONS
    jne .link
    mov r8, -1
.link:
    mov [rdx + linnea_connection.next_free], r8
    add rdx, linnea_connection_size
    inc rcx
    jmp .chain
.done:
    mov qword [free_head], 0
    ret

; linnea_connection_alloc() -> rax=connection* or 0 when the pool is empty.
linnea_connection_alloc:
    mov rax, [free_head]
    cmp rax, -1
    je .empty
    imul rdx, rax, linnea_connection_size
    add rdx, [pool_base]
    mov rcx, [rdx + linnea_connection.next_free]
    mov [free_head], rcx
    mov qword [rdx + linnea_connection.in_len], 0
    mov qword [rdx + linnea_connection.head_len], 0
    mov qword [rdx + linnea_connection.keep_alive], 0
    mov qword [rdx + linnea_connection.out_rem], 0
    mov qword [rdx + linnea_connection.file_base], 0
    mov qword [rdx + linnea_connection.file_size], 0
    mov qword [rdx + linnea_connection.file_ptr], 0
    mov qword [rdx + linnea_connection.file_rem], 0
    mov rax, rdx
    ret
.empty:
    xor eax, eax
    ret

; linnea_connection_free(rdi=connection*)
linnea_connection_free:
    mov rax, [free_head]
    mov [rdi + linnea_connection.next_free], rax
    mov rax, [rdi + linnea_connection.index]
    mov [free_head], rax
    ret

; linnea_connection_at(rdi=pool index) -> rax=connection*
linnea_connection_at:
    imul rax, rdi, linnea_connection_size
    add rax, [pool_base]
    ret
