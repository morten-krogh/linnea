; linnea_memory.asm — memory without libc: anonymous mmap.

default rel

%include "linnea_syscall.inc"

global linnea_memory_map

extern linnea_error_exit

section .rodata

msg_mmap:       db "cannot allocate memory (mmap failed)"
msg_mmap_len    equ $ - msg_mmap

section .text

; linnea_memory_map(rdi=size) -> rax=ptr
; Private anonymous read-write mapping, zero-filled by the kernel.
; Exits with an error on failure.
linnea_memory_map:
    mov rsi, rdi               ; length
    xor edi, edi               ; addr = NULL
    mov edx, LINNEA_PROT_READ | LINNEA_PROT_WRITE
    mov r10d, LINNEA_MAP_PRIVATE | LINNEA_MAP_ANONYMOUS
    mov r8, -1                 ; fd
    xor r9d, r9d               ; offset
    mov eax, LINNEA_SYS_MMAP
    syscall
    cmp rax, -4095
    jae .fail
    ret
.fail:
    lea rdi, [msg_mmap]
    mov esi, msg_mmap_len
    jmp linnea_error_exit
