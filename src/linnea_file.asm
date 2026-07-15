; linnea_file.asm — map the config file read-only into memory.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"

global linnea_file_map_readonly
global linnea_file_unmap

extern linnea_error_exit
extern linnea_error_open

section .rodata

msg_fstat:      db "cannot stat config file"
msg_fstat_len   equ $ - msg_fstat
msg_empty:      db "config file is empty"
msg_empty_len   equ $ - msg_empty
msg_too_big:    db "config file too large"
msg_too_big_len equ $ - msg_too_big
msg_mmap:       db "cannot mmap config file"
msg_mmap_len    equ $ - msg_mmap

section .bss

statbuf:        resb LINNEA_STAT_SIZE

section .text

; linnea_file_map_readonly(rdi=path cstr) -> rax=ptr, rdx=size
; open + fstat + mmap PROT_READ + close. Exits with an error message on
; any failure, on an empty file, and on a file larger than the sanity cap.
linnea_file_map_readonly:
    push rbx
    push r12
    mov rbx, rdi               ; path, kept for the open error message
    mov eax, LINNEA_SYS_OPEN
    xor esi, esi               ; O_RDONLY
    xor edx, edx
    syscall
    cmp rax, -4095
    jae .open_fail
    mov r12, rax               ; fd
    mov eax, LINNEA_SYS_FSTAT
    mov rdi, r12
    lea rsi, [statbuf]
    syscall
    cmp rax, -4095
    jae .fstat_fail
    mov rbx, [statbuf + LINNEA_STAT_ST_SIZE]
    test rbx, rbx
    jz .empty
    cmp rbx, LINNEA_MAX_CONFIG_FILE
    ja .too_big
    mov eax, LINNEA_SYS_MMAP
    xor edi, edi               ; addr = NULL
    mov rsi, rbx               ; length = file size
    mov edx, LINNEA_PROT_READ
    mov r10d, LINNEA_MAP_PRIVATE
    mov r8, r12                ; fd
    xor r9d, r9d               ; offset = 0
    syscall
    cmp rax, -4095
    jae .mmap_fail
    mov rdi, r12               ; fd
    mov r12, rax               ; keep ptr across close
    mov eax, LINNEA_SYS_CLOSE
    syscall                    ; close errors ignored, mapping stays valid
    mov rax, r12               ; ptr
    mov rdx, rbx               ; size
    pop r12
    pop rbx
    ret
.open_fail:
    mov rdi, rbx
    jmp linnea_error_open
.fstat_fail:
    lea rdi, [msg_fstat]
    mov esi, msg_fstat_len
    jmp linnea_error_exit
.empty:
    lea rdi, [msg_empty]
    mov esi, msg_empty_len
    jmp linnea_error_exit
.too_big:
    lea rdi, [msg_too_big]
    mov esi, msg_too_big_len
    jmp linnea_error_exit
.mmap_fail:
    lea rdi, [msg_mmap]
    mov esi, msg_mmap_len
    jmp linnea_error_exit

; linnea_file_unmap(rdi=ptr, rsi=size)
linnea_file_unmap:
    mov eax, LINNEA_SYS_MUNMAP
    syscall
    ret
