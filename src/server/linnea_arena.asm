; linnea_arena.asm -- per-worker pools of equal-sized arenas, borrowed on demand
; and returned on release. The layout and the reasoning are in linnea_arena.inc.

default rel

%include "linnea_syscall.inc"
%include "linnea_arena.inc"

global linnea_arena_pool_init
global linnea_arena_get
global linnea_arena_put

section .text

; linnea_arena_pool_init(rdi = pool*, rsi = arena bytes, rdx = capacity).
; Records the shape only; nothing is mapped until the first borrow. A capacity
; of zero is taken as one, so a pool is never unable to serve at all.
linnea_arena_pool_init:
    add rsi, 4095
    and rsi, -4096
    mov [rdi + linnea_arena_pool.elem], rsi
    test rdx, rdx
    jnz .pi_cap
    mov edx, 1
.pi_cap:
    mov [rdi + linnea_arena_pool.cap], rdx
    xor eax, eax
    mov [rdi + linnea_arena_pool.base], rax
    mov [rdi + linnea_arena_pool.fresh], rax
    mov [rdi + linnea_arena_pool.free_n], rax
    mov [rdi + linnea_arena_pool.stack], rax
    mov [rdi + linnea_arena_pool.used], rax
    mov [rdi + linnea_arena_pool.peak], rax
    mov [rdi + linnea_arena_pool.refused], rax
    ret

; linnea_arena_get(rdi = pool*) -> rax = a zero-filled arena, or 0 when the
; pool is exhausted (or its reservation could not be made). Clobbers only
; caller-saved registers.
linnea_arena_get:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + linnea_arena_pool.base], 0
    jne .g_mapped
    ; First borrow: reserve cap arenas plus the u32 free stack behind them.
    ; MAP_NORESERVE because this is a ceiling, not a working set -- only what
    ; is touched is ever backed, and returned arenas are given back below.
    mov rsi, [rbx + linnea_arena_pool.cap]
    imul rsi, [rbx + linnea_arena_pool.elem]
    mov rax, [rbx + linnea_arena_pool.cap]
    lea rax, [rax * 4 + 4095]
    and rax, -4096
    add rsi, rax
    xor edi, edi
    mov edx, LINNEA_PROT_READ | LINNEA_PROT_WRITE
    mov r10d, LINNEA_MAP_PRIVATE | LINNEA_MAP_ANONYMOUS | LINNEA_MAP_NORESERVE
    mov r8, -1
    xor r9d, r9d
    mov eax, LINNEA_SYS_MMAP
    syscall
    cmp rax, -4095
    jae .g_refuse                    ; no reservation: fail this borrow, try
                                     ; again on the next
    mov [rbx + linnea_arena_pool.base], rax
    mov rcx, [rbx + linnea_arena_pool.cap]
    imul rcx, [rbx + linnea_arena_pool.elem]
    add rax, rcx
    mov [rbx + linnea_arena_pool.stack], rax
.g_mapped:
    mov rcx, [rbx + linnea_arena_pool.free_n]
    test rcx, rcx
    jz .g_fresh
    dec rcx
    mov [rbx + linnea_arena_pool.free_n], rcx
    mov rdx, [rbx + linnea_arena_pool.stack]
    mov eax, [rdx + rcx * 4]         ; the most recently returned index
    jmp .g_have
.g_fresh:
    mov rax, [rbx + linnea_arena_pool.fresh]
    cmp rax, [rbx + linnea_arena_pool.cap]
    jae .g_refuse
    inc qword [rbx + linnea_arena_pool.fresh]
.g_have:
    imul rax, [rbx + linnea_arena_pool.elem]
    add rax, [rbx + linnea_arena_pool.base]
    mov rcx, [rbx + linnea_arena_pool.used]
    inc rcx
    mov [rbx + linnea_arena_pool.used], rcx
    cmp rcx, [rbx + linnea_arena_pool.peak]
    jbe .g_ret
    mov [rbx + linnea_arena_pool.peak], rcx
.g_ret:
    pop rbx
    ret
.g_refuse:
    inc qword [rbx + linnea_arena_pool.refused]
    xor eax, eax
    pop rbx
    ret

; linnea_arena_put(rdi = pool*, rsi = arena from linnea_arena_get, or 0).
; Its pages go back to the kernel (the next borrower sees zeroes, as a first
; use would) and its index goes on the free stack. Returning 0 is a no-op, so
; a caller can put back whatever it holds without testing first. The caller
; must know nothing -- not the kernel, not an in-flight io_uring op -- still
; reads or writes the arena. Clobbers only caller-saved registers.
linnea_arena_put:
    test rsi, rsi
    jz .p_none
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    mov rdi, rsi
    mov rsi, [rbx + linnea_arena_pool.elem]
    mov edx, LINNEA_MADV_DONTNEED
    mov eax, LINNEA_SYS_MADVISE
    syscall                          ; cannot fail on a mapped, aligned range;
                                     ; if it did the arena would merely stay
                                     ; resident, and a borrower re-initialises
                                     ; every field it reads
    mov rax, r12
    sub rax, [rbx + linnea_arena_pool.base]
    xor edx, edx
    div qword [rbx + linnea_arena_pool.elem]
    mov rcx, [rbx + linnea_arena_pool.free_n]
    mov rdx, [rbx + linnea_arena_pool.stack]
    mov [rdx + rcx * 4], eax
    inc rcx
    mov [rbx + linnea_arena_pool.free_n], rcx
    cmp qword [rbx + linnea_arena_pool.used], 0
    je .p_ret
    dec qword [rbx + linnea_arena_pool.used]
.p_ret:
    pop r12
    pop rbx
.p_none:
    ret
