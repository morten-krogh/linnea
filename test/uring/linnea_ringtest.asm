; linnea_ringtest.asm — the submission side of the io_uring rings, against the
; real kernel: what happens when io_uring_enter(2) consumes fewer sqes than it
; was told.
;
; It can. The kernel breaks out of its submission loop on an sqe it cannot
; initialise, and on failing to allocate a request under memory pressure, and
; reports the smaller count. linnea_ring_submit used to compute what to submit
; as (our tail - the tail we last published) and advance the published tail
; unconditionally, so the remainder was never offered again: the sq head trailed
; our tail by the shortfall for the life of the process. Every later batch then
; started that many operations behind, and a loop that went quiet left them
; unstarted — along with their linked timeouts, so nothing would time them out
; either. Counting from the kernel's head instead clears the shortfall on the
; next submit.
;
; The provocation is a three-sqe batch with an unknown opcode in the middle. The
; first check is the control: it asserts the kernel really did stop early, so a
; kernel that one day submits the whole batch says so here rather than letting
; the checks below pass while proving nothing.
;
; Prints "uring-ring <pass>/<total>" and exits 1 if any check fails.

default rel

%include "linnea_syscall.inc"
%include "linnea_uring.inc"

global _start

extern linnea_ring_init
extern linnea_ring_get_sqe
extern linnea_ring_submit
extern linnea_print_stdout
extern linnea_print_u64_stdout

LINNEA_IORING_OP_NOP equ 0
BAD_OPCODE           equ 250          ; not an opcode on any kernel yet

; EXPECT actual_reg, value — tally into r14d (total) / r15d (pass).
%macro EXPECT 2
    inc r14d
    mov r11, %2
    cmp %1, r11
    jne %%bad
    inc r15d
%%bad:
%endmacro

; PREP opcode, user_data — take an sqe, zero all 64 bytes, fill the two fields
; that matter here. Leaves the sqe pointer in rbx.
%macro PREP 2
    lea rdi, [ring]
    call linnea_ring_get_sqe
    mov rbx, rax
    mov rdi, rax
    xor eax, eax
    mov ecx, LINNEA_SQE_SIZE
    rep stosb
    mov byte [rbx + LINNEA_SQE_OPCODE], %1
    mov qword [rbx + LINNEA_SQE_USER_DATA], %2
%endmacro

; SHORTFALL — set r10d to (our tail - the head the kernel has consumed to),
; i.e. how many sqes the kernel has been shown but has not taken.
%macro SHORTFALL 0
    lea rbx, [ring]
    mov rcx, [rbx + linnea_ring.sq_khead]
    mov eax, [rcx]
    mov rdx, [rbx + linnea_ring.sq_tail]
    sub edx, eax
    mov r10d, edx
%endmacro

section .rodata
msg_head:  db "uring-ring "
msg_head_len equ $ - msg_head
msg_slash: db "/"
msg_nl:    db 10

section .bss
ring:      resb LINNEA_RING_SIZE

section .text
_start:
    xor r14d, r14d                    ; total
    xor r15d, r15d                    ; pass

    mov edi, 8                        ; entries
    lea rsi, [ring]
    xor edx, edx                      ; no setup flags
    xor ecx, ecx                      ; let the kernel size the cq
    call linnea_ring_init
    mov r10d, eax
    EXPECT r10, 0
    test eax, eax
    js .print                         ; no ring, so nothing below can run

    ; --- a batch the kernel cannot finish ---
    PREP LINNEA_IORING_OP_NOP, 100
    PREP BAD_OPCODE, 101              ; the kernel stops here
    PREP LINNEA_IORING_OP_NOP, 102
    lea rdi, [ring]
    call linnea_ring_submit
    mov r12d, eax                     ; what the kernel says it took

    ; the control: one sqe must be left behind, or the rest proves nothing
    SHORTFALL
    EXPECT r10, 1
    mov r10d, r12d
    EXPECT r10, 2                     ; and the count reports the same thing

    ; --- one ordinary submit later, nothing may still be waiting ---
    PREP LINNEA_IORING_OP_NOP, 200
    lea rdi, [ring]
    call linnea_ring_submit
    SHORTFALL
    EXPECT r10, 0

    ; and the stranded operation really ran: four sqes, four completions
    lea rbx, [ring]
    mov rcx, [rbx + linnea_ring.cq_ktail]
    mov eax, [rcx]
    mov r10d, eax
    EXPECT r10, 4

.print:
    lea rdi, [msg_head]
    mov esi, msg_head_len
    call linnea_print_stdout
    mov edi, r15d
    call linnea_print_u64_stdout
    lea rdi, [msg_slash]
    mov esi, 1
    call linnea_print_stdout
    mov edi, r14d
    call linnea_print_u64_stdout
    lea rdi, [msg_nl]
    mov esi, 1
    call linnea_print_stdout

    xor edi, edi
    cmp r15d, r14d
    je .exit
    mov edi, 1
.exit:
    mov eax, LINNEA_SYS_EXIT
    syscall
