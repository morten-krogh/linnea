; linnea_uring.asm — io_uring event loop built on liburing (vendored,
; nolibc build). One multishot accept is armed per listening socket; each
; accepted connection is logged and, for now, closed immediately.
; Connection handling arrives with the HTTP milestone.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"
%include "linnea_uring.inc"

global linnea_uring_run

extern io_uring_queue_init
extern io_uring_get_sqe
extern io_uring_submit
extern __io_uring_get_cqe

extern linnea_config_instance
extern linnea_error_exit
extern linnea_error_server
extern linnea_print_stdout
extern linnea_print_u64_stdout

section .rodata

msg_init:           db "io_uring_queue_init failed"
msg_init_len        equ $ - msg_init
msg_sqe:            db "io_uring submission queue full"
msg_sqe_len         equ $ - msg_sqe
msg_submit:         db "io_uring_submit failed"
msg_submit_len      equ $ - msg_submit
msg_wait:           db "io_uring wait failed"
msg_wait_len        equ $ - msg_wait
msg_accept:         db "accept failed on"
msg_accept_len      equ $ - msg_accept

log_accept:         db "accepted connection on "
log_accept_len      equ $ - log_accept
log_colon:          db ":"
log_fd:             db " (fd "
log_fd_len          equ $ - log_fd
log_close:          db ")", 10
log_close_len       equ $ - log_close

section .bss

ring:               resb LINNEA_URING_RING_SIZE
cqe_ptr:            resq 1

section .text

; linnea_uring_run(rdi=config*) — set up the ring, arm accepts, loop forever.
; Only returns by exiting the process on error.
linnea_uring_run:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi               ; config*

    mov edi, LINNEA_URING_ENTRIES
    lea rsi, [ring]
    xor edx, edx
    call io_uring_queue_init
    test eax, eax
    js .init_fail

    xor r12d, r12d             ; server index
.arm_loop:
    cmp r12, [rbx + linnea_config.server_count]
    jae .armed
    mov rdi, r12
    call linnea_uring_arm_accept
    inc r12
    jmp .arm_loop
.armed:
    lea rdi, [ring]
    call io_uring_submit
    test eax, eax
    js .submit_fail

.wait:
    lea rdi, [ring]
    lea rsi, [cqe_ptr]
    xor edx, edx               ; submit = 0
    mov ecx, 1                 ; wait_nr = 1
    xor r8d, r8d               ; sigmask = NULL
    call __io_uring_get_cqe
    cmp eax, -LINNEA_EINTR
    je .wait
    test eax, eax
    js .wait_fail

    mov r12, [cqe_ptr]
    mov r13, [r12 + LINNEA_CQE_USER_DATA]   ; server index
    mov r14d, [r12 + LINNEA_CQE_FLAGS]
    mov r15d, [r12 + LINNEA_CQE_RES]
    ; mark the cqe seen: *cq.khead += 1 (x86 stores have release ordering)
    lea rax, [ring]
    mov rcx, [rax + LINNEA_URING_CQ_KHEAD]
    mov edx, [rcx]
    inc edx
    mov [rcx], edx

    test r15d, r15d
    js .accept_fail
    mov rdi, r13
    mov esi, r15d
    call linnea_uring_log_accept
    mov edi, r15d              ; close the connection until HTTP exists
    mov eax, LINNEA_SYS_CLOSE
    syscall
    test r14d, LINNEA_IORING_CQE_F_MORE
    jnz .wait
    ; multishot accept was disarmed by the kernel: re-arm it
    mov rdi, r13
    call linnea_uring_arm_accept
    lea rdi, [ring]
    call io_uring_submit
    test eax, eax
    js .submit_fail
    jmp .wait

.init_fail:
    lea rdi, [msg_init]
    mov esi, msg_init_len
    jmp linnea_error_exit
.submit_fail:
    lea rdi, [msg_submit]
    mov esi, msg_submit_len
    jmp linnea_error_exit
.wait_fail:
    lea rdi, [msg_wait]
    mov esi, msg_wait_len
    jmp linnea_error_exit
.accept_fail:
    mov ecx, r15d
    neg ecx
    lea rdx, [linnea_config_instance]
    imul rax, r13, linnea_config_server_size
    lea rdx, [rdx + rax + linnea_config.servers]
    lea rdi, [msg_accept]
    mov esi, msg_accept_len
    jmp linnea_error_server

; linnea_uring_arm_accept(rdi=server index)
; Queue a multishot accept SQE for the server's listening socket.
; user_data carries the server index. Caller submits.
linnea_uring_arm_accept:
    push rbx
    mov rbx, rdi               ; index
    lea rdi, [ring]
    call io_uring_get_sqe
    test rax, rax
    jz .full
    mov qword [rax], 0         ; zero all 64 bytes of the sqe
    mov qword [rax + 8], 0
    mov qword [rax + 16], 0
    mov qword [rax + 24], 0
    mov qword [rax + 32], 0
    mov qword [rax + 40], 0
    mov qword [rax + 48], 0
    mov qword [rax + 56], 0
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_ACCEPT
    mov word [rax + LINNEA_SQE_IOPRIO], LINNEA_IORING_ACCEPT_MULTISHOT
    lea rdx, [linnea_config_instance]
    imul rcx, rbx, linnea_config_server_size
    lea rdx, [rdx + rcx + linnea_config.servers]
    mov ecx, [rdx + linnea_config_server.listen_fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov [rax + LINNEA_SQE_USER_DATA], rbx
    pop rbx
    ret
.full:
    lea rdi, [msg_sqe]
    mov esi, msg_sqe_len
    jmp linnea_error_exit

; linnea_uring_log_accept(rdi=server index, esi=connection fd)
; Logs "accepted connection on <host>:<port> (fd N)".
linnea_uring_log_accept:
    push rbx
    push r12
    push r13
    mov r12d, esi              ; fd
    lea rax, [linnea_config_instance]
    imul rcx, rdi, linnea_config_server_size
    lea rbx, [rax + rcx + linnea_config.servers]   ; server*
    lea rdi, [log_accept]
    mov esi, log_accept_len
    call linnea_print_stdout
    lea rdi, [rbx + linnea_config_server.host]
    mov rsi, [rbx + linnea_config_server.host_len]
    call linnea_print_stdout
    lea rdi, [log_colon]
    mov esi, 1
    call linnea_print_stdout
    movzx edi, word [rbx + linnea_config_server.port]
    call linnea_print_u64_stdout
    lea rdi, [log_fd]
    mov esi, log_fd_len
    call linnea_print_stdout
    mov edi, r12d
    call linnea_print_u64_stdout
    lea rdi, [log_close]
    mov esi, log_close_len
    call linnea_print_stdout
    pop r13
    pop r12
    pop rbx
    ret
