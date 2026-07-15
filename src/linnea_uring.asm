; linnea_uring.asm — io_uring event loop built on liburing (vendored,
; nolibc build). One multishot accept is armed per listening socket.
; Accepted connections get a pool slot and a recv; complete request heads
; are answered by linnea_http and the connection is closed after the send.
;
; CQE user_data encodes (index << 8) | op tag — see linnea_uring.inc.
; Listener/ring errors are fatal; per-connection errors just close and
; free that connection; accept errors are logged and the accept re-armed.

default rel

%include "linnea_syscall.inc"
%include "linnea_config.inc"
%include "linnea_connection.inc"
%include "linnea_uring.inc"

global linnea_uring_run

extern io_uring_queue_init
extern io_uring_get_sqe
extern io_uring_submit
extern __io_uring_get_cqe

extern linnea_config_instance
extern linnea_connection_alloc
extern linnea_connection_free
extern linnea_connection_at
extern linnea_http_handle
extern linnea_error_exit
extern linnea_print_stdout
extern linnea_print_stderr
extern linnea_print_u64_stdout
extern linnea_print_u64_stderr

section .rodata

msg_init:           db "io_uring_queue_init failed"
msg_init_len        equ $ - msg_init
msg_sqe:            db "io_uring submission queue full"
msg_sqe_len         equ $ - msg_sqe
msg_submit:         db "io_uring_submit failed"
msg_submit_len      equ $ - msg_submit
msg_wait:           db "io_uring wait failed"
msg_wait_len        equ $ - msg_wait

warn_accept:        db "linnea: accept failed (errno "
warn_accept_len     equ $ - warn_accept
warn_accept_end:    db ")", 10
warn_accept_end_len equ $ - warn_accept_end
warn_full:          db "linnea: connection limit reached, dropping connection", 10
warn_full_len       equ $ - warn_full

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
    call linnea_uring_submit_now

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
    mov r13, [r12 + LINNEA_CQE_USER_DATA]
    mov r14d, [r12 + LINNEA_CQE_FLAGS]
    mov r15d, [r12 + LINNEA_CQE_RES]
    ; mark the cqe seen: *cq.khead += 1 (x86 stores have release ordering)
    lea rax, [ring]
    mov rcx, [rax + LINNEA_URING_CQ_KHEAD]
    mov edx, [rcx]
    inc edx
    mov [rcx], edx

    mov eax, r13d
    and eax, 0xff              ; op tag
    shr r13, 8                 ; index
    cmp eax, LINNEA_UD_RECV
    je .on_recv
    cmp eax, LINNEA_UD_SEND
    je .on_send

; --- accept completion: r13 = server index, r15d = connection fd ------
.on_accept:
    test r15d, r15d
    js .accept_err
    mov rdi, r13
    mov esi, r15d
    call linnea_uring_log_accept
    call linnea_connection_alloc
    test rax, rax
    jz .conn_limit
    mov [rax + linnea_connection.fd], r15d
    mov [rax + linnea_connection.server], r13d
    mov rdi, rax
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
.accept_rearm:
    test r14d, LINNEA_IORING_CQE_F_MORE
    jnz .wait
    mov rdi, r13               ; kernel disarmed the multishot: re-arm
    call linnea_uring_arm_accept
    call linnea_uring_submit_now
    jmp .wait
.accept_err:
    lea rdi, [warn_accept]
    mov esi, warn_accept_len
    call linnea_print_stderr
    mov edi, r15d
    neg edi
    call linnea_print_u64_stderr
    lea rdi, [warn_accept_end]
    mov esi, warn_accept_end_len
    call linnea_print_stderr
    jmp .accept_rearm
.conn_limit:
    mov edi, r15d
    mov eax, LINNEA_SYS_CLOSE
    syscall
    lea rdi, [warn_full]
    mov esi, warn_full_len
    call linnea_print_stderr
    jmp .accept_rearm

; --- recv completion: r13 = connection index, r15d = bytes or -errno --
.on_recv:
    mov rdi, r13
    call linnea_connection_at
    mov r12, rax               ; connection*
    test r15d, r15d
    jle .conn_close            ; 0 = peer closed, <0 = connection error
    mov eax, r15d
    add [r12 + linnea_connection.in_len], rax
    mov rdi, r12
    call linnea_http_handle
    test eax, eax
    jz .recv_more
    mov rdi, r12               ; response ready
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait
.recv_more:
    mov rdi, r12
    call linnea_uring_arm_recv
    call linnea_uring_submit_now
    jmp .wait

; --- send completion: r13 = connection index, r15d = bytes or -errno --
.on_send:
    mov rdi, r13
    call linnea_connection_at
    mov r12, rax
    test r15d, r15d
    js .conn_close
    mov eax, r15d
    add [r12 + linnea_connection.out_ptr], rax
    sub [r12 + linnea_connection.out_rem], rax
    cmp qword [r12 + linnea_connection.out_rem], 0
    je .conn_close             ; fully sent: Connection: close
    mov rdi, r12
    call linnea_uring_arm_send
    call linnea_uring_submit_now
    jmp .wait

.conn_close:
    mov edi, [r12 + linnea_connection.fd]
    mov eax, LINNEA_SYS_CLOSE
    syscall
    mov rdi, r12
    call linnea_connection_free
    jmp .wait

.init_fail:
    lea rdi, [msg_init]
    mov esi, msg_init_len
    jmp linnea_error_exit
.wait_fail:
    lea rdi, [msg_wait]
    mov esi, msg_wait_len
    jmp linnea_error_exit

; linnea_uring_submit_now() — submit queued sqes, fatal on error.
linnea_uring_submit_now:
    sub rsp, 8                 ; keep calls 16-byte aligned
    lea rdi, [ring]
    call io_uring_submit
    add rsp, 8
    test eax, eax
    js .fail
    ret
.fail:
    lea rdi, [msg_submit]
    mov esi, msg_submit_len
    jmp linnea_error_exit

; linnea_uring_get_sqe_zeroed() — fetch an sqe and zero all 64 bytes.
linnea_uring_get_sqe_zeroed:
    sub rsp, 8
    lea rdi, [ring]
    call io_uring_get_sqe
    add rsp, 8
    test rax, rax
    jz .full
    mov qword [rax], 0
    mov qword [rax + 8], 0
    mov qword [rax + 16], 0
    mov qword [rax + 24], 0
    mov qword [rax + 32], 0
    mov qword [rax + 40], 0
    mov qword [rax + 48], 0
    mov qword [rax + 56], 0
    ret
.full:
    lea rdi, [msg_sqe]
    mov esi, msg_sqe_len
    jmp linnea_error_exit

; linnea_uring_arm_accept(rdi=server index)
; Queue a multishot accept for the server's listener. Caller submits.
linnea_uring_arm_accept:
    push rbx
    mov rbx, rdi
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_ACCEPT
    mov word [rax + LINNEA_SQE_IOPRIO], LINNEA_IORING_ACCEPT_MULTISHOT
    lea rdx, [linnea_config_instance]
    imul rcx, rbx, linnea_config_server_size
    lea rdx, [rdx + rcx + linnea_config.servers]
    mov ecx, [rdx + linnea_config_server.listen_fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov rcx, rbx
    shl rcx, 8
    or rcx, LINNEA_UD_ACCEPT
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    pop rbx
    ret

; linnea_uring_arm_recv(rdi=connection*)
; Queue a recv into the free tail of the connection's input buffer.
linnea_uring_arm_recv:
    push rbx
    mov rbx, rdi
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_RECV
    mov ecx, [rbx + linnea_connection.fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov rcx, [rbx + linnea_connection.in_len]
    lea rdx, [rbx + rcx + linnea_connection.in_buf]
    mov [rax + LINNEA_SQE_ADDR], rdx
    mov edx, LINNEA_CONN_IN_BUF
    sub edx, ecx               ; in_len <= LINNEA_CONN_IN_BUF
    mov [rax + LINNEA_SQE_LEN], edx
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_RECV
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    pop rbx
    ret

; linnea_uring_arm_send(rdi=connection*)
; Queue a send of the unsent response bytes.
linnea_uring_arm_send:
    push rbx
    mov rbx, rdi
    call linnea_uring_get_sqe_zeroed
    mov byte [rax + LINNEA_SQE_OPCODE], LINNEA_IORING_OP_SEND
    mov ecx, [rbx + linnea_connection.fd]
    mov [rax + LINNEA_SQE_FD], ecx
    mov rcx, [rbx + linnea_connection.out_ptr]
    mov [rax + LINNEA_SQE_ADDR], rcx
    mov ecx, [rbx + linnea_connection.out_rem]
    mov [rax + LINNEA_SQE_LEN], ecx
    mov rcx, [rbx + linnea_connection.index]
    shl rcx, 8
    or rcx, LINNEA_UD_SEND
    mov [rax + LINNEA_SQE_USER_DATA], rcx
    pop rbx
    ret

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
