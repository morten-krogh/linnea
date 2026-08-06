; linnea_spill.asm — capture a request body on disk before it is forwarded.
;
; A proxied upload larger than in_buf used to be relayed upstream as it
; arrived, which meant a client that died mid-upload left the backend holding a
; truncated request it could not tell from a complete one — and may already
; have acted on. So the body is captured in full first and only then forwarded,
; the way nginx's proxy_request_buffering does it.
;
; The capture file is opened O_TMPFILE: it has no name, so no other process can
; see it, two connections cannot collide over it, and it is reclaimed by the
; kernel when the fd closes — including if we are killed mid-upload. There is
; nothing to clean up and no directory to litter.
;
; Once the body is complete the file is mapped and handed to the connection's
; existing file_base/file_size pair, so it is sent by the same code that queues
; a static file behind a response head, and unmapped by the same teardown.
;
; The cap matters as much as the capture: without one a single client could
; fill the disk, so a body past max_body is refused (413) rather than spilled.

default rel

%include "linnea_syscall.inc"
%include "linnea_connection.inc"
%include "linnea_uring.inc"        ; errno names

global linnea_spill_open
global linnea_spill_write
global linnea_spill_finish
global linnea_spill_release

section .rodata

; The directory only supplies the filesystem — O_TMPFILE creates no entry in
; it. The unit runs with PrivateTmp, so this is a namespace of our own.
spill_dir: db "/tmp", 0

section .text

; linnea_spill_open(rdi=connection*) -> rax = 0 ok, -1 failed
; Idempotent: a body arriving in several chunks calls this once per chunk
; rather than tracking whose turn it is to create the file.
linnea_spill_open:
    cmp dword [rdi + linnea_connection.spill_fd], -1
    jne .already
    push rdi
    lea rdi, [spill_dir]
    mov esi, LINNEA_O_TMPFILE | LINNEA_O_RDWR | LINNEA_O_CLOEXEC
    mov edx, LINNEA_MODE_0600
    mov eax, LINNEA_SYS_OPEN
    syscall
    pop rdi
    cmp rax, -4095
    jae .fail
    mov [rdi + linnea_connection.spill_fd], eax
    mov qword [rdi + linnea_connection.spill_len], 0
.already:
    xor eax, eax
    ret
.fail:
    mov eax, -1
    ret

; linnea_spill_write(rdi=connection*, rsi=buf, rdx=len) -> rax = 0 ok, -1 failed
; A regular file's write returns short only on a full filesystem or a signal,
; so the loop is for correctness rather than for the common case.
linnea_spill_write:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    test r13, r13
    jz .done
    mov rdi, rbx                   ; the args are in rbx/r12/r13 now
    call linnea_spill_open
    test eax, eax
    js .fail
.loop:
    mov edi, [rbx + linnea_connection.spill_fd]
    mov rsi, r12
    mov rdx, r13
    mov eax, LINNEA_SYS_WRITE
    syscall
    cmp rax, -4095
    jae .retry_or_fail
    test rax, rax
    jz .fail                       ; no progress: treat as a full filesystem
    add [rbx + linnea_connection.spill_len], rax
    add r12, rax
    sub r13, rax
    jnz .loop
.done:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.retry_or_fail:
    cmp rax, -LINNEA_EINTR
    je .loop
    cmp rax, -LINNEA_EAGAIN
    je .loop
.fail:
    mov eax, -1
    pop r13
    pop r12
    pop rbx
    ret

; linnea_spill_finish(rdi=connection*) -> rax = 0 ok, -1 failed
; The body is complete: map it and point the connection's send cursor at it.
; MAP_PRIVATE read-only — nothing writes through the mapping, and the file is
; ours alone, so no one can change it underneath us either.
linnea_spill_finish:
    push rbx
    mov rbx, rdi
    mov rsi, [rbx + linnea_connection.spill_len]
    test rsi, rsi
    jz .empty
    xor edi, edi                   ; addr = NULL
    mov edx, LINNEA_PROT_READ
    mov r10d, LINNEA_MAP_PRIVATE
    mov r8d, [rbx + linnea_connection.spill_fd]
    xor r9d, r9d                   ; offset 0
    mov eax, LINNEA_SYS_MMAP
    syscall
    cmp rax, -4095
    jae .fail
    ; file_base/file_size own the mapping — the connection teardown unmaps it.
    ; file_ptr/file_rem are the send cursor the proxy head send drains.
    mov [rbx + linnea_connection.file_base], rax
    mov [rbx + linnea_connection.file_ptr], rax
    mov rcx, [rbx + linnea_connection.spill_len]
    mov [rbx + linnea_connection.file_size], rcx
    mov [rbx + linnea_connection.file_rem], rcx
    xor eax, eax
    pop rbx
    ret
.empty:
    mov qword [rbx + linnea_connection.file_rem], 0
    xor eax, eax
    pop rbx
    ret
.fail:
    mov eax, -1
    pop rbx
    ret

; linnea_spill_release(rdi=connection*)
; Closing the fd is what frees the disk space: an O_TMPFILE has no link, so the
; kernel reclaims it here. The mapping outlives the fd and is released by the
; connection's own file_base teardown.
linnea_spill_release:
    mov ecx, [rdi + linnea_connection.spill_fd]
    cmp ecx, -1
    je .none
    push rdi
    mov edi, ecx
    mov eax, LINNEA_SYS_CLOSE
    syscall
    pop rdi
    mov dword [rdi + linnea_connection.spill_fd], -1
    mov qword [rdi + linnea_connection.spill_len], 0
.none:
    ret
