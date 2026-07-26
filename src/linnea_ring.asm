; linnea_ring.asm — the io_uring submission/completion rings, direct to the kernel.
;
; This is everything the server used liburing for, which was four functions:
; set the ring up, hand out an sqe, publish the queued sqes, wait for a cqe. The
; library's real API (the io_uring_prep_* family) was never used — sqes are filled
; field by field from the offsets in linnea_uring.inc — so it contributed two
; syscall wrappers and a struct whose layout we had to pin by hand. Doing it here
; removes the last non-kernel dependency from the binary and, with it, the risk
; that a library upgrade silently moves a field we reach into.
;
; The rings are the io_uring(7) ABI, shared memory set up by io_uring_setup(2) and
; mapped three ways (the sq ring, the cq ring, the sqe array), with the kernel and
; this process each producing one queue and consuming the other:
;
;   submission: we fill sqes[tail & mask], then publish tail  -> kernel consumes
;   completion: kernel publishes tail                         -> we consume head
;
; Ordering is free on x86-64: stores are not reordered with other stores and loads
; are not reordered with other loads (TSO), so publishing a tail after filling an
; sqe, and reading a cqe after reading the tail that announced it, need no fence.
; That is why liburing's io_uring_smp_store_release is a plain store here. The one
; place the kernel documents a real barrier is the SQPOLL wakeup handshake, which
; this server does not use (no IORING_SETUP_SQPOLL).
;
; The sq array is an indirection table: array[i] names the sqe the kernel should
; read for submission i. We always place an sqe at (tail & mask) and advance the
; tail by one, so the identity mapping array[i] = i is correct forever and is
; written once, at setup.

default rel

%include "linnea_syscall.inc"
%include "linnea_uring.inc"

global linnea_ring_init
global linnea_ring_get_sqe
global linnea_ring_submit
global linnea_ring_get_cqe

section .bss
; struct io_uring_params, filled by the kernel at setup (see linnea_uring.inc for
; the field offsets). One ring per process, so one static block is enough.
params: resb LINNEA_URING_PARAMS_SIZE

section .text

; linnea_ring_init(edi = entries, rsi = ring*, edx = setup flags)
;   -> eax = 0, or a negative errno.
; io_uring_setup(2) sizes the queues (the kernel rounds entries up to a power of
; two and may give a larger cq), then the three regions are mapped and the ring's
; cached pointers filled in.
linnea_ring_init:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rsi                      ; ring*
    mov r13d, edi                     ; entries

    ; zero the ring struct and the params block: unset fields must read as 0,
    ; both for the kernel (reserved fields) and for our own cached counters.
    mov rdi, r12
    xor eax, eax
    mov ecx, LINNEA_RING_SIZE
    rep stosb
    lea rdi, [params]
    mov ecx, LINNEA_URING_PARAMS_SIZE
    rep stosb
    mov [params + LINNEA_URING_P_FLAGS], edx

    mov eax, LINNEA_SYS_IO_URING_SETUP
    mov edi, r13d
    lea rsi, [params]
    syscall
    test eax, eax
    js .ret                           ; -errno straight through
    mov r14d, eax                     ; ring fd
    mov [r12 + linnea_ring.fd], r14

    ; --- map the submission ring ---
    ; size = sq_off.array + sq_entries * sizeof(u32), and when the kernel reports
    ; IORING_FEAT_SINGLE_MMAP the cq ring lives in the same mapping, so the region
    ; must be the larger of the two.
    mov eax, [params + LINNEA_URING_P_SQ_OFF + LINNEA_SQ_OFF_ARRAY]
    mov ecx, [params + LINNEA_URING_P_SQ_ENTRIES]
    shl ecx, 2                        ; * sizeof(u32)
    add eax, ecx
    mov r15d, eax                     ; sq ring bytes
    mov eax, [params + LINNEA_URING_P_CQ_OFF + LINNEA_CQ_OFF_CQES]
    mov ecx, [params + LINNEA_URING_P_CQ_ENTRIES]
    shl ecx, 4                        ; * sizeof(struct io_uring_cqe)
    add eax, ecx
    mov ebx, eax                      ; cq ring bytes
    test dword [params + LINNEA_URING_P_FEATURES], LINNEA_IORING_FEAT_SINGLE_MMAP
    jz .map_sq
    cmp ebx, r15d
    jbe .map_sq
    mov r15d, ebx                     ; one mapping holds both: take the larger
.map_sq:
    mov esi, r15d
    mov r8d, r14d                     ; the ring fd
    xor r9d, r9d                      ; IORING_OFF_SQ_RING
    call ring_mmap
    test rax, rax
    js .close
    mov [r12 + linnea_ring.sq_base], rax
    mov [r12 + linnea_ring.sq_len], r15
    mov r13, rax                      ; sq ring base (entries is no longer needed)

    ; --- map the completion ring (or point it at the shared mapping) ---
    test dword [params + LINNEA_URING_P_FEATURES], LINNEA_IORING_FEAT_SINGLE_MMAP
    jz .map_cq
    mov rbx, r13                      ; shared with the submission ring
    jmp .have_cq
.map_cq:
    mov esi, ebx
    mov r15d, ebx                     ; keep the length for the ring struct
    mov r8d, r14d
    mov r9d, LINNEA_IORING_OFF_CQ_RING
    call ring_mmap
    test rax, rax
    js .close
    mov rbx, rax
    mov [r12 + linnea_ring.cq_base], rax
    mov [r12 + linnea_ring.cq_len], r15
.have_cq:

    ; --- map the sqe array ---
    mov esi, [params + LINNEA_URING_P_SQ_ENTRIES]
    shl esi, 6                        ; * sizeof(struct io_uring_sqe)
    mov r15d, esi
    mov r8d, r14d
    mov r9d, LINNEA_IORING_OFF_SQES
    call ring_mmap
    test rax, rax
    js .close
    mov [r12 + linnea_ring.sqes], rax
    mov [r12 + linnea_ring.sqes_len], r15

    ; --- cache the queue pointers the hot paths use ---
    ; each *_off field is a byte offset into its ring mapping
    mov eax, [params + LINNEA_URING_P_SQ_OFF + LINNEA_SQ_OFF_HEAD]
    lea rax, [r13 + rax]
    mov [r12 + linnea_ring.sq_khead], rax
    mov eax, [params + LINNEA_URING_P_SQ_OFF + LINNEA_SQ_OFF_TAIL]
    lea rax, [r13 + rax]
    mov [r12 + linnea_ring.sq_ktail], rax
    mov eax, [params + LINNEA_URING_P_SQ_OFF + LINNEA_SQ_OFF_FLAGS]
    lea rax, [r13 + rax]
    mov [r12 + linnea_ring.sq_kflags], rax
    mov eax, [params + LINNEA_URING_P_SQ_OFF + LINNEA_SQ_OFF_RING_MASK]
    mov eax, [r13 + rax]
    mov [r12 + linnea_ring.sq_mask], rax
    mov eax, [params + LINNEA_URING_P_SQ_ENTRIES]
    mov [r12 + linnea_ring.sq_entries], rax

    mov eax, [params + LINNEA_URING_P_CQ_OFF + LINNEA_CQ_OFF_HEAD]
    lea rax, [rbx + rax]
    mov [r12 + linnea_ring.cq_khead], rax
    mov eax, [params + LINNEA_URING_P_CQ_OFF + LINNEA_CQ_OFF_TAIL]
    lea rax, [rbx + rax]
    mov [r12 + linnea_ring.cq_ktail], rax
    mov eax, [params + LINNEA_URING_P_CQ_OFF + LINNEA_CQ_OFF_CQES]
    lea rax, [rbx + rax]
    mov [r12 + linnea_ring.cqes], rax
    mov eax, [params + LINNEA_URING_P_CQ_OFF + LINNEA_CQ_OFF_RING_MASK]
    mov eax, [rbx + rax]
    mov [r12 + linnea_ring.cq_mask], rax

    ; --- the sq array: identity, written once ---
    ; submission i reads sqes[array[i & mask]], and we always fill the sqe at
    ; (tail & mask), so array[i] = i holds for every tail we will ever publish.
    mov eax, [params + LINNEA_URING_P_SQ_OFF + LINNEA_SQ_OFF_ARRAY]
    lea rdi, [r13 + rax]
    mov ecx, [params + LINNEA_URING_P_SQ_ENTRIES]
    xor eax, eax
.fill_array:
    mov [rdi], eax
    add rdi, 4
    inc eax
    cmp eax, ecx
    jb .fill_array

    xor eax, eax
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.close:
    ; a failed mapping leaves the ring fd open; close it so a caller that reports
    ; the error and exits does not need to know the ring was half-built
    mov r13, rax                      ; keep the errno
    mov eax, LINNEA_SYS_CLOSE
    mov edi, r14d
    syscall
    mov rax, r13
    jmp .ret

; ring_mmap(esi = length, r8d = fd, r9d = offset) -> rax = address or -errno.
; Shared, read/write, populated up front: these pages are touched on every
; completion, so faulting them in lazily only moves the cost into the event loop.
ring_mmap:
    mov eax, LINNEA_SYS_MMAP
    xor edi, edi                      ; let the kernel choose the address
    mov edx, LINNEA_PROT_READ | LINNEA_PROT_WRITE
    mov r10d, LINNEA_MAP_SHARED | LINNEA_MAP_POPULATE
    syscall
    ret

; linnea_ring_get_sqe(rdi = ring*) -> rax = sqe*, or 0 when the queue is full.
; The queue is full while the entries we have taken but the kernel has not yet
; consumed cover the whole ring. sq_tail is our own counter: it runs ahead of the
; tail the kernel can see until linnea_ring_submit publishes it, which is what
; lets several sqes be prepared and submitted in one enter(2).
;
; Everything but rax is preserved. The callers are hand-written assembly that used
; to call into liburing, whose compiled leaf happened to leave rsi and rdi alone;
; rather than audit every arming site for a live register, these entry points are
; conservative — two pushes on a path with no syscall costs nothing measurable.
linnea_ring_get_sqe:
    push rcx
    push rsi
    mov rsi, [rdi + linnea_ring.sq_tail]
    mov rcx, [rdi + linnea_ring.sq_khead]
    mov ecx, [rcx]                    ; kernel-consumed head (u32, wraps at 2^32)
    ; the in-flight count is a 32-bit modular difference: sq_tail is our own
    ; unbounded 64-bit counter, but the kernel head is a u32, so a 64-bit
    ; subtraction reports ~2^32 (always >= entries -> permanently "full") once
    ; sq_tail passes 2^32. Compare the low 32 bits, the way the kernel does.
    mov eax, esi
    sub eax, ecx                      ; entries in our hands (mod 2^32)
    cmp eax, [rdi + linnea_ring.sq_entries]
    jae .full
    mov rax, rsi
    and rax, [rdi + linnea_ring.sq_mask]
    shl rax, 6                        ; * sizeof(struct io_uring_sqe)
    add rax, [rdi + linnea_ring.sqes]
    inc rsi
    mov [rdi + linnea_ring.sq_tail], rsi
    pop rsi
    pop rcx
    ret
.full:
    xor eax, eax
    pop rsi
    pop rcx
    ret

; linnea_ring_submit(rdi = ring*) -> eax = sqes submitted, or a negative errno.
; Publishes every sqe prepared since the last call and enters the kernel to start
; them. The kernel never writes the submission tail, so it doubles as the record
; of what has already been published. Everything but rax is preserved (see
; linnea_ring_get_sqe).
linnea_ring_submit:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    mov rcx, [rdi + linnea_ring.sq_ktail]
    mov edx, [rcx]                    ; last published tail
    mov rsi, [rdi + linnea_ring.sq_tail]
    mov eax, esi
    sub eax, edx                      ; sqes to submit
    jz .none
    mov [rcx], esi                    ; publish (plain store: x86 orders it after
                                      ; the sqe writes above)
    mov edi, [rdi + linnea_ring.fd]   ; fd (edi is preserved across ring_enter)
    push rax                          ; [rsp+8] to_submit (regs don't survive the
    mov r9d, 1024                     ;         syscall; keep it on the stack)
    push r9                           ; [rsp]   retry budget
    xor r8d, r8d                      ; flags = 0 on the first attempt
.enter_try:
    mov edx, [rsp + 8]                ; to_submit (the kernel has not consumed it)
    xor r10d, r10d                    ; min_complete = 0
    call ring_enter
    cmp eax, -LINNEA_EINTR
    je .enter_retry                   ; a signal arrived before it did anything
    cmp eax, -LINNEA_EBUSY
    jne .enter_done                   ; success, or a real error to report
    ; EBUSY: overflowed completions block new submissions. Flush them into the
    ; CQ (GETEVENTS reaps nothing here — the main loop consumes them), and retry
    ; a bounded number of times. Persistent EBUSY still falls through as fatal.
    mov r8d, LINNEA_IORING_ENTER_GETEVENTS
.enter_retry:
    dec qword [rsp]
    jz .enter_done                    ; budget spent: return the last errno (fatal)
    jmp .enter_try
.enter_done:
    add rsp, 16
    jmp .ret
.none:
    xor eax, eax
.ret:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret

; linnea_ring_get_cqe(rdi = ring*, rsi = cqe** out, edx = to_submit,
;                     ecx = wait_nr) -> eax = 0 with *out set, or -errno
;   (-EAGAIN when nothing is ready and the caller asked not to wait).
; The caller consumes the cqe and advances the completion head itself (one store
; through linnea_ring.cq_khead), which is why no "cqe_seen" call is needed.
linnea_ring_get_cqe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    mov rbx, rdi                      ; ring
    mov r12, rsi                      ; out
    mov r13d, edx                      ; to_submit
    mov r14d, ecx                      ; wait_nr
.loop:
    ; peek: a non-empty completion queue is the common case and costs no syscall
    mov rax, [rbx + linnea_ring.cq_khead]
    mov r8d, [rax]
    mov rax, [rbx + linnea_ring.cq_ktail]
    mov r9d, [rax]                    ; plain load: x86 orders it before the cqe
    cmp r8d, r9d
    je .empty
    mov rax, r8
    and rax, [rbx + linnea_ring.cq_mask]
    shl rax, 4                        ; * sizeof(struct io_uring_cqe)
    add rax, [rbx + linnea_ring.cqes]
    mov [r12], rax
    xor eax, eax
    jmp .ret
.empty:
    ; Nothing ready. Enter the kernel if there is work to submit, a wait was
    ; asked for, or the completion queue has overflowed — an overflowed ring
    ; keeps its backlog in the kernel and only an enter(2) with GETEVENTS
    ; flushes it into the shared ring, so skipping this would wedge the loop.
    mov rax, [rbx + linnea_ring.sq_kflags]
    mov eax, [rax]
    and eax, LINNEA_IORING_SQ_CQ_OVERFLOW
    or eax, r13d
    or eax, r14d
    jz .again                         ; no reason to enter: report emptiness
    mov edi, [rbx + linnea_ring.fd]
    mov edx, r13d                     ; to_submit
    mov r10d, r14d                    ; min_complete
    mov r8d, LINNEA_IORING_ENTER_GETEVENTS
    call ring_enter
    test eax, eax
    js .ret                           ; -EINTR and friends go back to the caller
    xor r13d, r13d                    ; whatever was queued is now submitted
    jmp .loop
.again:
    mov eax, -LINNEA_EAGAIN
.ret:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ring_enter(edi = fd, edx = to_submit, r10d = min_complete, r8d = flags)
;   -> eax = the count io_uring_enter(2) reports, or a negative errno.
; The signal mask is always NULL here: the event loop takes signals as cqes from
; a signalfd rather than having them interrupt the wait.
ring_enter:
    mov eax, LINNEA_SYS_IO_URING_ENTER
    mov esi, edx                      ; to_submit
    mov edx, r10d                     ; min_complete
    mov r10d, r8d                     ; flags
    xor r8d, r8d                      ; sig = NULL
    xor r9d, r9d                      ; sigsz
    syscall
    ret
