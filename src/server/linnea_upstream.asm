; linnea_upstream.asm — choosing among a proxy location's backends, and
; remembering which of them are answering.
;
; A location named one upstream until now, so "which backend" was not a question
; and an upstream that was down was a 502. With several, two things have to be
; decided: where a request goes, and what happens when it is not answered.
;
; HEALTH IS PASSIVE, the way nginx's max_fails/fail_timeout is: nothing is probed
; on a timer, and no traffic exists that a user did not ask for. A backend that
; refuses a connection is counted, and after LINNEA_UP_MAX_FAILS consecutive
; failures it is stepped over for LINNEA_UP_FAIL_NS. Recovery costs exactly one
; request: when the cooldown expires the backend is eligible again and the first
; success clears it.
;
; Being stepped over is NOT the same as a client paying for the failure.
; Failover happens INSIDE one request — a connect that fails moves to the next
; backend and the client is served by that one — so the counter only decides
; where a request STARTS, never whether it succeeds while any backend is up.
;
; WHY ONLY CONNECT FAILURES COUNT, and why failover is only tried there: a
; retry is safe exactly while no byte of the request has been sent. Once the
; head is out, a backend that then goes quiet may have already acted on it, and
; a second delivery is the proxy inventing a request the client made once. So
; the one place the request can be moved is also the one place a failure is
; unambiguous — a backend that accepts and then hangs is a slow backend, not an
; absent one, and is left to proxy_timeout.

%include "linnea_config.inc"
%include "linnea_syscall.inc"
%include "linnea_uring.inc"

; Consecutive failures before a backend stops being chosen first. Not a
; per-request cost: failover already covered those requests.
LINNEA_UP_MAX_FAILS equ 3
; How long it is stepped over. Ten seconds is nginx's default fail_timeout and
; is short enough that a backend restarting is picked up on its own.
LINNEA_UP_FAIL_NS   equ 10000000000

; --- the idle upstream pool -------------------------------------------------
; Connections are parked per worker, keyed by (location, backend). 32 slots is
; an absolute bound on idle upstream descriptors a worker can hold, which a
; per-location pool would not give: locations are configurable and their product
; with backends is not something a config author should have to reason about.
LINNEA_UP_POOL_SLOTS equ 32
; How long a parked connection may sit before it is thrown away rather than
; used. This must stay BELOW whatever the backend's own keep-alive timeout is,
; or the backend closes first and every reuse races its FIN. Five seconds is
; under every common default (nginx 75s, most frameworks 5-15s) and is the
; cheap half of the defence; the liveness peek in _take is the other half.
LINNEA_UP_IDLE_NS    equ 5000000000

global linnea_upstream_method_safe
global linnea_upstream_park
global linnea_upstream_take
global linnea_upstream_reap_one
global linnea_upstream_pool_close
global linnea_upstream_pick
global linnea_upstream_addr
global linnea_upstream_addrlen
global linnea_upstream_socket
global linnea_upstream_mark_ok
global linnea_upstream_mark_fail
global linnea_upstream_log_oversize
global linnea_upstream_mark_unanswered

extern linnea_uring_now
extern linnea_upstream_closed
extern linnea_log_stamp
extern linnea_log_write
extern linnea_log_u64

section .rodata
; A failover is invisible in the access log by construction: the client is
; served, so the line says 200 and names no backend. An operator whose primary
; is down would see nothing at all. These three lines are the whole record that
; anything happened, and they are also the only way the health state can be
; observed from outside — which is what makes it testable.
log_up_pre:     db "upstream "
log_up_pre_len  equ $ - log_up_pre
; No newline: up_log_reason appends the cause and ends the line. "connect
; failed" alone reaches an operator from three different mistakes -- nothing
; listening, no such socket path, and no permission to open it -- and sends
; them to the same place for all three. Which one it was IS the diagnosis.
log_up_fail:    db " connect failed"
log_up_fail_len equ $ - log_up_fail
; Said differently on purpose. "connect failed" sends an operator looking at
; listeners and firewalls; a backend that ACCEPTED and then went quiet is a
; different fault with a different place to look, and the two were reported
; with the same words until response-stage failures started counting.
log_up_noans:   db " accepted but did not answer", 10
log_up_noans_len equ $ - log_up_noans
; A response we REFUSED, delivered correctly by a backend that did nothing
; wrong: a head larger than the buffer we read it into. Said apart from "did not
; answer" because it sends an operator to a different place -- our limit, not
; their health -- and deliberately NOT counted against the backend below: taking
; a working backend out of rotation over our own buffer would turn a limit into
; an outage.
log_up_big:     db " answered with a head past our limit -- refused here, not its fault", 10
log_up_big_len  equ $ - log_up_big
log_up_out:     db " failed out of rotation", 10
log_up_out_len  equ $ - log_up_out
log_up_back:    db " back in rotation", 10
log_up_back_len equ $ - log_up_back
rsn_open:       db " ("
rsn_open_len    equ $ - rsn_open
rsn_refused:    db "connection refused -- nothing is listening there"
rsn_refused_len equ $ - rsn_refused
rsn_noent:      db "no such socket path"
rsn_noent_len   equ $ - rsn_noent
rsn_acces:      db "permission denied -- the backend is fine, its socket is not ours to open"
rsn_acces_len   equ $ - rsn_acces
rsn_timedout:   db "timed out"
rsn_timedout_len equ $ - rsn_timedout
rsn_hostunr:    db "host unreachable"
rsn_hostunr_len equ $ - rsn_hostunr
rsn_netunr:     db "network unreachable"
rsn_netunr_len  equ $ - rsn_netunr
rsn_errno:      db "errno "
rsn_errno_len   equ $ - rsn_errno
rsn_close:      db ")", 10
rsn_close_len   equ $ - rsn_close

section .text

; up_log(rdi = location, rsi = backend index, rdx = suffix, rcx = suffix len)
; "<stamp>upstream <ip:port><suffix>"
up_log:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    call linnea_log_stamp
    lea rdi, [log_up_pre]
    mov esi, log_up_pre_len
    call linnea_log_write
    mov rax, r12
    imul rax, rax, LINNEA_MAX_PROXY_STR + 1
    lea rdi, [rbx + linnea_config_location.proxy_str]
    add rdi, rax
    mov rsi, [rbx + linnea_config_location.proxy_str_len + r12 * 8]
    call linnea_log_write
    mov rdi, r13
    mov rsi, r14
    call linnea_log_write
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_upstream_addr(rdi = location, rsi = backend index) -> rax = sockaddr_in*
; The address lives in the parsed config, so it outlives any SQE pointing at it.
linnea_upstream_addr:
    mov rax, rsi
    imul rax, rax, LINNEA_PROXY_ADDR_SIZE
    lea rax, [rdi + rax + linnea_config_location.proxy_addr]
    ret

; linnea_upstream_addrlen(rdi = location, rsi = backend index) -> rax = addrlen
; How many bytes of the slot linnea_upstream_addr returned are the address.
; The slot is sized for the largest family; connect(2) must be told the size of
; the one actually in it.
linnea_upstream_addrlen:
    mov rax, [rdi + linnea_config_location.proxy_addrlen + rsi * 8]
    ret

; linnea_upstream_socket(rdi = location, rsi = backend index) -> rax = fd, or
; -errno from socket(2). Test it the way every caller does: cmp rax, -4095/jae.
;
; One place opens every upstream socket. The family is a property of the BACKEND
; being dialled rather than a constant, and seven copies of that decision would
; be six chances to miss one -- the shape that made report 54 a report. The
; family is read back out of the sockaddr the parser prebuilt, so exactly one
; place decides what family a backend is, and it is the place that built it.
;
; Callers must have CHOSEN the backend first: which family to open is not
; knowable before which backend it is being opened to.
linnea_upstream_socket:
    call linnea_upstream_addr          ; rdi/rsi are its arguments; clobbers rax
    movzx edi, word [rax]              ; sa_family, exactly as the parser wrote it
    mov esi, LINNEA_SOCK_STREAM
    xor edx, edx
    mov eax, LINNEA_SYS_SOCKET
    syscall
    ret

; linnea_upstream_pick(rdi = location) -> rax = backend index
;
; Round-robin over the backends that are not failed out. NEVER fails: with every
; one inside its cooldown it returns the one that has been out longest, because
; a 502 should come from having tried rather than from bookkeeping — and with no
; probe running, trying is the only way a recovery is ever noticed.
linnea_upstream_pick:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, [rbx + linnea_config_location.proxy_count]
    cmp r12, 2
    jb .only_one
    call linnea_uring_now             ; eats rdi/rsi; rbx and r12 survive
    mov r13, rax                      ; now, ns
    mov r14, [rbx + linnea_config_location.rr_cursor]
    xor r15d, r15d                    ; backends examined
.scan:
    cmp r15, r12
    jae .all_dead
    cmp r14, r12
    jb .have
    xor r14d, r14d
.have:
    mov rax, [rbx + linnea_config_location.bk_dead_at + r14 * 8]
    test rax, rax
    jz .chosen                        ; never failed out
    mov rcx, r13
    sub rcx, rax
    ; 10s in ns does not fit an imm32, and `cmp r64, imm` would silently
    ; sign-extend a truncated one — the constant goes through a register.
    mov rdx, LINNEA_UP_FAIL_NS
    cmp rcx, rdx
    jae .revive                       ; cooldown served: eligible again
    inc r14
    inc r15
    jmp .scan
.revive:
    mov qword [rbx + linnea_config_location.bk_dead_at + r14 * 8], 0
    mov qword [rbx + linnea_config_location.bk_fails + r14 * 8], 0
    mov rdi, rbx
    mov rsi, r14
    lea rdx, [log_up_back]
    mov ecx, log_up_back_len
    call up_log
.chosen:
    mov rax, r14
    inc r14                           ; the next request starts one along
    cmp r14, r12
    jb .save
    xor r14d, r14d
.save:
    mov [rbx + linnea_config_location.rr_cursor], r14
    jmp .ret
.all_dead:
    xor r14d, r14d
    mov r8, [rbx + linnea_config_location.bk_dead_at]
    mov rcx, 1
.oldest:
    cmp rcx, r12
    jae .oldest_done
    mov rax, [rbx + linnea_config_location.bk_dead_at + rcx * 8]
    cmp rax, r8
    jae .oldest_next
    mov r8, rax
    mov r14, rcx
.oldest_next:
    inc rcx
    jmp .oldest
.oldest_done:
    mov rax, r14
    jmp .ret
.only_one:
    xor eax, eax                      ; nothing to choose between
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_upstream_mark_ok(rdi = location, rsi = backend index)
; A connection was established: whatever it did before, this backend is up.
linnea_upstream_mark_ok:
    mov qword [rdi + linnea_config_location.bk_fails + rsi * 8], 0
    mov qword [rdi + linnea_config_location.bk_dead_at + rsi * 8], 0
    ret

; linnea_upstream_mark_fail(rdi = location, rsi = backend index,
;                           edx = the connect result, a NEGATIVE errno)
; A connect did not complete. With one backend there is nothing to step over, so
; the bookkeeping is skipped entirely rather than kept and ignored.
;
; The result is carried in rather than collapsed at the call site: the caller is
; the only one that still has it, and it is the difference between "start the
; backend", "fix the path" and "fix the ownership".
linnea_upstream_mark_fail:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13d, edx                     ; the result, before up_log clobbers rdx
    lea rdx, [log_up_fail]
    mov ecx, log_up_fail_len
    call up_log                       ; "upstream <addr> connect failed"
    mov edi, r13d
    call up_log_reason                ; " (<cause>)" and the newline
    mov rdi, rbx
    mov rsi, r12
    pop r13
    pop r12
    pop rbx
    jmp mark_fail_count

; up_log_reason(edi = a negative errno) -- appends " (<cause>)" and the newline
; that ends the line. Named for the causes where the name changes where an
; operator looks, and the bare number otherwise, which is still better than the
; nothing this line used to carry.
up_log_reason:
    push rbx
    mov ebx, edi
    neg ebx                           ; -errno -> errno
    lea rdi, [rsn_open]
    mov esi, rsn_open_len
    call linnea_log_write
    lea rdi, [rsn_refused]
    mov esi, rsn_refused_len
    cmp ebx, LINNEA_ECONNREFUSED
    je .named
    lea rdi, [rsn_noent]
    mov esi, rsn_noent_len
    cmp ebx, LINNEA_ENOENT
    je .named
    lea rdi, [rsn_acces]
    mov esi, rsn_acces_len
    cmp ebx, LINNEA_EACCES
    je .named
    lea rdi, [rsn_timedout]
    mov esi, rsn_timedout_len
    cmp ebx, LINNEA_ETIMEDOUT
    je .named
    lea rdi, [rsn_hostunr]
    mov esi, rsn_hostunr_len
    cmp ebx, LINNEA_EHOSTUNREACH
    je .named
    lea rdi, [rsn_netunr]
    mov esi, rsn_netunr_len
    cmp ebx, LINNEA_ENETUNREACH
    je .named
    lea rdi, [rsn_errno]              ; no words for it: the number
    mov esi, rsn_errno_len
    call linnea_log_write
    mov edi, ebx
    call linnea_log_u64
    jmp .close
.named:
    call linnea_log_write
.close:
    lea rdi, [rsn_close]
    mov esi, rsn_close_len
    call linnea_log_write
    pop rbx
    ret

; linnea_upstream_log_oversize(rdi = location, rsi = backend index)
; Log only. See log_up_big: this is our limit, not a backend fault, so it must
; not reach the health counters.
linnea_upstream_log_oversize:
    lea rdx, [log_up_big]
    mov ecx, log_up_big_len
    jmp up_log

; linnea_upstream_mark_unanswered(rdi = location, rsi = backend index)
; The backend accepted and then failed to answer -- a timeout, a closed
; connection, framing we will not relay. Counted identically; reported
; differently, because the two faults are looked for in different places.
;
; It logs its own line and JUMPS. It used to reach the logging by falling
; through into mark_fail_common, whose first act was the call to up_log --
; so splitting that function in two silently took this line away, and
; "counted as unanswered, not as a connect failure" went from 3 to 0. An
; implicit fall-through is a call site that no grep for the callee finds.
linnea_upstream_mark_unanswered:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    lea rdx, [log_up_noans]
    mov ecx, log_up_noans_len
    call up_log
    mov rdi, rbx
    mov rsi, r12
    pop r12
    pop rbx
    jmp mark_fail_count

; mark_fail_count(rdi = location, rsi = backend index) -- the health half of
; mark_fail, split out so the logging half can own the cause. Its own two
; pushes are what the alignment of the linnea_uring_now call below counts on.
mark_fail_count:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    cmp qword [rdi + linnea_config_location.proxy_count], 2
    jb .done
    inc qword [rdi + linnea_config_location.bk_fails + rsi * 8]
    cmp qword [rdi + linnea_config_location.bk_fails + rsi * 8], LINNEA_UP_MAX_FAILS
    jb .done
    ; already out: leave its clock alone, or a steady trickle of requests would
    ; keep pushing the cooldown forward and it would never be retried
    cmp qword [rdi + linnea_config_location.bk_dead_at + rsi * 8], 0
    jne .done
    push rdi
    push rsi
    sub rsp, 8                        ; 16-byte align the call
    call linnea_uring_now
    add rsp, 8
    pop rsi
    pop rdi
    mov [rdi + linnea_config_location.bk_dead_at + rsi * 8], rax
    lea rdx, [log_up_out]
    mov ecx, log_up_out_len
    call up_log
.done:
    pop r12
    pop rbx
    ret


; linnea_upstream_method_safe(rdi = method, rsi = length) -> eax = 1 for GET and
; HEAD, 0 for everything else.
;
; The rule that decides whether an upstream connection may be reused for this
; request. Not "idempotent" (PUT and DELETE are, and are still visible when
; repeated) but "safe": a pooled socket can lose a race with the backend's idle
; timeout, and the answer to that race is to send the request again. HTTP/1
; already classified its method while parsing and reuses that; h2 and h3 have
; the token in hand and ask here, so the rule is written once.
linnea_upstream_method_safe:
    xor eax, eax
    cmp rsi, 3
    jne .ms_head
    ; two bytes then one, rather than a dword masked down: the token may end at
    ; the last byte its buffer owns, and a wide read there is a fault waiting
    ; for the wrong page boundary
    cmp word [rdi], 'GE'
    jne .ms_no
    cmp byte [rdi + 2], 'T'
    jne .ms_no
    mov eax, 1
    ret
.ms_head:
    cmp rsi, 4
    jne .ms_no
    cmp dword [rdi], 0x44414548      ; "HEAD", little-endian
    jne .ms_no
    mov eax, 1
    ret
.ms_no:
    xor eax, eax
    ret

section .bss
; at == 0 means the slot is empty, so .bss's zeroing is the initialisation. A
; parked entry always carries a nonzero monotonic stamp, and fd 0 is a legal
; descriptor — which is why emptiness is not spelled with the fd.
up_pool_fd:     resd LINNEA_UP_POOL_SLOTS
up_pool_loc:    resq LINNEA_UP_POOL_SLOTS
up_pool_bk:     resq LINNEA_UP_POOL_SLOTS
up_pool_at:     resq LINNEA_UP_POOL_SLOTS

section .text

; pool_drop(rsi = slot) — close the parked descriptor and empty the slot.
pool_drop:
    push rsi
    mov edi, [up_pool_fd + rsi * 4]
    mov eax, LINNEA_SYS_CLOSE
    syscall
    call linnea_upstream_closed
    pop rsi
    mov qword [up_pool_at + rsi * 8], 0
    ret

; linnea_upstream_park(rdi = location, rsi = backend, edx = fd) -> eax
;   1 = parked (the pool owns the descriptor now)
;   0 = not parked; the caller still owns it and must close it
;
; The caller decides WHETHER a connection may be parked — that judgement is
; about the response that just came over it, not about the pool.
linnea_upstream_park:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13d, edx
    call linnea_uring_now             ; eats rdi/rsi
    xor ecx, ecx
.pk_scan:
    cmp rcx, LINNEA_UP_POOL_SLOTS
    jae .pk_full
    cmp qword [up_pool_at + rcx * 8], 0
    je .pk_free
    inc rcx
    jmp .pk_scan
.pk_free:
    mov [up_pool_fd + rcx * 4], r13d
    mov [up_pool_loc + rcx * 8], rbx
    mov [up_pool_bk + rcx * 8], r12
    mov [up_pool_at + rcx * 8], rax
    mov eax, 1
    jmp .pk_ret
.pk_full:
    xor eax, eax
.pk_ret:
    pop r13
    pop r12
    pop rbx
    ret

; linnea_upstream_take(rdi = location, rsi = backend) -> eax = fd, or -1
;
; A parked connection is only worth having if the backend has not closed it in
; the meantime, and the stamp alone cannot say: it records when WE parked it,
; not what the peer did afterwards. So a candidate is peeked at without
; blocking — EOF or unexpected bytes mean it is not reusable. That leaves a real
; but small race (the peer may close between the peek and our send), which is
; why reuse is confined to methods that may be retried.
;
; Stale slots met along the way are closed regardless of which backend they
; belong to: this walk is the only reaper there is.
linnea_upstream_take:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov rbx, rdi
    mov r12, rsi
    call linnea_uring_now
    mov r13, rax
    xor r14d, r14d
.tk_scan:
    cmp r14, LINNEA_UP_POOL_SLOTS
    jae .tk_none
    cmp qword [up_pool_at + r14 * 8], 0
    je .tk_next
    mov rax, r13
    sub rax, [up_pool_at + r14 * 8]
    mov rcx, LINNEA_UP_IDLE_NS
    cmp rax, rcx
    jb .tk_fresh
    mov rsi, r14                      ; too old for anyone: reap it
    call pool_drop
    jmp .tk_next
.tk_fresh:
    cmp [up_pool_loc + r14 * 8], rbx
    jne .tk_next
    cmp [up_pool_bk + r14 * 8], r12
    jne .tk_next
    ; a candidate: is the peer still there?
    mov r15d, [up_pool_fd + r14 * 4]
    mov eax, LINNEA_SYS_RECVFROM
    mov edi, r15d
    mov rsi, rsp                      ; one byte of scratch
    mov edx, 1
    mov r10d, LINNEA_MSG_PEEK | LINNEA_MSG_DONTWAIT
    xor r8d, r8d
    xor r9d, r9d
    syscall
    cmp rax, -LINNEA_EAGAIN
    jne .tk_dead                      ; 0 = closed, >0 = bytes we never asked for
    mov qword [up_pool_at + r14 * 8], 0   ; the caller owns it now
    mov eax, r15d
    jmp .tk_ret
.tk_dead:
    mov rsi, r14
    call pool_drop
.tk_next:
    inc r14
    jmp .tk_scan
.tk_none:
    mov eax, -1
.tk_ret:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_upstream_reap_one() -> eax = 1 if a parked connection was dropped, 0 if
; the pool held none. The fresh-connection path calls this when it is at the
; max_upstream ceiling: a parked connection serves no request, so it must yield
; to one that needs a socket. Without this the pool's own idle inventory refuses
; new work permanently -- a POST (or any non-GET/HEAD, or a GET to another
; backend) after a burst that filled the pool -- because `take` is the ONLY other
; reaper and it runs for GET/HEAD alone, to the same (location, backend). An
; entry past the idle cap is dropped first, it is stale for everyone anyway;
; failing that the oldest parked entry goes. Preserves rbx/r12-r15.
linnea_upstream_reap_one:
    push rbx
    push r12
    push r13
    push r14
    call linnea_uring_now             ; eats rdi/rsi; callee-saved survive
    mov r13, rax                      ; now
    xor r14d, r14d                    ; cursor
    mov r12, -1                       ; oldest parked slot found so far, -1 = none
    mov rbx, -1                       ; its stamp (unsigned max = "none yet")
.ro_scan:
    cmp r14, LINNEA_UP_POOL_SLOTS
    jae .ro_pick
    mov rax, [up_pool_at + r14 * 8]
    test rax, rax
    jz .ro_next                       ; empty slot
    mov rcx, r13
    sub rcx, rax
    mov rdx, LINNEA_UP_IDLE_NS
    cmp rcx, rdx
    jae .ro_drop                      ; past the idle cap: drop it now
    cmp rax, rbx
    jae .ro_next                      ; not older than the best so far
    mov rbx, rax
    mov r12, r14
.ro_next:
    inc r14
    jmp .ro_scan
.ro_pick:
    cmp r12, -1
    je .ro_empty                      ; nothing parked at all
    mov r14, r12                      ; drop the oldest
.ro_drop:
    mov rsi, r14
    call pool_drop
    mov eax, 1
    jmp .ro_ret
.ro_empty:
    xor eax, eax
.ro_ret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_upstream_pool_close() — drop every parked connection. For a worker on
; its way out: a descriptor the pool holds belongs to no request, so nothing
; waits on it and it would otherwise be closed only by process exit.
linnea_upstream_pool_close:
    push rbx
    xor ebx, ebx
.pc_loop:
    cmp rbx, LINNEA_UP_POOL_SLOTS
    jae .pc_done
    cmp qword [up_pool_at + rbx * 8], 0
    je .pc_next
    mov rsi, rbx
    call pool_drop
.pc_next:
    inc rbx
    jmp .pc_loop
.pc_done:
    pop rbx
    ret
