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

; Consecutive failures before a backend stops being chosen first. Not a
; per-request cost: failover already covered those requests.
LINNEA_UP_MAX_FAILS equ 3
; How long it is stepped over. Ten seconds is nginx's default fail_timeout and
; is short enough that a backend restarting is picked up on its own.
LINNEA_UP_FAIL_NS   equ 10000000000

global linnea_upstream_pick
global linnea_upstream_addr
global linnea_upstream_mark_ok
global linnea_upstream_mark_fail

extern linnea_uring_now
extern linnea_log_stamp
extern linnea_log_write

section .rodata
; A failover is invisible in the access log by construction: the client is
; served, so the line says 200 and names no backend. An operator whose primary
; is down would see nothing at all. These three lines are the whole record that
; anything happened, and they are also the only way the health state can be
; observed from outside — which is what makes it testable.
log_up_pre:     db "upstream "
log_up_pre_len  equ $ - log_up_pre
log_up_fail:    db " connect failed", 10
log_up_fail_len equ $ - log_up_fail
log_up_out:     db " failed out of rotation", 10
log_up_out_len  equ $ - log_up_out
log_up_back:    db " back in rotation", 10
log_up_back_len equ $ - log_up_back

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
    shl rax, 4
    lea rax, [rdi + rax + linnea_config_location.proxy_addr]
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

; linnea_upstream_mark_fail(rdi = location, rsi = backend index)
; A connect did not complete. With one backend there is nothing to step over, so
; the bookkeeping is skipped entirely rather than kept and ignored.
linnea_upstream_mark_fail:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    lea rdx, [log_up_fail]
    mov ecx, log_up_fail_len
    call up_log
    mov rdi, rbx
    mov rsi, r12
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
