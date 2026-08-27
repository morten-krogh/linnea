; linnea_random.asm — the one place that reads entropy.
;
; getrandom(2) returns the NUMBER OF BYTES it copied. It can return fewer than
; asked when interrupted, and a negative errno on failure. Ignoring that result
; is a fail-open: the destination keeps whatever it held, which for a pooled
; arena is the PREVIOUS handshake's key material, and the caller proceeds to
; build a handshake out of it (audit-report-96).
;
; So this loops until every byte is filled and reports failure otherwise. It
; never decides what a failure MEANS — a per-request backend handshake should
; abandon the leg, a pre-fork one-shot secret should stop the process — that
; belongs to the caller, which is the only one that knows.

%include "linnea_syscall.inc"

global linnea_random_bytes

section .text

; linnea_random_bytes(rdi = dest, rsi = len) -> rax = 0 filled, -1 could not.
; On failure the destination is left UNDEFINED and must not be used; callers
; that reuse a buffer must treat a failure as "the old bytes are still there".
linnea_random_bytes:
    push rbx
    push r12
    push r13
    mov rbx, rdi                     ; dest
    mov r12, rsi                     ; total wanted
    xor r13, r13                     ; filled so far
    test r12, r12
    jz .done                         ; nothing asked for is trivially filled
.loop:
    lea rdi, [rbx + r13]
    mov rsi, r12
    sub rsi, r13                     ; bytes still to fill
    xor edx, edx                     ; flags
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    test rax, rax
    jle .fail                        ; error, or a zero-byte "success"
    add r13, rax
    cmp r13, r12
    jb .loop
.done:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret
