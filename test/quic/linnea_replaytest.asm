; linnea_replaytest.asm — 0-RTT anti-replay strike-register unit tests. Exercises
; linnea_quic_replay_check in isolation: a fresh binder is recorded, a repeat
; within the window is a replay, a different binder is fresh, an entry past its
; window is reusable, the register fails closed when full, and frees again once
; its entries expire. Also exercises linnea_quic_ticket_within_lifetime (tls-7):
; a ticket at, before, and exactly on the lifetime boundary is fresh; one past it
; is expired; a future-dated one is rejected. Prints "quic-replay <pass>/<total>"
; and exits 1 on failure.

default rel

%include "linnea_syscall.inc"
%include "linnea_quic.inc"

global _start

extern linnea_quic_replay_check
extern linnea_quic_ticket_within_lifetime
extern linnea_quic_ack_delay_ms
extern linnea_print_stdout
extern linnea_print_u64_stdout

STRIKE_N equ 512                  ; must match the register size in linnea_quic_crypto.asm

; EXPECT actual_reg, value — tally into r14d (total) / r15d (pass).
%macro EXPECT 2
    inc r14d
    mov r11, %2
    cmp %1, r11
    jne %%bad
    inc r15d
%%bad:
%endmacro

; RCHECK key, now — set the binder's first 8 bytes and call replay_check.
%macro RCHECK 2
    mov qword [binder], %1
    lea rdi, [binder]
    mov esi, %2
    call linnea_quic_replay_check
%endmacro

section .rodata
msg_head:  db "quic-replay "
msg_head_len equ $ - msg_head
msg_slash: db "/"
msg_nl:    db 10

section .bss
binder:    resb 32

section .text
_start:
    xor r14d, r14d                   ; total
    xor r15d, r15d                   ; pass

    ; a fresh binder is accepted and recorded
    RCHECK 0x1111, 100
    EXPECT rax, 1
    ; the same binder within the window is a replay
    RCHECK 0x1111, 105
    EXPECT rax, 0
    ; a different binder is fresh
    RCHECK 0x2222, 105
    EXPECT rax, 1
    ; the first binder is reusable once its window has passed (100 + 10 < 200)
    RCHECK 0x1111, 200
    EXPECT rax, 1

    ; fill the register: with all prior entries long expired (now = 100000), every
    ; one of the STRIKE_N distinct binders is accepted
    xor r13d, r13d                   ; fresh count
    xor r12d, r12d                   ; index
.fill:
    lea rax, [r12 + 1000000]         ; distinct keys, clear of the ones above
    mov [binder], rax
    lea rdi, [binder]
    mov esi, 100000
    call linnea_quic_replay_check
    add r13d, eax                    ; rax is 0/1
    inc r12d
    cmp r12d, STRIKE_N
    jb .fill
    EXPECT r13, STRIKE_N             ; all accepted

    ; one more distinct binder now finds the register full: fail closed
    RCHECK 1000512, 100000
    EXPECT rax, 0

    ; once those entries expire, the register accepts again
    RCHECK 0x3333, 200000
    EXPECT rax, 1

    ; --- ticket lifetime (tls-7): linnea_quic_ticket_within_lifetime ---
    ; issued == now: fresh
    mov rdi, 1000000
    mov rsi, 1000000
    call linnea_quic_ticket_within_lifetime
    EXPECT rax, 1
    ; one second short of the lifetime: fresh
    mov rdi, 1000000
    mov rsi, 1000000 + LINNEA_QUIC_TICKET_LIFETIME - 1
    call linnea_quic_ticket_within_lifetime
    EXPECT rax, 1
    ; exactly at the lifetime boundary: still fresh (rejection is strict, ja)
    mov rdi, 1000000
    mov rsi, 1000000 + LINNEA_QUIC_TICKET_LIFETIME
    call linnea_quic_ticket_within_lifetime
    EXPECT rax, 1
    ; one second past the lifetime: expired
    mov rdi, 1000000
    mov rsi, 1000000 + LINNEA_QUIC_TICKET_LIFETIME + 1
    call linnea_quic_ticket_within_lifetime
    EXPECT rax, 0
    ; issued in the future (clock skew): rejected
    mov rdi, 1000001
    mov rsi, 1000000
    call linnea_quic_ticket_within_lifetime
    EXPECT rax, 0

    ; --- ACK Delay scaling (quic-12 / RFC 9000 19.3): the field counts
    ; 2^ack_delay_exponent microseconds, and the exponent belongs to whoever SENT
    ; the ACK. The old code shifted by a hardcoded 7 (~ /128), i.e. it assumed the
    ; peer used the default 3; a peer advertising anything else was mis-scaled.
    ; 125 units at the default exponent 3 = 1000us = 1ms
    mov rdi, 125
    mov rsi, 3
    call linnea_quic_ack_delay_ms
    EXPECT rax, 1
    ; 1000 units at exponent 3 = 8000us = 8ms
    mov rdi, 1000
    mov rsi, 3
    call linnea_quic_ack_delay_ms
    EXPECT rax, 8
    ; the case the hardcoded shift got wrong: exponent 0 means 1us units, so the
    ; same raw value is 1ms, not the 7ms the old raw>>7 produced
    mov rdi, 1000
    mov rsi, 0
    call linnea_quic_ack_delay_ms
    EXPECT rax, 1
    ; and a large exponent scales up: 1000 << 10 = 1024000us = 1024ms
    mov rdi, 1000
    mov rsi, 10
    call linnea_quic_ack_delay_ms
    EXPECT rax, 1024
    ; zero delay stays zero
    mov rdi, 0
    mov rsi, 3
    call linnea_quic_ack_delay_ms
    EXPECT rax, 0
    ; 18.2: an exponent above 20 is invalid — clamp rather than shift wild
    mov rdi, 1
    mov rsi, 25
    call linnea_quic_ack_delay_ms
    EXPECT rax, 1048                 ; as if the exponent were 20
    ; a peer may claim a delay of 2^62 units: saturate instead of wrapping, and
    ; let the caller's max_ack_delay cap turn it into something sane
    mov rdi, 0x4000000000000000
    mov rsi, 20
    call linnea_quic_ack_delay_ms
    EXPECT rax, -1

    ; print "quic-replay <pass>/<total>\n"
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
