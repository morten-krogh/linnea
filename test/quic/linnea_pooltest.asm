; linnea_pooltest.asm — QUIC connection-pool tests: allocation, exhaustion,
; the idle sweep and slot reuse. The sweep takes the clock as a parameter, so
; connections can be aged instantly instead of waiting out the idle window.
; Prints "quic-pool <pass>/<total>" and exits 1 if any check fails.

default rel

%include "linnea_syscall.inc"
%include "linnea_quic.inc"
%include "linnea_quic_conn.inc"

global _start

extern linnea_quic_conn_alloc
extern linnea_quic_conn_lookup
extern linnea_quic_conn_free
extern linnea_quic_conn_sweep
extern linnea_quic_conn_active
extern linnea_print_stdout
extern linnea_print_u64_stdout

; EXPECT actual_reg, value — tally into r14d (total) / r15d (pass).
%macro EXPECT 2
    inc r14d
    mov r11, %2
    cmp %1, r11
    jne %%bad
    inc r15d
%%bad:
%endmacro

section .rodata
peer:      db 2, 0, 0x8d, 0xb9, 127, 0, 0, 1
           times 8 db 0
msg_head:  db "quic-pool "
msg_head_len equ $ - msg_head
msg_slash: db "/"
msg_nl:    db 10

section .bss
saved_scid: resb LINNEA_QUIC_SCID_LEN

section .text
_start:
    xor r14d, r14d                   ; total
    xor r15d, r15d                   ; pass

    ; --- fill the pool: every slot must allocate ---
    xor r12d, r12d                   ; successes
    xor r13d, r13d                   ; attempts
.fill:
    lea rdi, [peer]
    mov esi, 16
    call linnea_quic_conn_alloc
    test rax, rax
    jz .filled
    inc r12d
    ; keep the first connection's id, to look it up again later
    cmp r13d, 0
    jne .fill_next
    mov rcx, [rax + linnea_quic_conn.scid]
    mov [saved_scid], rcx
.fill_next:
    inc r13d
    cmp r13d, LINNEA_QUIC_MAX_CONNS
    jb .fill
.filled:
    mov r10d, r12d
    EXPECT r10, LINNEA_QUIC_MAX_CONNS        ; the whole pool allocates

    ; --- a full pool refuses, rather than handing out a live slot ---
    lea rdi, [peer]
    mov esi, 16
    call linnea_quic_conn_alloc
    EXPECT rax, 0

    call linnea_quic_conn_active
    EXPECT rax, LINNEA_QUIC_MAX_CONNS

    ; --- a live connection is still reachable by its id ---
    lea rdi, [saved_scid]
    mov esi, LINNEA_QUIC_SCID_LEN
    call linnea_quic_conn_lookup
    inc r14d
    test rax, rax
    jz .no_lookup
    inc r15d
.no_lookup:

    ; --- freeing one slot lets exactly one more connection in ---
    lea rdi, [saved_scid]
    mov esi, LINNEA_QUIC_SCID_LEN
    call linnea_quic_conn_lookup
    mov rdi, rax
    call linnea_quic_conn_free
    call linnea_quic_conn_active
    EXPECT rax, LINNEA_QUIC_MAX_CONNS - 1
    lea rdi, [peer]
    mov esi, 16
    call linnea_quic_conn_alloc
    inc r14d
    test rax, rax
    jz .no_reuse
    inc r15d
.no_reuse:

    ; --- the idle sweep reclaims everything that has gone quiet ---
    ; A clock far past every slot's last packet ages them all at once.
    mov rdi, 1 << 30
    mov esi, LINNEA_QUIC_IDLE_SECS
    call linnea_quic_conn_sweep
    EXPECT rax, LINNEA_QUIC_MAX_CONNS
    call linnea_quic_conn_active
    EXPECT rax, 0

    ; --- and the pool is usable again afterwards ---
    lea rdi, [peer]
    mov esi, 16
    call linnea_quic_conn_alloc
    inc r14d
    test rax, rax
    jz .no_realloc
    inc r15d
.no_realloc:

    ; --- a sweep must not touch a connection still in use ---
    mov rdi, 1
    mov esi, LINNEA_QUIC_IDLE_SECS
    call linnea_quic_conn_sweep      ; "now" before any last_active: nothing ages
    EXPECT rax, 0
    call linnea_quic_conn_active
    EXPECT rax, 1

    ; --- the peer's max_idle_timeout shortens the window (quic-12) ---
    ; RFC 9000 10.1 makes the effective idle timeout the minimum of the two
    ; advertised values. A slot carries the agreed window in .idle_secs; the
    ; sweep used to ignore it and apply our LINNEA_QUIC_IDLE_SECS to everyone,
    ; so a client that had told us it would forget the connection in a few
    ; seconds still held a slot for the full thirty.
    ; The live slot from above is our subject: give it a 5-second window and a
    ; last_active of 0, then sweep at "now" values either side of it.
    ; clear the pool, then take a slot of our own so the pointer is in hand
    mov rdi, 1 << 30
    mov esi, LINNEA_QUIC_IDLE_SECS
    call linnea_quic_conn_sweep
    lea rdi, [peer]
    mov esi, 16
    call linnea_quic_conn_alloc
    mov rbx, rax
    mov qword [rbx + linnea_quic_conn.idle_secs], 5
    mov qword [rbx + linnea_quic_conn.last_active], 0
    mov qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_CONNECTED
    mov rdi, 4                       ; inside the agreed 5s: survives
    mov esi, LINNEA_QUIC_IDLE_SECS
    call linnea_quic_conn_sweep
    EXPECT rax, 0
    mov rdi, 9                       ; past 5s but well inside our own 30s:
    mov esi, LINNEA_QUIC_IDLE_SECS   ; the peer's number is the one that binds
    call linnea_quic_conn_sweep
    EXPECT rax, 1
    call linnea_quic_conn_active
    EXPECT rax, 0

    ; --- and a peer window LONGER than ours does not extend ours ---
    lea rdi, [peer]
    mov esi, 16
    call linnea_quic_conn_alloc
    mov rbx, rax
    mov qword [rbx + linnea_quic_conn.idle_secs], 300   ; the min() is still ours
    mov qword [rbx + linnea_quic_conn.last_active], 0
    mov qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_CONNECTED
    mov rdi, LINNEA_QUIC_IDLE_SECS + 1
    mov esi, LINNEA_QUIC_IDLE_SECS
    call linnea_quic_conn_sweep
    EXPECT rax, 1

    ; print "quic-pool <pass>/<total>\n"
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
