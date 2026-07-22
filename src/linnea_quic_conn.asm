; linnea_quic_conn.asm — the QUIC connection pool. Slots are demultiplexed by
; the connection ID we issued: its first two bytes hold the pool index, so an
; incoming packet is routed with an index read and one 8-byte compare, without
; a hash map. The remaining six bytes are random, so an ID cannot be guessed
; and a stale or spoofed one fails the compare.

default rel

%include "linnea_syscall.inc"
%include "linnea_quic.inc"
%include "linnea_quic_conn.inc"

global linnea_quic_conn_lookup
global linnea_quic_conn_alloc
global linnea_quic_conn_free
global linnea_quic_conn_sweep
global linnea_quic_conn_active
global linnea_quic_conn_slot
global linnea_worker_index

section .bss
conn_pool: resb LINNEA_QUIC_MAX_CONNS * linnea_quic_conn_size
; this worker's index (0-based), stamped into every connection id it issues so
; the BPF reuseport program can steer the connection's later packets back here.
; Zero until the master sets it after fork; a single-worker server never changes it.
linnea_worker_index: resq 1

section .text

; linnea_quic_conn_lookup(rdi=dcid ptr, rsi=dcid len) -> rax = conn* or 0.
linnea_quic_conn_lookup:
    cmp rsi, LINNEA_QUIC_SCID_LEN
    jne .miss                        ; not an ID we could have issued
    movzx eax, byte [rdi + 1]        ; pool index (byte 0 is the worker, for steering)
    cmp eax, LINNEA_QUIC_MAX_CONNS
    jae .miss
    imul rax, rax, linnea_quic_conn_size
    lea rax, [conn_pool + rax]
    cmp qword [rax + linnea_quic_conn.in_use], 0
    je .miss
    ; the full ID must match — the random tail authenticates the slot
    mov rcx, [rdi]
    cmp rcx, [rax + linnea_quic_conn.scid]
    jne .miss
    ; a packet arrived for it, so it is not idle
    push rax
    call conn_now
    pop rcx
    mov [rcx + linnea_quic_conn.last_active], rax
    mov rax, rcx
    ret
.miss:
    xor eax, eax
    ret

; linnea_quic_conn_alloc(rdi=peer ptr, rsi=peer len) -> rax = conn* or 0.
linnea_quic_conn_alloc:
    push rbx
    push r12
    push r13
    push r14
    mov r13, rdi                     ; peer
    mov r14, rsi                     ; peer len
    ; reclaim anything that has gone quiet before looking for a free slot, so
    ; connections abandoned without a close cannot fill the pool for good
    call conn_now
    mov rdi, rax
    mov esi, LINNEA_QUIC_IDLE_SECS
    call linnea_quic_conn_sweep
    xor r12d, r12d                   ; index
    lea rbx, [conn_pool]
.scan:
    cmp qword [rbx + linnea_quic_conn.in_use], 0
    je .found
    add rbx, linnea_quic_conn_size
    inc r12d
    cmp r12d, LINNEA_QUIC_MAX_CONNS
    jb .scan
    xor eax, eax                     ; pool exhausted
    jmp .aret
.found:
    ; zero the slot, then fill in identity and peer
    mov rdi, rbx
    xor eax, eax
    mov ecx, linnea_quic_conn_size
    rep stosb
    mov qword [rbx + linnea_quic_conn.in_use], 1
    mov qword [rbx + linnea_quic_conn.state], LINNEA_QUIC_ST_NEW
    ; connection id = worker index || pool index || 6 random bytes. The worker
    ; index steers the connection back to this worker (BPF reuseport); the pool
    ; index locates the slot; the random tail authenticates it.
    mov [rbx + linnea_quic_conn.scid + 1], r12b       ; pool index
    mov eax, [linnea_worker_index]
    mov [rbx + linnea_quic_conn.scid], al             ; worker index
    lea rdi, [rbx + linnea_quic_conn.scid + 2]
    mov esi, LINNEA_QUIC_SCID_LEN - 2
    xor edx, edx
    mov eax, LINNEA_SYS_GETRANDOM
    syscall
    cmp rax, LINNEA_QUIC_SCID_LEN - 2
    jne .arand_fail
    ; record the peer address
    mov rcx, r14
    cmp rcx, 16
    jbe .acplen
    mov ecx, 16
.acplen:
    mov [rbx + linnea_quic_conn.peer_len], rcx
    mov rsi, r13
    lea rdi, [rbx + linnea_quic_conn.peer]
    rep movsb
    call conn_now
    mov [rbx + linnea_quic_conn.last_active], rax
    mov rax, rbx
    jmp .aret
.arand_fail:
    mov qword [rbx + linnea_quic_conn.in_use], 0
    xor eax, eax
.aret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; linnea_quic_conn_sweep(rdi=now seconds, rsi=idle seconds) -> rax = slots freed.
; Frees every slot whose last packet is older than the idle window. The clock is
; a parameter rather than read here so a test can age connections instantly.
linnea_quic_conn_sweep:
    push rbx
    push r12
    xor r12d, r12d                   ; freed
    lea rbx, [conn_pool]
    mov rcx, LINNEA_QUIC_MAX_CONNS
.sw_slot:
    cmp qword [rbx + linnea_quic_conn.in_use], 0
    je .sw_next
    mov rax, rdi
    sub rax, [rbx + linnea_quic_conn.last_active]
    jb .sw_next                      ; stamped ahead of now: treat as active,
                                     ; never let the subtraction wrap and
                                     ; reclaim a live connection
    cmp rax, rsi
    jbe .sw_next                     ; still within the idle window
    mov qword [rbx + linnea_quic_conn.in_use], 0
    inc r12d
.sw_next:
    add rbx, linnea_quic_conn_size
    dec rcx
    jnz .sw_slot
    mov eax, r12d
    pop r12
    pop rbx
    ret

; linnea_quic_conn_active() -> rax = slots currently in use.
linnea_quic_conn_active:
    xor eax, eax
    lea rdx, [conn_pool]
    mov ecx, LINNEA_QUIC_MAX_CONNS
.ac_slot:
    cmp qword [rdx + linnea_quic_conn.in_use], 0
    je .ac_next
    inc eax
.ac_next:
    add rdx, linnea_quic_conn_size
    dec ecx
    jnz .ac_slot
    ret

; linnea_quic_conn_slot(rdi=index) -> rax = conn* if that slot is in use, else 0.
; Lets a caller walk the pool by index (the loss-recovery sweep needs every live
; connection) without exposing the pool array.
linnea_quic_conn_slot:
    cmp rdi, LINNEA_QUIC_MAX_CONNS
    jae .none
    imul rax, rdi, linnea_quic_conn_size
    lea rax, [conn_pool + rax]
    cmp qword [rax + linnea_quic_conn.in_use], 0
    je .none
    ret
.none:
    xor eax, eax
    ret

; conn_now() -> rax = CLOCK_MONOTONIC seconds. Monotonic so a clock step cannot
; make every connection look ancient (or eternally fresh).
conn_now:
    sub rsp, 24
    mov eax, LINNEA_SYS_CLOCK_GETTIME
    mov edi, LINNEA_CLOCK_MONOTONIC
    mov rsi, rsp
    syscall
    mov rax, [rsp]
    add rsp, 24
    ret

; linnea_quic_conn_free(rdi=conn) — return the slot to the pool.
linnea_quic_conn_free:
    test rdi, rdi
    jz .fret
    mov qword [rdi + linnea_quic_conn.in_use], 0
.fret:
    ret
