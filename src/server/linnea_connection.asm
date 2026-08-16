; linnea_connection.asm — fixed-size connection pool with a free list.
; The pool is one anonymous mmap allocated at startup; slots are linked
; through .next_free and handed out in O(1).

default rel

%include "linnea_connection.inc"

global linnea_connections_init
global linnea_connection_alloc
global linnea_connection_free
global linnea_connection_at
global linnea_connection_count_ip
global linnea_upstream_open
global linnea_upstream_closed
global linnea_upstream_count
global linnea_upstream_limit
global linnea_connection_active

extern linnea_memory_map

section .bss

; Upstream connections in flight, and the ceiling on them. Every proxied request
; opens a connection to the backend, and nothing tied that to the backend's
; capacity: a flood arriving here becomes a flood arriving there, and the server
; survives while what it proxies for does not. Counted rather than scanned
; because the scan would have to walk every connection's slots on every proxied
; request; the count is maintained at the few places an upstream socket is opened
; and closed, and every decrement is guarded by the same "was it open" test that
; guards the close itself.
linnea_upstream_inflight: resq 1
linnea_upstream_limit:    resq 1
pool_base:      resq 1
pool_size:      resq 1         ; slots in the pool (walkers need the bound)
free_head:      resq 1         ; pool index of first free slot, -1 = none
linnea_connection_active: resq 1   ; slots handed out; drains read it

section .text

; linnea_connections_init(rdi=pool size) — allocate and chain the free list.
linnea_connections_init:
    push rbx
    mov rbx, rdi               ; pool size
    mov [pool_size], rdi
    imul rdi, rdi, linnea_connection_size
    call linnea_memory_map
    mov [pool_base], rax
    mov rdx, rax               ; slot cursor
    xor ecx, ecx               ; index
.chain:
    cmp rcx, rbx
    jae .done
    mov [rdx + linnea_connection.index], rcx
    lea r8, [rcx + 1]
    cmp r8, rbx
    jne .link
    mov r8, -1
.link:
    mov [rdx + linnea_connection.next_free], r8
    add rdx, linnea_connection_size
    inc rcx
    jmp .chain
.done:
    mov qword [free_head], 0
    pop rbx
    ret

; linnea_connection_alloc() -> rax=connection* or 0 when the pool is empty.
linnea_connection_alloc:
    mov rax, [free_head]
    cmp rax, -1
    je .empty
    imul rdx, rax, linnea_connection_size
    add rdx, [pool_base]
    mov rcx, [rdx + linnea_connection.next_free]
    mov [free_head], rcx
    mov qword [rdx + linnea_connection.in_use], 1
    mov qword [rdx + linnea_connection.in_len], 0
    mov qword [rdx + linnea_connection.head_len], 0
    mov qword [rdx + linnea_connection.keep_alive], 0
    mov qword [rdx + linnea_connection.out_rem], 0
    mov qword [rdx + linnea_connection.file_base], 0
    mov qword [rdx + linnea_connection.file_size], 0
    mov qword [rdx + linnea_connection.file_ptr], 0
    mov qword [rdx + linnea_connection.file_rem], 0
    mov dword [rdx + linnea_connection.up_fd], -1
    mov dword [rdx + linnea_connection.spill_fd], -1
    mov qword [rdx + linnea_connection.spill_len], 0
    mov qword [rdx + linnea_connection.chunk_state], LINNEA_CHUNK_SIZE
    mov qword [rdx + linnea_connection.chunk_rem], 0
    mov qword [rdx + linnea_connection.chunk_digits], 0
    mov qword [rdx + linnea_connection.chunk_raw], 0
    mov qword [rdx + linnea_connection.capture_chunked], 0
    mov qword [rdx + linnea_connection.capture_done], 0
    mov qword [rdx + linnea_connection.pend_len], 0
    mov qword [rdx + linnea_connection.answer_linger], 0
    mov qword [rdx + linnea_connection.proxy_state], LINNEA_PROXY_IDLE
    mov qword [rdx + linnea_connection.h3_owner], 0   ; a client-facing slot
                                                      ; until an h3 leg claims it
    mov qword [rdx + linnea_connection.tls_phase], LINNEA_TLS_PHASE_NONE
    mov qword [rdx + linnea_connection.close_notified], 0
    mov qword [rdx + linnea_connection.is_h2], 0
    mov qword [rdx + linnea_connection.h2_state], 0
    mov qword [rdx + linnea_connection.h2_tx_busy], 0
    mov qword [rdx + linnea_connection.h2_rx_busy], 0
    mov qword [rdx + linnea_connection.tx_inflight], 0
    mov qword [rdx + linnea_connection.ku_pending], 0
    inc qword [rdx + linnea_connection.gen]      ; this slot's new incarnation
    inc qword [linnea_connection_active]
    mov rax, rdx
    ret
.empty:
    xor eax, eax
    ret

; linnea_connection_free(rdi=connection*)
linnea_connection_free:
    ; Idempotent: a double free would link the slot to itself, and every
    ; later alloc would hand out that same slot to every new client.
    cmp qword [rdi + linnea_connection.in_use], 0
    je .already_free
    mov qword [rdi + linnea_connection.in_use], 0
    mov rax, [free_head]
    mov [rdi + linnea_connection.next_free], rax
    mov rax, [rdi + linnea_connection.index]
    mov [free_head], rax
    dec qword [linnea_connection_active]
.already_free:
    ret

; linnea_connection_at(rdi=pool index) -> rax=connection*
linnea_connection_at:
    imul rax, rdi, linnea_connection_size
    add rax, [pool_base]
    ret


; linnea_connection_count_ip(rdi = address, rsi = length) -> rax = how many live
; connections come from that address. A walk of the pool rather than a table on
; the side: the pool is the truth, so the count cannot drift from it, and the
; walk happens once per accept.
linnea_connection_count_ip:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    xor r14d, r14d             ; count
    xor r15d, r15d             ; index
.ci_slot:
    cmp r15, [pool_size]
    jae .ci_done
    mov rdi, r15
    call linnea_connection_at
    mov rbx, rax
    cmp qword [rbx + linnea_connection.in_use], 0
    je .ci_next
    cmp [rbx + linnea_connection.peer_ip_len], r13
    jne .ci_next
    mov rax, [rbx + linnea_connection.peer_ip]        ; first 8 address bytes
    cmp rax, [r12]
    jne .ci_next
    cmp r13, 8
    jbe .ci_hit                ; IPv4 (len 4) is fully matched by the 8 bytes
    ; IPv6: cap on the /64 routing prefix — a client with an ordinary /64 has
    ; 2^64 addresses and matching the full /128 would let it evade the cap. But
    ; a zero /64 prefix is an IPv4-mapped address (::ffff:a.b.c.d) or loopback,
    ; whose distinguishing bits are in the low 8 bytes; the listeners are
    ; dual-stack, so IPv4 arrives mapped and must stay per-address. Match the
    ; full /128 there, the /64 otherwise.
    test rax, rax
    jnz .ci_hit                ; native IPv6 /64 prefix: enough on its own
    mov rax, [rbx + linnea_connection.peer_ip + 8]
    cmp rax, [r12 + 8]
    jne .ci_next
.ci_hit:
    inc r14d
.ci_next:
    inc r15
    jmp .ci_slot
.ci_done:
    mov rax, r14
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


; linnea_upstream_open() — one more upstream connection is live.
linnea_upstream_open:
    inc qword [linnea_upstream_inflight]
    ret

; linnea_upstream_closed() — one fewer. Floors at zero: a miscount must not be
; able to wrap into "billions in flight" and refuse every proxied request from
; then on.
linnea_upstream_closed:
    cmp qword [linnea_upstream_inflight], 0
    je .none
    dec qword [linnea_upstream_inflight]
.none:
    ret

; linnea_upstream_count() -> rax = upstream connections in flight, and whether
; that is at the limit is the caller's business.
linnea_upstream_count:
    mov rax, [linnea_upstream_inflight]
    ret
