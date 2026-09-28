; ============================================================================
; linnea_leg_pool.asm -- the backend legs' borrowed arenas.
;
; A leg to a proxy_tls backend needs a TLS 1.3 client handshake arena
; (linnea_tls_client_hs, ~58 KiB) until the socket is handed to kTLS, and a leg
; to a proxy_h2 backend needs an h2 driver context (linnea_h2c, ~1.2 MiB: it
; buffers the backend's whole response) until that response is delivered.
;
; They used to be laid out per connection slot -- one handshake arena and one
; driver context per slot for the h1/h3 legs, and one of each per (slot, h2p
; slot) for the h2-client legs, 9 x 1.26 MiB for every slot -- mapped for all
; max_connections at startup. That is where the 11.4 MiB of address space per
; connection slot went, and why max_connections could not reach 3000 on a
; 16 GB host. Now both kinds come from per-worker pools (linnea_arena.asm),
; borrowed only while a leg uses them. Every holder also holds (or has just
; released) an upstream connection, so max_upstream -- the ceiling on those --
; is the pool's capacity; an exhausted pool fails the one request with 503.
;
; Two ways in: the h2p slot path (an h2 client) borrows with linnea_leg_*_get
; and keeps the pointer in its slot; the connection path (an h1 client, an h3
; relay leg) borrows through linnea_up_*_acquire, which parks the pointer in
; the connection so the long-standing linnea_tls_client_hs_for /
; linnea_h2c_ctx_for lookups by connection index keep working unchanged.
; Only the server links this object.
; ============================================================================

default rel

%include "linnea_tls_client.inc"
%include "linnea_h2_client.inc"
%include "linnea_connection.inc"
%include "linnea_arena.inc"

global linnea_leg_pools_init
global linnea_leg_tls_get
global linnea_leg_tls_put
global linnea_leg_h2c_get
global linnea_leg_h2c_put
global linnea_up_tls_acquire
global linnea_up_tls_release
global linnea_up_h2c_acquire
global linnea_up_arenas_release
global linnea_tls_client_hs_for
global linnea_h2c_ctx_for
global linnea_leg_tls_pool
global linnea_leg_h2c_pool

extern linnea_arena_pool_init
extern linnea_arena_get
extern linnea_arena_put
extern linnea_connection_at

section .bss
alignb 8
linnea_leg_tls_pool: resb linnea_arena_pool_size
linnea_leg_h2c_pool: resb linnea_arena_pool_size

section .text

; linnea_leg_pools_init(rdi = capacity: max_upstream). Once, at worker start.
; Maps nothing: each pool reserves its space on its first borrow.
linnea_leg_pools_init:
    push rbx
    mov rbx, rdi
    lea rdi, [linnea_leg_tls_pool]
    mov esi, linnea_tls_client_hs_size
    mov rdx, rbx
    call linnea_arena_pool_init
    lea rdi, [linnea_leg_h2c_pool]
    mov esi, linnea_h2c_size
    mov rdx, rbx
    call linnea_arena_pool_init
    pop rbx
    ret

; linnea_leg_tls_get() / linnea_leg_h2c_get() -> rax = arena, 0 = pool full.
linnea_leg_tls_get:
    lea rdi, [linnea_leg_tls_pool]
    jmp linnea_arena_get
linnea_leg_h2c_get:
    lea rdi, [linnea_leg_h2c_pool]
    jmp linnea_arena_get

; linnea_leg_tls_put(rdi = arena or 0) / linnea_leg_h2c_put(rdi = arena or 0).
linnea_leg_tls_put:
    mov rsi, rdi
    lea rdi, [linnea_leg_tls_pool]
    jmp linnea_arena_put
linnea_leg_h2c_put:
    mov rsi, rdi
    lea rdi, [linnea_leg_h2c_pool]
    jmp linnea_arena_put

; linnea_up_tls_acquire(rdi = conn*) -> rax = the connection's handshake arena,
; borrowing one if it holds none; 0 = the pool is full. Preserves rdi.
linnea_up_tls_acquire:
    mov rax, [rdi + linnea_connection.up_hs]
    test rax, rax
    jnz .ta_ret
    push rdi
    call linnea_leg_tls_get
    pop rdi
    mov [rdi + linnea_connection.up_hs], rax
.ta_ret:
    ret

; linnea_up_h2c_acquire(rdi = conn*) -> rax = its h2 driver context, borrowing
; one if it holds none; 0 = the pool is full. Preserves rdi.
linnea_up_h2c_acquire:
    mov rax, [rdi + linnea_connection.up_h2c]
    test rax, rax
    jnz .ca_ret
    push rdi
    call linnea_leg_h2c_get
    pop rdi
    mov [rdi + linnea_connection.up_h2c], rax
.ca_ret:
    ret

; linnea_up_tls_release(rdi = conn*) -- the handshake is over (kTLS has the
; keys) or abandoned; give the arena back. Preserves rdi.
linnea_up_tls_release:
    push rdi
    mov rax, rdi
    mov rdi, [rax + linnea_connection.up_hs]
    mov qword [rax + linnea_connection.up_hs], 0
    call linnea_leg_tls_put
    pop rdi
    ret

; linnea_up_arenas_release(rdi = conn*) -- the exchange is over: give back
; whatever the connection still holds. Safe on a connection holding nothing.
; Only once no operation can still touch them: the handshake arena is read by
; the sends of hs.out, and the driver context by the client send of the body
; out of ctx.body_buf, both of which have completed by the time the response
; is done or the connection is freed. Preserves rdi.
linnea_up_arenas_release:
    call linnea_up_tls_release
    push rdi
    mov rax, rdi
    mov rdi, [rax + linnea_connection.up_h2c]
    mov qword [rax + linnea_connection.up_h2c], 0
    call linnea_leg_h2c_put
    pop rdi
    ret

; linnea_tls_client_hs_for(rdi = connection pool index) -> rax = that
; connection's handshake arena (borrowed at its connect; see acquire above).
linnea_tls_client_hs_for:
    call linnea_connection_at
    mov rax, [rax + linnea_connection.up_hs]
    ret

; linnea_h2c_ctx_for(rdi = connection pool index) -> rax = its h2 driver context.
linnea_h2c_ctx_for:
    call linnea_connection_at
    mov rax, [rax + linnea_connection.up_h2c]
    ret
