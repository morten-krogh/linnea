; ============================================================================
; linnea_h2p_leg_pool.asm — per-(connection, h2p slot) backend-h2 leg arenas.
;
; An h2 CLIENT proxied to a proxy_h2 location runs its backend leg on an h2p
; SLOT (up to LINNEA_H2P_SLOTS concurrent per connection), so the TLS handshake
; state and the h2 driver context are keyed by (conn.index, slot) — one arena
; per slot, lazily demand-paged like the h2p slot pool itself. Split out so the
; standalone h2 harness never links linnea_memory_map. Only the server links it.
;
; Per-(conn,slot) rather than a shared acquire-on-demand pool: the slots already
; carry a .gen staleness guard, and linnea_tls_client_start / linnea_h2c_drv_start
; fully reinitialize their arenas, so a fixed arena per slot needs no free-list
; (and cannot leak or be used after release). The address space is large but
; demand-paged; only active proxy_h2 h2-client legs touch it.
; ============================================================================

%include "linnea_tls_client.inc"
%include "linnea_h2_client.inc"
%include "linnea_config.inc"         ; LINNEA_MAX_ROOT (linnea_http2.inc needs it)
%include "linnea_connection.inc"
%include "linnea_http2.inc"          ; LINNEA_H2P_SLOTS

global linnea_h2p_leg_pool_init
global linnea_h2p_tls_hs_for
global linnea_h2p_h2c_for

extern linnea_memory_map

section .bss
alignb 8
h2p_tls_pool: resq 1                 ; base: (conn*SLOTS+slot) linnea_tls_client_hs
h2p_h2c_pool: resq 1                 ; base: (conn*SLOTS+slot) linnea_h2c

section .text

; linnea_h2p_leg_pool_init(rdi = connection pool size). Called once at startup
; beside linnea_h2p_init / linnea_h2c_pool_init.
linnea_h2p_leg_pool_init:
    push rbx
    mov rbx, rdi
    imul rdi, rdi, LINNEA_H2P_SLOTS
    imul rdi, rdi, linnea_tls_client_hs_size
    call linnea_memory_map
    mov [h2p_tls_pool], rax
    mov rdi, rbx
    imul rdi, rdi, LINNEA_H2P_SLOTS
    imul rdi, rdi, linnea_h2c_size
    call linnea_memory_map
    mov [h2p_h2c_pool], rax
    pop rbx
    ret

; linnea_h2p_tls_hs_for(rdi = conn index, rsi = slot index) -> rax = that leg's
; linnea_tls_client_hs.
linnea_h2p_tls_hs_for:
    imul rdi, rdi, LINNEA_H2P_SLOTS
    add rdi, rsi
    imul rdi, rdi, linnea_tls_client_hs_size
    add rdi, [h2p_tls_pool]
    mov rax, rdi
    ret

; linnea_h2p_h2c_for(rdi = conn index, rsi = slot index) -> rax = that leg's
; linnea_h2c driver context.
linnea_h2p_h2c_for:
    imul rdi, rdi, LINNEA_H2P_SLOTS
    add rdi, rsi
    imul rdi, rdi, linnea_h2c_size
    add rdi, [h2p_h2c_pool]
    mov rax, rdi
    ret
