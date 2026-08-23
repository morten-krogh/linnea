; ============================================================================
; linnea_tls_client_pool.asm — per-connection backend-TLS handshake arenas.
;
; Split out of linnea_tls_client.asm so the standalone handshake harness
; (bin/linnea-tlsclient) does not drag in linnea_memory_map and its whole
; error-exit chain: the harness uses a single .bss leg and never allocates a
; pool. Only the server links this object, beside linnea_h2p_init's arena.
; ============================================================================

%include "linnea_tls_client.inc"

global linnea_tls_client_pool_init
global linnea_tls_client_hs_for

extern linnea_memory_map

section .bss
alignb 8
tls_client_pool: resq 1          ; base of the array of per-leg arenas

section .text

; linnea_tls_client_pool_init(rdi = connection pool size) — map one handshake
; arena per connection slot (lazily demand-paged, like h2_dyn_pool). Called once
; at startup beside linnea_h2p_init.
linnea_tls_client_pool_init:
    imul rdi, rdi, linnea_tls_client_hs_size
    call linnea_memory_map
    mov [tls_client_pool], rax
    ret

; linnea_tls_client_hs_for(rdi = connection pool index) -> rax = that leg's
; linnea_tls_client_hs. linnea_tls_client_start fully reinitializes it, so no
; generation-reset dance is needed.
linnea_tls_client_hs_for:
    imul rdi, rdi, linnea_tls_client_hs_size
    add rdi, [tls_client_pool]
    mov rax, rdi
    ret
