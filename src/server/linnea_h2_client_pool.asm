; ============================================================================
; linnea_h2_client_pool.asm — per-connection backend HTTP/2 leg contexts.
;
; One linnea_h2c context per connection slot, lazily demand-paged like the TLS
; handshake pool and h2_dyn_pool. Split out so the standalone h2 harness does not
; drag in linnea_memory_map and its error-exit chain. Only the server links this.
; ============================================================================

%include "linnea_h2_client.inc"

global linnea_h2c_pool_init
global linnea_h2c_ctx_for

extern linnea_memory_map

section .bss
alignb 8
h2c_pool: resq 1                 ; base of the array of per-leg contexts

section .text

; linnea_h2c_pool_init(rdi = connection pool size) — map one h2 leg context per
; connection slot. Called once at startup beside linnea_h2p_init.
linnea_h2c_pool_init:
    imul rdi, rdi, linnea_h2c_size
    call linnea_memory_map
    mov [h2c_pool], rax
    ret

; linnea_h2c_ctx_for(rdi = connection pool index) -> rax = that leg's linnea_h2c.
; linnea_h2c_drv_start fully reinitializes it, so no generation-reset is needed.
linnea_h2c_ctx_for:
    imul rdi, rdi, linnea_h2c_size
    add rdi, [h2c_pool]
    mov rax, rdi
    ret
