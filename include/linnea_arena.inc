; linnea_arena.inc -- a per-worker pool of equal-sized arenas, borrowed while a
; request needs one and handed back when it ends (src/server/linnea_arena.asm).
;
; The big per-request state (a proxied HTTP/2 stream's relay slot, a backend
; leg's TLS handshake arena and h2 driver context) used to be laid out once per
; connection slot at startup, max_connections times over, so the address space
; a worker reserved grew with max_connections and not with what it was doing:
; 11.4 MiB per slot, and a worker at max_connections 3000 could not start on a
; 16 GB host. A pool is sized instead by the most that can be in use at once,
; which a documented limit already bounds (max_upstream and friends), and it
; costs nothing until it is used:
;
;   - the reservation is made on the FIRST borrow, not at startup, and with
;     MAP_NORESERVE, so an idle worker holds neither memory nor commit charge
;     for it, and a pool no location can use (no proxy_h2 in the config) is
;     never mapped at all;
;   - a returned arena is MADV_DONTNEED'd, so its pages go back to the kernel
;     and the next borrower finds it zero-filled, exactly as a first use would;
;   - an exhausted pool answers 0, and every caller turns that into the one
;     request failing cleanly (REFUSED_STREAM, 503) -- never the connection.
;
; Free arenas are a stack of indices, so the most recently returned (whose
; page tables are still warm) is reused first; indices never handed out are
; taken from `fresh` upward, so the stack needs no initialising walk.

struc linnea_arena_pool
    .base:     resq 1        ; the reservation, 0 until the first borrow
    .elem:     resq 1        ; arena size, rounded up to whole pages
    .cap:      resq 1        ; arenas in the reservation
    .fresh:    resq 1        ; indices below this have been handed out once
    .free_n:   resq 1        ; entries on the free stack
    .stack:    resq 1        ; u32 free-index stack (inside the reservation)
    .used:     resq 1        ; arenas currently borrowed
    .peak:     resq 1        ; the most ever borrowed at once
    .refused:  resq 1        ; borrows answered 0 because the pool was full
endstruc
