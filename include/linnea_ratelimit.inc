; linnea_ratelimit.inc — the per-address token bucket's table shape.

; Slots per worker. A power of two so the probe can mask instead of divide.
; 4096 entries at 40 bytes is 160 KB of .bss per worker, faulted lazily like
; every other pool here — and far more addresses than max_connections can have
; open at once, so an ordinary load never evicts anything.
LINNEA_RL_SHIFT   equ 12
LINNEA_RL_SLOTS   equ 1 << LINNEA_RL_SHIFT
; How far to probe before evicting the least recently seen of the slots looked
; at. Short on purpose: the cost of giving up early is a full bucket for one
; address, which errs toward allowing rather than refusing.
LINNEA_RL_PROBES  equ 4

struc linnea_rl_entry
    .key_hi:  resq 1      ; first 8 address bytes
    .key_lo:  resq 1      ; the second 8, for a zero /64 (mapped IPv4, loopback)
    .klen:    resq 1      ; address length; 0 = the slot is free
    .tokens:  resq 1      ; milli-tokens held
    .last:    resq 1      ; when the bucket was last refilled, ms
endstruc
