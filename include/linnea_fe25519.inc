; Field arithmetic modulo p = 2^255 - 19, for X25519.
;
; A field element is five 64-bit limbs in radix 2^51 (the "donna64"
; representation): value = h0 + h1*2^51 + h2*2^102 + h3*2^153 + h4*2^204,
; limbs kept below ~2^52 between operations. 40 bytes, 8-byte aligned.

LINNEA_FE25519_SIZE     equ 40
LINNEA_FE25519_MASK51   equ 0x7ffffffffffff
