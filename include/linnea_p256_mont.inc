; Montgomery arithmetic modulo a 256-bit prime, parameterised by the modulus.
;
; ECDSA P-256 needs two moduli: the field prime p, for point coordinates, and
; the group order n, for scalars (s = k^-1 * (e + r*d) mod n). They differ in
; one structural way -- p0 = -1 mod 2^64 gives p the multiplier shortcut
; n0' = 1, while n's n0' is a real constant -- but the reduction is otherwise
; identical, and its carry handling is subtle enough (a round's carry ripples
; two limbs past its window; getting that wrong fails about one multiply in
; 30,000) that having two copies of it would be a liability. So the core takes
; a context and both moduli share it, at the cost of one imul per round on the
; p path.
;
; A value is four 64-bit limbs, little-endian, in Montgomery form (value * R
; mod m, R = 2^256), always fully reduced below m. 32 bytes.
;
; Callers do not normally use this module directly: linnea_p256_fe.asm binds
; it to p and linnea_p256_scalar.asm binds it to n, each exposing a plain
; two/three-argument API. See those files.

LINNEA_P256_LIMB_BYTES  equ 32

; The modulus context. Laid out by hand in each binding module's .rodata, so
; the field offsets here are load-bearing.
struc linnea_p256_mont_ctx
    .m:    resb 32     ; the modulus, four little-endian limbs
    .n0:   resq 1      ; -m^-1 mod 2^64: the reduction round's multiplier
    .r1:   resb 32     ; R mod m -- Montgomery's "one"
    .r2:   resb 32     ; R^2 mod m -- multiply by this to enter the form
    .exp:  resb 32     ; m-2, the Fermat exponent used by inv
endstruc
