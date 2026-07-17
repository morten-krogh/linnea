; Field arithmetic modulo the NIST P-256 prime, for ECDSA signing.
;
; p = 2^256 - 2^224 + 2^192 + 2^96 - 1
;
; A field element is four 64-bit limbs, little-endian, held in MONTGOMERY
; form (the value times 2^256 mod p). 32 bytes, 8-byte aligned.
;
; Unlike 2^255-19 this prime affords no lazy reduction: it is not close to a
; power of two, there is no radix-2^51 slack to carry between operations, and
; every multiply must reduce. Limbs are therefore always fully reduced
; (< p) on entry and exit -- the opposite discipline to fe25519, where limbs
; float below ~2^52 and only tobytes canonicalises. Do not carry habits
; across.
;
; P-256 does have one happy structural property: p0 = 2^64-1 = -1 mod 2^64,
; so -p^-1 mod 2^64 = 1 and each Montgomery reduction round's multiplier is
; just the low limb itself -- no multiply needed to find it. That is why this
; module uses Montgomery form rather than Solinas reduction (OpenSSL's P-256
; makes the same call for the same reason).
;
; Montgomery form does not escape this module: frombytes converts in, tobytes
; converts out, and both speak the BIG-endian SEC1 encoding used on the wire.
; Note that is the reverse of the 25519 modules, which are little-endian
; throughout -- the two coexist in one binary (x25519 is still the key
; exchange), so the byte order is a per-module property, not a codebase one.
;
; Everything here runs during the handshake only (one signature per
; connection), never on bulk data: written for correctness, not the last
; cycle. No secret-dependent branches or memory indices.

LINNEA_P256_FE_SIZE     equ 32
