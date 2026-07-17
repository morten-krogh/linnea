; Points on NIST P-256: y^2 = x^3 - 3x + b over GF(p).
;
; Homogeneous projective coordinates (X:Y:Z), each a field element in
; Montgomery form, representing the affine point (X/Z, Y/Z). Z = 0 is the
; identity. 96 bytes. NOT Jacobian: the complete addition formula this module
; uses is stated in projective coordinates.
;
; Only what signing needs: addition and scalar multiplication. There is no
; point decompression, no verification, and no variable-base ladder -- the
; server signs and never verifies, so the only scalar multiplication that
; ever happens is k*G.

LINNEA_P256_POINT_SIZE  equ 96

struc linnea_p256_point
    .x:  resb 32
    .y:  resb 32
    .z:  resb 32
endstruc
