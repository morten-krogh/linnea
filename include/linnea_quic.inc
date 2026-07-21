; QUIC (RFC 9000 / 9001) constants and structures.

; A packet-protection key set for one direction and encryption level.
struc linnea_quic_keys
    .key:  resb 16      ; AEAD_AES_128_GCM key
    .iv:   resb 12      ; AEAD nonce base (XORed with the packet number)
    .hp:   resb 16      ; header-protection key (AES-128-ECB)
endstruc

LINNEA_QUIC_MAX_CID   equ 20      ; RFC 9000: connection IDs are 0..20 bytes
