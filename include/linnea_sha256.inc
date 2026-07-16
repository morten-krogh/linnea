; SHA-256, HMAC-SHA256 and HKDF-SHA256 — the hash primitives the TLS 1.3
; key schedule is built on. Incremental hashing (init/update/final) exists
; because the handshake transcript is absorbed message by message.

struc linnea_sha256_ctx
    .h:     resd 8     ; the eight working state words
    .len:   resq 1     ; total bytes absorbed so far
    .buf:   resb 64    ; the partial block not yet compressed
endstruc

LINNEA_SHA256_DIGEST    equ 32
LINNEA_SHA256_BLOCK     equ 64
