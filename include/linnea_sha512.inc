; SHA-512 — needed inside Ed25519 (key expansion, nonce, challenge hashes)
; and structurally identical to SHA-256 but with 64-bit words, 128-byte
; blocks, 80 rounds. Incremental hashing is used because Ed25519 hashes
; concatenations (prefix || M, R || A || M) whose message part can be large.

struc linnea_sha512_ctx
    .h:     resq 8     ; eight 64-bit state words
    .len:   resq 1     ; total bytes absorbed (assumed < 2^61)
    .buf:   resb 128   ; the partial block
endstruc

LINNEA_SHA512_DIGEST    equ 64
LINNEA_SHA512_BLOCK     equ 128
