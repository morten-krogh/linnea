; Ed25519 signatures (RFC 8032). The server signs the TLS 1.3
; CertificateVerify; it never verifies, so only signing is implemented.

LINNEA_ED25519_SEED     equ 32     ; private key (the RFC's "seed")
LINNEA_ED25519_PUBLIC   equ 32
LINNEA_ED25519_SIG      equ 64     ; R (32) || S (32)
